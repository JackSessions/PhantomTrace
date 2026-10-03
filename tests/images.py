"""Builds real NTFS images with mkntfs/ntfscp, then tampers with copies so the detector can be tested against known answers."""
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import phantom_trace as pt  # noqa: E402


def have_tools() -> bool:
    return all(shutil.which(t) for t in ("mkntfs", "ntfscp"))


def build_clean(path: str, files: int = 24, size_mb: int = 64, step: int = 5000):
    subprocess.run(["truncate", "-s", f"{size_mb}M", path], check=True)
    subprocess.run(["mkntfs", "-F", "-f", "-Q", "-L", "pt", "-c", "4096", path], check=True, capture_output=True)
    with tempfile.TemporaryDirectory() as d:
        for i in range(files):
            src = os.path.join(d, f"file{i}.bin")
            with open(src, "wb") as f:
                f.write(os.urandom(300 if i % 4 == 0 else 6000 + (i * step) % 120000))      # some resident, most non-resident
            subprocess.run(["ntfscp", "-f", path, src, f"file{i}.bin"], check=True, capture_output=True)


def open_fs(path):
    fh = open(path, "rb")
    return fh, pt.Ntfs(fh)


def find(fs, name):
    for i, raw, rec in fs.records():
        if rec and rec.in_use and rec.name() == name:
            return rec
    raise KeyError(name)


def first_run(rec):
    for a in rec.attrs:
        if a.type == pt.ATTR_DATA and a.nonresident:
            return a, a.runs[0]
    raise KeyError("no non-resident data")


def patch(path, pos, data: bytes):
    with open(path, "r+b") as f:
        f.seek(pos)
        f.write(data)


def tamper_bitmap_free(path, name="file1.bin"):
    """Clear the volume-bitmap bits for a file's clusters (hiding / un-allocating data)."""
    fh, fs = open_fs(path)
    rec = find(fs, name); _, (lcn, length) = first_run(rec)
    brec = pt.parse_record(pt.MFT_REC_BITMAP, fs.raw_record(pt.MFT_REC_BITMAP))
    bruns = next(a.runs for a in brec.attrs if a.type == pt.ATTR_DATA)
    bm_start = bruns[0][0] * fs.cluster
    bm = bytearray(fs.volume_bitmap()); fh.close()
    for c in range(lcn, lcn + length):
        bm[c >> 3] &= ~(1 << (c & 7)) & 0xFF
    patch(path, bm_start, bytes(bm[:bruns[0][1] * fs.cluster]))


def tamper_flag_flip(path, name="file2.bin"):
    """Mark an in-use record as deleted in its header only."""
    fh, fs = open_fs(path)
    rec = find(fs, name); pos = fs.record_offset(rec.number) + 0x16; fh.close()
    patch(path, pos, (rec.flags & ~pt.REC_IN_USE).to_bytes(2, "little"))


def tamper_cross_alloc(path, a_name="file3.bin", b_name="file5.bin"):
    """Rewrite file B's first run so it starts where file A's data starts."""
    fh, fs = open_fs(path)
    a = find(fs, a_name); b = find(fs, b_name)
    _, (alcn, _) = first_run(a); battr, (blcn, _) = first_run(b)
    raw = bytearray(fs.raw_record(b.number)); fh.close()
    off = pt.u16(raw, 0x14)
    while True:                                                   # locate B's $DATA attribute in the raw record
        t = pt.u32(raw, off)
        if t == pt.ATTR_DATA and raw[off + 8] == 1:
            break
        off += pt.u32(raw, off + 4)
    rl = off + pt.u16(raw, off + 0x20); h = raw[rl]; ls, os_ = h & 0xF, h >> 4
    raw_new = alcn.to_bytes(os_, "little", signed=True)         # the first run's offset is absolute
    assert int.from_bytes(raw_new, "little", signed=True) == alcn, "does not fit"
    # patch inside the on-disk record (fixups only touch bytes 510-511 and 1022-1023, outside the run list here)
    patch(path, fs.record_offset(b.number) + rl + 1 + ls, raw_new)


def tamper_torn(path, name="file4.bin"):
    fh, fs = open_fs(path)
    rec = find(fs, name); pos = fs.record_offset(rec.number) + 510; fh.close()
    patch(path, pos, b"\xde\xad")


def tamper_mirror(path):
    fh, fs = open_fs(path)
    pos = fs.mirr_lcn * fs.cluster + fs.rec_size + 0x30; fh.close()
    patch(path, pos, b"\xff")


SCENARIOS = {
    "bitmap_free": (tamper_bitmap_free, "clusters_free_in_bitmap"),
    "flag_flip": (tamper_flag_flip, "mft_flag_vs_bitmap"),
    "cross_alloc": (tamper_cross_alloc, "cross_allocated"),
    "torn_record": (tamper_torn, "bad_fixup"),
    "mirror": (tamper_mirror, "mirror_mismatch"),
}


def can_mount() -> bool:
    return have_tools() and shutil.which("ntfs-3g") is not None and os.path.exists("/dev/fuse") and shutil.which("fusermount") is not None


class MountUnavailable(Exception):
    """ntfs-3g could not mount the image (common on CI runners and in containers without FUSE permission)."""


def build_churned(path: str, size_mb: int = 128):
    """A volume used the way a real one is: created through a live ntfs-3g mount with many files, deletions, rewrites and fragmentation."""
    subprocess.run(["truncate", "-s", f"{size_mb}M", path], check=True)
    subprocess.run(["mkntfs", "-F", "-f", "-Q", "-L", "churn", "-c", "4096", path], check=True, capture_output=True)
    mnt = tempfile.mkdtemp()
    try:
        subprocess.run(["ntfs-3g", path, mnt, "-o", "rw"], check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        os.rmdir(mnt)
        raise MountUnavailable(e.stderr.decode(errors="replace").strip()[:200]) from e
    try:
        for d in ("a", "a/b", "c"):
            os.makedirs(os.path.join(mnt, d), exist_ok=True)
        rnd = lambda n: os.urandom(n)
        for i in range(1, 121):
            with open(f"{mnt}/a/f{i}.bin", "wb") as f: f.write(rnd(100 + (i * 7919) % 60000))
        for i in range(3, 121, 3): os.remove(f"{mnt}/a/f{i}.bin")
        for i in range(1, 41):
            with open(f"{mnt}/a/b/g{i}.bin", "wb") as f: f.write(rnd(5000 + (i * 104729) % 120000))
        for i in range(1, 301):
            with open(f"{mnt}/c/t{i}.txt", "w") as f: f.write(f"tiny {i}\n")
        for i in range(5, 41, 5):
            shutil.copy(f"{mnt}/a/b/g{i}.bin", f"{mnt}/a/b/h{i}.bin"); os.remove(f"{mnt}/a/b/g{i}.bin")
        with open(f"{mnt}/big.dat", "wb") as f: f.write(rnd(6_000_000))
        with open(f"{mnt}/big.dat", "ab") as f: f.write(rnd(2_000_000))
        os.sync()
    finally:
        subprocess.run(["fusermount", "-u", mnt], check=True)
        os.rmdir(mnt)


def tamper_timestomp(path, name="file6.bin"):
    """Backdate all four $STANDARD_INFORMATION times to a whole-second value, the way simple timestomp tools do."""
    from datetime import datetime
    fh, fs = open_fs(path)
    rec = find(fs, name); raw = fs.raw_record(rec.number); fh.close()
    off = pt.u16(raw, 0x14)
    while pt.u32(raw, off) != 0x10:
        off += pt.u32(raw, off + 4)
    content = off + pt.u16(raw, off + 0x14)
    ft = int((datetime(2005, 1, 1) - datetime(1601, 1, 1)).total_seconds()) * 10_000_000
    patch(path, fs.record_offset(rec.number) + content, ft.to_bytes(8, "little") * 4)


def build_disk(path, layout="msdos", tamper=None):
    """A whole-disk image: partition table + one NTFS partition at 1 MiB (needs sfdisk)."""
    with tempfile.TemporaryDirectory() as d:
        part = os.path.join(d, "part.img")
        build_clean(part)
        if tamper:
            tamper(part)
        subprocess.run(["truncate", "-s", "100M", path], check=True)
        spec = "label: dos\nstart=2048, type=7\n" if layout == "msdos" else "label: gpt\nstart=2048, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7\n"
        subprocess.run(["sfdisk", path], input=spec.encode(), check=True, capture_output=True)
        subprocess.run(["dd", f"if={part}", f"of={path}", "bs=1M", "seek=1", "conv=notrunc"], check=True, capture_output=True)
