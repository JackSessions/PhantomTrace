#!/usr/bin/env python3
"""PhantomTrace: cross-layer consistency checks for NTFS.

NTFS describes the same disk in several places. Honest activity keeps those descriptions in agreement; tampering
(and corruption) often does not. PhantomTrace reads a raw NTFS image or device, read-only, and reports where the layers disagree:

  A  MFT record "in use" flag      vs  the $MFT's own record bitmap ($MFT:$BITMAP)
  B  clusters a file's data runs claim  vs  the volume cluster bitmap ($Bitmap)
  C  two different records claiming the same cluster (cross-allocation)
  D  update-sequence (fix-up) failures: torn or hand-edited MFT records
  E  the first MFT records vs their copy in $MFTMirr

Only the Python 3 standard library is used. Exit codes: 0 clean, 1 findings, 2 error.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import dataclass, field

__version__ = "0.2.0"
FIXUP_STRIDE = 512
MFT_REC_MFT, MFT_REC_MIRR, MFT_REC_BITMAP = 0, 1, 6
ATTR_ATTRLIST, ATTR_FILENAME, ATTR_DATA, ATTR_BITMAP, ATTR_END = 0x20, 0x30, 0x80, 0xB0, 0xFFFFFFFF
REC_IN_USE, REC_DIR = 0x01, 0x02

WHY = {
    "mft_flag_vs_bitmap": "The MFT record flag and the $MFT record bitmap should always agree. A mismatch can come from direct edits to the MFT, a rootkit hiding or resurrecting entries, or crash damage.",
    "clusters_free_in_bitmap": "A file's data runs point at clusters the volume bitmap says are free. The next write may overwrite them. This is a classic sign of the bitmap being altered to hide data, or of corruption.",
    "cross_allocated": "Two records claim the same clusters. Normal NTFS never does this; it points at manual run-list edits or serious damage.",
    "run_out_of_bounds": "A data run points outside the volume. Valid files cannot do this.",
    "bad_fixup": "The update-sequence check on this MFT record failed, so the record was not written by NTFS in one piece. It may be torn, corrupt or hand-edited.",
    "mirror_mismatch": "The first MFT records differ from their copy in $MFTMirr. NTFS keeps them in sync, so a mismatch is worth a look (low confidence: a crash can cause it too).",
    "parse_warning": "The tool could not fully read part of the structure. Results for that area are incomplete.",
}
SEVERITY = {"mft_flag_vs_bitmap": "high", "clusters_free_in_bitmap": "high", "cross_allocated": "high", "run_out_of_bounds": "high",
            "bad_fixup": "medium", "mirror_mismatch": "low", "parse_warning": "low"}


class NtfsError(Exception):
    pass


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]


@dataclass
class Attr:
    type: int
    name: str
    nonresident: bool
    runs: list[tuple[int | None, int]] = field(default_factory=list)   # (lcn or None for sparse, length in clusters)
    size: int = 0                                                       # real size for non-resident, content size for resident
    content: bytes = b""                                                # resident data
    start_vcn: int = 0


@dataclass
class Record:
    number: int
    raw: bytes
    flags: int
    base: int
    seq: int
    attrs: list[Attr]
    fixup_ok: bool
    attr_error: str = ""

    @property
    def in_use(self) -> bool: return bool(self.flags & REC_IN_USE)

    def name(self) -> str:
        best = None
        for a in self.attrs:
            if a.type == ATTR_FILENAME and not a.nonresident and len(a.content) > 0x42:
                ln, ns = a.content[0x40], a.content[0x41]
                nm = a.content[0x42:0x42 + ln * 2].decode("utf-16le", "replace")
                if best is None or (ns != 2 and best[0] == 2):
                    best = (ns, nm)
        return best[1] if best else ""


def decode_runs(data: bytes, pos: int, end: int) -> list[tuple[int | None, int]]:
    runs, lcn = [], 0
    while pos < end:
        h = data[pos]
        if h == 0:
            break
        ls, os_ = h & 0x0F, h >> 4
        if ls == 0 or pos + 1 + ls + os_ > end:
            raise NtfsError("malformed run list")
        length = int.from_bytes(data[pos + 1:pos + 1 + ls], "little")
        if os_ == 0:
            runs.append((None, length))
        else:
            lcn += int.from_bytes(data[pos + 1 + ls:pos + 1 + ls + os_], "little", signed=True)
            runs.append((lcn, length))
        pos += 1 + ls + os_
    return runs


def parse_record(number: int, raw: bytes) -> Record | None:
    """Parse one MFT record. Returns None when the slot is not a FILE record (empty/zeroed)."""
    if raw[:4] != b"FILE":
        return None
    buf = bytearray(raw)
    usa_off, usa_cnt = u16(buf, 4), u16(buf, 6)
    ok = True
    if usa_cnt < 2 or usa_off + usa_cnt * 2 > len(buf) or (usa_cnt - 1) * FIXUP_STRIDE > len(buf):
        ok = False
    else:
        usn = bytes(buf[usa_off:usa_off + 2])
        for i in range(usa_cnt - 1):
            end = (i + 1) * FIXUP_STRIDE
            if bytes(buf[end - 2:end]) != usn:
                ok = False
            buf[end - 2:end] = buf[usa_off + 2 + i * 2:usa_off + 4 + i * 2]
    first, flags = u16(buf, 0x14), u16(buf, 0x16)
    used = min(u32(buf, 0x18), len(buf))
    base = u64(buf, 0x20) & 0xFFFFFFFFFFFF
    rec = Record(number, bytes(buf), flags, base, u16(buf, 0x10), [], ok)
    off = first
    try:
        while off + 8 <= used:
            atype = u32(buf, off)
            if atype == ATTR_END:
                break
            alen = u32(buf, off + 4)
            if alen < 16 or off + alen > len(buf):
                raise NtfsError(f"bad attribute length at offset {off}")
            nonres, nlen, noff = buf[off + 8], buf[off + 9], u16(buf, off + 10)
            name = bytes(buf[off + noff:off + noff + nlen * 2]).decode("utf-16le", "replace") if nlen else ""
            if nonres:
                svcn, rl_off = u64(buf, off + 0x10), u16(buf, off + 0x20)
                runs = decode_runs(bytes(buf), off + rl_off, off + alen)
                rec.attrs.append(Attr(atype, name, True, runs, u64(buf, off + 0x30), b"", svcn))
            else:
                clen, coff = u32(buf, off + 0x10), u16(buf, off + 0x14)
                rec.attrs.append(Attr(atype, name, False, [], clen, bytes(buf[off + coff:off + coff + clen])))
            off += alen
    except NtfsError as e:
        rec.attr_error = str(e)
    return rec


class Ntfs:
    def __init__(self, fh, offset: int = 0):
        self.fh, self.offset = fh, offset
        bs = self.read(0, 512)
        if bs[3:11] != b"NTFS    ":
            raise NtfsError("not an NTFS volume (OEM ID is not 'NTFS    '). Use --offset for a partition inside a disk image.")
        self.bps, self.spc = u16(bs, 0x0B), bs[0x0D]
        if self.bps == 0 or self.spc == 0:
            raise NtfsError("corrupt boot sector")
        self.cluster = self.bps * self.spc
        self.total_clusters = u64(bs, 0x28) // self.spc
        self.mft_lcn, self.mirr_lcn = u64(bs, 0x30), u64(bs, 0x38)
        cpr = struct.unpack_from("b", bs, 0x40)[0]
        self.rec_size = cpr * self.cluster if cpr > 0 else 1 << -cpr
        self.warnings: list[str] = []
        self._load_mft()

    def read(self, pos: int, n: int) -> bytes:
        self.fh.seek(self.offset + pos)
        data = self.fh.read(n)
        if len(data) != n:
            raise NtfsError(f"unexpected end of image at byte {pos}")
        return data

    def read_runs(self, runs, size: int) -> bytes:
        out = bytearray()
        for lcn, length in runs:
            need = min(length * self.cluster, size - len(out))
            if need <= 0:
                break
            out += bytes(need) if lcn is None else self.read(lcn * self.cluster, need)
        return bytes(out)

    def attr_data(self, rec: Record, atype: int, name: str = "") -> bytes | None:
        for a in rec.attrs:
            if a.type == atype and a.name == name and a.start_vcn == 0:
                return self.read_runs(a.runs, a.size) if a.nonresident else a.content
        return None

    def _load_mft(self):
        rec0 = parse_record(0, self.read(self.mft_lcn * self.cluster, self.rec_size))
        if rec0 is None:
            raise NtfsError("MFT record 0 is not a valid FILE record")
        if any(a.type == ATTR_ATTRLIST for a in rec0.attrs):
            self.warnings.append("$MFT uses an $ATTRIBUTE_LIST (heavily fragmented MFT); only the first extent is read")
        self.mft_runs = next((a.runs for a in rec0.attrs if a.type == ATTR_DATA and a.nonresident), None)
        if self.mft_runs is None:
            raise NtfsError("$MFT:$DATA is missing or resident")
        size = next(a.size for a in rec0.attrs if a.type == ATTR_DATA and a.nonresident)
        self.mft = self.read_runs(self.mft_runs, size)
        self.n_records = len(self.mft) // self.rec_size
        self.rec0 = rec0
        self.mft_bitmap = self.attr_data(rec0, ATTR_BITMAP) or b""

    def raw_record(self, i: int) -> bytes:
        return self.mft[i * self.rec_size:(i + 1) * self.rec_size]

    def record_offset(self, i: int) -> int:
        """Byte offset of MFT record i inside the volume, following the $MFT run list."""
        pos = i * self.rec_size
        for lcn, length in self.mft_runs:
            span = length * self.cluster
            if pos < span:
                return lcn * self.cluster + pos
            pos -= span
        raise NtfsError("record outside MFT")

    def records(self):
        for i in range(self.n_records):
            raw = self.raw_record(i)
            if len(raw) == self.rec_size:
                yield i, raw, parse_record(i, raw)

    def volume_bitmap(self) -> bytes:
        rec = parse_record(MFT_REC_BITMAP, self.raw_record(MFT_REC_BITMAP))
        data = self.attr_data(rec, ATTR_DATA) if rec else None
        if data is None:
            raise NtfsError("could not read $Bitmap (MFT record 6)")
        return data


def bit(bm: bytes, i: int) -> bool:
    b = i >> 3
    return b < len(bm) and bool(bm[b] >> (i & 7) & 1)


@dataclass
class Finding:
    check: str
    message: str
    record: int | None = None
    name: str = ""
    detail: dict = field(default_factory=dict)

    @property
    def severity(self) -> str: return SEVERITY[self.check]

    def as_dict(self) -> dict:
        return {"check": self.check, "severity": self.severity, "record": self.record, "name": self.name, "message": self.message,
                "why": WHY[self.check], "detail": self.detail}


def analyse(fs: Ntfs) -> list[Finding]:
    out: list[Finding] = []
    for w in fs.warnings:
        out.append(Finding("parse_warning", w))
    vbm = fs.volume_bitmap()
    intervals: list[tuple[int, int, int]] = []     # (start, end_exclusive, record)
    for i, raw, rec in fs.records():
        flag_used = rec.in_use if rec else False
        bm_used = bit(fs.mft_bitmap, i)
        if rec is None:
            if bm_used:
                out.append(Finding("mft_flag_vs_bitmap", f"Record {i} is marked allocated in the MFT bitmap but is not a FILE record", i))
            continue
        nm = rec.name()
        if not rec.fixup_ok:
            out.append(Finding("bad_fixup", f"Record {i} failed its update-sequence check", i, nm))
        if rec.attr_error:
            out.append(Finding("parse_warning", f"Record {i}: {rec.attr_error}", i, nm))
        if flag_used != bm_used:
            out.append(Finding("mft_flag_vs_bitmap", f"Record {i} is {'in use' if flag_used else 'free'} in its header but {'allocated' if bm_used else 'free'} in the MFT bitmap", i, nm,
                               {"header_in_use": flag_used, "bitmap_allocated": bm_used}))
        if not flag_used:
            continue
        for a in rec.attrs:
            if not a.nonresident:
                continue
            free = 0
            for lcn, length in a.runs:
                if lcn is None:
                    continue
                if lcn < 0 or lcn + length > fs.total_clusters:
                    out.append(Finding("run_out_of_bounds", f"Record {i} has a data run at cluster {lcn} (+{length}) outside the volume ({fs.total_clusters} clusters)", i, nm, {"lcn": lcn, "length": length}))
                    continue
                free += sum(1 for c in range(lcn, lcn + length) if not bit(vbm, c))
                intervals.append((lcn, lcn + length, i))
            if free:
                out.append(Finding("clusters_free_in_bitmap", f"Record {i} owns {free} cluster(s) that the volume bitmap marks free", i, nm, {"free_clusters": free, "attribute": hex(a.type)}))
    intervals.sort()
    top_end, top_rec = -1, -1
    seen = set()
    for s, e, r in intervals:
        if s < top_end and r != top_rec and (min(r, top_rec), max(r, top_rec)) not in seen:
            seen.add((min(r, top_rec), max(r, top_rec)))
            out.append(Finding("cross_allocated", f"Records {top_rec} and {r} both claim cluster {s}", r, "", {"records": [top_rec, r], "cluster": s}))
        if e > top_end:
            top_end, top_rec = e, r
    # E: mirror
    try:
        n = min(4, fs.n_records)
        mirror = fs.read(fs.mirr_lcn * fs.cluster, n * fs.rec_size)
        for i in range(n):
            if mirror[i * fs.rec_size:(i + 1) * fs.rec_size] != fs.raw_record(i):
                out.append(Finding("mirror_mismatch", f"MFT record {i} differs from its $MFTMirr copy", i))
    except NtfsError:
        pass
    return out


def report_text(fs: Ntfs, findings: list[Finding], limit: int) -> str:
    lines = [f"PhantomTrace {__version__}", f"  cluster {fs.cluster} B | MFT record {fs.rec_size} B | {fs.n_records} MFT records | {fs.total_clusters} clusters", ""]
    if not findings:
        lines.append("No cross-layer inconsistencies found.")
        return "\n".join(lines)
    order = {"high": 0, "medium": 1, "low": 2}
    shown = 0
    for sev in ("high", "medium", "low"):
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        lines.append(f"[{sev.upper()}] {len(group)} finding(s)")
        for f in group:
            if shown >= limit:
                break
            shown += 1
            lines.append(f"  - {f.message}" + (f"  ({f.name})" if f.name else ""))
        lines.append("")
    seen = []
    for f in sorted(findings, key=lambda x: order[x.severity]):
        if f.check not in seen:
            seen.append(f.check)
    lines.append("What this means:")
    lines += [f"  * {WHY[c]}" for c in seen]
    if shown < len(findings):
        lines.append(f"\n({len(findings) - shown} more not shown; use --max or --json)")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Cross-layer consistency checks for NTFS (read-only).")
    ap.add_argument("target", help="raw NTFS image, or a device such as /dev/sdb1 or \\\\.\\C: (needs admin/root)")
    ap.add_argument("--offset", type=lambda x: int(x, 0), default=0, help="byte offset of the NTFS partition inside the image")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--max", type=int, default=50, help="maximum findings to print in text mode")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    try:
        with open(args.target, "rb") as fh:
            fs = Ntfs(fh, args.offset)
            findings = analyse(fs)
            if args.json:
                print(json.dumps({"version": __version__, "volume": {"cluster_size": fs.cluster, "record_size": fs.rec_size, "records": fs.n_records, "clusters": fs.total_clusters},
                                  "findings": [f.as_dict() for f in findings]}, indent=2))
            else:
                print(report_text(fs, findings, args.max))
            return 1 if any(f.severity in ("high", "medium") for f in findings) else 0
    except PermissionError:
        print("Permission denied. Run as Administrator/root, or analyse a raw image instead.", file=sys.stderr)
    except FileNotFoundError:
        print(f"Target not found: {args.target}", file=sys.stderr)
    except NtfsError as e:
        print(f"Error: {e}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
