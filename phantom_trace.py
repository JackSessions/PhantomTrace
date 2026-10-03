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
import csv
import html
import json
import os
import struct
import sys
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field

__version__ = "0.6.0"
__author__ = "Jack Sessions"
__license__ = "MIT"
__url__ = "https://github.com/JackSessions/PhantomTrace"
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
WHY["timestomp_si_before_fn"] = ("Heuristic. The $STANDARD_INFORMATION created time (easy for tools to change) is earlier than the $FILE_NAME created time (harder to change). "
                                 "This is a well-known timestomping sign, but file extraction and some copy tools can cause it too.")
WHY["timestomp_zero_fraction"] = ("Heuristic. All four $STANDARD_INFORMATION times have a zero sub-second part while $FILE_NAME does not. Some timestomp tools cannot set sub-second values. "
                                  "Archive extraction and some copy tools can also do this.")
SEVERITY = {"timestomp_si_before_fn": "low", "timestomp_zero_fraction": "low", "mft_flag_vs_bitmap": "high", "clusters_free_in_bitmap": "high", "cross_allocated": "high", "run_out_of_bounds": "high",
            "bad_fixup": "medium", "mirror_mismatch": "low", "parse_warning": "low"}


class NtfsError(Exception):
    pass


ALIGN = 4096    # raw devices (especially on Windows) only accept sector-aligned reads; 4096 is safe for 512e and 4Kn disks


def raw_read(fh, pos: int, n: int) -> bytes:
    start = pos & ~(ALIGN - 1)
    end = (pos + n + ALIGN - 1) & ~(ALIGN - 1)
    fh.seek(start)
    data = fh.read(end - start)
    out = data[pos - start:pos - start + n]
    if len(out) != n:
        raise NtfsError(f"unexpected end of image at byte {pos}")
    return out


GPT_BASIC_DATA = bytes.fromhex("A2A0D0EBE5B9334487C068B6B72699C7")


def _is_ntfs_at(fh, off: int) -> bool:
    try:
        bs = raw_read(fh, off, 512)
    except (NtfsError, OSError):
        return False
    return bs[3:11] == b"NTFS    " and bs[510:512] == b"\x55\xaa"


def locate_volumes(fh) -> list[tuple[int, str]]:
    """Find NTFS volumes in a raw volume, MBR disk image or GPT disk image. Returns [(byte offset, description)]."""
    if _is_ntfs_at(fh, 0):
        return [(0, "volume at start of image")]
    found: list[tuple[int, str]] = []
    try:
        mbr = raw_read(fh, 0, 512)
    except (NtfsError, OSError):
        return found
    if mbr[510:512] != b"\x55\xaa":
        return found
    parts = [mbr[446 + 16 * i:462 + 16 * i] for i in range(4)]
    if any(p[4] == 0xEE for p in parts):                              # GPT
        try:
            hdr = raw_read(fh, 512, 92)
            if hdr[:8] == b"EFI PART":
                lba, count, size = u64(hdr, 0x48), u32(hdr, 0x50), u32(hdr, 0x54)
                table = raw_read(fh, lba * 512, min(count, 128) * size)
                for i in range(min(count, 128)):
                    e = table[i * size:(i + 1) * size]
                    if e[:16] == GPT_BASIC_DATA and _is_ntfs_at(fh, u64(e, 0x20) * 512):
                        found.append((u64(e, 0x20) * 512, f"GPT partition {i + 1}"))
        except (NtfsError, OSError):
            pass
    else:                                                              # MBR
        for i, p in enumerate(parts):
            if p[4] in (0x07, 0x17, 0x27) and u32(p, 8) and _is_ntfs_at(fh, u32(p, 8) * 512):
                found.append((u32(p, 8) * 512, f"MBR partition {i + 1}"))
    return found


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
        return raw_read(self.fh, self.offset + pos, n)

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


def analyse(fs: Ntfs, progress=None, heuristics: bool = False) -> list[Finding]:
    out: list[Finding] = []
    for w in fs.warnings:
        out.append(Finding("parse_warning", w))
    vbm = fs.volume_bitmap()
    intervals: list[tuple[int, int, int]] = []     # (start, end_exclusive, record)
    for i, raw, rec in fs.records():
        if progress and i % 256 == 0:
            progress(i, fs.n_records)
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
        if heuristics and rec.base == 0 and i >= 24:
            ts = timestamps(rec)
            if ts and all(ts[0]) and all(ts[1]):
                si, fn = ts
                if si[0] < fn[0] - 20_000_000:
                    out.append(Finding("timestomp_si_before_fn", f"Record {i}: $SI created {filetime(si[0])} is before $FN created {filetime(fn[0])}", i, nm,
                                       {"si_created": filetime(si[0]), "fn_created": filetime(fn[0])}))
                if all(t % 10_000_000 == 0 for t in si) and fn[0] % 10_000_000 != 0:
                    out.append(Finding("timestomp_zero_fraction", f"Record {i}: all $SI times end in .0000000 but $FN times do not", i, nm, {"si": [filetime(t) for t in si]}))
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
                out.append(Finding("clusters_free_in_bitmap", f"Record {i} owns {free} cluster(s) that the volume bitmap marks free", i, nm, {"free_clusters": free, "attribute": hex(a.type), "runs": [(l, n) for l, n in a.runs if l is not None]}))
    intervals.sort()
    top_end, top_rec = -1, -1
    seen = set()
    for s, e, r in intervals:
        if s < top_end and r != top_rec and (min(r, top_rec), max(r, top_rec)) not in seen:
            seen.add((min(r, top_rec), max(r, top_rec)))
            out.append(Finding("cross_allocated", f"Records {top_rec} and {r} both claim cluster {s}", r, "", {"records": [top_rec, r], "cluster": s, "runs": [(s, min(e, top_end) - s)]}))
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


@dataclass
class ScanResult:
    target: str
    offset: int
    info: dict
    findings: list
    cmap: dict
    elapsed: float
    volumes: list


def volume_info(fs: Ntfs) -> dict:
    return {"cluster_size": fs.cluster, "record_size": fs.rec_size, "records": fs.n_records, "clusters": fs.total_clusters}


def scan(target: str, offset: int | None = None, partition: int = 1, heuristics: bool = False, progress=None, notify=None, with_map: bool = True) -> ScanResult:
    """Open an image or device read-only, find the NTFS volume, run every check. Used by the CLI and the GUI."""
    t0 = time.time()
    with open(target, "rb") as fh:
        vols: list = []
        if offset is None:
            vols = locate_volumes(fh)
            if not vols:
                raise NtfsError("no NTFS volume found (not NTFS, or an unsupported partition layout). Use --offset if you know where it starts.")
            if len(vols) > 1 and notify:
                notify("Several NTFS volumes found: " + "; ".join(f"{i + 1}) {d} at byte {o}" for i, (o, d) in enumerate(vols)) + f". Using {partition}; change with --partition.")
            if not 1 <= partition <= len(vols):
                raise NtfsError(f"--partition must be between 1 and {len(vols)}")
            offset = vols[partition - 1][0]
            if offset and notify:
                notify(f"Using NTFS volume at byte offset {offset}")
        fs = Ntfs(fh, offset)
        findings = analyse(fs, progress, heuristics)
        cmap = cluster_map(fs, findings) if with_map else {}
        return ScanResult(target, offset, volume_info(fs), findings, cmap, time.time() - t0, vols)


def csv_text(findings: list) -> str:
    import io
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["severity", "check", "record", "name", "message", "why"])
    for x in findings:
        w.writerow([x.severity, x.check, x.record if x.record is not None else "", x.name, x.message, WHY[x.check]])
    return buf.getvalue()


def json_text(res: "ScanResult") -> str:
    return json.dumps({"version": __version__, "target": res.target, "volume": res.info, "findings": [f.as_dict() for f in res.findings]}, indent=2)


def filetime(t: int) -> str:
    try:
        return (datetime(1601, 1, 1) + timedelta(microseconds=t // 10)).strftime("%Y-%m-%d %H:%M:%S")
    except OverflowError:
        return "invalid"


def timestamps(rec: Record):
    """(SI times, FN times) as lists of four FILETIMEs, or None when an attribute is missing."""
    si = next((a for a in rec.attrs if a.type == 0x10 and not a.nonresident and len(a.content) >= 32), None)
    fns = [a for a in rec.attrs if a.type == ATTR_FILENAME and not a.nonresident and len(a.content) >= 0x42]
    if not si or not fns:
        return None
    fn = next((a for a in fns if a.content[0x41] != 2), fns[0])             # prefer Win32/POSIX over the DOS 8.3 name
    return [u64(si.content, o) for o in (0, 8, 16, 24)], [u64(fn.content, o) for o in (8, 16, 24, 32)]


def hsv_rgb(h: float) -> tuple[int, int, int]:
    i = int(h * 6) % 6; f = h * 6 - int(h * 6)
    p, q, t = 0.0, 1 - f, f
    r, g, b = [(1, t, p), (q, 1, p), (p, 1, t), (p, q, 1), (t, p, 1), (1, p, q)][i]
    return int(r * 255), int(g * 255), int(b * 255)


class _Help(argparse.Action):
    """-h / --help: shows the rainbow banner first when talking to a terminal."""
    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        if sys.stdout.isatty():
            if os.name == "nt":
                os.system("")
            st = Style("NO_COLOR" not in os.environ)
            print(st.rainbow(BANNER.strip("\n")) + "\n" + st("dim", f"  v{__version__}") + "\n")
        parser.print_help()
        parser.exit()


class Style:
    """ANSI colour that switches itself off for pipes, NO_COLOR and --no-color."""
    CODES = {"red": "31;1", "yellow": "33;1", "cyan": "36", "green": "32;1", "dim": "2", "bold": "1", "mag": "35;1"}

    def __init__(self, on: bool): self.on = on
    def __call__(self, name: str, text: str) -> str: return f"\x1b[{self.CODES[name]}m{text}\x1b[0m" if self.on else text

    def rainbow(self, text: str) -> str:
        """A diagonal rainbow across multi-line text (24-bit colour; plain text when colour is off)."""
        if not self.on:
            return text
        out = []
        for row, line in enumerate(text.split("\n")):
            chars = []
            for col, ch in enumerate(line):
                if ch == " ":
                    chars.append(ch)
                    continue
                r, g, b = hsv_rgb(((col * 5 + row * 18) % 360) / 360)
                chars.append(f"\x1b[1;38;2;{r};{g};{b}m{ch}")
            out.append("".join(chars) + "\x1b[0m")
        return "\n".join(out)


SEV_COLOR = {"high": "red", "medium": "yellow", "low": "cyan"}
BANNER = r"""
  ___ _                 _               _____
 | _ \ |_  __ _ _ _  __| |_ ___ _ __   |_   _| _ __ _ __ ___
 |  _/ ' \/ _` | ' \/ _|  _/ _ \ '  \    | || '_/ _` / _/ -_)
 |_| |_||_\__,_|_||_\__|\__\___/_|_|_|   |_||_| \__,_\__\___|
"""


def verdict(findings: list[Finding]) -> tuple[str, str]:
    high = sum(f.severity == "high" for f in findings); med = sum(f.severity == "medium" for f in findings)
    if high:
        return "red", f"{high} high-severity inconsistenc{'y' if high == 1 else 'ies'} found. Verify with a second tool before drawing conclusions."
    if med:
        return "yellow", f"{med} medium-severity issue(s) found."
    if findings:
        return "cyan", "Only low-confidence notes."
    return "green", "No cross-layer inconsistencies found."


def report_text(info: dict, findings: list[Finding], limit: int, st: Style, target: str = "", elapsed: float = 0.0, quiet: bool = False) -> str:
    L: list[str] = []
    if not quiet:
        L.append(st.rainbow(BANNER.rstrip("\n")))
        L.append(st("dim", f"  v{__version__}  |  read-only NTFS cross-layer consistency checker"))
        L.append("")
        L.append(f"  {st('bold', 'Target ')} {target}")
        L.append(f"  {st('bold', 'Volume ')} {info['cluster_size']} B clusters | {info['record_size']} B MFT records | {info['records']} records | {info['clusters']} clusters")
        L.append("")
    shown = 0
    if not quiet:
        for check in WHY:
            group = [f for f in findings if f.check == check]
            if not group:
                continue
            sev = SEVERITY[check]
            L.append(f"  {st(SEV_COLOR[sev], f'[{sev.upper()}]')} {st('bold', check)} {st('dim', f'x{len(group)}')}")
            for f in group:
                if shown >= limit:
                    break
                shown += 1
                L.append(f"      {st('dim', chr(0x2022))} {f.message}" + (st("dim", f"  ({f.name})") if f.name else ""))
            L.append(f"      {st('dim', WHY[check])}")
            L.append("")
        if shown < len(findings):
            L.append(st("dim", f"  ... {len(findings) - shown} more finding(s) not shown (use --max, --json, --csv or --html)"))
            L.append("")
    counts = {s: sum(f.severity == s for f in findings) for s in ("high", "medium", "low")}
    color, msg = verdict(findings)
    L.append(f"  {st('bold', 'Summary')}  " + "  ".join(st(SEV_COLOR[s], f"{s} {n}") for s, n in counts.items()) + st("dim", f"   ({elapsed:.2f}s)"))
    L.append(f"  {st(color, 'Verdict')}  {msg}")
    return "\n".join(L)


def report_csv(findings: list[Finding], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        f.write(csv_text(findings))


def cluster_map(fs: Ntfs, findings: list[Finding], cols: int = 128, rows: int = 40):
    """Allocation fraction per cell (0-100) and a parallel flag per cell for clusters named in findings."""
    vbm = fs.volume_bitmap(); total = fs.total_clusters; cells = cols * rows
    per = max(1, -(-total // cells)); n = -(-total // per)
    frac, flag = [], [0] * n
    for c in range(n):
        a, b = c * per, min(total, (c + 1) * per)
        bits = sum(1 for k in range(a, b) if bit(vbm, k)) if b - a <= 64 else sum(bin(x).count("1") for x in vbm[a >> 3:b >> 3])
        frac.append(round(100 * bits / max(1, b - a)))
    for f in findings:
        for lcn, ln in f.detail.get("runs", []):
            for c in range(lcn // per, min(n - 1, (lcn + max(ln, 1) - 1) // per) + 1):
                flag[c] = 1
    return {"cols": cols, "per": per, "cells": n, "frac": frac, "flag": flag}


def report_html(info: dict, findings: list[Finding], target: str, cm: dict) -> str:
    e = html.escape
    color, msg = verdict(findings)
    chip = {"high": "#ff4d5e", "medium": "#ffb02e", "low": "#38d6ff"}
    rows = "".join(
        f'<tr><td><span class="chip" style="--c:{chip[f.severity]}">{f.severity}</span></td><td><code>{e(f.check)}</code></td>'
        f'<td>{"" if f.record is None else f.record}</td><td>{e(f.name)}</td><td>{e(f.message)}<div class="why">{e(WHY[f.check])}</div></td></tr>'
        for f in sorted(findings, key=lambda x: ("high", "medium", "low").index(x.severity)))
    counts = "".join(f'<div class="stat" style="--c:{chip[s]}"><b>{sum(f.severity == s for f in findings)}</b><span>{s}</span></div>' for s in ("high", "medium", "low"))
    verdict_col = {"red": "#ff4d5e", "yellow": "#ffb02e", "cyan": "#38d6ff", "green": "#4af0a2"}[color]
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhantomTrace report</title><style>
:root{{color-scheme:dark}}body{{margin:0;background:#07090c;color:#d7e3ea;font:15px/1.5 system-ui,sans-serif}}main{{max-width:64rem;margin:0 auto;padding:2rem 1rem 4rem}}
h2{{font:600 1rem ui-monospace,monospace;color:#7fa7b5;margin:1.6rem 0 .4rem}}canvas{{display:block;max-width:100%;image-rendering:pixelated;border:1px solid #1c252d;border-radius:6px;background:#05070a}}h1{{font:700 1.6rem ui-monospace,monospace;letter-spacing:.04em;margin:0;background:linear-gradient(90deg,#ff5f6d,#ffb02e,#ffe14a,#4af0a2,#38d6ff,#8b7bff,#e04aff);-webkit-background-clip:text;background-clip:text;color:transparent;display:inline-block}}small,.why{{color:#7fa7b5}}.why{{font-size:.82rem;margin-top:.3rem}}
.meta{{margin:.4rem 0 1.4rem;font:13px ui-monospace,monospace;color:#7fa7b5}}.verdict{{border-left:4px solid {verdict_col};padding:.7rem 1rem;background:#0c1116;margin:1rem 0}}
.stats{{display:flex;gap:.8rem;margin:1rem 0}}.stat{{flex:1;border:1px solid var(--c);border-radius:6px;padding:.6rem;text-align:center}}.stat b{{display:block;font-size:1.6rem;color:var(--c)}}
table{{width:100%;border-collapse:collapse;margin-top:1rem}}td,th{{text-align:left;padding:.55rem .5rem;border-bottom:1px solid #1c252d;vertical-align:top}}th{{font:12px ui-monospace,monospace;color:#7fa7b5;text-transform:uppercase}}
.chip{{display:inline-block;border:1px solid var(--c);color:var(--c);border-radius:999px;padding:0 .6rem;font:12px ui-monospace,monospace;text-transform:uppercase}}code{{color:#ffb02e}}
</style><main><h1>PhantomTrace</h1><div class="meta">v{__version__} | {e(target)} | {info['cluster_size']} B clusters, {info['record_size']} B records, {info['records']} MFT records, {info['clusters']} clusters</div>
<div class="verdict"><b>Verdict.</b> {e(msg)}</div><div class="stats">{counts}</div>
<h2>Volume map</h2><canvas id="map" height="10"></canvas>
<p><small>Each square is a slice of the volume (<span id="per"></span> clusters). Brightness is how full that slice is according to the volume bitmap. Red outlines contain clusters named in findings.</small></p>
<table><tr><th>Severity</th><th>Check</th><th>Record</th><th>Name</th><th>Finding</th></tr>{rows or '<tr><td colspan="5">No findings.</td></tr>'}</table>
<script>const M={json.dumps(cm)};const cv=document.getElementById('map'),cols=M.cols,sz=Math.floor(Math.min(1000,document.querySelector('main').clientWidth)/cols),rows=Math.ceil(M.cells/cols);
cv.width=sz*cols;cv.height=sz*rows;const g=cv.getContext('2d');document.getElementById('per').textContent=M.per;
for(let i=0;i<M.cells;i++){{const x=(i%cols)*sz,y=Math.floor(i/cols)*sz,f=M.frac[i]/100;g.fillStyle=`rgba(56,214,255,${{(0.07+0.85*f).toFixed(2)}})`;g.fillRect(x,y,sz-1,sz-1);if(M.flag[i]){{g.strokeStyle='#ff4d5e';g.lineWidth=2;g.strokeRect(x+1,y+1,sz-3,sz-3);}}}}</script>
<p><small>Created by <a href="{__url__}" style="color:#38d6ff">Jack Sessions</a> (PhantomTrace v{__version__}, MIT licence). Findings are leads, not proof. Confirm with a second tool (for example The Sleuth Kit) before drawing conclusions.</small></p></main></html>"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="phantom-trace", add_help=False, formatter_class=argparse.RawDescriptionHelpFormatter, usage="phantom-trace [options] TARGET",
        description=(
            "PhantomTrace: a read-only NTFS cross-layer consistency checker for DFIR.\n\n"
            "NTFS describes the same disk in several places. Honest activity keeps them in agreement; tampering and\n"
            "corruption often do not. PhantomTrace compares the layers and reports where they disagree:\n\n"
            "  mft_flag_vs_bitmap       MFT record 'in use' flag vs the $MFT record bitmap\n"
            "  clusters_free_in_bitmap  clusters a file owns vs the volume cluster bitmap ($Bitmap)\n"
            "  cross_allocated          two records claiming the same clusters\n"
            "  run_out_of_bounds        data runs pointing outside the volume\n"
            "  bad_fixup                MFT records that fail their update-sequence check\n"
            "  mirror_mismatch          first MFT records vs $MFTMirr (low confidence)\n"
            "  --heuristics adds weak timestamp checks ($STANDARD_INFORMATION vs $FILE_NAME)."),
        epilog=(
            "examples:\n"
            "  phantom-trace disk.img                        scan an image (the NTFS partition is found automatically)\n"
            "  phantom-trace disk.img --html report.html     also write a shareable report with a volume map\n"
            "  phantom-trace disk.img --json > out.json      machine-readable output for scripts\n"
            "  phantom-trace disk.img -q                     one-line verdict, handy in scripts (check the exit code)\n"
            "  phantom-trace disk.img --partition 2          pick the second NTFS volume in the image\n"
            "  phantom-trace disk.img --offset 1048576       NTFS volume at a known byte offset\n"
            "  phantom-trace /dev/sdb1                       a device on Linux (needs root; an image is safer)\n"
            "  phantom-trace \\\\.\\C:                          a volume on Windows (Administrator; an image is safer)\n\n"
            "  phantom-trace --gui                           open the point-and-click interface in your browser\n\n"
            "exit codes:  0 clean   1 findings (high or medium)   2 error\n\n"
            "notes:\n"
            "  * Read-only: it never writes to the target.\n"
            "  * Findings are leads, not proof. Confirm with a second tool (for example The Sleuth Kit).\n"
            "  * A live volume changes while it is read, which can cause harmless mismatches. Prefer a raw image.\n"
            "  * Encrypted volumes (BitLocker) must be unlocked and imaged first.\n\n"
            "\n"
            "Created by Jack Sessions | MIT licence | https://github.com/JackSessions/PhantomTrace"))
    ap.add_argument("-h", "--help", action=_Help, help="show this help message and exit")
    ap.add_argument("target", nargs="?", metavar="TARGET", help="raw NTFS image (.img/.dd/.vhd), whole-disk image, or a device (needs admin/root)")
    g = ap.add_argument_group("locating the volume")
    g.add_argument("--offset", type=lambda x: int(x, 0), default=None, metavar="BYTES", help="byte offset of the NTFS volume (default: detected automatically)")
    g.add_argument("--partition", type=int, default=1, metavar="N", help="which NTFS volume to use when an image holds several (default: 1)")
    g = ap.add_argument_group("output")
    g.add_argument("--json", action="store_true", help="print machine-readable JSON instead of the report")
    g.add_argument("--html", metavar="FILE", help="also write a self-contained HTML report (with a volume map)")
    g.add_argument("--csv", metavar="FILE", help="also write the findings to a CSV file")
    g.add_argument("--max", type=int, default=50, metavar="N", help="maximum findings to print in the text report (default: 50)")
    g.add_argument("-q", "--quiet", action="store_true", help="print only the summary and verdict")
    g.add_argument("--no-color", action="store_true", help="disable colour (NO_COLOR is also honoured)")
    g = ap.add_argument_group("analysis")
    g.add_argument("--heuristics", action="store_true", help="also run weaker timestamp checks ($SI vs $FN); more false positives, always low severity")
    g = ap.add_argument_group("graphical interface")
    g.add_argument("--gui", action="store_true", help="open the browser-based GUI (runs only on this computer; TARGET is optional)")
    g.add_argument("--port", type=int, default=0, metavar="N", help="port for --gui (default: a free one)")
    g.add_argument("--no-browser", action="store_true", help="with --gui: print the address instead of opening a browser")
    g = ap.add_argument_group("information")
    g.add_argument("--list-checks", action="store_true", help="list every check with its severity and meaning, then exit")
    g.add_argument("--version", action="version", version=f"phantom-trace {__version__}")
    if os.name == "nt":
        os.system("")          # enables ANSI colour in the Windows console
    args = ap.parse_args(argv)
    if args.list_checks:
        for name in WHY:
            print(f"{name:28} [{SEVERITY[name]:6}] {WHY[name]}")
        return 0
    if args.gui:
        from phantom_trace_gui import serve
        return serve(args.port, not args.no_browser, args.target)
    if not args.target:
        ap.error("TARGET is required (a raw NTFS image or device). Try --help for examples.")
    st = Style(sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ)
    try:
        tty = sys.stderr.isatty() and not args.json
        def progress(i, n):
            if tty:
                sys.stderr.write(f"\r  scanning MFT {i * 100 // max(n, 1)}% ")
        res = scan(args.target, args.offset, args.partition, args.heuristics, progress, lambda m: print(m, file=sys.stderr), with_map=bool(args.html))
        if tty:
            sys.stderr.write("\r" + " " * 30 + "\r")
        if args.csv:
            report_csv(res.findings, args.csv)
        if args.html:
            with open(args.html, "w", encoding="utf-8") as hf:
                hf.write(report_html(res.info, res.findings, args.target, res.cmap))
        if args.json:
            print(json_text(res))
        else:
            print(report_text(res.info, res.findings, args.max, st, args.target, res.elapsed, args.quiet))
        return 1 if any(f.severity in ("high", "medium") for f in res.findings) else 0
    except PermissionError:
        print("Permission denied. Run as Administrator/root, or analyse a raw image instead.", file=sys.stderr)
    except FileNotFoundError:
        print(f"Target not found: {args.target}", file=sys.stderr)
    except NtfsError as e:
        print(f"Error: {e}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
