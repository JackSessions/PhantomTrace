# PhantomTrace

A small NTFS forensics prototype that cross-checks two layers of a volume and flags records where they disagree: the `$MFT` record's "in use" flag versus the allocation bitmap. Disagreement between layers is one place anti-forensic tampering (or ordinary corruption) can show up.

> **Status: experimental prototype.** It has not been validated against known-tampered images, and it will produce false positives. See "Known limitations".

## Usage

```
python3 phantom_trace.py <raw-image.img | \\.\C:>
```

Run it on a raw image (recommended) or a live device as Administrator/root. It is read-only and needs only the Python 3 standard library.

## What it does

1. Parses the NTFS boot sector (cluster size, `$MFT` location).
2. Reads MFT record 6 (`$Bitmap`) and loads the bitmap's first data run.
3. Walks up to the first 10,000 MFT records and flags:
   - `MFT_SAYS_USED_BITMAP_SAYS_FREE`: record marked in use but the bitmap bit is clear.
   - `MFT_SAYS_FREE_BITMAP_SAYS_USED`: record marked free but the bitmap bit is set.

## Known limitations

- The current comparison maps MFT record number `i` straight to bit `i` of `$Bitmap`. `$Bitmap` tracks **cluster** allocation, while record allocation lives in the `$MFT`'s own `$BITMAP` attribute, so this needs reworking before the results mean much. A sounder check compares each in-use record's data runs against the cluster bitmap.
- Assumes 1024-byte MFT records and reads only the first `$Bitmap` data run.
- Scans at most 10,000 records.

## Roadmap

- Compare against the `$MFT` `$BITMAP` attribute and per-file data runs
- Detect record size and `$MFT` length from the boot sector
- Full runlist handling and fragmented `$Bitmap`
- Test images and a regression suite
