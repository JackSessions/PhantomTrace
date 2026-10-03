# PhantomTrace

![tests](https://github.com/JackSessions/PhantomTrace/actions/workflows/test.yml/badge.svg)

NTFS describes the same disk in several places. Honest activity keeps those descriptions in agreement; tampering (and corruption) often doesn't. PhantomTrace reads a raw NTFS image or device, **read-only**, and reports where the layers disagree.

## Checks

| ID | What it compares | Why it matters |
|---|---|---|
| `mft_flag_vs_bitmap` | A record's "in use" flag vs the `$MFT`'s own record bitmap (`$MFT:$BITMAP`) | Hidden or resurrected entries, edited MFT, crash damage |
| `clusters_free_in_bitmap` | Clusters a file's data runs claim vs the volume `$Bitmap` | Bitmap altered to hide data, or corruption; the next write may overwrite it |
| `cross_allocated` | Two records claiming the same cluster | Manual run-list edits or serious damage |
| `run_out_of_bounds` | A data run outside the volume | Invalid or forged run list |
| `bad_fixup` | MFT update-sequence (fix-up) verification | Torn, corrupt or hand-edited records |
| `mirror_mismatch` | First MFT records vs `$MFTMirr` (low confidence) | Worth a look; crashes can cause it too |

## Usage

```
python3 phantom_trace.py image.img                 # human-readable
python3 phantom_trace.py image.img --json          # for scripts and reports
python3 phantom_trace.py disk.img --offset 1048576 # NTFS partition inside a disk image
```

Standard library only (Python 3.9+). Use a raw image where you can; a live device needs admin/root. It never writes. Exit codes: `0` clean, `1` findings, `2` error.

## How it is tested

The test suite builds **real NTFS volumes** with `mkntfs`/`ntfscp`, then makes controlled changes and checks the result:

| Scenario | Expected |
|---|---|
| Fresh volume with 24 files; a second with 700 files | no findings (no false positives) |
| Clear a file's clusters in `$Bitmap` | `clusters_free_in_bitmap` |
| Flip an in-use record to "deleted" in its header only | `mft_flag_vs_bitmap` |
| Point one file's run at another file's clusters | `cross_allocated` |
| Corrupt a record's fix-up bytes | `bad_fixup` |
| Alter a `$MFTMirr` record | `mirror_mismatch` |

Run them with `python3 -m unittest discover -s tests -v` (needs `ntfs-3g` for the image tools).

## Known limitations

- The test images were made with the ntfs-3g tools and tampered with by this project's own helper. They have not yet been checked against volumes formatted and used by Windows, or against known real-world anti-forensic tooling. Treat a finding as a lead to verify with another tool (for example The Sleuth Kit), not as proof.
- A heavily fragmented `$MFT` that uses an `$ATTRIBUTE_LIST` is only read from its first extent (the tool warns when it sees this).
- Compressed and sparse files: sparse runs are skipped; compressed streams are not checked in depth.
- Only the unnamed and named non-resident attributes in in-use records are checked; `$LogFile` and `$UsnJrnl` analysis are not implemented.

## Roadmap

- Validate against Windows-made images and real tampering tools
- `$ATTRIBUTE_LIST` and fragmented-MFT support
- Timeline output (CSV / bodyfile) and `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamp comparison
- Compare results with The Sleuth Kit and MFTECmd on shared images

## Licence

Not set yet. Add one before others reuse the code.
