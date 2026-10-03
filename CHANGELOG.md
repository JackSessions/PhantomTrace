# Changelog

## 0.6.1
- **New look** for the GUI and the HTML report: frosted glass over a night-security backdrop, Google colours, a four-colour shield, glowing rainbow-ring buttons, a DFIR field note, and reduced-motion support. One shared design in `phantom_trace.py`.
- Fixes a release-ordering slip: 0.6.0 on PyPI was built before the new look was committed, so 0.6.1 is the first version with it.

## 0.6.0
- First PyPI release (`pipx install phantom-trace-ntfs`).
- README: "why would anyone use this", GUI screenshot, install and PyPI badges. Added `SECURITY.md`, `CONTRIBUTING.md`, issue templates (including a false-positive report) and `docs/RELEASING.md`.
- Richer package metadata (keywords, Python versions, changelog and docs links).

## 0.5.0
- MIT licence, browser GUI (`phantom-trace --gui`), PyPI metadata, HTML report with volume map.

## 0.4.0 and earlier
- Windows-ready reads, partition auto-detect, volume map, timestamp heuristics, Windows CI, live-mount churn test.
