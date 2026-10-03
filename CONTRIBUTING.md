# Contributing

Thanks for looking. This is a small project by one person, so the process is light.

1. Open an issue first for anything bigger than a bug fix.
2. `python3 -m unittest discover -s tests -v` must pass. The image tests need `ntfs-3g` (`sudo apt install ntfs-3g`); without it they are skipped.
3. Keep it dependency-free (Python standard library only) and strictly read-only.
4. A new check needs a test that builds a real NTFS volume, tampers with it, and proves both that the check fires and that a clean volume stays quiet (no false positives).
5. Never include real evidence images or personal data in issues, tests or screenshots.

PhantomTrace is MIT licensed.
