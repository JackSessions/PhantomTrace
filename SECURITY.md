# Security

PhantomTrace is a **read-only** analysis tool. It opens the image or device you give it for reading and never writes to it.

## Design choices you can rely on

- It never modifies the target. Prefer a copy (a raw image or a snapshot) over a live device, which can change while it is read.
- The optional browser GUI listens on `127.0.0.1` only, with a random one-time token and a host-name check, and only reads files you point it at.
- It has no network access and no third-party dependencies (Python standard library only).

## Reporting a problem

Please open a private security advisory on GitHub (Security tab, "Report a vulnerability"), or an issue for anything that is not sensitive. Include the version (`phantom-trace --version`), your operating system, and steps to reproduce. **Do not attach real evidence images or personal data.** If you can, reproduce the problem on a small image made with `mkntfs`.

## Using findings responsibly

PhantomTrace reports *inconsistencies*. They can come from tampering, corruption or a live system that was still writing. Treat every finding as a lead to verify with a second tool (for example The Sleuth Kit or MFTECmd) before drawing conclusions.
