# Releasing to PyPI

The PyPI project name is **phantom-trace-ntfs** (the commands you type are still `phantom-trace` and `phantom-trace-gui`).

One-time setup (about 5 minutes):

1. Push `main` to `github.com/JackSessions/PhantomTrace`.
2. On https://pypi.org: **Your account > Publishing > Add a new pending publisher**
   - PyPI project name: `phantom-trace-ntfs`
   - Owner: `JackSessions`
   - Repository name: `PhantomTrace`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
   (Type the values by hand rather than pasting, so no hidden character sneaks in.)
3. On GitHub: **Settings > Environments > New environment**, name it `pypi`.

Before each release:

1. Update the version in `pyproject.toml`, `phantom_trace.py` and `CITATION.cff`, and add a section to `CHANGELOG.md`.
2. `python3 -m unittest discover -s tests` and `python3 -m build && python3 -m twine check dist/*`.
3. Run the **windows** workflow from the Actions tab (it formats a real NTFS volume with Windows and checks that PhantomTrace reports it clean). If it passes, update the README's "Known limitations" to say so. Do this before announcing.
4. Commit, push, then create a GitHub Release with the tag `vX.Y.Z` (the tag must match the version). Publishing the release runs `.github/workflows/publish.yml`.
5. Check https://pypi.org/project/phantom-trace-ntfs/ and try `pipx install phantom-trace-ntfs` on a clean machine.

A version number can only be uploaded once, even if you delete the release, so run the checks first.
