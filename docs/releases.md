# Releases

Vership prepares release commits, tags and pushes the exact checked version.
GitHub Actions builds five native Python wheels (Linux/macOS x64 and ARM64,
Windows x64), validates metadata and installed commands, then publishes all
wheels and a source distribution to PyPI. No crates.io, Homebrew, or GitHub
Release publication is enabled.

## Initial repository setup

Creating the public repository, uploading source/tags, and setting the
`PYPI_API_TOKEN` repository secret require explicit user approval. Store the
existing PyPI token through secret input; never print it or put it in argv.
Keep required pull-request and status-check protection enabled for bots and
external contributors. The repository owner can integrate directly on main.

## Prepare and publish

1. Fetch and inspect local/remote divergence, preserving unrelated work. Start
   from the current remote default branch.
2. Run `vership status`, `vership config show`, and the relevant commands' `--help`.
3. Run `make check`, `make conformance`, the Rust 1.90 check, and `actionlint`.
   Build a local wheel/sdist, run `twine check --strict`, and install the wheel
   into a clean environment to exercise `--version` and `schema`.
4. For a new version, run `vership bump patch --prepare` (or minor/major).
   Prepare initial 0.0.1 with `vership release --prepare`. Review the version,
   changelog, and exact release commit. Do not bump again after preparation.
5. Once the user approves pushing and publishing that release, run
   `vership release`. The tag starts the PyPI workflow. A workflow dispatch
   with `dry_run` builds and validates without publishing.
6. Wait for every release job, then run `vership verify VERSION --targets tag,pypi`.
   Confirm all five wheels and the sdist on PyPI. Install from the published
   index, verify the version/schema, and reconcile the primary checkout with
   the remote default branch before reporting completion.

Use `--skip-checks` only when the exact release content has already passed those
checks; state which results are reused. For interrupted releases inspect tags
and publication state, and preview recovery with `--dry-run`. If only a brief
public tag exists and no artifact or package was published, delete/recreate the
tag and retry the same version. Once artifacts have been published outside
GitHub, preserve the tag and issue a patch release for content corrections.
