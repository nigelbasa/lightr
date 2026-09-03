# Releasing

Two artifacts, one version number.

| Artifact | Who it is for | Where it comes from |
| --- | --- | --- |
| `lightr-<version>-py3-none-any.whl` on PyPI | someone embedding Lightr, or running it in a container they build | `python -m build` |
| `lightr_<version>_all.deb` | someone installing a mail server on a Debian or Ubuntu host | `scripts/build-deb.sh` |

The `.deb` is the one to point people at. `pip install` into a
virtualenv, a service user, a systemd unit and a Dovecot configuration
is a lot of steps to get right before any mail moves; `apt install`
does all of it.

## The interpreter problem

Lightr needs Python 3.11 — `StrEnum`, `datetime.UTC` and `typing.Self`
are all 3.11, and the code does not import without them.

That is fine on Debian 12 (3.11) and Ubuntu 24.04 (3.12), and it is a
problem on Ubuntu 22.04, whose `python3` is 3.10. A package declaring
`python3 (>= 3.11)` there is simply uninstallable, which is a confusing
way for someone to discover the requirement.

So the `.deb` depends on **the interpreter it was actually built
against**, and the build script works that out:

```bash
# Debian 12, Ubuntu 24.04 -- the system python3 is new enough
./scripts/build-deb.sh

# Ubuntu 22.04 -- python3 is 3.10, so bundle deadsnakes' 3.12
add-apt-repository -y ppa:deadsnakes/ppa
apt install -y python3.12 python3.12-venv
LIGHTR_PYTHON=python3.12 ./scripts/build-deb.sh
```

The venv is bundled whole, so **build on the distribution you will
install on**. Its `site-packages` is named for the interpreter's minor
version and it carries compiled wheels; a package built against 3.11
does not work on a host running 3.12.

That means one `.deb` per target, not one `.deb`. Name them for what
they are — `lightr_0.4.0_all_ubuntu2204.deb` — rather than letting
someone find out by installing.

## Cutting a release

```bash
# 1. Version, in one place
$EDITOR pyproject.toml            # version = "x.y.z"

# 2. Prove it
python -m pytest && ruff check src tests

# 3. Prove it on the platform, not just in the test runner
#    (the Lua passdb passed every unit test it ever had and could not
#    work at all on the target)
ssh <a real host> 'lightr preflight'

# 4. Build
python -m build                   # wheel and sdist
./scripts/build-deb.sh            # once per target distribution

# 5. Publish
python -m twine upload dist/lightr-x.y.z*
gh release create vx.y.z dist/*.deb --notes-file <notes>
```

`twine upload` asks for a token. That is yours to type — nothing in
this repository, and nobody working on it, should be handling it.

## Retiring old versions

PyPI does not let a version be replaced, and deleting one breaks anyone
who pinned it. The honest options are narrower than they look:

* **Yank** (`pip` will not select it, an existing pin still resolves) —
  the right answer for a release with a bug bad enough that nobody new
  should get it. `0.1.0` through `0.3.x` are pre-Dovecot-2.3-fix
  releases whose IMAP login cannot work on any supported platform, so
  they should be yanked, not left as plausible-looking choices.
* **Delete** — only for something published by mistake, such as a file
  containing a credential.

For the `.deb`, delete the old GitHub release assets. There is no
resolver to break, and leaving a package that cannot log a user in
where someone can download it serves nobody.

Leave exactly one version installable at a time. Someone arriving at
this project should not have to work out which of five releases is the
one that works.

## What CI does and does not check

CI runs the tests and the linter. It does not build the `.deb` — that
needs a matrix of target distributions and a real `dpkg` — and it does
not install one.

`scripts/build-deb.sh` therefore checks what it built rather than what
it meant to build: every maintainer script is parsed with `sh -n`, the
contents and dependencies are printed, and the bundled console scripts
are checked for a shebang still pointing at the build directory — which
would break every command in the package and is invisible until
install.

A `.deb` nobody has installed is not a verified `.deb`. Install it on a
scratch host before pointing anyone at it.
