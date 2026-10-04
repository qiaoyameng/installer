# Reproducible installations

Installing the same wheel twice normally produces artifacts that differ in
non-content ways: modification times reflect when the install happened,
permissions depend on the process umask, and generated `.pyc` files use
timestamp-based invalidation (and embed absolute paths).

A *reproducible installation* mode makes these artifacts byte-for-byte
identical across installs, while keeping the staging directory (`destdir`)
separate from the logical, runtime installation paths:

- Scripts embed the configured `interpreter`; generated code and bytecode
  embed the **logical** installation paths from the scheme dictionary, never
  the random staging directory.
- `RECORD` is written with entries in a fixed, sorted order.
- Regular files get `0o644` permissions; executable files, scripts and
  directories get `0o755`.
- Every file and created directory gets the modification time given by
  [`SOURCE_DATE_EPOCH`](https://reproducible-builds.org/docs/source-date-epoch/).

```python
import os
import sys

os.environ["SOURCE_DATE_EPOCH"] = "1700000000"

destination = SchemeDictionaryDestination(
    scheme_dict=logical_scheme_paths,
    interpreter=sys.executable,
    script_kind="posix",
    bytecode_optimization_levels=(0, 1),
    destdir="/path/to/staging/root",
    reproducible=True,
)
```

The equivalent CLI invocation is:

```sh
SOURCE_DATE_EPOCH=1700000000 python -m installer --reproducible \
    -d /path/to/staging/root package-1.0.0-py3-none-any.whl
```

## Bytecode

When bytecode compilation is requested, reproducible installs use explicit
:pep:`552` **hash-based** invalidation (`CHECKED_HASH`). The `.pyc` header
stores a hash of the source instead of its modification time and size, and
each code object's filename is the logical installation path.

Because the running interpreter performs the compilation, its bytecode must
be usable by the target interpreter. Reproducible installs verify the target
`interpreter` can run, supports hash-based bytecode (Python 3.7+), and has a
matching bytecode magic number.

If `SOURCE_DATE_EPOCH` is unset/invalid, or the target interpreter is
insufficient, a {class}`~installer.exceptions.ReproducibleInstallError` is
raised. The installer never silently falls back to timestamp-based bytecode.

```{note}
Identical bytes across different Python (bytecode) versions are not
promised; reproducibility is defined for a fixed interpreter, fixed logical
paths and fixed wheel contents.
```

The default, non-reproducible installation behavior is unchanged when
`reproducible` is not enabled.
