# EruditionTX Object Storage

`eruditiontx-objectstore` is a maintained fork of [MinIO](https://github.com/minio/minio), the S3-compatible object
storage server, released under the GNU AGPL v3.0. The upstream open-source project is no longer maintained
(final commit `7aac2a2c5`, February 2026); this fork keeps it on a supported Go toolchain, upgrades vulnerable dependencies and
carries its own fixes for security advisories that were not fixed in the open-source tree.

This project is **not affiliated with or endorsed by MinIO, Inc.** "MinIO" is a trademark of MinIO, Inc. and is used
here only to identify the upstream project.

## What differs from upstream

- Go 1.27 toolchain and patched third-party modules (govulncheck: 0 reachable vulnerabilities at the time of writing).
- Fixes for [GHSA-9c4q-hq6p-c237](https://github.com/advisories/GHSA-9c4q-hq6p-c237) (CVE-2026-40344) and
  [GHSA-hv4r-mvr4-25vw](https://github.com/advisories/GHSA-hv4r-mvr4-25vw) (CVE-2026-41145), with regression tests.
- Nothing else is renamed: the Go module path stays `github.com/minio/minio`, and the `minio` command and the
  `MINIO_*` environment variables are unchanged, so it is a drop-in replacement for the upstream binary.

The full change history is in the [pull requests](https://github.com/Eruditiontx/eruditiontx-objectstore/pulls?q=is%3Apr+is%3Amerged).

## Building from source

```sh
git clone https://github.com/Eruditiontx/eruditiontx-objectstore.git
cd eruditiontx-objectstore
make build   # produces ./minio
```

The toolchain version is set in `go.mod`. Usage, configuration and deployment are as documented upstream; the original
README is kept as [UPSTREAM-README.md](UPSTREAM-README.md).

## Branches

- `DEVELOPMENT`: default branch; all changes land here through pull requests.
- `master`: the untouched upstream history, kept for reference.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

GNU Affero General Public License v3.0; see [LICENSE](LICENSE). Original copyright notices of MinIO, Inc. are retained
in [NOTICE](NOTICE) and in the source files. Under AGPL §13, the complete corresponding source of any build we run is
this repository.
