# Crystal Grotto

Crystal Grotto is a Go port of [Crystal Palace](https://tradecraftgarden.org/crystalpalace.html), a linker and linker-script language for building and transforming position-independent Windows code. The port aims to preserve the upstream command and specification-language contracts in a native Go implementation and command-line application.

The project is under active development. Compatibility is measured against a pinned upstream distribution and backed by unit, end-to-end, and differential tests.

## Compatibility baseline

Crystal Grotto targets the Crystal Palace source distribution dated **2026-07-16**:

- Source: `https://tradecraftgarden.org/download/cpsrc20260716.tgz`
- SHA-256: `d93563767130adc525f80bfabdecbbe7f803595356f0aec7cf1669490e529855`
- Upstream runtime version string: `06.29.26`

The archive date and upstream runtime version string intentionally identify the same baseline; the values differ in the upstream release itself. Compatibility tooling therefore pins the dated URL and checksum rather than relying on the displayed version.

The upstream Java source is not committed to this repository. The local `cpsrc/` path is ignored, and CI downloads the pinned archive into temporary runner storage only after verifying its checksum.

## Compatibility status

The supported command, object-format, transformation, and sidecar surface—and
the remaining porting work—is tracked in
[docs/compatibility.md](docs/compatibility.md). Program-affecting features that
are not yet implemented return explicit errors instead of silently producing
incomplete output.

## Command-line interface

The `crystal-grotto` executable uses [Cobra](https://github.com/spf13/cobra) for its command tree and help interface. Its primary subcommands follow Crystal Palace:

| Command | Purpose |
| --- | --- |
| `build` | Build a program for an x86 or x64 specification target. |
| `coffparse` | Print a COFF object as the linker sees it. |
| `disassemble` | Disassemble object code from a COFF object. |
| `link` | Apply a specification to a Windows DLL or COFF object. |
| `server` | Start the loopback JSON-over-HTTP linker sidecar. |
| `help` | Show command-specific help. |

Typical invocations are:

```console
crystal-grotto link loader.spec module.x64.o out.bin
crystal-grotto build program.spec x64 out.bin
crystal-grotto coffparse module.x64.o
```

Use `crystal-grotto help <command>` for the complete arguments and options supported by a command.

## Requirements

Building Crystal Grotto requires Go **1.26.5**, as recorded in `go.mod`.

The ordinary Go build and test suite does not require Java, Ant, MinGW, or a checkout of Crystal Palace. Differential compatibility testing additionally requires:

- a Java 11 or newer JDK;
- Apache Ant;
- `curl`, `tar`, and a SHA-256 utility; and
- MinGW-w64 for the compatibility modules that exercise real x86 and x64 COFF inputs.

## Build

Run the command directly from the checkout:

```console
go run ./cmd/crystal-grotto --help
```

Or build a standalone executable:

```console
go build -trimpath -o crystal-grotto ./cmd/crystal-grotto
./crystal-grotto --help
```

## Tests

Run all unit tests and deterministic Go end-to-end tests with:

```console
go test -count=1 ./...
```

Before submitting a change, run the core checks locally:

```console
go test -race -count=1 ./...
go vet ./...
go build -trimpath -o crystal-grotto ./cmd/crystal-grotto
```

The full transformation race suites are deliberately exhaustive and can take
several minutes because portable decoder instances have substantial
WebAssembly startup costs. CI runs every ordinary test, race-tests core
packages as a group, and runs each decoder-heavy transformation's dedicated
concurrency test in an independent matrix job.

The normal suite is hermetic: it does not download, compile, or execute Crystal Palace. Test modules maintained in this repository are original Crystal Grotto fixtures; upstream Java and demo source remain outside the repository.

### Differential compatibility tests

The `compat` build tag enables black-box tests that run Crystal Grotto and the pinned Crystal Palace JAR against identical inputs. The tests receive the two executable paths through `CRYSTAL_PALACE_JAR` and `CRYSTAL_GROTTO_BIN`.

The fetch helper downloads, verifies, extracts, and builds the reference implementation without copying it into the repository:

```console
compat_dir="$(mktemp -d)"
./scripts/fetch-crystal-palace.sh "$compat_dir"
go build -trimpath -o "$compat_dir/crystal-grotto" ./cmd/crystal-grotto

CRYSTAL_PALACE_JAR="$compat_dir/cpsrc/build/crystalpalace.jar" \
CRYSTAL_GROTTO_BIN="$compat_dir/crystal-grotto" \
go test -tags=compat -count=1 ./...
```

The helper refuses to overwrite an existing `cpsrc/` directory. Use a new temporary directory for each run. Deterministic compatibility cases are compared byte-for-byte. Features whose upstream implementation is intentionally randomized must instead be checked with structural assertions.

## Continuous integration

GitHub Actions runs on every pull request targeting `main` and every push to `main` (including merges). The workflow has three layers:

1. formatting, module verification, `go vet`, the complete unit/end-to-end suite, and a CLI build;
2. core and focused transformation race-detector jobs; and
3. a Linux compatibility job with Java, Ant, and MinGW-w64 that builds the checksum-pinned Crystal Palace reference in runner-temporary storage and runs the `compat` test suite.

No upstream source or generated JAR is uploaded or committed by the workflow.

## Upstream attribution

Crystal Grotto is based on Crystal Palace by Raphael Mudge and the Adversary Fan Fiction Writers Guild. The upstream project and documentation are available from [Tradecraft Garden](https://tradecraftgarden.org/crystalpalace.html).

Crystal Palace is licensed under the 3-clause BSD license. Its original copyright notice, license conditions, and disclaimer are preserved verbatim in [LICENSE.upstream](LICENSE.upstream) and summarized in [NOTICE](NOTICE).

## License

Crystal Grotto's original code and modifications are distributed under the **GNU General Public License, version 3 only** (`GPL-3.0-only`). See [LICENSE](LICENSE) for the complete license text.

The upstream Crystal Palace material on which this port is based remains subject to its 3-clause BSD terms. `LICENSE.upstream` is included to preserve those terms and attribution; it does not make Crystal Grotto as a whole available under the BSD license. Third-party Go dependencies retain their own licenses.
