# Crystal Palace compatibility

This document tracks behavior against the pinned Crystal Palace 2026-07-16
source distribution. “Supported” means the behavior is implemented in Go and
covered by unit or end-to-end tests. “Differential” additionally means GitHub
Actions runs the same original Crystal Grotto fixture through the pinned Java
implementation and compares the result.

## Supported surface

| Area | Status | Verification |
| --- | --- | --- |
| Cobra commands (`build`, `link`, `coffparse`, `disassemble`, `server`) | Supported | CLI unit and black-box E2E tests |
| Legacy `run` and `buildPic` command names | Supported as hidden aliases | CLI unit tests |
| Core spec parsing, labels, calls, hooks, variables, packing, byte transforms, and configuration specs | Supported | Unit, E2E, and differential tests |
| PE/COFF parsing and import discovery | Supported with strict bounds checks | Unit and fuzz tests |
| COFF merge and ZIP `mergelib` behavior | Supported | Unit tests, including upstream all-member semantics |
| COFF, PIC, PIC64, and PICO output | Supported for x86/x64 relocation forms exercised by the suite | Unit and real-MinGW differential tests |
| `+gofirst`, `+optimize`, and `+disco` ordering passes | Supported | Unit tests |
| x64 `.refptr` `+relax` | Supported | Unit and real-MinGW differential tests |
| `fixptrs` and x86/x64 `fixbss` easy-PIC rewrites | Supported for proven instruction forms | Exact-vector, race, fuzz, E2E, and real-MinGW differential tests |
| `dfr` dynamic function resolution | Supported for canonical x86/x64 indirect call, jump, and move forms | Exact-vector, COFF round-trip, linker, race, fuzz, and live amd64 differential execution tests |
| Easy-PIC helper safety walk | Supported for proven direct, relocation, RIP-relative, and `.refptr` graph edges | Graph, malformed-input, race, and fuzz tests |
| `+mutate` constant blinding | Supported for the five upstream mutation families and proven control-flow repairs | Exact upstream-Iced vectors, direct upstream pass probes, unit, race, and fuzz tests |
| `rule` and `-g` YARA generation | Supported with conservative candidate selection | Unit, CLI integration, and structural differential tests |
| Loopback JSON sidecar (`link`, `build`, and legacy `piclink` actions on `/link`) | Supported | Handler, application, and concurrency tests |

## Deliberate limits and work in progress

- Attach/redirect hook encoding, user-intrinsic expansion, `ised`,
  `+blockparty`, `+shatter`, `+regdance`, and generated x64 unwind information
  are still being ported. A configured program-affecting feature fails with a
  typed error; it is never silently ignored.
- The built-in DFR backend preserves the upstream resolver calling contracts
  but uses guarded, same-length branch sites and resolver stubs instead of
  Iced's inline byte sequence. Existing source offsets remain stable; generated
  stubs do not yet receive synthesized Windows unwind metadata.
- The Go Capstone binding does not expose Iced-x86's architecture-specific
  instruction-detail model. Rewriters accept byte forms whose register, flag,
  stack, relocation, and branch behavior can be proven and reject unproven
  forms transactionally. YARA generation likewise omits unsafe candidates and
  records warnings.
- Diagnostic text is native Go/Capstone output and is not byte-for-byte
  identical to Java/Iced output. Deterministic program bytes are compared
  exactly; randomized transformations require structural comparison.
- The COFF model cannot preserve upstream parser details that it does not
  expose, including raw label-symbol entries and line-number record bytes.
- The sidecar intentionally omits upstream `/die`, which terminates the server
  process remotely. It binds IPv4 loopback by default, limits request bodies,
  and uses HTTP timeouts.

## Differential-test contract

Normal `go test ./...` runs without Java or a network connection. Tests built
with the `compat` tag require explicit `CRYSTAL_PALACE_JAR` and
`CRYSTAL_GROTTO_BIN` paths and fail when either reference is absent. CI obtains
the dated upstream archive in runner-temporary storage, verifies its pinned
SHA-256 checksum, builds it with Ant, compiles original GPLv3 MinGW fixtures,
and compares both implementations. Upstream code and generated JARs are never
committed to this repository.
