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
| `disassemble -o` BTF transforms and `-f` flag | Supported through the same object/export pipeline as linker specs | Cobra unit and transformed-output tests |
| Core spec parsing, labels, calls, hooks, variables, packing, byte transforms, configuration-installed hooks, and canonical file resolution | Supported | Unit, E2E, race, and differential tests |
| PE/COFF parsing, capability validation, and import discovery | Supported with strict bounds checks | Unit and fuzz tests, including malformed capability rejection |
| COFF merge and ZIP `mergelib` behavior | Supported | Unit tests, including upstream all-member semantics |
| COFF, PIC, PIC64, and PICO output | Supported for x86/x64 relocation forms exercised by the suite, including relocation-free `.rdata` in raw x86/x64 PIC | Unit and real-MinGW differential tests |
| `+gofirst`, `+optimize`, and `+disco` ordering passes | Supported with relocation-free direct-edge discovery, displacement repair, LTO roots, and padding trimming | Exact-vector, race, real-MinGW differential, structural, and live amd64 execution tests |
| x64 `.refptr` `+relax` | Supported | Unit and real-MinGW differential tests |
| `fixptrs` and x86/x64 `fixbss` easy-PIC rewrites | Supported for proven instruction forms | Exact-vector, race, fuzz, E2E, and real-MinGW differential tests |
| `dfr` dynamic function resolution | Supported for canonical x86/x64 indirect call, jump, and move forms | Exact-vector, COFF round-trip, linker, race, fuzz, and live amd64 differential execution tests |
| Easy-PIC helper safety walk | Supported for proven direct, relocation, RIP-relative, and `.refptr` graph edges | Graph, malformed-input, race, and fuzz tests |
| `+mutate` constant blinding | Supported for the five upstream mutation families and proven control-flow repairs | Exact upstream-Iced vectors, direct upstream pass probes, unit, race, and fuzz tests |
| Attach/redirect hooks and intrinsic expansion | Supported for canonical x86/x64 call, jump, address-load, hash/tag, and arbitrary-length user-intrinsic forms | Exact vectors, COFF round-trip, race/fuzz tests, and byte-exact real-MinGW differential tests |
| `__resolve_hook` linker intrinsic | Supported with guarded per-call resolver stubs and upstream hook-selection semantics | Exact vectors, COFF/linker tests, race/fuzz tests, and live amd64 differential execution tests |
| x64 `__transfer` linker intrinsic | Supported for proven push/sub stack frames with relocation, branch, symbol, and metadata repair | Exact upstream vectors, unit/race/fuzz tests, and byte-exact live real-MinGW differential tests |
| `ised` instruction rewriting | Supported for conservatively lifted x86/x64 forms, arbitrary-length raw edits, relocation/symbol repair, and final `+split` jump healing | Unit/race/fuzz tests and byte-exact real-MinGW differential tests |
| `+regdance` saved-register permutation | Supported for proven x86/x64 instruction forms and metadata repairs | Exact seeded upstream vectors, unit, race, and fuzz tests |
| `+blockparty` function-local basic-block permutation | Supported for proven x86/x64 control flow and metadata repairs | Exact seeded upstream vectors, unit, race, and fuzz tests |
| `+shatter` program-wide basic-block permutation | Supported for proven x86/x64 control flow and metadata repairs; takes precedence over `+blockparty` | Exact seeded upstream vectors, unit, race, and fuzz tests |
| Generated x64 unwind data, `catch`, PICO unwind resources, and PIC `linkpost ... unwind` | Supported for provable fixed and frame-pointer stack layouts | Exact pdata/xdata vectors, unit/race/fuzz tests, and byte-exact real-MinGW differential tests |
| `rule` and `-g` YARA generation | Supported with conservative candidate selection | Unit, CLI integration, and structural differential tests |
| Repeated diagnostic outputs | Supported with truncate-once/append-later canonical-file semantics | Unit and concurrency tests |
| Loopback JSON sidecar (`link`, `build`, and legacy `piclink` actions on `/link`) | Supported | Handler, application, and concurrency tests |
| Upstream `/die` sidecar shutdown | Supported with explicit `server --enable-die` opt-in | Default non-exposure and delayed graceful-shutdown tests |

## Deliberate limits and work in progress

- The built-in DFR backend preserves the upstream resolver calling contracts
  but uses guarded, same-length branch sites and resolver stubs instead of
  Iced's inline byte sequence. Existing source offsets remain stable. Generated
  stubs are included in later unwind analysis when `+unwind` is requested; any
  stack behavior that cannot be proven fails closed.
- Hook-resolver expansion is semantically compatible but uses guarded stubs so
  original call-site offsets remain stable instead of reproducing Iced's
  inline byte layout. Differential tests execute both generated programs on
  amd64 hosts.
- `+shatter` is incompatible with `+unwind`, matching upstream validation.
  The structural passes reject control-flow or existing unwind metadata that
  cannot be repaired with the available portable instruction detail.
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
- The upstream `/die` endpoint accepts an unauthenticated request using any HTTP
  method, returns an empty HTTP 200 response, waits 200ms, and terminates the
  server process. Crystal Grotto leaves this browser-triggerable loopback
  shutdown surface disabled by default. `server --enable-die` opts into the
  endpoint; the standalone command shuts down gracefully after the same delay
  instead of calling `os.Exit` from library code. The sidecar also limits
  request bodies and uses HTTP timeouts.

## Differential-test contract

Normal `go test ./...` runs without Java or a network connection. Tests built
with the `compat` tag require explicit `CRYSTAL_PALACE_JAR` and
`CRYSTAL_GROTTO_BIN` paths and fail when either reference is absent. CI obtains
the dated upstream archive in runner-temporary storage, verifies its pinned
SHA-256 checksum, builds it with Ant, compiles original GPLv3 MinGW fixtures,
and compares both implementations. Upstream code and generated JARs are never
committed to this repository.
