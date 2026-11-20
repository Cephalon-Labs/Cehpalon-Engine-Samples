# Retained agent attempts

These are historical observations from the isolated agent worktree, not the
integrated Engine acceptance result.

- `restore-attempt01.txt` / `build-attempt01.txt`: initial restore inherited two
  machine package sources and produced NU1507; the analyzer also reported RS2008
  because diagnostic release tracking was absent. Scoped NuGet.Config now clears
  to official nuget.org; unshipped diagnostic release files now enable tracking.
- `build-attempt02.txt`: the new test harness had CS1525 from a missing space
  between C# null-forgiving `!` and equality `==`. Corrected the test expression;
  this was not a generator/Engine runtime failure. The initial driver build had
  zero warnings/errors and all38 checks passed; independent review subsequently
  exposed missing semantic-identity coverage as described below.
- First package-inventory collector attempt raised
  `ValueError: Cache/lock content hash mismatch: microsoft.codeanalysis.analyzers`.
  The collector incorrectly compared `.nupkg.sha512` (raw signed archive hash)
  with NuGet lock contentHash. Corrected collector checks actual raw archive
  against `.nupkg.sha512`, and separately compares `.nupkg.metadata.contentHash`
  with every lock graph. All13 package records now pass those distinct checks.
  This correction does not replace either hash or alter any package bytes.
- Initial compiler fixture emitted generator output under its source directory
  because `IntermediateOutputPath` was not initialized at that evaluation point.
  Moved the retained generated output to ignored `.local/codegen/generated-attempt01`
  and changed the output property to `$(BaseIntermediateOutputPath)generated`,
  inside excluded `obj/`. A subsequent actual SDK build/run passes; no generated
  `.cs` remains in the fixture's source glob.
- The first advisory CLI query implicitly restored using the machine cache;
  final locked restore explicitly uses the private cache and the retained final
  advisory query uses `--no-restore`. No global runtime/settings were changed.

Final data files are `win-driver.json`, `win-compiler-consumer.json`,
`package-inventory.json`, `package-advisory.json` and `provenance.json`.
Their scope does not include listed-supported Windows, hosted CI, real transports,
tenant/security conformance, benchmarks, AOT or production qualification.

## Independent review correction after the initial38 passing checks

The peer supplied valid C# containing a normal handler and a file-local handler
whose display strings were identical. The initial generator deduplicated by that
display string and silently dropped the file-local diagnostic when the normal
declaration came first. Reversed declaration order rejected it, exposing the
order-dependent defect. The peer also found annotations split over partial parts
were not counted together, and a namespace at the reserved registry name was not
reported with the generator's own collision diagnostic.

The corrected generator reports every candidate error, deduplicates registrations
by semantic symbol identity, counts matching attributes over the complete partial
symbol and checks the reserved namespace/type path. Four regression cases bring
the driver suite to42/42; the actual SDK compiler fixture passes again. The
initial38-check output and source hashes are retained as historical observations,
not used as proof of the corrected source. Raw peer before/after observations are
retained beside this note; no test threshold or invalid-input rule was relaxed.
