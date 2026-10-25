import Lake
open Lake DSL

package firmware_verifier where
  version := v!"0.1.0"

@[default_target]
lean_lib Verifier where
  roots := #[`Verifier]

@[default_target]
lean_exe ingest_check where
  root := `Main
