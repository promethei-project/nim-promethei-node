import std/os
import ./imports

importTests(currentSourcePath().parentDir() / "promethei")

{.warning[UnusedImport]: off.}
