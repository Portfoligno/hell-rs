# Language baseline

The compatibility target is Hell `2026-05-29` at upstream commit
`d4d028609ed46a560c62caea8c70e7e91d1afd29`.

The implementation preserves qualified `Main.*` global expansion, monomorphic
local bindings, concrete annotations, exact `main :: IO ()`, and call-by-need
evaluation. Unsupported Haskell syntax is diagnosed and is never silently
reinterpreted.

