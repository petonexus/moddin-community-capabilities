# Changelog — community-specialk-tweak-profile

## 1.0.0 — 2026-09-30

- Second community capability recipe. Exists to cover the parts of the
  runner the fps-unlocker never touches: `write-text-file`, `move-file`,
  the `verify` check section, the `file-exists` / `file-absent` /
  `process-running` check kinds, the `enum` and `number` config field
  types, and a `supportedEngines: []` (engine-agnostic) declaration.
- Deliberately does not use `registry-write`. The step takes `key`,
  `value` and `type` literally, renders no templates into any of them,
  and never passes `/d` to `reg.exe`, so it can only create an empty
  REG_SZ value under a fixed key. No registry value a game actually reads
  can be written with it, and a recipe that claimed otherwise would be
  shipping a lie. The requirement is written up in the maintainer notes.
- `status: planned` because the upstream half is unverifiable from this
  repository: the tweak file name, the INI section and keys, and the
  loader DLL. Every step param is verified against `builtin_steps.rs`.
- Writes through a staging file in the game folder and promotes it with
  `move-file`, so a partial write cannot truncate the live tweak file and
  both ends of the move sit in the transaction's rollback scope.

---

Maintainer: petonexus community.
Maintainer signing key: TBD (first release pins it via
`public-keys.json`).