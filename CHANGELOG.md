# Changelog

## 0.3.0

### Minor Changes

- b4cbbeb: Breaking! Moves to foundryvtt/cli. Removed pack_nedb and v11 support. Added remove_input flag which deletes the input directory after packing. Bumped action runtime to node24 LTS.

### Patch Changes

- b4cbbeb: Fix: Items with embedded ActiveEffects no longer lose their effects when packed.

  The previous release bundled an older copy of the foundryvtt-cli pack logic that predated the document-hierarchy walker, so embedded effects on items were never written as standalone `!items.effects!...` entries in the compendium. The action now defers to `compilePack` from a pinned, globally-installed `@foundryvtt/foundryvtt-cli@3.0.3` (whose `classic-level` dependency ships prebuilt binaries for the runner's platform). Inputs (`inputdir`, `packsdir`, `remove_input`) are unchanged. Resolves #11.

- b4cbbeb: Maintenance

## 0.2.2

### Patch Changes

- f749c0a: Makes sure the package can find the classic-level external binary even when run in an isolated context

## 0.2.1

### Patch Changes

- 78ef14e: Minor fixes to input requirement, bump node version and update docs

## 0.2.0

### Minor Changes

- 4f5e4bb: Globally installs `cassic-level`-package if it does not already exist

## 0.1.0

### Minor Changes

- 7e73f6f: Initial Setup
