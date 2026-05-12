---
"foundry-db-packer": patch
---

Fix: Items with embedded ActiveEffects no longer lose their effects when packed.

The previous release bundled an older copy of the foundryvtt-cli pack logic that predated the document-hierarchy walker, so embedded effects on items were never written as standalone `!items.effects!...` entries in the compendium. The action now defers to `compilePack` from a pinned, globally-installed `@foundryvtt/foundryvtt-cli@3.0.3` (whose `classic-level` dependency ships prebuilt binaries for the runner's platform). Inputs (`inputdir`, `packsdir`, `remove_input`) are unchanged. Resolves #11.
