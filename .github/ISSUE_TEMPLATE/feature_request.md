---
name: New technique / feature request
about: Propose a new obfuscation pass or a change in scope
title: "[technique] "
labels: enhancement
---

**Which category does this fall under?**
Lexical & Data / Control Flow / Virtualization & Advanced / Anti-Analysis & Integrity / Anti-AI

**Is this already listed as declined?**
Check [`README.md`](../../README.md#whats-actually-in-here) and
[`README.md#declined-techniques`](../../README.md#declined-techniques)
first. If it's listed as a "no," you'll need a concrete technical argument for
why the stated objection no longer applies, not just that it's on a
checklist. See [`CONTRIBUTING.md`](../../CONTRIBUTING.md#the-rules).

**What would this technique do, concretely, to this specific fixture?**

**How would you measure its effect against REA?**
(before/after `inspect-managed-members` output, corpus pass rate, etc.)

**Does it require anything memory-unsafe or non-deterministic?**
If yes, see ground rule 2 and 3 in `CONTRIBUTING.md`. This is usually a
blocker, not a detail to work around.
