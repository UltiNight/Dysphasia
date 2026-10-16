---
name: Bug report
about: A pass regresses correctness, determinism, or verification
title: "[bug] "
labels: bug
---

**Which pass / report does this affect?**
e.g. `tools/obfuscator/FunctionInliningPass.cs`, or `reports/function-inlining.md`

**What broke?**
- [ ] Behavioral corpus regression (which case ID(s) from `logs/evaluation01/corpus.json`?)
- [ ] `ilverify` failure (paste the exact message)
- [ ] Non-determinism (same seed, same input, different output bytes)
- [ ] Native build warning/error (`/W4` output)
- [ ] Something else

**Exact command you ran**

```powershell

```

**Expected vs. actual output**

**Policy file used** (if applicable)
