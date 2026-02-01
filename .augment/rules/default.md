---
type: "always_apply"
---

# Marvain — repo-local Augment rules (default)

These rules are **repo-specific** and layer on top of the global rules in `~/.augment/rules/*`.

## Environment
- Primary environment manager is **Conda**.
  - Env name: `marvain`
  - Spec file: `config/marvain_conda.yaml`
  - Python: **3.11**
- Prefer activating with:
  - `. ./marvain_activate`
- `marvain` cli should explose all functionality needed to build, deploy, run, monitor, debug, stop, start, restart, user manage, and so on marvain

