<div align="right"><sub><b>English</b>&nbsp;&nbsp;⇄&nbsp;&nbsp;<a href="./README.md">简体中文</a></sub></div>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/hero-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./assets/hero-light.svg">
    <img src="./assets/hero-light.svg" width="880" alt="RedactGate — local outbound redaction gateway for coding agents">
  </picture>
</p>

<p align="center"><sub>The local outbound gateway that masks checksum-validated Chinese PII before your Claude Code / Codex agent sends it offshore.</sub></p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-black.svg" alt="License: MIT"></a>
  <a href="https://github.com/SuperMarioYL/redactgate/releases"><img src="https://img.shields.io/github/v/release/SuperMarioYL/redactgate?color=DC2626&label=release" alt="Latest release"></a>
  <a href="https://github.com/SuperMarioYL/redactgate/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/SuperMarioYL/redactgate/ci.yml?branch=main&label=CI" alt="CI status"></a>
  <img src="https://img.shields.io/badge/python-3.12%2B-3776AB.svg" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/Claude%20Code-ready-D97757.svg" alt="Claude Code ready">
  <img src="https://img.shields.io/badge/Agent-egress%20guard-5E5CE6.svg" alt="Agent egress guard">
</p>

**Pain → fix:** a cloud Coding Agent streams a whole source file — business logic mixed with a hard-coded ID card and phone number — straight to an offshore model, and you have no way to intercept it. RedactGate sits between the agent and the model and masks **only checksum-validated** Chinese PII field-level before it leaves the machine, while the logic reaches the model untouched and every masked field is written to an audit log.

```bash
pip install redactgate
redactgate scan examples/demo-repo/leaky.py     # list every hit with line/type/checksum
redactgate proxy --stdin < examples/demo-repo/leaky.py | head   # mask on egress
```

---

## Table of contents

- [Architecture](#architecture)
- [Why this exists](#why-this-exists)
- [Install](#install)
- [Quickstart](#quickstart)
- [Usage](#usage)
- [Demo](#demo)
- [Configuration](#configuration)
- [Pricing (Team / Enterprise)](#pricing-team--enterprise)
- [Roadmap](#roadmap)
- [Comparison](#comparison-vs-codex-file-level-exclusion)
- [License](#license)

---

<h2 id="architecture"><img src="https://api.iconify.design/tabler:topology-star-3.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Architecture</h2>

A single-process CLI — no external services, no database, no containers. Three responsibilities: **intercept** (`proxy.py`), **detect + mask** (`detectors/` + `redactor.py`), and **trail** (`audit.py`).

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/atlas-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./assets/atlas-light.svg">
    <img src="./assets/atlas-light.svg" width="880" alt="Architecture: Coding Agent → RedactGate proxy (detectors + redactor + audit) → Model API">
  </picture>
</p>

<h2 id="why-this-exists"><img src="https://api.iconify.design/tabler:shield-lock.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Why this exists</h2>

Developers at Chinese enterprises (banks, 政企, fintech) are told to use a cloud **Coding Agent**, but an internal repo's source file routinely **mixes business logic they want the model to see with a hard-coded ID card or intranet host they are legally forbidden** (个保法 / 数据安全法) from shipping offshore. Codex's file-level exclusion ([issue #2847](https://github.com/openai/codex/issues/2847), 133 HN points, still unimplemented) is the wrong granularity — it blocks the whole file or sends it all; gitleaks / trufflehog only scan secrets in CI, not the live **Agent**↔model path, and never validate GB 11643 / 统一社会信用代码 checksums.

RedactGate masks at the **field (diff-hunk) granularity the agent actually operates on**: the logic still reaches the model, the regulated PII is replaced with stable placeholders. The defensible primitive is a **checksum-validated Chinese-PII recognizer + field-level diff masking + an outbound audit trail** — only strings that **pass their check digit** get masked, so the "every 18-digit number flagged" false-positive rate drops to something usable. It is the missing piece in **Claude Code** ecosystem lists like [affaan-m/everything-claude-code](https://github.com/affaan-m/everything-claude-code): the outbound redactor that lets a cloud agent touch a private repo without leaking PII.

<h2 id="install"><img src="https://api.iconify.design/tabler:download.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Install</h2>

```bash
pip install redactgate          # requires Python 3.12+
```

From source:

```bash
git clone https://github.com/SuperMarioYL/redactgate.git
cd redactgate && pip install -e ".[dev]" && pytest
```

<h2 id="quickstart"><img src="https://api.iconify.design/tabler:rocket.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Quickstart</h2>

Three commands from a cold clone to a visible result — zero config:

```bash
pip install redactgate
redactgate scan examples/demo-repo/leaky.py                       # 1) see where the PII is
redactgate proxy --stdin < examples/demo-repo/leaky.py | head     # 2) mask it on egress
```

<details>
<summary>Sample output (scan)</summary>

```
            CN-PII in examples/demo-repo/leaky.py
 Line  Col  Type             类型                Checksum  Confidence
   12    42  id_card          身份证                  ✓          0.99
   25    12  intranet_domain  内网域名                 —          0.85
   26    15  intranet_domain  内网域名                 —          0.90
   32    17  id_card          身份证                  ✓          0.99
   33    15  phone            手机号                  —          0.80
   34    19  bank_card        银行卡                  ✓          0.90
   40    14  uscc             统一社会信用代码           ✓          0.97
   41    23  phone            手机号                  —          0.80
8 hit(s) — checksum-validated only.
```

The id card / bank card / USCC rows carry `✓` — they actually pass their check digit (GB 11643 / Luhn / mod-11-2). Phone / intranet-domain are matched by number plan / format, so their Checksum column is `—`. Line 35, `order_id = "110101199003078500"`: 18 digits but a **bad check digit**, so it is **not** flagged — ordinary serial numbers are not masked.

</details>

<h2 id="usage"><img src="https://api.iconify.design/tabler:terminal-2.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Usage</h2>

Three subcommands cover the v0.1 path. Full runnable examples live in [`examples/`](./examples/).

**1. `scan` — list CN-PII in a file (library or pre-commit hook)**

```bash
redactgate scan path/to/file.py            # table output; exits non-zero on a hit (gate CI on it)
redactgate scan path/to/file.py --json     # one JSON object per line for scripting
```

**2. `proxy` — the outbound redaction surface (stdin filter or local HTTP forward proxy)**

```bash
# stdin filter: masked text to stdout, hits appended to audit.jsonl
redactgate proxy --stdin < outbound.txt > masked.txt

# HTTP proxy: bind a local forward proxy and point your agent's model client at it
redactgate proxy --listen 127.0.0.1:8888
export HTTPS_PROXY=http://127.0.0.1:8888   # outbound request bodies masked field-level before forwarding
```

**3. `report` — the egress-redaction compliance view**

```bash
redactgate report                          # reads audit.jsonl, summarizes by type / action
redactgate report --audit ./logs/audit.jsonl
```

Library use:

```python
from redactgate.redactor import redact_text

result = redact_text(open("leaky.py", encoding="utf-8").read())
print(result.count, "field(s) masked")     # field-level — business logic preserved
print(result.text)                          # the redacted buffer
```

<h2 id="demo"><img src="https://api.iconify.design/tabler:photo.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Demo</h2>

Before/after diff: the planted ID card `110101199003078515` is masked to `1101**********8515` before egress, while the surrounding business logic is left byte-for-byte intact.

<p align="center">
  <img src="./assets/demo.gif" width="880" alt="RedactGate demo: scan finds every hit, proxy masks field-level on egress, report summarizes the audit log">
</p>

<h2 id="configuration"><img src="https://api.iconify.design/tabler:adjustments.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Configuration</h2>

Zero-config by default. To customize, write a YAML and merge it on top of the bundled [`rules/default.yaml`](./rules/default.yaml) with `--rules my.yaml` (scalars override, `detectors` merges per type, `allowlist` / `custom_patterns` concatenate). Top-level keys:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `default_policy` | `mask` \| `block` | `mask` | Default action on a hit: `mask` replaces the value field-level; `block` stops the whole outbound request (proxy only) |
| `min_confidence` | float | `0.5` | Hits below this confidence are ignored |
| `masking.style` | `partial` \| `full` \| `label` | `partial` | `partial` keeps head/tail (`1101**********8515`); `full` masks the whole span; `label` replaces with `[身份证-已脱敏]` |
| `masking.keep_prefix` / `keep_suffix` | int | `4` / `4` | Head/tail chars kept under `partial` |
| `detectors.<type>.enabled` | bool | `true` | Disable a recognizer (`id_card` / `phone` / `bank_card` / `uscc` / `intranet_domain`) |
| `allowlist` | list | `[]` | Literals/patterns never masked (e.g. fixed test values) |

<h2 id="pricing-team--enterprise"><img src="https://api.iconify.design/tabler:building-bank.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Pricing (Team / Enterprise)</h2>

The open-source core (local proxy + Chinese-PII checksum library) is **free forever to self-host** — for adoption and trust. What compliance teams actually buy is centralized control + deliverable reports, which lives in the paid tiers:

| Tier | For | Capabilities | Price (estimate) |
|---|---|---|---|
| **Open source** | Individuals / single team, self-hosted | Proxy + scan + field-level masking + JSONL audit | Free |
| **Team** | Bank / 政企 / fintech dev teams | Central rule rollout · merged audit log · **block policy** (not just mask) · exportable egress-redaction compliance report · SSO | ¥4,800/team/yr (≤10 seats) or ¥980/seat/yr |
| **Enterprise** | 信创 / on-prem procurement | Everything in Team + private deployment + 信创 environment adaptation + industry custom PII rule packs + support SLA | from ¥60,000+/yr |

> "Data-not-out" buyers reject hosting by reflex — the paid layer touches only **policy / audit metadata**, never your code. Billing is WeChat Pay / Alipay / bank transfer, not offshore Stripe.
> Team / on-prem inquiries: open an issue or email with subject "RedactGate Team".

<h2 id="roadmap"><img src="https://api.iconify.design/tabler:map-2.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Roadmap</h2>

- [x] **m1** — checksum-validated CN-PII recognizers (id card / phone / bank card / USCC / intranet domain) as a library + `redactgate scan`
- [x] **m2** — `redactgate proxy` outbound interception + field-level diff masking + JSONL audit
- [x] **m3** — pip-installable, bundled `default.yaml`, `redactgate report` summary, bilingual README + demo GIF
- [ ] Team tier: central rule rollout + merged audit + block policy
- [ ] Enterprise tier: on-prem deployment + 信创 adaptation + compliance report export
- [ ] Non-CN PII (US SSN, GDPR EU formats)
- [ ] Inbound (model→repo) scanning

<h2 id="comparison-vs-codex-file-level-exclusion"><img src="https://api.iconify.design/tabler:git-compare.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Comparison vs Codex file-level exclusion</h2>

An honest comparison against the file-level exclusion asked for in [openai/codex #2847](https://github.com/openai/codex/issues/2847):

| Capability | RedactGate | Codex file-level exclusion (#2847) |
|---|:---:|:---:|
| Shipped, usable today | ✓ | — (still open) |
| Field-level / diff-hunk granularity (logic still reaches the model) | ✓ | ✗ (whole-file exclusion) |
| Checksum-validated Chinese PII (GB 11643 / Luhn / mod-11-2) | ✓ | ✗ |
| Outbound audit log (deliverable for compliance) | ✓ | ✗ |
| Deep, native agent integration | partial (explicit proxy / wrapper) | ✓ (native once shipped) |

If upstream ships #2847 as field-level with a pluggable PII hook, the moat narrows to "Chinese-PII checksum library + 信创 compliance story" — and we are honest about that (see [why this exists](#why-this-exists)).

<h2 id="license"><img src="https://api.iconify.design/tabler:license.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> License</h2>

[MIT](./LICENSE). Issues and PRs welcome — especially new industry PII rules and false-positive samples. File an [issue](https://github.com/SuperMarioYL/redactgate/issues).

## Share this

```
RedactGate — the local outbound gateway for your Coding Agent: mask checksum-validated Chinese PII before Claude Code sends it offshore. https://github.com/SuperMarioYL/redactgate
```

---

<p align="center"><sub><a href="./LICENSE">MIT</a> © 2026 SuperMarioYL</sub></p>
