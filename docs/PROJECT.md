# Project record

## Objective

Check that every Prometheus alert links to a runbook that exists: local files, heading anchors, base-URL mapping, path containment and suggested links for missing ones

## Scope

- In scope: the public API documented in [README.md](../README.md), typed and tested.
- Out of scope: anything that needs runtime dependencies or I/O without an accepted ADR.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 627688 / 55640 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.0704 |

## Factory run u238 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | deepseek-v4-pro | yes | 1907 | 18739 | 0 | 3200 | 0.0384 |
| fix-1 | deepseek-flash | no | 14102 | 2694 | 0 | 142720 | 0.0042 |
| fix-2 | deepseek-flash | no | 9076 | 4600 | 0 | 33792 | 0.0042 |
| audit | deepseek-flash | no | 18703 | 26619 | 0 | 269184 | 0.0196 |
| fix-3 | deepseek-flash | no | 12508 | 2988 | 0 | 122496 | 0.0040 |

Total: $0.0704. Prices: deepseek line, as measured by its adapter.
