## Evaluation: provider `rules` (keyword-rules-v1), prompt v1

| Metric | Value |
|---|---|
| window precision | 1.0 |
| window recall | 1.0 |
| window f1 | 1.0 |
| incidents detected | 4/4 |
| false incidents | 0 |
| root cause accuracy | 0.75 |
| mean citation precision | 1.0 |
| clean outputs | 4/4 |

| Incident | Detected | Delay (s) | Root cause correct | Citation precision | Confidence |
|---|---|---|---|---|---|
| A: database connection pool exhaustion | yes | 0 | yes | 1.00 | medium |
| B: disk full on storage node | yes | 0 | yes | 1.00 | medium |
| C: credential stuffing against auth | yes | 0 | yes | 1.00 | medium |
| D: expired TLS certificate on payments upstream | yes | 0 | no | 1.00 | low |
