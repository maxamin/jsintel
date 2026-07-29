# Configuration reference

`config/config.yaml` remains compatible with Phase 1. The typed loader validates
the following values before a platform scan starts.

| Key | Type | Default | Meaning |
|---|---:|---:|---|
| `threads` | positive integer | 50 | Maximum collection/download workers. |
| `crawler.depth` | positive integer | 5 | Katana crawl depth. |
| `crawler.javascript` | boolean | true | Enable JavaScript-aware crawling. |
| `download.timeout` | positive integer | 15 | Per-request timeout in seconds. |
| `download.retries` | non-negative integer | 3 | Retry count for retryable HTTP failures. |
| `database.path` | non-empty string | `output/database/recon.db` | Legacy database path; future platform scans resolve it through the asset store. |

Plugin configuration will live under a future `plugins.<plugin-id>` section and
be validated against each plugin's `schema()` contract.
