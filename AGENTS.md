# Agent orientation

`dev-resources-MCP` provides anonymous developer knowledge and Rust package research.
The Rust workspace separates domain contracts, application retrieval policy, adapters,
and HTTP/WebTransport composition. Read [Contributing](CONTRIBUTING.md) first.

| Work | Canonical guidance |
| --- | --- |
| Public behavior and source coverage | [Specification](docs/Specification.md) |
| Configuration and operating limits | [Configuration](docs/Configuration.md) |
| Dependency direction and durable captures | [Architecture](docs/architecture.md) |
| Provider budgets, freshness, and licensing | [Sources](docs/sources.md) |
| Local containers and Kubernetes acceptance | [Operations](docs/operations.md) |
| Bounded delegation | [Delegation skill](.agents/skills/subagent-delegation/SKILL.md) |

Preserve request-only audit privacy throughout logging, errors, persistence, and
resources. Never execute inspected package code. Keep permanent public captures
separate from disposable test artifacts. Report compilation, fixture tests, live
provider checks, native architecture CI, edge/cluster acceptance, and production
operations as separate evidence. Agent review is not a human GitHub approval.
