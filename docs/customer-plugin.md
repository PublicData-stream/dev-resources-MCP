# Customer skills and client packages

The customer package teaches ChatGPT, Codex, and Claude how to use this MCP
server for three workflows. It contains instructions and remote connection
metadata, not a server deployment or package-execution environment.

| Skill | Workflow |
| --- | --- |
| `devres-standards-research` | RFCs, MDN/browser compatibility, WHATWG/W3C, and Chromium documentation/history |
| `devres-package-research` | Exact Rust/npm releases, captured sources, documentation/APIs, declarations, and release comparisons |
| `devres-lockfile-audit` | Request-local Cargo/npm/pnpm/Yarn assessment and public advisory research |

Shared sources live in [the customer package](../plugins/dev-resources/).
Plugin version `0.1.0` is independent of the server version. First-party package
content is AGPL-3.0-only; upstream evidence retains its own notices and terms.

## Generate packages

Run from the repository root on Linux with Python 3. Supply the actual HTTPS `/mcp`
endpoint operated for your customers; this repository does not select a production
hostname. Replace the illustrative hostname before running:

```sh
python3 scripts/package-plugin.py \
  --mcp-url https://mcp.your-domain.example/mcp \
  --output /tmp/devres-customer-packages
```

The output directory must not already exist. `--target` accepts `openai`,
`claude-code`, `claude-skills`, or `all` (the default). Generation is offline:
it does not probe the endpoint, install anything, modify account settings, or
publish a listing. Outputs are confined below `/tmp`.
Nested output ancestors must belong to the invoking user and must not be writable
by group or other users. Newly created packaging ancestors and the output root
are private (0700); inner file and directory permissions also depend on the umask.
Source and output paths with symlinked ancestors are rejected; packaging on
macOS's symlinked `/tmp` layout is not supported by this Linux-qualified command.
These packaging restrictions do not restrict the client platforms of generated ZIPs.

| Output | Purpose |
| --- | --- |
| `openai/dev-resources/` and `openai/dev-resources.zip` | Portable OpenAI plugin plus synchronized Codex compatibility manifests and skill metadata |
| `claude-code/dev-resources/` and `claude-code/dev-resources.zip` | Claude Code plugin with an anonymous remote HTTP MCP connection |
| `claude-skills/<skill-name>/` and `claude-skills/<skill-name>.zip` | One standalone skill folder/ZIP per workflow for Claude custom-skill upload |

The table's paths are relative to `--output`. Regenerate into a new output
directory when changing the endpoint or package sources; do not hand-edit the
generated platform manifests independently. Credentials are not supported in the
endpoint or bundled files. A package pointing to a disposable fixture endpoint is
a **test artifact**, not a production connection.

The shared skill descriptions fit Claude's custom-upload limit of 200 characters.
The packager enforces that limit for `claude-skills` and `all`; OpenAI and Claude
Code packages retain their developer-side 1,024-character limit. See
[Anthropic's custom-skill metadata requirements](https://support.claude.com/en/articles/12512198-how-to-create-custom-skills).

## ChatGPT and Codex

The OpenAI package contains portable `plugin.json` and `mcp.json`, a
`.codex-plugin/plugin.json` compatibility manifest with its MCP configuration,
and `agents/openai.yaml` metadata for each skill. Follow the current
[OpenAI local-plugin installation guidance](https://developers.openai.com/plugins/build/plugins#install-a-local-plugin-manually)
to add the expanded `openai/dev-resources/` folder to a local marketplace and
install through the supported desktop surface. Local marketplace support varies
by client; the ZIP alone does not install a plugin into an account.

Once installed, select the skill with `@` in ChatGPT or `$`/`/skills` in Codex,
using the name exposed by that client. For example:

```text
Use $devres-package-research to compare the captured API evidence for these two Rust releases.
```

Confirm that the plugin's MCP tools are available before relying on the skill.
This documentation provides setup instructions; it does not establish native
ChatGPT or Codex UI acceptance. See [OpenAI skill usage](https://learn.chatgpt.com/docs/build-skills).

## Claude Code

Temporarily load the expanded Claude Code plugin without a persistent account or
marketplace installation:

```sh
claude plugin validate --strict /tmp/devres-customer-packages/claude-code/dev-resources
claude --plugin-dir /tmp/devres-customer-packages/claude-code/dev-resources
```

In that session, use a namespaced skill command such as
`/dev-resources:devres-standards-research` followed by the research request.
The skills can also activate when their descriptions match a request. Check the
session's MCP status and available tools before making research claims. See
[Claude Code plugins](https://code.claude.com/docs/en/plugins) and
[skill command names](https://code.claude.com/docs/en/skills#how-a-skill-gets-its-command-name).

For a connection-only setup instead of the bundled plugin connection, add a remote
server using the actual endpoint:

```sh
claude mcp add --transport http dev-resources https://mcp.your-domain.example/mcp
```

This alternative changes Claude Code configuration and does not install skills.
Choose one connection path to avoid duplicate servers. The package generator does
not run either setup command. See [Claude Code MCP configuration](https://code.claude.com/docs/en/mcp).

## Claude Connectors and custom skills

Connectors and skills are separate components. In Claude's **Customize >
Connectors**, add a custom connector with your server's public HTTPS `/mcp` URL,
select **No sign in**, and enable it for the conversation. This server is
anonymous; do not add OAuth configuration, API keys, or caller credentials.

Claude Connectors reach the endpoint from Anthropic's cloud infrastructure. The
endpoint therefore needs public reachability and a publicly trusted TLS
certificate. A local address, private minikube route, or locally trusted fixture
certificate cannot prove this path. Follow
[Anthropic's connector setup and network requirements](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).

Separately, in **Customize > Skills**, upload each desired ZIP from
`claude-skills/` and enable it. Each ZIP contains one skill folder with `SKILL.md`
and its references. Claude's skill feature requires its host code-execution/file
creation capability to be enabled; these research instructions still forbid
executing inspected packages. Refer to
[Anthropic's skill prerequisites and upload steps](https://support.claude.com/en/articles/12512180-use-skills-in-claude).

Ask Claude to use the named skill and the connector, then verify that MCP tools
were called and evidence was returned. Registering a connector does not import
these skill files, and uploading skills does not connect the server. Account
setup and an actual Claude Connector session are separate acceptance steps.

## Evidence, privacy, and verification

The skills discover live schemas and preserve returned captures, snapshots,
cursors, resource identifiers, original source URLs, and notices. Citations can be
structured evidence even when a host does not render native resource links.
Missing corpus coverage and stale evidence remain explicit. Supplementary official
upstream browsing is labeled separately from MCP-retained evidence.

Send supplied lockfile text only to the appropriate audit tool. Server-side
lockfiles and reports remain request-local; never put them in package files,
captures, shared fixtures, or unrelated uploads. The skills do not install,
build, or execute inspected packages. See [Specification](Specification.md) and
[npm assessment](npm.md) for the owning contracts.

Packaging checks, synthetic skill evaluations, actual Claude Code invocation,
fixture protocol checks, native architecture CI, native ChatGPT/Codex UI, Claude
Connector sessions, provider coverage, and production operations are distinct
evidence. Passing local checks does not establish the others. This package does
not change the server's supported MCP revisions or add administrative tools.

## Implementation validation: 2026-10-27

The initial implementation passed the following checks on local Linux amd64:

- All three Skill Creator validations, generated JSON/YAML parsing, local Markdown
  links, eight packaging tests, and the complete 146-test Python suite.
- Claude Code `2.1.311` strict plugin validation, with no manifest errors or warnings.
  Separate directory-profile diagnostics identify missing listing materials;
  this private package has not qualified for directory submission.
- Claude child-process scenarios using the reported model `claude-opus-5-5`:
  standards versus browser support, incomplete package comparisons, qualified
  audits, missing input, and an unrelated translation request. Synthetic cases
  also exercised embedded instructions, fixed pagination and unavailable evidence.
- A temporary Claude Code plugin load connected through its own packaged MCP
  configuration to a local HTTPS fixture and invoked only `server.info` and
  `crate.corpus_status`. The fixture's collectors were disabled and its corpus
  snapshot was absent. No provider retrieval was requested.
- Rust formatting, Clippy, workspace tests, `cargo audit`, and `cargo deny check`.
- Real PostgreSQL persistence and pinned OxiBelt HTTP/WebTransport acceptance.
  The initial configured rootless Docker attempt failed an overlay mount;
  both container gates passed using the repository's isolated Docker helper
  with disposable state under `/tmp`.
- Independent agent review of the integrated implementation and final corrections;
  this is not a human GitHub approval.

Follow-up checks on the same date passed all 12 packaging tests and the complete
150-test Python suite after the packaging corrections. Tests cover the documented
200-character custom-upload limit, the developer-side 1,024-character boundary,
decoded Unicode, private output ownership/modes, a concurrent symlink-insertion
attempt, and final expanded-package integrity. Strict Claude Code validation was
rerun against the regenerated final package.

Skill Creator validation and Claude's description-matching check ran after the
descriptions were shortened to 199, 194 and 196 characters (standards, package and
audit). The later output-verification changes did not change bundled skill files.
Claude `claude-opus-5-5` selected the intended three workflows and left an unrelated
translation request outside them. Additional read-only Claude source review of a
frozen snapshot confirmed the prior packaging findings were addressed, with no
blocking findings; independent agent review also found no blockers. Rust and
container baseline gates above were not repeated for this packaging-only correction.

No Kubernetes/minikube gate was needed because this change does not modify
deployment or network behavior. Hosted CI/native arm64, native ChatGPT/Codex UI,
Claude Connector cloud reachability, live-provider coverage, account installation,
directory submission and production deployment remain unverified by these checks.
