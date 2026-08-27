# Contributing

Thanks for contributing to `solana-keychain`.

This library holds signing keys and talks to production key-management services, so the bar for changes is higher than for most repositories. Read the [Making a change](#making-a-change) and [Cross-language parity](#cross-language-parity) sections before you start writing code.

## Before you start

- Search existing issues and pull requests before opening a new one.
- For substantial changes, open an issue or start a discussion first so maintainers can confirm the approach. Small PRs are preferred.
- Do not include secrets, private keys, seed phrases, API keys, or production credentials in issues, pull requests, commits, logs, or screenshots. Integration tests read credentials from a local `.env` that is gitignored: keep it that way, and never paste its contents into a PR or an issue.
- All commits into a Solana Foundation repository require [commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification) to be enabled. Your PRs will not be merged without this.

## Security vulnerabilities

Do not report security vulnerabilities in public issues. Follow this repository's [security policy](./SECURITY.md).

Parts of this codebase are covered by a third-party audit. Audit status, the audited-through commit, and the current unaudited delta are tracked in [audits/AUDIT_STATUS.md](audits/AUDIT_STATUS.md). If your change touches audited code, say so in the PR description.

## Development setup

Use `just`. The recipes encode flags that are easy to get wrong by hand: `just rust-test` runs the `sdk-v2`, `sdk-v3`, and `sdk-v4` matrices, whereas `cargo test --all-features` fails outright because the SDK features are mutually exclusive.

```sh
just build              # all four languages
just test               # unit tests, all four languages
just fmt                # format and lint, all four languages
just test-integration   # spins up a local Vault, runs integration tests
just test-all           # test + test-integration
```

Run `just` with no arguments to list every recipe, including the per-language ones (`rust-*`, `ts-*`, `py-*`, `go-*`).

Integration recipes spawn a local `vault server -dev` and load `.env` from the repository root themselves. Do not start Vault yourself or pass secrets on the command line.

Use the toolchain versions checked into the repository. Do not bump the Rust toolchain, the Go version in `go.mod`, `pnpm`, the Solana SDK majors, or the Python dependency pins as an incidental part of another change: each of those has cross-language consequences and belongs in its own PR.

## Making a change

Keep changes focused. A pull request should solve one problem and include the tests and documentation needed to keep the repository usable.

Before opening a pull request:

- Format, lint, build, and test the affected code with `just fmt`, `just build`, and `just test`.
- Add or update tests when behavior changes. Unit tests must not make live API calls: mock HTTP with `wiremock` (Rust), `respx` (Python), `httptest` (Go), or the package's fetch mock (TypeScript).
- Update documentation and examples when they are part of the user-facing contract. There are no changelog files: each release's notes are generated from the merged PR titles, so the PR title is the note.
- Explain any new dependency and why the existing dependency set is insufficient. A signing library pays for every transitive dependency it adds.

### Cross-language parity

`solana-keychain` ships one `SolanaSigner` contract over 14 backends in Rust, TypeScript, Python, and Go. A behavior change in one language is a bug in the other three until it lands there too.

If your change alters signing behavior, error codes, validation, or the wire format, either implement it across all four languages in the same PR, or open tracking issues for the rest and say so explicitly in the PR description. Do not let the implementations drift silently.

The golden wire-format vectors (for example `python/tests/test_parity.py`) exist to catch exactly this. Never regenerate them to make a failing suite pass: a changed vector means the serialization changed, which is the thing the test is there to notice.

### Security-sensitive changes

This library sits on a trust boundary. [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) states what Keychain does and does not guarantee; keep it in sync when a change alters the signing or sending shapes. When your change touches one of the following, document the reasoning in the PR:

- Signature verification and public-key binding: anything deciding whether a provider-returned signature belongs to the key you asked to sign with, and at the position you asked for.
- Transaction serialization, or the capability a backend exposes (transaction-signing, modifying, or sending).
- Broadcast-managed backends, where a failure does not mean nothing landed.
- HTTPS enforcement, redirect handling, timeouts, or credential handling in a remote signer.
- Error messages and their redaction. Messages, `Debug`/`repr`, and sanitized remote bodies are redacted deliberately so key material and raw provider responses cannot leak through logs: keep them generic and let callers match on stable codes.

### Adding a signer backend

Adding a new backend touches Rust, TypeScript, Python, Go, the TypeScript umbrella, and CI. [docs/ADDING_SIGNERS.md](docs/ADDING_SIGNERS.md) has code templates and checklists for Rust, TypeScript, and Python. Go has no written guide yet: use an existing backend under `go/signers/` as the pattern, and see [go/README.md](go/README.md) for the package layout. Go deliberately has no umbrella package, so there is no dispatcher to update there.

Open an issue first. New backends need a maintainer-side CI preparation step, handled through the [`add-signer-ci`](.claude/skills/add-signer-ci/SKILL.md) skill, before your PR can run its integration tests.

## Pull requests

Write a clear title and description explaining the problem, the approach, and how you tested it. Link related issues and call out behavior changes, compatibility concerns, or follow-up work. See the [AI use](#ai-use) section for how to disclose AI use in your PRs.

Use [Conventional Commits](https://www.conventionalcommits.org/) for commit and PR titles, scoped by backend or language where it helps (`fix(turnkey):`, `feat(python):`).

Branch and target rules:

- Branch from `main` using `feat/*`, `fix/*`, or `chore/*`. Urgent fixes to a released version branch from the stable tag as `hotfix/*`.
- Target `main`. The `release/*` flow is deprecated and CI rejects PRs from those branches.
- `just branch-info` prints the full guidance.

Review and CI:

- [CODEOWNERS](.github/CODEOWNERS) assigns reviewers automatically; Rust and TypeScript directories each have a designated owner.
- By default, [Greptile](https://www.greptile.com) is enabled on all Solana Foundation repositories. Before maintainers review, all Greptile comments must be resolved with either a code fix or an explanation of why no change is needed.
- Once CI is approved to run by maintainers, all CI errors must be addressed before the PR will be merged.
- **Pull requests from forks** additionally require a live-test gate. Integration tests against real signing providers cannot run with fork credentials, so a maintainer runs them manually and posts a marker comment tied to your head commit. Pushing new commits invalidates that marker and the gate must be re-run: batch your changes rather than force-pushing repeatedly once a maintainer has started.

Maintainers may ask you to rebase, split a broad change, add tests, or revise documentation before merging.

## AI use

You may use AI-assisted tools, but you should review the generated code, understand its behavior, and run the same checks expected of any other contribution.

If you are building with AI on Solana, check out the [Solana Dev Skill](https://github.com/solana-foundation/solana-dev-skill) or the [Solana MCP](https://mcp.solana.com/) to aid in your work.

Ensure that the generated code adheres to the project's coding standards and best practices. Maintainers can close PRs if they appear to be low-effort AI slop. In particular, audit your changes for the following AI code smells that increase maintenance burden:

- Comments that explain why the _previous_ behavior was wrong and the new behavior is correct. This can be helpful context for reviewers as a GitHub comment in the review, but we do not need a history of every code change living in the codebase.
- Large blocks of comments with high density of technical jargon; comments should be distilled to clearly explain _why_ this code is doing something (if it's not obvious), not _what_ (the code should speak for itself).
- Drive-by refactoring of code that is not relevant to the actual change being made.

Two more that matter specifically here:

- **Plausible-looking cryptography.** Assistants will happily produce signature handling, key derivation, or padding logic that compiles, passes a happy-path test, and is wrong. Anything touching signatures or key material needs you to have verified it against the provider's documentation yourself.
- **Silently broken parity.** Applying a change to one language and letting the assistant "port" it to the other three without running each suite is how the implementations drift. Run `just test` and the per-language recipes for every language you touched.

### Repository context for assistants

This repository ships configuration that makes AI-assisted work go better, and you are welcome to use it:

- [CLAUDE.md](CLAUDE.md) carries the commands, the security standing, and the cross-language gotchas that the code alone does not teach.
- [.claude/skills/](.claude/skills/) contains guides for the repository's multi-step workflows: `add-signer-ci` for wiring CI for a forked backend PR, `release` and `complete-release` for cutting a release.

Keep these current. If you learn something during your change that the next contributor would need (a failure mode, a non-obvious constraint), a line in the relevant `CLAUDE.md` is worth more than a comment buried in the diff.

### Disclosure

It can be helpful to note the extent to which AI was used in the change. For example, adding

> I wrote all of the code for this feature, and had Claude update the documentation and create tests accordingly

or

> I architected the change and handed all implementation over to Codex

to the pull request description can be helpful context for reviewers.

### Communication

If maintainers have suggested changes, feedback, or questions about your code, you should not be copy/pasting the questions to an LLM and copy/pasting the response. You being able to distill the information that AI produces is what makes your contribution valuable.

## License

By contributing, you agree that your contributions are licensed under the project's [LICENSE](./LICENSE).
