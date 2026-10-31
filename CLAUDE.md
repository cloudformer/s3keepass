# s3keepass — working notes for Claude

This repository is one project of the **IdleFree** series (https://cloudformer.github.io; review notes in the template's SERIES.md): an AWS service that
bills while idle, rebuilt on primitives that cost ≈ $0 when idle, behind the standard client's API.
s3rds (github.com/cloudformer/s3rds) is the reference implementation; when in doubt, do what it does.

## s3keepass: what differs from the series template (overrides the principles below where they conflict)

s3keepass is **app-serverless** (next to lambdavault and lambdachecks): KeePass — a desktop app and its file —
rebuilt as a serverless web vault, not an AWS service behind its standard client. It is Frank's own daily
password manager. Goal of 0.1.0 (settled 2026-10-29): it replaces Frank's local KeePass client and where the
file is kept — he opens the URL instead of KeePassXC, and the vaults live in S3 instead of on his disk.

- **Storage**: one bucket, `keepass/<name>.kdbx`, any number of vaults (库1, 库2 …); one S3 key = one vault, like
  s3rds' one key = one database. Bucket: private, TLS-only, versioned (lifecycle keeps `keep_versions` old
  versions per vault, max 100), SSE-KMS with the AWS-managed `aws/s3` key (a customer key may come later).
- **The browser decrypts.** The Lambda only lists / reads / writes / deletes encrypted bytes; the master password
  and plaintext never leave the browser (as KeeWeb). KDBX 4 via vendored kdbxweb + argon2-browser in
  `src/server/vendor/` (pinned by SHA-256 in its README, checked by a test) — never hand-written crypto. All
  crypto calls go through the `vault-core` `<script>` block of `index.html`; nothing else touches kdbxweb.
- **Saves are conditional**: `PUT If-Match <ETag read>` (create: `If-None-Match: *`); unconditional PUT is 428.
  A refused save (412) never overwrites: the UI offers the local copy as a download and a reopen.
- **UI** (principle 6 adapted): modelled on KeePassXC's window — vault list (the "folder") → unlock → group tree |
  entries | details; copy (clipboard cleared after 30 s), reveal, add / edit / delete entries and groups
  (recycle bin), generator, new vault, upload / download `.kdbx`, versions, change master password, lock (also
  idle). No command box (there is no native command language); search instead. The status bar + history show
  each call's server time and S3 action. Strict CSP: inline scripts by hash (computed by the Lambda), so the
  page must use `<script>` blocks without attributes and no inline event handlers.
- **Sign-in**: HTTP Basic, user / password from the Terraform variable file named after the project:
  `terraform/real-s3keepass.json` (gitignored; `example.json` committed).
- **Master key = password + optional key file**, as in KeePass (KeePassXC `.keyx` / `.key`, a generated `.keyx`, any
  file by SHA-256 — vault-core `keyMaterial` hashes XML that is not a key file, as KeePassXC does). The key file is
  read in the browser and never uploaded. "No key file" in the kickoff meant no KMS / customer key encrypting the
  .kdbx itself (S3's SSE-KMS with `aws/s3` is all), not the KeePass key-file feature. **Command line in 0.2.0** (`s3keepass entry get
  github` …, designed 2026-10-28); in 0.1.0 `client/` holds only the version.
- **Testing (principle 5 for this project)**: the reference is KeePassXC's `keepassxc-cli` in Docker (compose
  service `keepassxc`, container `s3keepass-keepassxc`, env `KEEPASSXC_CONTAINER`). The same container runs
  `tests/compat/kdbx_node.js`, which loads the vendored libraries and the `vault-core` block into Node — the UI's
  own crypto path, headless. Every file one side writes is read by both and the readings must match. The server
  is tested in-process against the fake S3 in `tests/conftest.py` (versions, conditional PUT, delete markers).
- PyPI name and github.com/cloudformer/s3keepass were free on 2026-10-29; reserve with
  `python3 ~/repo-private/redefine-aws-serverless-workflow/scripts/reserve_pypi.py s3keepass --upload` when Frank says.
- Frank's commands use absolute paths: `git -C /Users/frankzhang/repo-private/s3keepass …`,
  `terraform -chdir=/Users/frankzhang/repo-private/s3keepass/terraform … -var-file=real-s3keepass.json`.

## Product principles

1. **≈ $0 when idle.** Only pay-per-request primitives (S3, DynamoDB, SQS, Lambda, Step Functions,
   EventBridge). Nothing runs, polls or is provisioned while nobody is using it.
2. **Compatible with the existing client.** The driver has the standard client's API, exception classes
   and error codes; `from <project> import <client>` today, `import <client>` on the real service later —
   nothing else changes. Submodules are named after the client they mirror.
3. **Blacklist → whitelist → test, for every translated statement and function.** What is known to be
   impossible is blacklisted and refused up front (`NotSupportedError`, with the reason and "move to the real
   service"). Everything else is parsed (sqlglot where a dialect is involved) and checked node by node against
   a whitelist: only statement types and functions that passed a comparison test against the real service are
   on it. Anything not on the whitelist is refused by default — "sqlglot translated it" is not evidence it is
   right. To support something new: write the comparison test first, make it pass, then add it to the
   whitelist (the whitelist table lives next to its tests). `strict=False` on connect() may opt into
   best-effort translation, always with a warning.
4. **What is hard is unsupported, not imitated.** Anything that needs a real server (sessions, locks,
   blocking calls, server-side code) raises `NotSupportedError` with a one-line reason and is listed under
   "Not supported". Never silently different. MIGRATION.md says this is the moment to move to the real service.
5. **Only tested features count as supported.** `tests/compat/` verifies every feature, by the project's
   own method: the same operations on the real service and on the project where the real service
   runs in Docker (databases, caches), otherwise moto plus one run against a real AWS account. The feature
   list is fixed and only grows; `REPORT.md` is regenerated by every run and is the only source for compatibility claims in the README. Gaps point to
   numbered tasks in `TASKS.md`; quirks are documented differences we deliberately keep. With a Docker
   reference (RDS / Redis kind) the project side runs two ways: `--docker run` = the reference in Docker vs
   `lambda_handler` called in-process (every push, CI); `--docker run --aws <var-file>` = the reference in
   Docker vs the deployed Lambda Function URL (URL from `terraform output`, user / password from the
   variable file; once before a release). Other kinds of project decide their own.
6. **Console: the service's usual management tool, as one page.** One Lambda Function URL serves one
   `index.html` (no build, no framework, no external dependency); `console=false` leaves the API only.
   Model it on the tool people already use (database → DataGrip, Redis → RedisInsight, Airflow → the
   Airflow UI, Kafka → Kafka UI, Mongo → Compass, RabbitMQ → its management page):
   - sign-in = the service's own user / password (HTTP Basic, the same the driver uses)
   - navigation follows the service's natural hierarchy (database → table → rows; key prefix → key → value;
     DAG → run → task; topic → partition → message)
   - a command box in the service's native language (SQL, redis commands, trigger a DAG, publish a message),
     ⌘/Ctrl+Enter runs it
   - every call shows the server's own time and the backend action (cache-hit / download / +upload for S3;
     capacity units for DynamoDB; enqueued / received for SQS)
   - a history log (one line per call, timestamp, errors in red) and direct data editing (add a row,
     change a value, delete a key, re-run a task) without typing commands
7. **Architecture image** (`docs/architecture.svg`, top of the README): your code → Lambda Function URL →
   the primitives; label what each primitive holds, where durability happens, and the idle cost. Below it a
   table comparing the real service and the project (idle cost, endpoint, storage, client, console,
   compatibility %).
   The same image is the first thing on the PyPI page: `client/README.md` embeds it right under the bold
   intro by absolute URL (`https://raw.githubusercontent.com/cloudformer/<project>/main/docs/architecture.svg`);
   PyPI cannot resolve relative paths.
8. **Terraform first, every command from the repo root.** 0.1.0 ships Terraform only
   (`terraform -chdir=terraform …`); CloudFormation is optional and comes later, producing the same
   resources. `example.json` / `example-params.json` are committed, real variable files are gitignored. Least-privilege IAM. Destroy must work.
   Everything built for a Lambda (Linux wheels, container images) is built for both arm64 and x86_64, and
   both are tested; a deployment runs one, `var.architecture`, default arm64 (~20% cheaper). Switching it
   needs no rebuild.
9. **Guarantees are stated and pinned by tests.** Atomicity, durability, isolation, retry policy ("fail
   rather than duplicate a write") each get one line in the README and a test.
10. **Release = tag.** `git tag vX.Y.Z && git push --tags` runs tests, builds `client/`, publishes to PyPI via
   trusted publishing; the tag must equal the version in `client/pyproject.toml`. CHANGELOG per release.
11. **English everywhere except README.zh.md.** UI text, code, comments, commit messages, CHANGELOG, TASKS —
    all English; the only Chinese file is README.zh.md (same section order as README.md). The series footer
    links to the homepage, https://cloudformer.github.io (README: "Part of IdleFree"; README.zh: #zh), and
    `[project.urls]` carries `IdleFree = "https://cloudformer.github.io/"`. The project list lives only in the
    homepage's projects.json; new repositories get the `idlefree` topic and the homepage as their website.

## How we work

- **Discuss first, build after an explicit go.** During discussion answer fast and short, conclusions first.
  Agreement with one point is not a go; only "开始 / 建吧 / 可以了" is.
- **Frank runs every command** (terraform, aws, docker, pytest, git, pip, publishing). Claude edits code and
  gives the commands to run, always from the repo root; never `cd`.
- **One task, one run.** Fix a task completely, verify locally first, then Frank runs the comparison suite
  once. Failures are read from `tests/compat/REPORT.md` (🔴 rows carry the actual diff), not pasted.
- **Only split when necessary** — repos, modules, services. Prefer one of each.
- **Shared vs project-specific.** Identical across projects → template or workflow repo, referenced
  (`uses:`), differences passed as variables; change it once. Different per project → only in the project.
  Identical-but-copied pieces (console shell, HTTP helpers, compat_report.py) are fixed in the template and
  ported by hand until they are worth referencing.
- **No maintenance work by design**: no generated code to keep in sync, no abstractions for one caller,
  standard library over dependencies.

## CI and release (what to edit, what not to)

- `.github/workflows/test.yml` and `publish.yml` are thin callers of the public repo
  `cloudformer/redefine-aws-serverless-workflow`. In this project edit only their three `with:` values:
  `install` (pip packages the tests need besides pytest boto3: the real service's client + our optional
  deps, e.g. `"pytest boto3 pymysql sqlglot"`), `compose-service` (the container in
  `tests/compat/docker-compose.yml`: mysql / redis / postgres) and `test-env` (the env var the compat tests
  read, e.g. `"MYSQL_DSN=mysql://root:test@127.0.0.1:3306/compat"`). `compose-service` and `test-env`
  stay empty when the project has no Docker reference service. Never put CI logic here; change it in the workflow repo once for the whole series.
- `tests/compat/docker-compose.yml` defines mysql, redis and postgres; only the named one starts. Another
  reference service: add it there.
- **The test commands are the same in every project** (implemented once in `tests/compat_docker.py`, a
  plugin with no settings — copy it unchanged; it reads the container and env var from `compose-service` /
  `test-env` above; never hard-code them elsewhere):

  | command | Docker | after the run |
  |---|---|---|
  | `python3 -m pytest tests -q` | left alone: live if the service is running and healthy, otherwise the project's fallback (skip, recorded outcomes, dry run) and the summary says how to go live | untouched |
  | `... --docker up` | starts it (or reuses it), waits until healthy, then tests | keeps running |
  | `... --docker run` | the same | stopped if all passed; on a failure it keeps running and the summary says so |
  | `... --docker down` | the same | stopped whatever the result |

  Not healthy within 300 s: nothing runs, the container keeps starting, the message says to run again.
  A project without a Docker reference (empty `compose-service`) takes the same commands; `--docker` only
  says so. Readiness beyond the healthcheck (e.g. Airflow's scheduler) is waited for in the project's own
  compat fixture when `compat_docker.docker["mode"]` is set. README "Compatibility" shows these four lines.
- The package name is read from `client/pyproject.toml` by `tests/conftest.py` (`PACKAGE`); nothing else
  hard-codes it.
- Release: bump `version` in `client/pyproject.toml` and `__version__` in `client/<package>/__init__.py`,
  CHANGELOG entry, commit, `git tag vX.Y.Z && git push --tags`. Once per package Frank adds the PyPI
  trusted publisher (owner cloudformer, this repo, `publish.yml`, environment `pypi`).

## Layout (do not move things)

```
src/server/       lambda_function.py (shared helpers on top, routes below), index.html (console)
client/<project>/ the pip package; pyproject.toml; README.md is the PyPI page
terraform/ cloudformation/ (optional, after 0.1.0)
tests/            regression; tests/compat/ compatibility (conftest = harness, test_<ref>.py = feature list,
                  REPORT.md generated, TASKS.md numbered tasks), tests/compat_report.py (edit CONFIG only)
.github/workflows test.yml (every push), publish.yml (tags)
```
