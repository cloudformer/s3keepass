# Redefine AWS Serverless

AWS "serverless" services that still bill while idle, rebuilt on primitives that cost ≈ $0 when idle — and
existing applications that normally need a server all day, run unchanged on the same primitives.
All projects: [github.com/topics/redefine-aws-serverless](https://github.com/topics/redefine-aws-serverless).
This (private) repository is the template every project starts from ("Use this template"); the public face of the series is the topic page, later a site.

## infra-serverless — an AWS service rebuilt, behind the client its users already have

| Replaces | Idle floor / month | Built on | Project | Usage | Status |
|---|---|---|---|---|---|
| RDS / Aurora Serverless | ~$14–45 | S3 + Lambda | [**s3rds**](https://github.com/cloudformer/s3rds) | `from s3rds import pymysql` · `sqlite` · `psycopg2` · SQLAlchemy · Django | 0.2.1 on PyPI — always in the series |
| Redis / ElastiCache Serverless | ~$90 (1 GB minimum) | DynamoDB | [**dynamoredis**](https://github.com/cloudformer/dynamoredis) | `from dynamoredis import redis` | 0.1.2 on PyPI — always in the series |
| Airflow / MWAA | ~$360 | Lambda + EventBridge + Step Functions | [**lambdaflow**](https://github.com/cloudformer/lambdaflow) | `from lambdaflow import airflow` | 0.1.0 on PyPI — passes: Step Functions is pay-per-use, but a DAG is not a state machine (a rewrite) |
| Redshift Serverless | ~$3/h once it wakes | Lambda + DuckDB over your real S3 and RDS data | [**s3shift**](https://github.com/cloudformer/s3shift) | `from s3shift import redshift_connector` | 0.1.1 on PyPI — reviewed, kept (Frank): the target is Redshift itself — redshift_connector and Redshift SQL, S3 files and RDS tables joined in place, no 60-second minimum per query; Athena covers only SQL over S3 |
| DocumentDB (MongoDB) | ~$30 (Serverless, 0.5 DCU minimum) | SQLite JSON1 (on s3rds) | **s3mongo** | `from s3mongo import pymongo` | planned — passes: DynamoDB is pay-per-use, but leaving MongoDB's model for it is a rewrite |
| Client VPN / Verified Access | ~$70–200 | IAM + Session Manager | [**ztna**](https://pypi.org/project/ztna/) | `pip install ztna` → `ztna ssm-session dev-bastion` | name reserved (0.0.1) |
| Network Firewall | ~$290 per AZ ($0.395/h per endpoint) | — | [**ngfw**](https://pypi.org/project/ngfw/) | — | name reserved (0.0.1) — not reviewed |
| Cloud WAN (SD-WAN) | ~$365 per core network edge ($0.50/h) | — | [**sdwan**](https://pypi.org/project/sdwan/) | — | name reserved (0.0.1) — not reviewed |
| OpenSearch Serverless | ~$350 | S3 + SQLite FTS5 (on s3rds) | **s3search** | `from s3search import opensearchpy` | on hold — fits application search only; OpenSearch is mostly used for logs, which need high-rate ingest (see s3shift) |
| Kafka / MSK Serverless | ~$550 | SQS | **sqskafka** | `from sqskafka import kafka` | for review — fails checks 2 and 3: SQS / Kinesis on-demand are AWS's own pay-per-use streams |
| Amazon MQ (RabbitMQ) | ~$20–50 | SQS | **sqsmq** | `from sqsmq import pika` | for review — fails checks 2 and 3: SQS is AWS's own pay-per-use queue; Celery takes it with one setting |

## app-serverless — an existing application, its code unchanged, on Lambda; ≈ $0 when idle

| Application | Usually runs on (idle floor / month) | Built on | Project | Only change | Status |
|---|---|---|---|---|---|
| Vault | EC2 (3 + ALB for HA) or HCP Vault Dedicated (~$450) | Lambda + S3 + KMS | [**lambdavault**](https://github.com/cloudformer/lambdavault) | vault CLI · Terraform provider · UI — only `VAULT_ADDR` changes | 0.1.0 on PyPI — passes: Secrets Manager is pay-per-use ($0.40 per secret), but leaving the Vault API (policies, auth methods, engines) for it is a rewrite |
| Healthchecks (cron monitoring) | a VM or container + its database, all day | Lambda + EventBridge + s3rds (its database) | **lambdachecks** | ping URLs, API and UI — only the host changes | planned — Django 6.1.2 on s3rds' Django backend; `sendalerts` (a 2-second polling loop) becomes one EventBridge run per minute |

An app-serverless project ships no driver and no console of its own: the application's own clients and UI are the
interface, and the compatibility suite compares the original (in Docker) with the project. The three checks below
apply with "AWS's own service" read as "the application's hosted or pay-per-use offering".

## Before a project starts (the three checks)

s3rds and dynamoredis are the series' core and are not re-examined. Every other candidate goes through all
three checks before any code is written. A failed check does not drop it: the candidate goes to Frank with the
reason, and Frank decides (build anyway, not built, or later). The Status column records the result and the
decision:

1. **AWS's own service bills while idle.** Look up its serverless option and any free tier first: if it
   scales to zero (or a lasting free tier covers small use), there is nothing to rebuild.
2. **No AWS pay-per-use service that the application can switch to with a small change.** If one exists
   (SQS for a queue, Athena for SQL over S3), point users to it instead of imitating the old API on top of it.
   A switch that means rewriting the data model or the code (SQL → DynamoDB, DAG → state machine) does not count.
3. **Never dress an AWS pay-per-use service up as another product.** SQS, SNS, DynamoDB, Kinesis, Step
   Functions and Athena are AWS's own serverless answer and the series' building blocks; translating one back
   into another product's API (SQS as RabbitMQ or Kafka) adds nothing. A project rebuilds a service that bills
   while idle, behind the client its users already have (pymysql, redis-py, Airflow, pymongo, redshift_connector).

## The standard

Every project has the same shape, so a reader who knows one knows all of them.

| Part | Rule |
|---|---|
| Name | repo = pip package = import name; submodules are named after the standard client they mirror (`s3rds.pymysql`), so moving back to the real service is one import line |
| Backend | AWS primitives only (S3, DynamoDB, SQS, Lambda, Step Functions, EventBridge); nothing runs while idle; everything built for a Lambda built for arm64 and x86_64; a deployment runs one (`var.architecture`, default arm64); Terraform from 0.1.0, CloudFormation optional later (same resources); every command from the repo root (`terraform -chdir=terraform …`) |
| Console | one Lambda Function URL serving one HTML page: browse the data, run commands, see server time per call; HTTP Basic auth = the service's user / password |
| Driver | pure client library, standard library only where possible; the real client's API, error classes and codes |
| Compatibility | every feature verified by the project's own method — the same operations on the real service and on the project where one runs in Docker, otherwise moto + one run on a real AWS account; a fixed feature list that only grows; `tests/compat/REPORT.md` (status per feature, support %) and `tests/compat/TASKS.md` (numbered tasks the gaps point to), regenerated by every test run |
| Translation | blacklist what is known to be impossible (refused up front); parse everything else and check it node by node against a whitelist of what passed a comparison test; anything unknown is refused until a test proves it. New support = test first, then whitelist |
| Unsupported | refused with `NotSupportedError`, never silently different; documented as "the moment to move to the real service" (MIGRATION.md) |
| Release | `git tag vX.Y.Z && git push --tags` → tests → build → PyPI trusted publishing; the tag must equal the version |
| Docs | README (EN + ZH): architecture image, comparison table, quick start (deploy → console → connect), compatibility, guarantees, who this is for, layout, releasing, series footer |

## Shared vs project-specific (the rule)

- **Identical across projects → lives in the template or the workflow repo and is referenced, never
  copied**: CI (`uses: cloudformer/redefine-aws-serverless-workflow/...@main`). Differences between
  projects go in as variables / inputs (`with:` values), never as edited copies. One place to change.
- **Different per project → lives only in the project**: routes, the console's views, the driver's API,
  the backend resources, the feature list. Nobody syncs these.
- **Identical today but copied** (console shell, Lambda HTTP helpers, `compat_report.py`): kept in the
  template as the source; a fix is made in the template and ported to the projects by hand. Promote to a
  referenced piece once the sync becomes a chore.

## Starting a project

One block, no comments inside (zsh does not accept `#` in pasted commands). Only the first four lines change;
the three TEST_ values may stay "" (CI then runs without a reference service) and be filled later in
`.github/workflows/test.yml` + `publish.yml`:

| variable | meaning | s3rds |
|---|---|---|
| NAME | repo name | `s3rds` |
| TEST_DEPS | pip packages the tests need besides pytest boto3: the real service's client + our optional deps | `"pymysql sqlglot"` |
| TEST_CONTAINER | the real service's Docker container (mysql / redis / postgres) | `"mysql"` |
| TEST_DSN | the env var the compat tests read | `"MYSQL_DSN=mysql://root:test@127.0.0.1:3306/compat"` |

```bash
NAME=xxx
TEST_DEPS=""
TEST_CONTAINER=""
TEST_DSN=""
cd ~/repo-private
gh repo create cloudformer/$NAME --public --template cloudformer/redefine-aws-serverless --clone
gh repo edit cloudformer/$NAME --add-topic redefine-aws-serverless
gh api -X PUT repos/cloudformer/$NAME/environments/pypi >/dev/null
gh secret set PYPI_TOKEN -R cloudformer/$NAME --body "$(awk '/password/{print $3; exit}' ~/.pypirc)"
rm $NAME/SERIES.md
git -C $NAME mv client/project client/$NAME && sed -i '' "s/\"project\"/\"$NAME\"/" $NAME/client/pyproject.toml
sed -i '' "s/^name: project-compat/name: $NAME-compat/" $NAME/tests/compat/docker-compose.yml
sed -i '' "s|install: \"pytest boto3\"|install: \"pytest boto3 $TEST_DEPS\"|; s|compose-service: \"\"|compose-service: \"$TEST_CONTAINER\"|; s|test-env: \"\"|test-env: \"$TEST_DSN\"|" $NAME/.github/workflows/test.yml $NAME/.github/workflows/publish.yml
git -C $NAME add -A && git -C $NAME commit -m "from template" && git -C $NAME push
gh run list -R cloudformer/$NAME --limit 1
```

### Manual steps (everything the block cannot do)

| when | where | what |
|---|---|---|
| once, template repo | GitHub → redefine-aws-serverless → Settings → General | "Template repository" on (or `gh repo edit --template`) |
| — | (nothing on pypi.org) | the block stores the account-wide API token from `~/.pypirc` as the repo secret `PYPI_TOKEN`; publish.yml uses it. Without the secret it falls back to trusted publishing, which needs a pending publisher on pypi.org |
| per project | the clone | fill the three `with:` values in `.github/workflows/test.yml` and `publish.yml`; replace `<placeholders>` (`grep -rn "<" --include=*.md --include=*.py --include=*.tf --include=*.yml .`); fill `src/server/`, `terraform/`, `cloudformation/`, `tests/compat/` — CLAUDE.md carries the principles |
| per project | AWS | deploy once to get the console URL (`terraform -chdir=terraform apply -var-file=my.json`) and check the production engine's limits (e.g. the Lambda runtime's SQLite version) |
| per release | the clone | bump the version in `client/pyproject.toml` and `client/$NAME/__init__.py`, CHANGELOG entry, commit, `git tag vX.Y.Z && git push --tags` |

The workflows are referenced (`uses: cloudformer/redefine-aws-serverless-workflow/...@main`, a public repo), so CI changes are made there once. The other
shared files (`tests/compat_report.py`, the HTTP helpers in `src/server/lambda_function.py`, the console
shell) are copied: each project evolves on its own; improvements worth sharing are ported back here by hand.
