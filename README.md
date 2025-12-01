# Vulnerable Java App (for security scanner testing)

This repository contains a deliberately insecure Java application and a variety of supporting files that intentionally contain secrets (all fake) so you can validate secrets scanning and static analysis. DO NOT run this in production or expose it to the internet.

What's included:
- `src/main/java/com/example/VulnApp.java` - Spark Java app with multiple vulnerabilities: reflected XSS, SQL injection (concatenated queries), insecure crypto (MD5), path traversal file write, endpoints that return configuration (secrets).
- `src/main/resources/application.properties` - hard-coded secrets (FAKE values).
- `.env`, `gcp-service-account.json`, `aws_credentials.txt`, `azure-credentials.json`, `terraform.tfvars`, `k8s-secret.yaml`, `Dockerfile` - multiple filetypes containing fake secrets to test scanner coverage.
- `pom.xml` - Maven project file to build the app.

Quick start (local testing):

1. Build the jar:

```bash
mvn -q package
```

2. Run locally:

```bash
java -jar target/vuln-app-0.1.0-SNAPSHOT.jar
```

3. Try endpoints:

- `http://localhost:4567/` - landing
- `http://localhost:4567/xss?name=<script>alert(1)</script>` - reflected XSS
- `http://localhost:4567/sql?user=admin` - vulnerable SQL
- `POST /login` with `username=admin&password=password` - returns a fake JWT secret
- `GET /secrets` - dumps properties (secrets)

Safety notes:
- All secrets in this repository are fake placeholders. Replace with safe test values if needed.
- Run this only in an isolated environment.

Cycode-focused notes
--------------------

This repository contains many intentionally-leaked/fake secrets to exercise detection rules similar to what Cycode scans for. Patterns and example files included here:

- **Cloud provider keys**: `src/main/resources/application.properties`, `.env`, `aws_credentials.txt`, `gcp-service-account.json`, `azure-credentials.json`, `terraform.tfvars` — AWS/GCP/Azure keys and JSON service account private keys.
- **Private keys / PEM / SSH**: `secrets/private.pem`, `secrets/id_rsa` — RSA/PEM formatted private keys.
- **Container registries / Docker**: `.dockerconfig.json`, `Dockerfile` — base64 auth in Docker config and env vars in Dockerfile.
- **Package manager tokens**: `.npmrc` — npm auth token.
- **CI/CD leaks**: `.github/workflows/leaky-ci.yml`, `.circleci/config.yml`, `azure-pipelines.yml` — hard-coded environment variables or pipeline variables.
- **Credential files**: `.git-credentials`, `.netrc`, `gradle.properties`, `.dockerconfig.json` — common credential storage formats.
- **Payment & API keys**: `stripe.env`, `sendgrid.key`, `terraform.tfvars` — Stripe/SendGrid/API keys in environment and terraform files.
- **Kubernetes / Helm**: `k8s-secret.yaml`, `helm/values.yaml` — Kubernetes secrets and Helm values that contain secrets.

How this helps with Cycode validation
- The files cover a wide range of encodings (plain, base64, PEM blocks, JSON blobs) and locations (code, config, CI, infra-as-code, container files). Use your Cycode policies to verify detection coverage across:
	- Static patterns (API keys, AWS access key IDs, private key headers)
	- Encoded secrets (base64-encoded auth tokens inside JSON)
	- Structured credentials (service account JSON blobs)
	- CI/CD pipeline leakage (tokens in workflow YAMLs)

If you'd like, I can:
- add a `cycode-sample-policy.yml` illustrating detection rules that map to these files,
- produce a small sample Cycode-like scan output JSON to test parsing pipelines,
- or add more filetypes (e.g. `.p12`, `.pem` with passphrases, `.npmrc` scoped tokens, `.ruby-version` credentials) to increase coverage.
