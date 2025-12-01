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
