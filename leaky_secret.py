"""
Intentional leak file for scanner testing.
All secrets here are fake and included to exercise secret-detection tooling.
Do NOT use any real credentials in this repository.
"""

# Hard-coded API token (fake)
GITHUB_PAT = "ghp_FAKE_PY_TOKEN_ABCDEF1234567890"

# Fake AWS credentials
AWS_ACCESS_KEY_ID = "AKIAFAKEPYACCESSKEYEXAMPLE"
AWS_SECRET_ACCESS_KEY = "FAKE_AWS_SECRET_PY_KEY_9876543210"

# Database URL containing a password
DATABASE_URL = "postgresql://admin:veryinsecurepassword@localhost:5432/vulndb"

# Example of multi-line private key (PEM) - FAKE
PRIVATE_KEY_PEM = '''-----BEGIN PRIVATE KEY-----
FAKE_PY_PRIVATE_KEY_LINE_1
FAKE_PY_PRIVATE_KEY_LINE_2
-----END PRIVATE KEY-----'''

def reveal_secrets():
    """Return a dict with the fake secrets to simulate accidental exposure."""
    return {
        "github": GITHUB_PAT,
        "aws_key": AWS_ACCESS_KEY_ID,
        "aws_secret": AWS_SECRET_ACCESS_KEY,
        "db": DATABASE_URL,
        "private_key": PRIVATE_KEY_PEM,
    }

if __name__ == '__main__':
    # Print to stdout to simulate accidental logging/exposure in dev environments
    print(reveal_secrets())
