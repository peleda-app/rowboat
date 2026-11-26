# Security policy

## Supported versions

Only the latest release gets security fixes. Skein is in early development; upgrade to the newest release before reporting.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub security advisories: open the repository's **Security** tab and choose **Report a vulnerability**. Please do not open a public issue, pull request or discussion for a suspected vulnerability.

Include the affected version or commit, the component (for example `skein-server` or `skein-view`), how to reproduce it with invented data, and the impact you see. You will get an answer in the advisory thread; a fix and an advisory are published together once a release carries the fix.

The latest review against the OWASP API Security Top 10 is in [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md); it predates the removal of the HTTP management API on 2026-11-25 and marks which findings still apply.
