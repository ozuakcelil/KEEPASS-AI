# Security policy

KeePassAI is a guard against mistakes and casual bypasses by an AI assistant, not a
cryptographic boundary. The limits are listed in the README under
[Security model](README.md#security-model-what-this-does-and-does-not-protect).

## Reporting a problem

Please report a way to read a secret, or to change the gate or the guard without the user's
consent, **privately** through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Do not open a public issue for it.

Include the tool call (or the command) that gets through, your OS and shell, and the
assistant and its version. Never include real secrets, vault files or key files.

Known limitations that the README already lists (code that builds paths at run time,
transformations by a remote program, other AI tools) are not treated as vulnerabilities.
Better mitigations for them are welcome as pull requests.
