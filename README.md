# THE-CEI-EXAM

Preparation Platform for Certificate of Employment Intermediaries Exam

## Production edge release authority

The production workflow consumes three GitHub release-asset IDs from this
repository: the immutable schema-v2 release manifest bytes, the detached GO
authority receipt, and its detached Ed25519 signature. It recomputes the
manifest SHA-256, candidate fingerprint, payload hash and GO-readiness binding;
then it requires the manifest, receipt, selected `main` revision and running
edge commit to agree before the Cloudflare credential step is reached.

`cloudflare-edge/release-authority-trust.json` deliberately contains no trusted
issuer yet. A repository owner must approve the real release-authority public
key and key scopes in that file, then place the exact file SHA-256 in the
protected `production` environment variable
`CEI_RELEASE_AUTHORITY_TRUST_POLICY_SHA256`. Missing keys, a missing/mismatched
environment hash, a non-main dispatch, a stale or out-of-order receipt, or an
invalid signature all fail closed.

The owner must create and protect the GitHub `production` environment before
adding Cloudflare credentials. The workflow does not create an approval,
choose a signer, upload release evidence, merge a candidate or deploy on push.
