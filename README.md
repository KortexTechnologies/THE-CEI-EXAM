# THE-CEI-EXAM

Preparation Platform for Certificate of Employment Intermediaries Exam

## Production edge release authority

The production workflow consumes the immutable schema-v2 release manifest, the
detached GO authority receipt and signature, signed Project B then Project A
production-deployment readbacks, and a separate post-readback edge-deployment
authority. It recomputes the manifest SHA-256, candidate fingerprint, payload
hash and exact GO-readiness binding. It then requires the signed sequence
`GO -> Project B -> Project A -> edge deployment authority`, including the
candidate and rollback identifiers, before the Cloudflare credential step is
reached.

`cloudflare-edge/release-authority-trust.json` deliberately contains no trusted
issuer yet. A repository owner must approve the real GO, provider-readback and
edge-deployment-authority public keys and their narrow scopes in that file,
then place the exact file SHA-256 in the
protected `production` environment variable
`CEI_RELEASE_AUTHORITY_TRUST_POLICY_SHA256`. Missing keys, a missing/mismatched
environment hash, a non-main dispatch, a stale or out-of-order receipt, or an
invalid signature all fail closed.

The owner must create and protect the GitHub `production` environment before
adding Cloudflare credentials. The workflow does not create an approval,
choose a signer, upload release evidence, merge a candidate or deploy on push.
