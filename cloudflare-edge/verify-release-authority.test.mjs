import assert from "node:assert/strict";
import { generateKeyPairSync, createHash, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  ReleaseAuthorityError,
  verifyReleaseAuthority,
} from "./verify-release-authority.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const CANDIDATE_SHA = "89a4ef249bcc6c94ed1861ee6beb01cff37deeb7";
const TREE_SHA = "1111111111111111111111111111111111111111";
const NOW = new Date("2026-09-11T00:00:00.000Z");
const REPOSITORY_URL = "https://github.com/KortexTechnologies/THE-CEI-EXAM.git";

const requiredGoReceipts = [
  { receiptType: "evidence", phase: "go", subject: "local_release" },
  { receiptType: "evidence", phase: "go", subject: "connected_qa" },
  { receiptType: "security", phase: "go", subject: "security_diff" },
  { receiptType: "security", phase: "go", subject: "content_boundary" },
  { receiptType: "provider", phase: "go", subject: "github_project_a" },
  { receiptType: "provider", phase: "go", subject: "github_project_b" },
  { receiptType: "provider", phase: "go", subject: "github_edge" },
  { receiptType: "provider", phase: "go", subject: "supabase_project_a" },
  { receiptType: "provider", phase: "go", subject: "supabase_project_b" },
  { receiptType: "provider", phase: "go", subject: "stripe" },
  { receiptType: "provider", phase: "go", subject: "cookiebot" },
  { receiptType: "provider", phase: "go", subject: "cloudflare_edge" },
  { receiptType: "approval", phase: "go", subject: "product_owner" },
  { receiptType: "approval", phase: "go", subject: "dpo" },
  { receiptType: "approval", phase: "go", subject: "singapore_legal" },
  { receiptType: "approval", phase: "go", subject: "engineering_security" },
];

function requirementId(requirement) {
  if (requirement.receiptType === "provider")
    return `signed_${requirement.subject}_provider_receipt`;
  if (requirement.receiptType === "approval")
    return `signed_${requirement.subject}_approval`;
  return `signed_${requirement.subject}_receipt`;
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function makeFixture({
  now = NOW,
  candidateSha = CANDIDATE_SHA,
  authorityIssuedAt = "2026-09-10T23:30:00.000Z",
  prerequisiteIssuedAt = "2026-09-10T23:00:00.000Z",
  expiresAt = "2026-09-12T00:00:00.000Z",
  goPasses = true,
  trusted = true,
} = {}) {
  const directory = mkdtempSync(join(tmpdir(), "cei-edge-authority-"));
  const paths = {
    policy: join(directory, "trust.json"),
    manifest: join(directory, "manifest.json"),
    receipt: join(directory, "receipt.json"),
    signature: join(directory, "receipt.sig"),
  };
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const policy = {
    marker: "CEI_EDGE_RELEASE_AUTHORITY_TRUST_POLICY",
    schemaVersion: 1,
    expectedRepositoryUrl: REPOSITORY_URL,
    maximumManifestAgeHours: 24,
    maximumReleaseAuthorityAgeHours: 24,
    maximumFutureSkewMinutes: 5,
    releaseAuthority: {
      receiptType: "approval",
      phase: "go",
      subject: "release_authority",
    },
    requiredGoReceipts,
    trustedIssuers: trusted
      ? [
          {
            keyId: "release-key-2026-09",
            algorithm: "ed25519",
            publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
            allowedReceiptTypes: ["approval"],
            allowedSubjects: ["release_authority"],
          },
        ]
      : [],
  };
  writeJson(paths.policy, policy);

  const repositoryEnvelope = {
    expectedRepositoryUrl: REPOSITORY_URL,
    repositoryUrl: REPOSITORY_URL,
    commitSha: candidateSha,
    treeSha: TREE_SHA,
    sourceWorkingTreeSha256: "1".repeat(64),
    lockfileAggregateSha256: "2".repeat(64),
    buildSha256: "3".repeat(64),
    buildArtifactSha256: "4".repeat(64),
    buildMetadataSha256: "5".repeat(64),
    buildConfigurationSha256: "6".repeat(64),
  };
  const candidateEnvelope = {
    schemaVersion: 1,
    repositories: {
      projectA: {
        ...repositoryEnvelope,
        repositoryUrl: "https://github.com/example/a.git",
      },
      projectB: {
        ...repositoryEnvelope,
        repositoryUrl: "https://github.com/example/b.git",
      },
      edge: repositoryEnvelope,
    },
    database: { projectA: {}, projectB: {} },
    programmeSchedule: { sha256: "7".repeat(64) },
    productContract: { semanticHash: "8".repeat(64) },
    legal: { wordingSha256: "9".repeat(64) },
    stripe: { accountId: "acct_fixture" },
    cookiebot: { configurationId: "cb-fixture" },
    deploymentBaseline: {
      projectA: {
        currentDeploymentId: "a-current",
        rollbackDeploymentId: "a-rollback",
      },
      projectB: {
        currentDeploymentId: "b-current",
        rollbackDeploymentId: "b-rollback",
      },
      edge: {
        currentDeploymentId: "edge-current",
        rollbackDeploymentId: "edge-rollback",
      },
    },
    intendedEffectiveAt: "2026-09-12T00:00:00.000Z",
    observationWindow: {
      startsAt: "2026-09-12T00:00:00.000Z",
      endsAt: "2026-09-12T01:00:00.000Z",
    },
    trustPolicySha256: "a".repeat(64),
  };
  const candidateFingerprint = sha256(JSON.stringify(candidateEnvelope));
  const prerequisiteReceipts = requiredGoReceipts.map((requirement, index) => ({
    id: requirement.subject,
    receiptType: requirement.receiptType,
    phase: requirement.phase,
    subject: requirement.subject,
    receiptSha256: sha256(`receipt-${index}`),
    artifactSha256:
      requirement.receiptType === "approval"
        ? null
        : sha256(`artifact-${index}`),
    candidateFingerprint,
    bindingSha256: sha256(`binding-${index}`),
    keyId: `prerequisite-key-${index}`,
    issuedAt: prerequisiteIssuedAt,
    expiresAt,
    signatureVerified: true,
  }));
  const acceptedRequiredReceipts = prerequisiteReceipts
    .map((receipt) => ({
      receiptType: receipt.receiptType,
      phase: receipt.phase,
      subject: receipt.subject,
      receiptSha256: receipt.receiptSha256,
      artifactSha256: receipt.artifactSha256,
      keyId: receipt.keyId,
      issuedAt: receipt.issuedAt,
      expiresAt: receipt.expiresAt,
    }))
    .sort((left, right) =>
      `${left.receiptType}:${left.phase}:${left.subject}:${left.receiptSha256}`.localeCompare(
        `${right.receiptType}:${right.phase}:${right.subject}:${right.receiptSha256}`,
        "en",
      ),
    );
  const goReadinessSha256 = sha256(
    JSON.stringify({
      schemaVersion: 1,
      candidateFingerprint,
      requiredReceipts: requiredGoReceipts,
      acceptedRequiredReceipts,
    }),
  );
  const receipt = {
    marker: "CEI_SIGNED_RELEASE_RECEIPT",
    schemaVersion: 1,
    receiptType: "approval",
    phase: "go",
    subject: "release_authority",
    candidateFingerprint,
    bindingSha256: goReadinessSha256,
    artifactSha256: null,
    result: "approved",
    issuedAt: authorityIssuedAt,
    expiresAt,
    keyId: "release-key-2026-09",
    displayName: "Release Authority",
    reference: "GO-2026-09-11",
  };
  writeJson(paths.receipt, receipt);
  const receiptBytes = readFileSync(paths.receipt);
  writeFileSync(
    paths.signature,
    `${sign(null, receiptBytes, privateKey).toString("base64")}\n`,
    "utf8",
  );
  const authorityManifestReceipt = {
    id: receipt.subject,
    receiptType: receipt.receiptType,
    phase: receipt.phase,
    subject: receipt.subject,
    receiptSha256: sha256(receiptBytes),
    artifactSha256: null,
    candidateFingerprint,
    bindingSha256: receipt.bindingSha256,
    keyId: receipt.keyId,
    issuedAt: receipt.issuedAt,
    expiresAt: receipt.expiresAt,
    displayName: receipt.displayName,
    reference: receipt.reference,
    signatureVerified: true,
  };
  const goReadinessRequirements = [
    { id: "trust_policy_valid", passed: true },
    ...requiredGoReceipts.map((requirement) => ({
      id: requirementId(requirement),
      passed: true,
    })),
  ];
  const goReadinessPredicate = {
    passes: goPasses,
    blockers: goPasses ? [] : ["local_release_failed"],
    requirements: goPasses
      ? goReadinessRequirements
      : goReadinessRequirements.map((requirement, index) =>
          index === 0 ? { ...requirement, passed: false } : requirement,
        ),
  };
  const goPredicate = {
    passes: goPasses,
    blockers: goPasses ? [] : ["local_release_failed"],
    requirements: [
      ...goReadinessPredicate.requirements,
      { id: "signed_action_time_release_authority_approval", passed: true },
    ],
  };
  const repositories = {
    projectA: {},
    projectB: {},
    edge: {
      expectedRepositoryUrl: REPOSITORY_URL,
      repositoryUrl: REPOSITORY_URL,
      commitSha: candidateSha,
      treeSha: TREE_SHA,
      clean: true,
      build: { metadataBoundToCandidate: true },
    },
  };
  const database = { projectA: {}, projectB: {} };
  const releaseFacts = {
    programmeSchedule: candidateEnvelope.programmeSchedule,
    productContract: candidateEnvelope.productContract,
    legal: candidateEnvelope.legal,
    stripe: candidateEnvelope.stripe,
    cookiebot: candidateEnvelope.cookiebot,
    intendedEffectiveAt: candidateEnvelope.intendedEffectiveAt,
    observationWindow: candidateEnvelope.observationWindow,
  };
  const expectedDeployments = {
    projectA: {
      currentDeploymentId: "a-current",
      rollbackDeploymentId: "a-rollback",
    },
    projectB: {
      currentDeploymentId: "b-current",
      rollbackDeploymentId: "b-rollback",
    },
    edge: {
      currentDeploymentId: "edge-current",
      rollbackDeploymentId: "edge-rollback",
    },
  };
  const signedReceipts = {
    accepted: [...prerequisiteReceipts, authorityManifestReceipt],
    rejected: [],
  };
  const authorisationBindings = {
    goReadinessSha256,
    liveReadinessSha256: "b".repeat(64),
  };
  const deterministicPayload = {
    schemaVersion: 2,
    ecosystem: "THE CEI EXAM",
    candidateEnvelope,
    candidateFingerprint,
    repositories,
    database,
    releaseFacts,
    expectedDeployments,
    signedReceipts,
    authorisationBindings,
    goReadinessPredicate,
    goPredicate,
    liveReadinessPredicate: {
      passes: false,
      blockers: ["not_deployed"],
      requirements: [],
    },
    livePredicate: {
      passes: false,
      blockers: ["not_deployed"],
      requirements: [],
    },
  };
  const manifest = {
    marker: "ECOSYSTEM_RELEASE_MANIFEST",
    schemaVersion: 2,
    releaseId: "cei-release-20260911",
    generatedAt: now.toISOString(),
    status: goPasses ? "GO" : "BLOCKED",
    immutableIdentity: {
      candidateFingerprint,
      manifestPayloadSha256: sha256(JSON.stringify(deterministicPayload)),
      trustPolicySha256: candidateEnvelope.trustPolicySha256,
    },
    ...deterministicPayload,
    policy: { goRequiresSignedActionTimeAuthority: true },
  };
  writeJson(paths.manifest, manifest);

  const input = {
    manifestPath: paths.manifest,
    authorityReceiptPath: paths.receipt,
    authoritySignaturePath: paths.signature,
    trustPolicyPath: paths.policy,
    expectedManifestSha256: sha256(readFileSync(paths.manifest)),
    expectedTrustPolicySha256: sha256(readFileSync(paths.policy)),
    expectedReleaseId: manifest.releaseId,
    candidateSha: CANDIDATE_SHA,
    dispatchedCandidateSha: CANDIDATE_SHA,
    githubEventName: "workflow_dispatch",
    githubRef: "refs/heads/main",
    productionDeploymentApproved: true,
    now,
  };
  return {
    directory,
    input,
    manifest,
    receipt,
    privateKey,
    rewriteManifest() {
      const payload = {
        schemaVersion: manifest.schemaVersion,
        ecosystem: manifest.ecosystem,
        candidateEnvelope: manifest.candidateEnvelope,
        candidateFingerprint: manifest.candidateFingerprint,
        repositories: manifest.repositories,
        database: manifest.database,
        releaseFacts: manifest.releaseFacts,
        expectedDeployments: manifest.expectedDeployments,
        signedReceipts: manifest.signedReceipts,
        authorisationBindings: manifest.authorisationBindings,
        goReadinessPredicate: manifest.goReadinessPredicate,
        goPredicate: manifest.goPredicate,
        liveReadinessPredicate: manifest.liveReadinessPredicate,
        livePredicate: manifest.livePredicate,
      };
      manifest.immutableIdentity.manifestPayloadSha256 = sha256(
        JSON.stringify(payload),
      );
      writeJson(paths.manifest, manifest);
      input.expectedManifestSha256 = sha256(readFileSync(paths.manifest));
    },
    cleanup() {
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

function expectCode(fixture, code, mutate = () => {}) {
  try {
    mutate(fixture);
    assert.throws(
      () => verifyReleaseAuthority(fixture.input),
      (error) => error instanceof ReleaseAuthorityError && error.code === code,
    );
  } finally {
    fixture.cleanup();
  }
}

test("accepts an exact main candidate with a fresh trusted GO authority signature", () => {
  const fixture = makeFixture();
  try {
    const result = verifyReleaseAuthority(fixture.input);
    assert.equal(result.status, "verified");
    assert.equal(result.edgeCandidateCommitSha, CANDIDATE_SHA);
    assert.equal(result.releaseId, "cei-release-20260911");
  } finally {
    fixture.cleanup();
  }
});

test("rejects an arbitrary manifest hash", () => {
  expectCode(makeFixture(), "release_manifest_sha256_mismatch", (fixture) => {
    fixture.input.expectedManifestSha256 = "0".repeat(64);
  });
});

test("rejects a caller checkbox that is not approved", () => {
  expectCode(makeFixture(), "production_deployment_not_approved", (fixture) => {
    fixture.input.productionDeploymentApproved = false;
  });
});

test("rejects dispatch from a non-main ref", () => {
  expectCode(makeFixture(), "dispatch_ref_not_main", (fixture) => {
    fixture.input.githubRef = "refs/heads/codex/attacker-controlled";
  });
});

test("rejects a dispatched candidate that differs from the running revision", () => {
  expectCode(makeFixture(), "dispatched_candidate_sha_mismatch", (fixture) => {
    fixture.input.dispatchedCandidateSha = "f".repeat(40);
  });
});

test("rejects a manifest whose edge candidate differs from the running revision", () => {
  const fixture = makeFixture({ candidateSha: "e".repeat(40) });
  expectCode(fixture, "release_manifest_edge_candidate_mismatch");
});

test("rejects a detached signature not made by the trusted key", () => {
  expectCode(
    makeFixture(),
    "release_authority_signature_invalid",
    (fixture) => {
      const { privateKey } = generateKeyPairSync("ed25519");
      writeFileSync(
        fixture.input.authoritySignaturePath,
        `${sign(null, readFileSync(fixture.input.authorityReceiptPath), privateKey).toString("base64")}\n`,
        "utf8",
      );
    },
  );
});

test("rejects an authority receipt issued before its latest prerequisite", () => {
  expectCode(
    makeFixture({
      authorityIssuedAt: "2026-09-10T22:59:59.000Z",
      prerequisiteIssuedAt: "2026-09-10T23:00:00.000Z",
    }),
    "release_authority_receipt_stale_future_or_out_of_order",
  );
});

test("rejects a stale authority receipt", () => {
  expectCode(
    makeFixture({
      now: new Date("2026-09-12T00:00:00.000Z"),
      authorityIssuedAt: "2026-09-10T23:00:00.000Z",
      prerequisiteIssuedAt: "2026-09-10T22:00:00.000Z",
      expiresAt: "2026-09-13T00:00:00.000Z",
    }),
    "release_authority_receipt_stale_future_or_out_of_order",
  );
});

test("rejects GO when the manifest predicate is not positive", () => {
  expectCode(
    makeFixture({ goPasses: false }),
    "release_manifest_schema_or_status_invalid",
  );
});

test("rejects a trust store with no approved signer", () => {
  expectCode(
    makeFixture({ trusted: false }),
    "trust_policy_no_trusted_issuers",
  );
});

test("rejects a missing protected-environment trust-store hash", () => {
  expectCode(
    makeFixture(),
    "expected_trust_policy_sha256_invalid",
    (fixture) => {
      fixture.input.expectedTrustPolicySha256 = "";
    },
  );
});

test("workflow keeps deployment behind main, verified evidence and credential resolution order", () => {
  const workflow = readFileSync(
    new URL("../.github/workflows/deploy-cloudflare-edge.yml", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /release_manifest_asset_id:/);
  assert.match(workflow, /release_authority_receipt_asset_id:/);
  assert.match(workflow, /release_authority_signature_asset_id:/);
  const verifyIndex = workflow.indexOf("node verify-release-authority.mjs");
  const credentialIndex = workflow.indexOf(
    "Resolve an existing scoped Cloudflare token",
  );
  const deployIndex = workflow.indexOf(
    "wrangler@4.123.0 deploy --env production",
  );
  assert.ok(verifyIndex >= 0);
  assert.ok(credentialIndex > verifyIndex);
  assert.ok(deployIndex > credentialIndex);
});
