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
const localGoRequirementIds = [
  "trust_policy_valid",
  "peer_trust_policy_matches",
  "trusted_release_issuers_configured",
  ...["projectA", "projectB", "edge"].flatMap((role) => [
    `${role}_repository_present`,
    `${role}_authoritative_repository`,
    `${role}_identity_stable_during_hashing`,
    `${role}_working_tree_clean`,
    `${role}_source_hash_present`,
    `${role}_candidate_bound_production_build`,
  ]),
  "project_a_lockfile_hash_present",
  "project_b_lockfile_hash_present",
  "project_a_migration_head_present",
  "project_b_migration_head_present",
  "project_a_edge_function_hashes_present",
  "project_b_edge_function_hashes_present",
  "programme_schedule_file_hash_verified",
  "product_contract_parity",
  "legal_v2_2_copy_hashes_match",
  "legal_effective_metadata_matches_candidate",
  "complete_canonical_stripe_offer_matrix",
  "cookiebot_expected_configuration_present",
  "current_and_rollback_deployments_expected",
  "observation_window_valid",
  "intended_effective_timestamp_present",
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

  const repositoryEnvelopeFor = (repositoryUrl, commitSha, seed) => ({
    expectedRepositoryUrl: repositoryUrl,
    repositoryUrl,
    commitSha,
    treeSha: seed.repeat(40),
    sourceWorkingTreeSha256: seed.repeat(64),
    lockfileAggregateSha256: seed.repeat(64),
    buildSha256: seed.repeat(64),
    buildArtifactSha256: seed.repeat(64),
    buildMetadataSha256: seed.repeat(64),
    buildConfigurationSha256: seed.repeat(64),
  });
  const repositoryEnvelope = {
    projectA: repositoryEnvelopeFor(
      "https://github.com/Kortex-Technologies-Private-Limited/theceiexam.git",
      "a".repeat(40),
      "a",
    ),
    projectB: repositoryEnvelopeFor(
      "https://github.com/Kortex-Technologies-Private-Limited/dashboard-theceiexam.git",
      "b".repeat(40),
      "b",
    ),
    edge: {
      ...repositoryEnvelopeFor(REPOSITORY_URL, candidateSha, "c"),
      treeSha: TREE_SHA,
    },
  };
  const database = { projectA: { migrations: {} }, projectB: { migrations: {} } };
  const deploymentBaseline = {
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
  const candidateEnvelope = {
    schemaVersion: 1,
    repositories: repositoryEnvelope,
    database,
    programmeSchedule: { sha256: "7".repeat(64) },
    productContract: { semanticHash: "8".repeat(64) },
    legal: { wordingSha256: "9".repeat(64) },
    stripe: { accountId: "acct_fixture" },
    cookiebot: { configurationId: "cb-fixture" },
    deploymentBaseline,
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
  const goReadinessRequirements = [
    ...localGoRequirementIds.map((id) => ({ id, passed: true })),
    ...requiredGoReceipts.map((requirement) => ({
      id: requirementId(requirement),
      passed: true,
    })),
  ];
  const goReadinessPredicate = {
    passes: goPasses,
    blockers: goPasses ? [] : ["trust_policy_valid"],
    requirements: goPasses
      ? goReadinessRequirements
      : goReadinessRequirements.map((requirement, index) =>
          index === 0 ? { ...requirement, passed: false } : requirement,
        ),
  };
  const goReadinessSha256 = sha256(
    JSON.stringify({
      schemaVersion: 2,
      candidateFingerprint,
      requiredReceipts: requiredGoReceipts,
      acceptedRequiredReceipts,
      goReadinessPredicate,
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
  const goPredicate = {
    passes: goPasses,
    blockers: goPasses ? [] : ["trust_policy_valid"],
    requirements: [
      ...goReadinessPredicate.requirements,
      { id: "signed_action_time_release_authority_approval", passed: true },
    ],
  };
  const repositories = Object.fromEntries(
    Object.entries(repositoryEnvelope).map(([role, envelope]) => [
      role,
      {
        expectedRepositoryUrl: envelope.expectedRepositoryUrl,
        repositoryUrl: envelope.repositoryUrl,
        commitSha: envelope.commitSha,
        treeSha: envelope.treeSha,
        sourceWorkingTreeSha256: envelope.sourceWorkingTreeSha256,
        clean: true,
        lockfiles: { aggregateSha256: envelope.lockfileAggregateSha256 },
        build: {
          sha256: envelope.buildSha256,
          artifactSha256: envelope.buildArtifactSha256,
          metadataSha256: envelope.buildMetadataSha256,
          configurationSha256: envelope.buildConfigurationSha256,
          metadataBoundToCandidate: true,
        },
      },
    ]),
  );
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
      candidateDeploymentId: null,
      deployedCommitSha: null,
    },
    projectB: {
      currentDeploymentId: "b-current",
      rollbackDeploymentId: "b-rollback",
      candidateDeploymentId: null,
      deployedCommitSha: null,
    },
    edge: {
      currentDeploymentId: "edge-current",
      rollbackDeploymentId: "edge-rollback",
      candidateDeploymentId: null,
      deployedCommitSha: null,
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
    policy: {
      unsignedEnvironmentAssertionsAreNeverAuthority: true,
      evidenceBytesAndDetachedSignaturesRequired: true,
      providerReadbackReceiptsRequired: true,
      readyStatusesDoNotAuthoriseRelease: true,
      goRequiresSignedActionTimeAuthority: true,
      liveRequiresSignedPostObservationAuthority: true,
      secretsRawLearnerIdentifiersAndPaymentDataForbidden: true,
    },
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

test("rejects a rewritten readiness predicate even when the manifest self-hash is refreshed", () => {
  expectCode(
    makeFixture(),
    "release_manifest_go_readiness_derivation_invalid",
    (fixture) => {
      fixture.manifest.goReadinessPredicate.requirements.splice(3, 1);
      fixture.manifest.goPredicate.requirements = [
        ...fixture.manifest.goReadinessPredicate.requirements,
        { id: "signed_action_time_release_authority_approval", passed: true },
      ];
      fixture.rewriteManifest();
    },
  );
});

test("rejects duplicate or additional accepted receipts", () => {
  expectCode(makeFixture(), "release_manifest_signed_receipt_set_invalid", (fixture) => {
    fixture.manifest.signedReceipts.accepted.push({
      ...fixture.manifest.signedReceipts.accepted[0],
      id: "duplicate-local-release",
    });
    fixture.rewriteManifest();
  });
});

test("rejects a top-level Project A identity that differs from the signed candidate envelope", () => {
  expectCode(
    makeFixture(),
    "release_manifest_projectA_repository_inconsistent",
    (fixture) => {
      fixture.manifest.repositories.projectA.commitSha = "d".repeat(40);
      fixture.rewriteManifest();
    },
  );
});

test("rejects release facts or deployment baselines rewritten outside the signed envelope", () => {
  expectCode(
    makeFixture(),
    "release_manifest_candidate_duplicates_inconsistent",
    (fixture) => {
      fixture.manifest.releaseFacts.cookiebot = {
        ...fixture.manifest.releaseFacts.cookiebot,
        configurationId: "rewritten",
      };
      fixture.rewriteManifest();
    },
  );
  expectCode(
    makeFixture(),
    "release_manifest_projectB_deployment_inconsistent",
    (fixture) => {
      fixture.manifest.expectedDeployments.projectB.rollbackDeploymentId =
        "rewritten-rollback";
      fixture.rewriteManifest();
    },
  );
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

test("workflow deploys the hash-attested Worker only after authority and credential resolution", () => {
  const workflow = readFileSync(
    new URL("../.github/workflows/deploy-cloudflare-edge.yml", import.meta.url),
    "utf8",
  );
  const wranglerConfiguration = readFileSync(
    new URL("./wrangler.jsonc", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /release_manifest_asset_id:/);
  assert.match(workflow, /release_authority_receipt_asset_id:/);
  assert.match(workflow, /release_authority_signature_asset_id:/);
  const verifyIndex = workflow.indexOf("node verify-release-authority.mjs");
  const buildIndex = workflow.lastIndexOf(
    "--outfile=dist/worker.mjs",
  );
  const metadataIndex = workflow.lastIndexOf(
    "node write-release-build-metadata.mjs --verify-production",
  );
  const credentialIndex = workflow.indexOf(
    "Resolve an existing scoped Cloudflare token",
  );
  const deployIndex = workflow.indexOf(
    "wrangler@4.123.0 deploy --no-bundle --env production",
  );
  assert.ok(verifyIndex >= 0);
  assert.ok(buildIndex > verifyIndex);
  assert.ok(metadataIndex > buildIndex);
  assert.ok(credentialIndex > metadataIndex);
  assert.ok(deployIndex > credentialIndex);
  assert.match(wranglerConfiguration, /^\s*"main"\s*:\s*"dist\/worker\.mjs"/m);
  assert.doesNotMatch(workflow, /wrangler@4\.123\.0 deploy --env production/);
});
