#!/usr/bin/env node

import {
  createHash,
  createPublicKey,
  verify as verifyDetachedSignature,
} from "node:crypto";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const RELEASE_AUTHORITY_VERIFICATION =
  "CEI_EDGE_RELEASE_AUTHORITY_VERIFICATION";
const RELEASE_MANIFEST_MARKER = "ECOSYSTEM_RELEASE_MANIFEST";
const RELEASE_RECEIPT_MARKER = "CEI_SIGNED_RELEASE_RECEIPT";
const PRODUCTION_DEPLOYMENT_RECEIPT_MARKER =
  "CEI_SIGNED_PRODUCTION_DEPLOYMENT_RECEIPT";
const TRUST_POLICY_MARKER = "CEI_EDGE_RELEASE_AUTHORITY_TRUST_POLICY";
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const GIT_SHA_PATTERN = /^[a-f0-9]{40}$/;
const SAFE_REFERENCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,199}$/;
const MAX_FILE_BYTES = 10 * 1024 * 1024;
const REQUIRED_GO_RECEIPTS = Object.freeze([
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
]);
const LOCAL_GO_REQUIREMENT_IDS = Object.freeze([
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
]);
const MANIFEST_POLICY = Object.freeze({
  unsignedEnvironmentAssertionsAreNeverAuthority: true,
  evidenceBytesAndDetachedSignaturesRequired: true,
  providerReadbackReceiptsRequired: true,
  readyStatusesDoNotAuthoriseRelease: true,
  goRequiresSignedActionTimeAuthority: true,
  liveRequiresSignedPostObservationAuthority: true,
  secretsRawLearnerIdentifiersAndPaymentDataForbidden: true,
});

export class ReleaseAuthorityError extends Error {
  constructor(code) {
    super(code);
    this.name = "ReleaseAuthorityError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new ReleaseAuthorityError(code);
};

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const isRecord = (value) =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);
const hasExactKeys = (value, keys) =>
  isRecord(value) &&
  Object.keys(value).length === keys.length &&
  Object.keys(value).every((key) => keys.includes(key));
const sameJson = (left, right) => JSON.stringify(left) === JSON.stringify(right);

function readRegularFile(path, code) {
  if (!path || !existsSync(path)) fail(`${code}_missing`);
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) fail(`${code}_not_regular_file`);
  if (stat.size < 1 || stat.size > MAX_FILE_BYTES) fail(`${code}_size_invalid`);
  return readFileSync(path);
}

function parseJson(bytes, code) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    fail(`${code}_invalid_json`);
  }
}

function parseZuluTimestamp(value, code) {
  if (typeof value !== "string" || !value.endsWith("Z"))
    fail(`${code}_invalid`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value)
    fail(`${code}_invalid`);
  return parsed;
}

function receiptRequirementId(requirement) {
  if (requirement.receiptType === "provider") {
    return `signed_${requirement.subject}_provider_receipt`;
  }
  if (requirement.receiptType === "approval") {
    return `signed_${requirement.subject}_approval`;
  }
  return `signed_${requirement.subject}_receipt`;
}

function validateTrustPolicy(policy, expectedPolicySha256, policyBytes) {
  const policyKeys = [
    "marker",
    "schemaVersion",
    "expectedRepositoryUrl",
    "maximumManifestAgeHours",
    "maximumReleaseAuthorityAgeHours",
    "maximumProductionDeploymentReceiptAgeHours",
    "maximumEdgeDeploymentAuthorityAgeHours",
    "maximumFutureSkewMinutes",
    "releaseAuthority",
    "productionDeployments",
    "edgeDeploymentAuthority",
    "requiredGoReceipts",
    "trustedIssuers",
  ];
  if (!SHA256_PATTERN.test(expectedPolicySha256 ?? ""))
    fail("expected_trust_policy_sha256_invalid");
  if (sha256(policyBytes) !== expectedPolicySha256)
    fail("trust_policy_sha256_mismatch");
  if (
    !hasExactKeys(policy, policyKeys) ||
    policy.marker !== TRUST_POLICY_MARKER ||
    policy.schemaVersion !== 1 ||
    policy.expectedRepositoryUrl !==
      "https://github.com/KortexTechnologies/THE-CEI-EXAM.git" ||
    !Number.isFinite(policy.maximumManifestAgeHours) ||
    policy.maximumManifestAgeHours <= 0 ||
    !Number.isFinite(policy.maximumReleaseAuthorityAgeHours) ||
    policy.maximumReleaseAuthorityAgeHours <= 0 ||
    !Number.isFinite(policy.maximumProductionDeploymentReceiptAgeHours) ||
    policy.maximumProductionDeploymentReceiptAgeHours <= 0 ||
    !Number.isFinite(policy.maximumEdgeDeploymentAuthorityAgeHours) ||
    policy.maximumEdgeDeploymentAuthorityAgeHours <= 0 ||
    !Number.isSafeInteger(policy.maximumFutureSkewMinutes) ||
    policy.maximumFutureSkewMinutes < 0 ||
    policy.maximumFutureSkewMinutes > 30 ||
    !hasExactKeys(policy.releaseAuthority, [
      "receiptType",
      "phase",
      "subject",
    ]) ||
    policy.releaseAuthority.receiptType !== "approval" ||
    policy.releaseAuthority.phase !== "go" ||
    policy.releaseAuthority.subject !== "release_authority" ||
    !sameJson(policy.productionDeployments, [
      {
        receiptType: "provider",
        phase: "deploy",
        subject: "project_b_production_deployment",
        role: "projectB",
      },
      {
        receiptType: "provider",
        phase: "deploy",
        subject: "project_a_production_deployment",
        role: "projectA",
      },
    ]) ||
    !hasExactKeys(policy.edgeDeploymentAuthority, [
      "receiptType",
      "phase",
      "subject",
    ]) ||
    policy.edgeDeploymentAuthority.receiptType !== "approval" ||
    policy.edgeDeploymentAuthority.phase !== "deploy" ||
    policy.edgeDeploymentAuthority.subject !== "edge_deployment_authority" ||
    !Array.isArray(policy.requiredGoReceipts) ||
    !sameJson(policy.requiredGoReceipts, REQUIRED_GO_RECEIPTS) ||
    !Array.isArray(policy.trustedIssuers)
  ) {
    fail("trust_policy_schema_invalid");
  }

  const requirementKeys = new Set();
  for (const requirement of policy.requiredGoReceipts) {
    if (
      !hasExactKeys(requirement, ["receiptType", "phase", "subject"]) ||
      !["approval", "evidence", "provider", "security"].includes(
        requirement.receiptType,
      ) ||
      requirement.phase !== "go" ||
      !SAFE_REFERENCE_PATTERN.test(requirement.subject ?? "") ||
      requirement.subject === policy.releaseAuthority.subject
    ) {
      fail("trust_policy_go_requirement_invalid");
    }
    const key = `${requirement.receiptType}:${requirement.phase}:${requirement.subject}`;
    if (requirementKeys.has(key)) fail("trust_policy_go_requirement_duplicate");
    requirementKeys.add(key);
  }

  if (policy.trustedIssuers.length === 0)
    fail("trust_policy_no_trusted_issuers");
  const issuers = new Map();
  const recognisedScopes = [
    ["approval", policy.releaseAuthority.subject],
    ...policy.productionDeployments.map((requirement) => [
      requirement.receiptType,
      requirement.subject,
    ]),
    ["approval", policy.edgeDeploymentAuthority.subject],
  ];
  for (const issuer of policy.trustedIssuers) {
    const supportsRecognisedScope = recognisedScopes.some(
      ([receiptType, subject]) =>
        issuer?.allowedReceiptTypes?.includes(receiptType) &&
        issuer?.allowedSubjects?.includes(subject),
    );
    if (
      !hasExactKeys(issuer, [
        "keyId",
        "algorithm",
        "publicKeyPem",
        "allowedReceiptTypes",
        "allowedSubjects",
      ]) ||
      !SAFE_REFERENCE_PATTERN.test(issuer.keyId ?? "") ||
      issuer.algorithm !== "ed25519" ||
      typeof issuer.publicKeyPem !== "string" ||
      !Array.isArray(issuer.allowedReceiptTypes) ||
      issuer.allowedReceiptTypes.length === 0 ||
      new Set(issuer.allowedReceiptTypes).size !== issuer.allowedReceiptTypes.length ||
      !Array.isArray(issuer.allowedSubjects) ||
      issuer.allowedSubjects.length === 0 ||
      new Set(issuer.allowedSubjects).size !== issuer.allowedSubjects.length ||
      !supportsRecognisedScope ||
      issuers.has(issuer.keyId)
    ) {
      fail("trust_policy_issuer_invalid");
    }
    try {
      const key = createPublicKey(issuer.publicKeyPem);
      if (key.asymmetricKeyType !== "ed25519")
        fail("trust_policy_issuer_key_invalid");
    } catch (error) {
      if (error instanceof ReleaseAuthorityError) throw error;
      fail("trust_policy_issuer_key_invalid");
    }
    issuers.set(issuer.keyId, issuer);
  }
  return issuers;
}

function validateDispatch({
  githubEventName,
  githubRef,
  productionDeploymentApproved,
  candidateSha,
  dispatchedCandidateSha,
}) {
  if (githubEventName !== "workflow_dispatch") fail("dispatch_event_invalid");
  if (githubRef !== "refs/heads/main") fail("dispatch_ref_not_main");
  if (
    productionDeploymentApproved !== true &&
    productionDeploymentApproved !== "true"
  ) {
    fail("production_deployment_not_approved");
  }
  if (!GIT_SHA_PATTERN.test(candidateSha ?? "")) fail("candidate_sha_invalid");
  if (!GIT_SHA_PATTERN.test(dispatchedCandidateSha ?? ""))
    fail("dispatched_candidate_sha_invalid");
  if (candidateSha !== dispatchedCandidateSha)
    fail("dispatched_candidate_sha_mismatch");
}

function calculateCandidateFingerprint(manifest) {
  return sha256(JSON.stringify(manifest.candidateEnvelope));
}

function calculateManifestPayloadSha256(manifest) {
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
  return sha256(JSON.stringify(payload));
}

function validatePositivePredicate(predicate, code) {
  if (
    !hasExactKeys(predicate, ["passes", "blockers", "requirements"]) ||
    predicate.passes !== true ||
    !Array.isArray(predicate.blockers) ||
    predicate.blockers.length !== 0 ||
    !Array.isArray(predicate.requirements) ||
    predicate.requirements.length === 0
  ) {
    fail(`${code}_not_positive`);
  }
  const ids = new Set();
  for (const requirement of predicate.requirements) {
    if (
      !hasExactKeys(requirement, ["id", "passed"]) ||
      !SAFE_REFERENCE_PATTERN.test(requirement.id ?? "") ||
      requirement.passed !== true ||
      ids.has(requirement.id)
    ) {
      fail(`${code}_requirement_invalid`);
    }
    ids.add(requirement.id);
  }
  return ids;
}

function validateExactGoReadinessPredicate(predicate, policy) {
  validatePositivePredicate(predicate, "release_manifest_go_readiness");
  const expectedRequirements = [
    ...LOCAL_GO_REQUIREMENT_IDS,
    ...policy.requiredGoReceipts.map(receiptRequirementId),
  ].map((id) => ({ id, passed: true }));
  if (!sameJson(predicate.requirements, expectedRequirements)) {
    fail("release_manifest_go_readiness_derivation_invalid");
  }
}

function repositoryEnvelopeFromManifest(repository) {
  if (!isRecord(repository) || !isRecord(repository.lockfiles) || !isRecord(repository.build)) {
    fail("release_manifest_repository_identity_invalid");
  }
  return {
    expectedRepositoryUrl: repository.expectedRepositoryUrl,
    repositoryUrl: repository.repositoryUrl,
    commitSha: repository.commitSha,
    treeSha: repository.treeSha,
    sourceWorkingTreeSha256: repository.sourceWorkingTreeSha256,
    lockfileAggregateSha256: repository.lockfiles.aggregateSha256,
    buildSha256: repository.build.sha256,
    buildArtifactSha256: repository.build.artifactSha256,
    buildMetadataSha256: repository.build.metadataSha256,
    buildConfigurationSha256: repository.build.configurationSha256,
  };
}

function validateManifestConsistency(manifest) {
  const manifestKeys = [
    "marker",
    "schemaVersion",
    "releaseId",
    "generatedAt",
    "status",
    "immutableIdentity",
    "ecosystem",
    "candidateEnvelope",
    "candidateFingerprint",
    "repositories",
    "database",
    "releaseFacts",
    "expectedDeployments",
    "signedReceipts",
    "authorisationBindings",
    "goReadinessPredicate",
    "goPredicate",
    "liveReadinessPredicate",
    "livePredicate",
    "policy",
  ];
  const envelopeKeys = [
    "schemaVersion",
    "repositories",
    "database",
    "programmeSchedule",
    "productContract",
    "legal",
    "stripe",
    "cookiebot",
    "deploymentBaseline",
    "intendedEffectiveAt",
    "observationWindow",
    "trustPolicySha256",
  ];
  const repositoryEnvelopeKeys = [
    "expectedRepositoryUrl",
    "repositoryUrl",
    "commitSha",
    "treeSha",
    "sourceWorkingTreeSha256",
    "lockfileAggregateSha256",
    "buildSha256",
    "buildArtifactSha256",
    "buildMetadataSha256",
    "buildConfigurationSha256",
  ];
  if (
    !hasExactKeys(manifest, manifestKeys) ||
    !hasExactKeys(manifest.immutableIdentity, [
      "candidateFingerprint",
      "manifestPayloadSha256",
      "trustPolicySha256",
    ]) ||
    !hasExactKeys(manifest.candidateEnvelope, envelopeKeys) ||
    manifest.candidateEnvelope.schemaVersion !== 1 ||
    !hasExactKeys(manifest.repositories, ["projectA", "projectB", "edge"]) ||
    !hasExactKeys(manifest.candidateEnvelope.repositories, [
      "projectA",
      "projectB",
      "edge",
    ]) ||
    !hasExactKeys(manifest.database, ["projectA", "projectB"]) ||
    !hasExactKeys(manifest.candidateEnvelope.database, ["projectA", "projectB"]) ||
    !hasExactKeys(manifest.releaseFacts, [
      "programmeSchedule",
      "productContract",
      "legal",
      "stripe",
      "cookiebot",
      "intendedEffectiveAt",
      "observationWindow",
    ]) ||
    !hasExactKeys(manifest.expectedDeployments, ["projectA", "projectB", "edge"]) ||
    !hasExactKeys(manifest.candidateEnvelope.deploymentBaseline, [
      "projectA",
      "projectB",
      "edge",
    ]) ||
    !sameJson(manifest.policy, MANIFEST_POLICY)
  ) {
    fail("release_manifest_exact_schema_invalid");
  }

  for (const role of ["projectA", "projectB", "edge"]) {
    const envelopeRepository = manifest.candidateEnvelope.repositories[role];
    const repository = manifest.repositories[role];
    if (
      !hasExactKeys(envelopeRepository, repositoryEnvelopeKeys) ||
      !sameJson(envelopeRepository, repositoryEnvelopeFromManifest(repository))
    ) {
      fail(`release_manifest_${role}_repository_inconsistent`);
    }
    const expectedDeployment = manifest.expectedDeployments[role];
    const deploymentBaseline = manifest.candidateEnvelope.deploymentBaseline[role];
    if (
      !hasExactKeys(expectedDeployment, [
        "currentDeploymentId",
        "rollbackDeploymentId",
        "candidateDeploymentId",
        "deployedCommitSha",
      ]) ||
      !hasExactKeys(deploymentBaseline, [
        "currentDeploymentId",
        "rollbackDeploymentId",
      ]) ||
      !sameJson(deploymentBaseline, {
        currentDeploymentId: expectedDeployment.currentDeploymentId,
        rollbackDeploymentId: expectedDeployment.rollbackDeploymentId,
      })
    ) {
      fail(`release_manifest_${role}_deployment_inconsistent`);
    }
  }

  const expectedReleaseFacts = {
    programmeSchedule: manifest.candidateEnvelope.programmeSchedule,
    productContract: manifest.candidateEnvelope.productContract,
    legal: manifest.candidateEnvelope.legal,
    stripe: manifest.candidateEnvelope.stripe,
    cookiebot: manifest.candidateEnvelope.cookiebot,
    intendedEffectiveAt: manifest.candidateEnvelope.intendedEffectiveAt,
    observationWindow: manifest.candidateEnvelope.observationWindow,
  };
  if (
    !sameJson(manifest.database, manifest.candidateEnvelope.database) ||
    !sameJson(manifest.releaseFacts, expectedReleaseFacts)
  ) {
    fail("release_manifest_candidate_duplicates_inconsistent");
  }
}

function validateExactAcceptedReceiptSet(manifest, policy) {
  if (
    !hasExactKeys(manifest.signedReceipts, ["accepted", "rejected"]) ||
    !Array.isArray(manifest.signedReceipts.accepted) ||
    !Array.isArray(manifest.signedReceipts.rejected) ||
    manifest.signedReceipts.rejected.length !== 0
  ) {
    fail("release_manifest_signed_receipt_set_invalid");
  }
  const expected = [
    ...policy.requiredGoReceipts,
    policy.releaseAuthority,
  ].map(({ receiptType, phase, subject }) => `${receiptType}:${phase}:${subject}`);
  const actual = manifest.signedReceipts.accepted.map(
    (receipt) => `${receipt?.receiptType}:${receipt?.phase}:${receipt?.subject}`,
  );
  if (
    actual.length !== expected.length ||
    new Set(actual).size !== actual.length ||
    new Set(manifest.signedReceipts.accepted.map((receipt) => receipt?.receiptSha256)).size !==
      actual.length ||
    !sameJson([...actual].sort(), [...expected].sort())
  ) {
    fail("release_manifest_signed_receipt_set_invalid");
  }
}

function requiredReceiptIdentity(receipt) {
  return {
    receiptType: receipt.receiptType,
    phase: receipt.phase,
    subject: receipt.subject,
    receiptSha256: receipt.receiptSha256,
    artifactSha256: receipt.artifactSha256,
    keyId: receipt.keyId,
    issuedAt: receipt.issuedAt,
    expiresAt: receipt.expiresAt,
  };
}

function acceptedPrerequisiteReceipts(
  manifest,
  policy,
  candidateFingerprint,
  nowMs,
  manifestGeneratedAt,
) {
  const accepted = manifest.signedReceipts?.accepted;
  if (!Array.isArray(accepted)) fail("manifest_signed_receipts_invalid");
  return policy.requiredGoReceipts.map((requirement) => {
    const matches = accepted.filter(
      (receipt) =>
        receipt?.receiptType === requirement.receiptType &&
        receipt?.phase === requirement.phase &&
        receipt?.subject === requirement.subject,
    );
    if (matches.length !== 1)
      fail(`manifest_required_receipt_${requirement.subject}_invalid`);
    const receipt = matches[0];
    if (
      receipt.signatureVerified !== true ||
      receipt.candidateFingerprint !== candidateFingerprint ||
      !SHA256_PATTERN.test(receipt.receiptSha256 ?? "") ||
      !SHA256_PATTERN.test(receipt.bindingSha256 ?? "") ||
      !SAFE_REFERENCE_PATTERN.test(receipt.keyId ?? "") ||
      (receipt.receiptType === "approval"
        ? receipt.artifactSha256 !== null
        : !SHA256_PATTERN.test(receipt.artifactSha256 ?? ""))
    ) {
      fail(`manifest_required_receipt_${requirement.subject}_invalid`);
    }
    const issuedAt = parseZuluTimestamp(
      receipt.issuedAt,
      `manifest_required_receipt_${requirement.subject}_issued_at`,
    );
    const expiresAt = parseZuluTimestamp(
      receipt.expiresAt,
      `manifest_required_receipt_${requirement.subject}_expires_at`,
    );
    if (
      issuedAt > manifestGeneratedAt ||
      expiresAt <= issuedAt ||
      expiresAt <= nowMs
    ) {
      fail(
        `manifest_required_receipt_${requirement.subject}_expired_or_future`,
      );
    }
    return receipt;
  });
}

function validateManifest({
  manifest,
  manifestBytes,
  expectedManifestSha256,
  expectedReleaseId,
  candidateSha,
  policy,
  nowMs,
}) {
  if (!SHA256_PATTERN.test(expectedManifestSha256 ?? ""))
    fail("expected_manifest_sha256_invalid");
  const manifestSha256 = sha256(manifestBytes);
  if (manifestSha256 !== expectedManifestSha256)
    fail("release_manifest_sha256_mismatch");
  if (!SAFE_REFERENCE_PATTERN.test(expectedReleaseId ?? ""))
    fail("expected_release_id_invalid");
  if (
    !isRecord(manifest) ||
    manifest.marker !== RELEASE_MANIFEST_MARKER ||
    manifest.schemaVersion !== 2 ||
    manifest.ecosystem !== "THE CEI EXAM" ||
    manifest.releaseId !== expectedReleaseId ||
    manifest.status !== "GO" ||
    !isRecord(manifest.immutableIdentity) ||
    !isRecord(manifest.candidateEnvelope) ||
    !isRecord(manifest.repositories) ||
    !isRecord(manifest.database) ||
    !isRecord(manifest.releaseFacts) ||
    !isRecord(manifest.expectedDeployments) ||
    !isRecord(manifest.signedReceipts) ||
    !isRecord(manifest.authorisationBindings)
  ) {
    fail("release_manifest_schema_or_status_invalid");
  }
  validateManifestConsistency(manifest);
  validateExactAcceptedReceiptSet(manifest, policy);

  const futureSkewMs = policy.maximumFutureSkewMinutes * 60_000;
  const generatedAt = parseZuluTimestamp(
    manifest.generatedAt,
    "release_manifest_generated_at",
  );
  if (
    generatedAt > nowMs + futureSkewMs ||
    nowMs - generatedAt > policy.maximumManifestAgeHours * 60 * 60_000
  ) {
    fail("release_manifest_stale_or_future");
  }

  const candidateFingerprint = calculateCandidateFingerprint(manifest);
  if (
    !SHA256_PATTERN.test(manifest.candidateFingerprint ?? "") ||
    manifest.candidateFingerprint !== candidateFingerprint ||
    manifest.immutableIdentity.candidateFingerprint !== candidateFingerprint ||
    !SHA256_PATTERN.test(manifest.candidateEnvelope.trustPolicySha256 ?? "") ||
    manifest.immutableIdentity.trustPolicySha256 !==
      manifest.candidateEnvelope.trustPolicySha256
  ) {
    fail("release_manifest_candidate_fingerprint_mismatch");
  }
  const payloadSha256 = calculateManifestPayloadSha256(manifest);
  if (
    !SHA256_PATTERN.test(
      manifest.immutableIdentity.manifestPayloadSha256 ?? "",
    ) ||
    manifest.immutableIdentity.manifestPayloadSha256 !== payloadSha256
  ) {
    fail("release_manifest_payload_sha256_mismatch");
  }

  const repository = manifest.repositories.edge;
  const envelopeRepository = manifest.candidateEnvelope.repositories?.edge;
  if (
    !isRecord(repository) ||
    !isRecord(envelopeRepository) ||
    repository.expectedRepositoryUrl !== policy.expectedRepositoryUrl ||
    repository.repositoryUrl !== policy.expectedRepositoryUrl ||
    repository.commitSha !== candidateSha ||
    envelopeRepository.expectedRepositoryUrl !== policy.expectedRepositoryUrl ||
    envelopeRepository.repositoryUrl !== policy.expectedRepositoryUrl ||
    envelopeRepository.commitSha !== candidateSha ||
    envelopeRepository.treeSha !== repository.treeSha ||
    repository.clean !== true ||
    repository.build?.metadataBoundToCandidate !== true
  ) {
    fail("release_manifest_edge_candidate_mismatch");
  }

  const edgeDeployment = manifest.expectedDeployments.edge;
  if (
    !isRecord(edgeDeployment) ||
    !SAFE_REFERENCE_PATTERN.test(edgeDeployment.currentDeploymentId ?? "") ||
    !SAFE_REFERENCE_PATTERN.test(edgeDeployment.rollbackDeploymentId ?? "") ||
    edgeDeployment.currentDeploymentId === edgeDeployment.rollbackDeploymentId
  ) {
    fail("release_manifest_edge_rollback_identity_invalid");
  }

  validateExactGoReadinessPredicate(manifest.goReadinessPredicate, policy);
  validatePositivePredicate(manifest.goPredicate, "release_manifest_go");
  const expectedGoRequirements = [
    ...manifest.goReadinessPredicate.requirements,
    { id: "signed_action_time_release_authority_approval", passed: true },
  ];
  if (
    JSON.stringify(manifest.goPredicate.requirements) !==
    JSON.stringify(expectedGoRequirements)
  ) {
    fail("release_manifest_go_predicate_derivation_invalid");
  }

  const prerequisiteReceipts = acceptedPrerequisiteReceipts(
    manifest,
    policy,
    candidateFingerprint,
    nowMs,
    generatedAt,
  );
  const requiredReceipts = policy.requiredGoReceipts.map((item) => ({
    ...item,
  }));
  const acceptedRequiredReceipts = prerequisiteReceipts
    .map(requiredReceiptIdentity)
    .sort((left, right) =>
      `${left.receiptType}:${left.phase}:${left.subject}:${left.receiptSha256}`.localeCompare(
        `${right.receiptType}:${right.phase}:${right.subject}:${right.receiptSha256}`,
        "en",
      ),
    );
  const goReadinessSha256 = sha256(
    JSON.stringify({
      schemaVersion: 2,
      candidateFingerprint,
      requiredReceipts,
      acceptedRequiredReceipts,
      goReadinessPredicate: manifest.goReadinessPredicate,
    }),
  );
  if (manifest.authorisationBindings.goReadinessSha256 !== goReadinessSha256) {
    fail("release_manifest_go_readiness_binding_mismatch");
  }

  const latestPrerequisiteTime = Math.max(
    ...prerequisiteReceipts.map((receipt) =>
      parseZuluTimestamp(
        receipt.issuedAt,
        `manifest_required_receipt_${receipt.subject}_issued_at`,
      ),
    ),
  );
  return {
    manifestSha256,
    payloadSha256,
    candidateFingerprint,
    goReadinessSha256,
    generatedAt,
    latestPrerequisiteTime,
  };
}

function canonicalBase64(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value))
    return null;
  const bytes = Buffer.from(value, "base64");
  return bytes.toString("base64") === value ? bytes : null;
}

function verifyTrustedReceiptSignature({
  receipt,
  receiptBytes,
  signatureBytes,
  issuers,
  code,
}) {
  const issuer = issuers.get(receipt.keyId);
  if (
    !issuer ||
    !issuer.allowedReceiptTypes.includes(receipt.receiptType) ||
    !issuer.allowedSubjects.includes(receipt.subject)
  ) {
    fail(`${code}_issuer_untrusted_or_out_of_scope`);
  }
  const encodedSignature = signatureBytes.toString("utf8").trim();
  const signature = canonicalBase64(encodedSignature);
  if (!signature || signature.length !== 64)
    fail(`${code}_signature_encoding_invalid`);
  let signatureValid = false;
  try {
    signatureValid = verifyDetachedSignature(
      null,
      receiptBytes,
      createPublicKey(issuer.publicKeyPem),
      signature,
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) fail(`${code}_signature_invalid`);
  return issuer;
}

function validateAuthorityReceipt({
  receipt,
  receiptBytes,
  signatureBytes,
  manifest,
  manifestIdentity,
  policy,
  issuers,
  nowMs,
}) {
  const receiptKeys = [
    "marker",
    "schemaVersion",
    "receiptType",
    "phase",
    "subject",
    "candidateFingerprint",
    "bindingSha256",
    "artifactSha256",
    "result",
    "issuedAt",
    "expiresAt",
    "keyId",
    "displayName",
    "reference",
  ];
  if (
    !hasExactKeys(receipt, receiptKeys) ||
    receipt.marker !== RELEASE_RECEIPT_MARKER ||
    receipt.schemaVersion !== 1 ||
    receipt.receiptType !== policy.releaseAuthority.receiptType ||
    receipt.phase !== policy.releaseAuthority.phase ||
    receipt.subject !== policy.releaseAuthority.subject ||
    receipt.result !== "approved" ||
    receipt.artifactSha256 !== null ||
    receipt.candidateFingerprint !== manifestIdentity.candidateFingerprint ||
    receipt.bindingSha256 !== manifestIdentity.goReadinessSha256 ||
    !SAFE_REFERENCE_PATTERN.test(receipt.keyId ?? "") ||
    typeof receipt.displayName !== "string" ||
    receipt.displayName.trim() !== receipt.displayName ||
    receipt.displayName.length < 2 ||
    receipt.displayName.length > 120 ||
    /[@<>\r\n]/.test(receipt.displayName) ||
    !SAFE_REFERENCE_PATTERN.test(receipt.reference ?? "")
  ) {
    fail("release_authority_receipt_schema_or_binding_invalid");
  }

  const issuedAt = parseZuluTimestamp(
    receipt.issuedAt,
    "release_authority_issued_at",
  );
  const expiresAt = parseZuluTimestamp(
    receipt.expiresAt,
    "release_authority_expires_at",
  );
  const futureSkewMs = policy.maximumFutureSkewMinutes * 60_000;
  if (
    issuedAt > nowMs + futureSkewMs ||
    issuedAt < manifestIdentity.latestPrerequisiteTime ||
    issuedAt > manifestIdentity.generatedAt ||
    expiresAt <= nowMs ||
    expiresAt <= issuedAt ||
    nowMs - issuedAt > policy.maximumReleaseAuthorityAgeHours * 60 * 60_000
  ) {
    fail("release_authority_receipt_stale_future_or_out_of_order");
  }

  verifyTrustedReceiptSignature({
    receipt,
    receiptBytes,
    signatureBytes,
    issuers,
    code: "release_authority",
  });

  const receiptSha256 = sha256(receiptBytes);
  const accepted = manifest.signedReceipts.accepted.filter(
    (entry) =>
      entry?.receiptType === receipt.receiptType &&
      entry?.phase === receipt.phase &&
      entry?.subject === receipt.subject,
  );
  if (accepted.length !== 1)
    fail("release_authority_manifest_receipt_missing_or_duplicate");
  const manifestReceipt = accepted[0];
  if (
    manifestReceipt.receiptSha256 !== receiptSha256 ||
    manifestReceipt.artifactSha256 !== null ||
    manifestReceipt.candidateFingerprint !== receipt.candidateFingerprint ||
    manifestReceipt.bindingSha256 !== receipt.bindingSha256 ||
    manifestReceipt.keyId !== receipt.keyId ||
    manifestReceipt.issuedAt !== receipt.issuedAt ||
    manifestReceipt.expiresAt !== receipt.expiresAt ||
    manifestReceipt.displayName !== receipt.displayName ||
    manifestReceipt.reference !== receipt.reference ||
    manifestReceipt.signatureVerified !== true
  ) {
    fail("release_authority_manifest_receipt_mismatch");
  }
  return { receiptSha256, issuedAt, expiresAt, keyId: receipt.keyId };
}

function productionDeploymentBinding(manifest, requirement) {
  const repository = manifest.candidateEnvelope.repositories[requirement.role];
  const deployment = manifest.expectedDeployments[requirement.role];
  if (
    !isRecord(repository) ||
    !isRecord(deployment) ||
    !GIT_SHA_PATTERN.test(repository.commitSha ?? "") ||
    !SAFE_REFERENCE_PATTERN.test(deployment.currentDeploymentId ?? "") ||
    !SAFE_REFERENCE_PATTERN.test(deployment.rollbackDeploymentId ?? "") ||
    !SAFE_REFERENCE_PATTERN.test(deployment.candidateDeploymentId ?? "") ||
    !GIT_SHA_PATTERN.test(deployment.deployedCommitSha ?? "") ||
    deployment.deployedCommitSha !== repository.commitSha ||
    deployment.currentDeploymentId === deployment.rollbackDeploymentId ||
    deployment.candidateDeploymentId === deployment.currentDeploymentId ||
    deployment.candidateDeploymentId === deployment.rollbackDeploymentId
  ) {
    fail(`production_${requirement.role}_deployment_manifest_identity_invalid`);
  }
  return {
    schemaVersion: 1,
    candidateFingerprint: manifest.candidateFingerprint,
    role: requirement.role,
    repositoryCommitSha: repository.commitSha,
    currentDeploymentId: deployment.currentDeploymentId,
    rollbackDeploymentId: deployment.rollbackDeploymentId,
    candidateDeploymentId: deployment.candidateDeploymentId,
    deployedCommitSha: deployment.deployedCommitSha,
  };
}

function validateProductionDeploymentReceipt({
  receipt,
  receiptBytes,
  signatureBytes,
  manifest,
  requirement,
  issuers,
  policy,
  nowMs,
  strictlyAfter,
}) {
  const receiptKeys = [
    "marker",
    "schemaVersion",
    "receiptType",
    "phase",
    "subject",
    "candidateFingerprint",
    "bindingSha256",
    "result",
    "role",
    "repositoryCommitSha",
    "currentDeploymentId",
    "rollbackDeploymentId",
    "candidateDeploymentId",
    "deployedCommitSha",
    "issuedAt",
    "expiresAt",
    "keyId",
    "reference",
  ];
  const binding = productionDeploymentBinding(manifest, requirement);
  const expectedBindingSha256 = sha256(JSON.stringify(binding));
  if (
    !hasExactKeys(receipt, receiptKeys) ||
    receipt.marker !== PRODUCTION_DEPLOYMENT_RECEIPT_MARKER ||
    receipt.schemaVersion !== 1 ||
    receipt.receiptType !== requirement.receiptType ||
    receipt.phase !== requirement.phase ||
    receipt.subject !== requirement.subject ||
    receipt.candidateFingerprint !== manifest.candidateFingerprint ||
    receipt.bindingSha256 !== expectedBindingSha256 ||
    receipt.result !== "verified" ||
    receipt.role !== binding.role ||
    receipt.repositoryCommitSha !== binding.repositoryCommitSha ||
    receipt.currentDeploymentId !== binding.currentDeploymentId ||
    receipt.rollbackDeploymentId !== binding.rollbackDeploymentId ||
    receipt.candidateDeploymentId !== binding.candidateDeploymentId ||
    receipt.deployedCommitSha !== binding.deployedCommitSha ||
    !SAFE_REFERENCE_PATTERN.test(receipt.keyId ?? "") ||
    !SAFE_REFERENCE_PATTERN.test(receipt.reference ?? "")
  ) {
    fail(`production_${requirement.role}_deployment_receipt_invalid`);
  }
  const issuedAt = parseZuluTimestamp(
    receipt.issuedAt,
    `production_${requirement.role}_deployment_issued_at`,
  );
  const expiresAt = parseZuluTimestamp(
    receipt.expiresAt,
    `production_${requirement.role}_deployment_expires_at`,
  );
  const futureSkewMs = policy.maximumFutureSkewMinutes * 60_000;
  if (
    issuedAt <= strictlyAfter ||
    issuedAt > nowMs + futureSkewMs ||
    expiresAt <= nowMs ||
    expiresAt <= issuedAt ||
    nowMs - issuedAt >
      policy.maximumProductionDeploymentReceiptAgeHours * 60 * 60_000
  ) {
    fail(`production_${requirement.role}_deployment_stale_or_out_of_order`);
  }
  verifyTrustedReceiptSignature({
    receipt,
    receiptBytes,
    signatureBytes,
    issuers,
    code: `production_${requirement.role}_deployment`,
  });
  return {
    ...binding,
    receiptType: receipt.receiptType,
    phase: receipt.phase,
    subject: receipt.subject,
    receiptSha256: sha256(receiptBytes),
    bindingSha256: receipt.bindingSha256,
    keyId: receipt.keyId,
    issuedAt: receipt.issuedAt,
    expiresAt: receipt.expiresAt,
    issuedTime: issuedAt,
  };
}

function validateEdgeDeploymentAuthority({
  receipt,
  receiptBytes,
  signatureBytes,
  manifest,
  manifestIdentity,
  goAuthorityIdentity,
  productionDeployments,
  policy,
  issuers,
  nowMs,
}) {
  const edgeDeployment = manifest.expectedDeployments.edge;
  const readiness = {
    schemaVersion: 1,
    candidateFingerprint: manifestIdentity.candidateFingerprint,
    goAuthorityReceiptSha256: goAuthorityIdentity.receiptSha256,
    productionDeployments: productionDeployments.map(({ issuedTime, ...item }) => item),
    edge: {
      commitSha: manifest.candidateEnvelope.repositories.edge.commitSha,
      treeSha: manifest.candidateEnvelope.repositories.edge.treeSha,
      currentDeploymentId: edgeDeployment.currentDeploymentId,
      rollbackDeploymentId: edgeDeployment.rollbackDeploymentId,
    },
  };
  const readinessSha256 = sha256(JSON.stringify(readiness));
  const requirement = policy.edgeDeploymentAuthority;
  if (
    !hasExactKeys(receipt, [
      "marker",
      "schemaVersion",
      "receiptType",
      "phase",
      "subject",
      "candidateFingerprint",
      "bindingSha256",
      "artifactSha256",
      "result",
      "issuedAt",
      "expiresAt",
      "keyId",
      "displayName",
      "reference",
    ]) ||
    receipt.marker !== RELEASE_RECEIPT_MARKER ||
    receipt.schemaVersion !== 1 ||
    receipt.receiptType !== requirement.receiptType ||
    receipt.phase !== requirement.phase ||
    receipt.subject !== requirement.subject ||
    receipt.candidateFingerprint !== manifestIdentity.candidateFingerprint ||
    receipt.bindingSha256 !== readinessSha256 ||
    receipt.artifactSha256 !== null ||
    receipt.result !== "approved" ||
    !SAFE_REFERENCE_PATTERN.test(receipt.keyId ?? "") ||
    typeof receipt.displayName !== "string" ||
    receipt.displayName.trim() !== receipt.displayName ||
    receipt.displayName.length < 2 ||
    receipt.displayName.length > 120 ||
    /[@<>\r\n]/.test(receipt.displayName) ||
    !SAFE_REFERENCE_PATTERN.test(receipt.reference ?? "")
  ) {
    fail("edge_deployment_authority_receipt_invalid");
  }
  const issuedAt = parseZuluTimestamp(
    receipt.issuedAt,
    "edge_deployment_authority_issued_at",
  );
  const expiresAt = parseZuluTimestamp(
    receipt.expiresAt,
    "edge_deployment_authority_expires_at",
  );
  const latestDeploymentTime = productionDeployments.at(-1).issuedTime;
  const futureSkewMs = policy.maximumFutureSkewMinutes * 60_000;
  if (
    issuedAt <= latestDeploymentTime ||
    issuedAt > nowMs + futureSkewMs ||
    expiresAt <= nowMs ||
    expiresAt <= issuedAt ||
    nowMs - issuedAt > policy.maximumEdgeDeploymentAuthorityAgeHours * 60 * 60_000
  ) {
    fail("edge_deployment_authority_stale_or_out_of_order");
  }
  verifyTrustedReceiptSignature({
    receipt,
    receiptBytes,
    signatureBytes,
    issuers,
    code: "edge_deployment_authority",
  });
  return {
    readinessSha256,
    receiptSha256: sha256(receiptBytes),
    keyId: receipt.keyId,
    issuedAt,
    expiresAt,
  };
}

export function verifyReleaseAuthority({
  manifestPath,
  authorityReceiptPath,
  authoritySignaturePath,
  projectBDeploymentReceiptPath,
  projectBDeploymentSignaturePath,
  projectADeploymentReceiptPath,
  projectADeploymentSignaturePath,
  edgeDeploymentAuthorityReceiptPath,
  edgeDeploymentAuthoritySignaturePath,
  trustPolicyPath,
  expectedManifestSha256,
  expectedTrustPolicySha256,
  expectedReleaseId,
  candidateSha,
  dispatchedCandidateSha,
  githubEventName,
  githubRef,
  productionDeploymentApproved,
  now = new Date(),
}) {
  validateDispatch({
    githubEventName,
    githubRef,
    productionDeploymentApproved,
    candidateSha,
    dispatchedCandidateSha,
  });
  const nowMs = now instanceof Date ? now.valueOf() : Number(now);
  if (!Number.isFinite(nowMs)) fail("verification_time_invalid");

  const policyBytes = readRegularFile(trustPolicyPath, "trust_policy");
  const policy = parseJson(policyBytes, "trust_policy");
  const issuers = validateTrustPolicy(
    policy,
    expectedTrustPolicySha256,
    policyBytes,
  );
  const manifestBytes = readRegularFile(manifestPath, "release_manifest");
  const manifest = parseJson(manifestBytes, "release_manifest");
  const manifestIdentity = validateManifest({
    manifest,
    manifestBytes,
    expectedManifestSha256,
    expectedReleaseId,
    candidateSha,
    policy,
    nowMs,
  });
  const receiptBytes = readRegularFile(
    authorityReceiptPath,
    "release_authority_receipt",
  );
  const receipt = parseJson(receiptBytes, "release_authority_receipt");
  const signatureBytes = readRegularFile(
    authoritySignaturePath,
    "release_authority_signature",
  );
  const receiptIdentity = validateAuthorityReceipt({
    receipt,
    receiptBytes,
    signatureBytes,
    manifest,
    manifestIdentity,
    policy,
    issuers,
    nowMs,
  });
  const deploymentPaths = {
    projectB: {
      receipt: projectBDeploymentReceiptPath,
      signature: projectBDeploymentSignaturePath,
    },
    projectA: {
      receipt: projectADeploymentReceiptPath,
      signature: projectADeploymentSignaturePath,
    },
  };
  const productionDeployments = [];
  let strictlyAfter = receiptIdentity.issuedAt;
  for (const requirement of policy.productionDeployments) {
    const paths = deploymentPaths[requirement.role];
    const deploymentReceiptBytes = readRegularFile(
      paths?.receipt,
      `production_${requirement.role}_deployment_receipt`,
    );
    const deploymentReceipt = parseJson(
      deploymentReceiptBytes,
      `production_${requirement.role}_deployment_receipt`,
    );
    const deploymentSignatureBytes = readRegularFile(
      paths?.signature,
      `production_${requirement.role}_deployment_signature`,
    );
    const deploymentIdentity = validateProductionDeploymentReceipt({
      receipt: deploymentReceipt,
      receiptBytes: deploymentReceiptBytes,
      signatureBytes: deploymentSignatureBytes,
      manifest,
      requirement,
      issuers,
      policy,
      nowMs,
      strictlyAfter,
    });
    productionDeployments.push(deploymentIdentity);
    strictlyAfter = deploymentIdentity.issuedTime;
  }
  const edgeAuthorityReceiptBytes = readRegularFile(
    edgeDeploymentAuthorityReceiptPath,
    "edge_deployment_authority_receipt",
  );
  const edgeAuthorityReceipt = parseJson(
    edgeAuthorityReceiptBytes,
    "edge_deployment_authority_receipt",
  );
  const edgeAuthoritySignatureBytes = readRegularFile(
    edgeDeploymentAuthoritySignaturePath,
    "edge_deployment_authority_signature",
  );
  const edgeAuthorityIdentity = validateEdgeDeploymentAuthority({
    receipt: edgeAuthorityReceipt,
    receiptBytes: edgeAuthorityReceiptBytes,
    signatureBytes: edgeAuthoritySignatureBytes,
    manifest,
    manifestIdentity,
    goAuthorityIdentity: receiptIdentity,
    productionDeployments,
    policy,
    issuers,
    nowMs,
  });
  return {
    marker: RELEASE_AUTHORITY_VERIFICATION,
    schemaVersion: 1,
    status: "verified",
    releaseId: manifest.releaseId,
    manifestSha256: manifestIdentity.manifestSha256,
    manifestPayloadSha256: manifestIdentity.payloadSha256,
    candidateFingerprint: manifestIdentity.candidateFingerprint,
    edgeCandidateCommitSha: candidateSha,
    authorityReceiptSha256: receiptIdentity.receiptSha256,
    authorityKeyId: receiptIdentity.keyId,
    authorityIssuedAt: new Date(receiptIdentity.issuedAt).toISOString(),
    authorityExpiresAt: new Date(receiptIdentity.expiresAt).toISOString(),
    projectBDeploymentReceiptSha256: productionDeployments[0].receiptSha256,
    projectADeploymentReceiptSha256: productionDeployments[1].receiptSha256,
    edgeDeploymentReadinessSha256: edgeAuthorityIdentity.readinessSha256,
    edgeDeploymentAuthorityReceiptSha256: edgeAuthorityIdentity.receiptSha256,
    edgeDeploymentAuthorityKeyId: edgeAuthorityIdentity.keyId,
    edgeDeploymentAuthorityIssuedAt: new Date(
      edgeAuthorityIdentity.issuedAt,
    ).toISOString(),
    edgeDeploymentAuthorityExpiresAt: new Date(
      edgeAuthorityIdentity.expiresAt,
    ).toISOString(),
  };
}

function parseArguments(argv) {
  const allowed = new Set([
    "manifest",
    "manifest-sha256",
    "release-id",
    "authority-receipt",
    "authority-signature",
    "project-b-deployment-receipt",
    "project-b-deployment-signature",
    "project-a-deployment-receipt",
    "project-a-deployment-signature",
    "edge-deployment-authority-receipt",
    "edge-deployment-authority-signature",
    "trust-policy",
    "expected-trust-policy-sha256",
    "candidate-sha",
    "dispatched-candidate-sha",
    "github-event-name",
    "github-ref",
    "production-deployment-approved",
  ]);
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    const rawKey = argv[index];
    const value = argv[index + 1];
    if (!rawKey?.startsWith("--") || value === undefined)
      fail("arguments_invalid");
    const key = rawKey.slice(2);
    if (!allowed.has(key) || Object.hasOwn(parsed, key))
      fail("arguments_invalid");
    parsed[key] = value;
  }
  if (Object.keys(parsed).length !== allowed.size) fail("arguments_incomplete");
  return parsed;
}

if (
  process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url
) {
  try {
    const args = parseArguments(process.argv.slice(2));
    const result = verifyReleaseAuthority({
      manifestPath: args.manifest,
      authorityReceiptPath: args["authority-receipt"],
      authoritySignaturePath: args["authority-signature"],
      projectBDeploymentReceiptPath: args["project-b-deployment-receipt"],
      projectBDeploymentSignaturePath:
        args["project-b-deployment-signature"],
      projectADeploymentReceiptPath: args["project-a-deployment-receipt"],
      projectADeploymentSignaturePath:
        args["project-a-deployment-signature"],
      edgeDeploymentAuthorityReceiptPath:
        args["edge-deployment-authority-receipt"],
      edgeDeploymentAuthoritySignaturePath:
        args["edge-deployment-authority-signature"],
      trustPolicyPath: args["trust-policy"],
      expectedManifestSha256: args["manifest-sha256"],
      expectedTrustPolicySha256: args["expected-trust-policy-sha256"],
      expectedReleaseId: args["release-id"],
      candidateSha: args["candidate-sha"],
      dispatchedCandidateSha: args["dispatched-candidate-sha"],
      githubEventName: args["github-event-name"],
      githubRef: args["github-ref"],
      productionDeploymentApproved: args["production-deployment-approved"],
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    const code =
      error instanceof ReleaseAuthorityError
        ? error.code
        : "release_authority_verification_failed";
    process.stderr.write(`[${RELEASE_AUTHORITY_VERIFICATION}] ${code}\n`);
    process.exitCode = 1;
  }
}
