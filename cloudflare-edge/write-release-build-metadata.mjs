#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const MARKER = "CEI_CANDIDATE_BUILD_METADATA";
const SCHEMA_VERSION = 1;
const EXPECTED_REPOSITORY_URL = "https://github.com/KortexTechnologies/THE-CEI-EXAM.git";
const MAXIMUM_AGE_HOURS = 24;
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const buildDirectory = "cloudflare-edge/dist";
const metadataRelativePath = `${buildDirectory}/release-metadata.json`;
const metadataPath = join(root, metadataRelativePath);
const deployArtifactRelativePath = `${buildDirectory}/worker.mjs`;
const deployArtifactPath = join(root, deployArtifactRelativePath);
const command = process.argv.slice(2);
const writeMode = command.length === 1 && command[0] === "--production";
const verifyMode = command.length === 1 && command[0] === "--verify-production";

if (!writeMode && !verifyMode) throw new Error("edge_release_build_metadata_command_invalid");

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const normalisePath = (value) => value.split(sep).join("/");
const isSha256 = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const isGitSha = (value) => typeof value === "string" && /^[a-f0-9]{40}$/.test(value);
const hasExactKeySet = (value, expected) =>
  value &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === expected.size &&
  Object.keys(value).every((key) => expected.has(key));

function runGit(args, { trim = true } = {}) {
  const result = spawnSync("git", ["-C", root, ...args], { encoding: "utf8", windowsHide: true });
  if (result.status !== 0) throw new Error("edge_release_build_git_identity_unavailable");
  return trim ? result.stdout.trim() : result.stdout;
}

function canonicalRepositoryUrl(value) {
  if (typeof value !== "string") return null;
  const match = value.match(
    /^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?$/,
  );
  return match ? `https://github.com/${match[1]}/${match[2]}.git` : null;
}

function gitSnapshot() {
  const repositoryRoot = resolve(runGit(["rev-parse", "--show-toplevel"]));
  if (repositoryRoot.toLowerCase() !== root.toLowerCase()) {
    throw new Error("edge_release_build_repository_root_mismatch");
  }
  return {
    commitSha: runGit(["rev-parse", "HEAD"]),
    treeSha: runGit(["rev-parse", "HEAD^{tree}"]),
    repositoryUrl: canonicalRepositoryUrl(runGit(["remote", "get-url", "origin"])),
    porcelain: runGit(["status", "--porcelain=v1", "--untracked-files=all"]),
  };
}

function listFiles(base, relativePath = "") {
  const absolutePath = join(base, relativePath);
  if (!existsSync(absolutePath)) return [];
  const stat = lstatSync(absolutePath);
  if (stat.isSymbolicLink()) {
    return [{ path: normalisePath(relativePath), link: readlinkSync(absolutePath) }];
  }
  if (stat.isFile()) return [{ path: normalisePath(relativePath), absolutePath }];
  if (!stat.isDirectory()) return [];
  return readdirSync(absolutePath, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name, "en"))
    .flatMap((entry) => listFiles(base, join(relativePath, entry.name)));
}

function hashEntries(entries) {
  if (entries.length === 0) return null;
  const hash = createHash("sha256");
  for (const entry of entries.sort((left, right) => left.path.localeCompare(right.path, "en"))) {
    hash.update(entry.path);
    hash.update("\0");
    if (entry.link !== undefined) {
      hash.update("link\0");
      hash.update(entry.link);
    } else {
      hash.update(readFileSync(entry.absolutePath));
    }
    hash.update("\0");
  }
  return hash.digest("hex");
}

function trackedSourceHash() {
  const entries = runGit(["ls-files", "-z"], { trim: false })
    .split("\0")
    .filter(Boolean)
    .sort((left, right) => left.localeCompare(right, "en"))
    .map((path) => {
      const absolutePath = join(root, path);
      if (!existsSync(absolutePath)) throw new Error("edge_release_build_tracked_source_missing");
      const stat = lstatSync(absolutePath);
      return stat.isSymbolicLink()
        ? { path, link: readlinkSync(absolutePath) }
        : { path, absolutePath };
    });
  return hashEntries(entries);
}

function artifactHash() {
  return hashEntries(
    listFiles(root, buildDirectory).filter(
      (entry) => entry.path !== normalisePath(metadataRelativePath),
    ),
  );
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error("edge_release_build_metadata_invalid_json");
  }
}

function productionConfigurationValid() {
  const configuration = readFileSync(join(root, "cloudflare-edge/wrangler.jsonc"), "utf8");
  const mainEntries = [
    ...configuration.matchAll(/^\s*"main"\s*:\s*"([^"]+)"\s*,?\s*$/gm),
  ].map((match) => match[1]);
  return (
    mainEntries.length === 1 &&
    mainEntries[0] === "dist/worker.mjs" &&
    existsSync(deployArtifactPath) &&
    lstatSync(deployArtifactPath).isFile() &&
    !lstatSync(deployArtifactPath).isSymbolicLink()
  );
}

const before = gitSnapshot();
if (
  before.porcelain !== "" ||
  before.repositoryUrl !== EXPECTED_REPOSITORY_URL ||
  !isGitSha(before.commitSha) ||
  !isGitSha(before.treeSha) ||
  !productionConfigurationValid()
) {
  throw new Error("edge_release_build_repository_not_clean_authoritative_candidate");
}

const sourceSha256 = trackedSourceHash();
const distSha256 = artifactHash();
if (!isSha256(sourceSha256) || !isSha256(distSha256)) {
  throw new Error("edge_release_build_artifact_identity_unavailable");
}
const configurationSha256 = sha256(readFileSync(join(root, "cloudflare-edge/wrangler.jsonc")));
const metadataKeys = new Set([
  "marker",
  "schemaVersion",
  "repositoryUrl",
  "commitSha",
  "treeSha",
  "sourceSha256",
  "distSha256",
  "buildMode",
  "configurationBound",
  "configurationSha256",
  "publicBackendConfigured",
  "publicBackendProjectIdSha256",
  "publicBackendUrlSha256",
  "cleanBefore",
  "cleanAfter",
  "generatedAt",
]);

function metadataValid(metadata, now) {
  const generatedTime = Date.parse(metadata?.generatedAt);
  return Boolean(
    hasExactKeySet(metadata, metadataKeys) &&
    metadata.marker === MARKER &&
    metadata.schemaVersion === SCHEMA_VERSION &&
    metadata.repositoryUrl === EXPECTED_REPOSITORY_URL &&
    metadata.commitSha === before.commitSha &&
    metadata.treeSha === before.treeSha &&
    metadata.sourceSha256 === sourceSha256 &&
    metadata.distSha256 === distSha256 &&
    metadata.buildMode === "production" &&
    metadata.configurationBound === true &&
    metadata.configurationSha256 === configurationSha256 &&
    metadata.publicBackendConfigured === false &&
    metadata.publicBackendProjectIdSha256 === null &&
    metadata.publicBackendUrlSha256 === null &&
    metadata.cleanBefore === true &&
    metadata.cleanAfter === true &&
    Number.isFinite(generatedTime) &&
    generatedTime <= now &&
    now - generatedTime <= MAXIMUM_AGE_HOURS * 60 * 60 * 1000
  );
}

const previousMetadata = existsSync(metadataPath) ? readFileSync(metadataPath) : null;
let wroteMetadata = false;
try {
  if (writeMode) {
    const metadata = {
      marker: MARKER,
      schemaVersion: SCHEMA_VERSION,
      repositoryUrl: EXPECTED_REPOSITORY_URL,
      commitSha: before.commitSha,
      treeSha: before.treeSha,
      sourceSha256,
      distSha256,
      buildMode: "production",
      configurationBound: true,
      configurationSha256,
      publicBackendConfigured: false,
      publicBackendProjectIdSha256: null,
      publicBackendUrlSha256: null,
      cleanBefore: true,
      cleanAfter: true,
      generatedAt: new Date().toISOString(),
    };
    mkdirSync(dirname(metadataPath), { recursive: true });
    writeFileSync(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`, "utf8");
    wroteMetadata = true;
  }

  if (!existsSync(metadataPath) || !lstatSync(metadataPath).isFile()) {
    throw new Error("edge_release_build_metadata_missing");
  }
  const metadata = readJson(metadataPath);
  if (!metadataValid(metadata, Date.now())) {
    throw new Error("edge_release_build_metadata_invalid_or_stale");
  }

  const after = gitSnapshot();
  if (
    after.porcelain !== "" ||
    after.commitSha !== before.commitSha ||
    after.treeSha !== before.treeSha ||
    after.repositoryUrl !== before.repositoryUrl ||
    trackedSourceHash() !== sourceSha256 ||
    artifactHash() !== distSha256
  ) {
    throw new Error("edge_release_build_candidate_changed_during_attestation");
  }
} catch (error) {
  if (wroteMetadata) {
    if (previousMetadata) writeFileSync(metadataPath, previousMetadata);
    else rmSync(metadataPath, { force: true });
  }
  throw error;
}

console.log(
  `[edge-release-build-metadata] ${verifyMode ? "verified" : "wrote"} ${metadataRelativePath}`,
);
