import * as dotenv from "dotenv";

dotenv.config();

// sbom-scan.mjs
// Scans an org's repositories via GitHub's SBOM API (Dependency Graph)
// and reports which repos contain any package@version listed in an input file.
//
// Input file format: one npm package per line: `name@version`
//   - supports scoped names, e.g. `@scope/name@1.2.3`
//
// Output JSON (only matches):
// {
//   org: "...",
//   generated_at: "...",
//   input_entries: 526,
//   repos_scanned: 123,
//   matches: [
//     { package: "@scope/name", version: "1.2.3", repositories: ["org/repoA","org/repoB"] },
//     ...
//   ]
// }
//
// Requirements:
//   npm i octokit
// Auth:
//   - Fine-grained PAT: repository "Contents: Read" permission (private repos)
//   - Classic PAT: `repo` scope for private repos
//
// Notes:
//   - SBOM endpoint returns SPDX JSON for the HEAD of the default branch.
//   - We match primarily by purl `pkg:npm/...@version` and fall back to name+version.
//   - Forks/archived repos are skipped by default (flags available).
//
// CLI:
//   node sbom-scan.mjs --org=<org> [--in=affected.txt] [--out=matches.json]
//                       [--include-forks] [--include-archived] [--concurrency=6]

import { Octokit } from "octokit";
import { readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import semver from "semver";

// -------------------- CLI args --------------------
const args = Object.fromEntries(
  process.argv.slice(2).map((a) => {
    const m = a.match(/^--([^=]+)=(.*)$/);
    return m ? [m[1], m[2]] : [a.replace(/^--/, ""), true];
  }),
);
const ORG = args.org || process.env.ORG;
const IN = args.in || "affected.txt";
const OUT = args.out || "matches.json";
const INCLUDE_FORKS = Boolean(args["include-forks"]);
const INCLUDE_ARCHIVED = Boolean(args["include-archived"]);
const CONCURRENCY = Number(args.concurrency ?? 6);

if (!ORG) {
  console.error("Missing --org or environment ORG");
  process.exit(1);
}
if (!process.env.GITHUB_TOKEN) {
  console.error("Missing GITHUB_TOKEN env");
  process.exit(1);
}

// -------------------- Helpers --------------------
function parsePkgNameVersionFromSpdx(p) {
  const n = (p.name || "").toString();
  const v = (p.versionInfo || "").toString();
  if (n && semver.valid(v)) return { name: n, version: v };

  // fallback: try purl
  const ext = Array.isArray(p.externalRefs) ? p.externalRefs : [];
  const purl = ext.find((e) => e?.referenceType === "purl")?.referenceLocator;
  if (typeof purl === "string" && purl.startsWith("pkg:npm/")) {
    const m = purl.match(/^pkg:npm\/(.+)@(.+)$/);
    if (m) {
      const pathPart = decodeURIComponent(m[1]); // may include @scope/name
      const version = m[2];
      if (semver.valid(version)) return { name: pathPart, version };
    }
  }
  return null;
}
function parseLine(line) {
  const s = line.trim();
  if (!s || s.startsWith("#")) return null;
  // Expect `name@version` (scoped or unscoped)
  const at = s.lastIndexOf("@");
  if (at <= 0) return null;
  const name = s.slice(0, at).trim();
  const version = s.slice(at + 1).trim();
  if (!name || !version) return null;
  return { name, version };
}

// purl for npm requires encoding the '@' of the scope to %40, but keeps '/':
//   @scope/name@1.2.3 -> pkg:npm/%40scope/name@1.2.3
function npmPurl(name, version) {
  if (name.startsWith("@")) {
    const [scope, pkg] = name.slice(1).split("/");
    if (!scope || !pkg) return null;
    return `pkg:npm/%40${scope}/${pkg}@${version}`;
  }
  return `pkg:npm/${name}@${version}`;
}

function keyNameVersion(name, version) {
  return `${name.toLowerCase()}@${version}`;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// Simple promise pool
async function pool(items, limit, worker) {
  const results = [];
  let i = 0;
  const active = new Set();
  async function runOne(idx) {
    const p = (async () => worker(items[idx], idx))();
    active.add(p);
    try {
      const r = await p;
      results[idx] = r;
    } finally {
      active.delete(p);
    }
  }
  while (i < items.length) {
    while (active.size < limit && i < items.length) {
      void runOne(i++);
    }
    if (active.size) {
      await Promise.race(active);
    }
  }
  // drain
  while (active.size) await Promise.race(active);
  return results;
}

// -------------------- Input & lookups --------------------
const lines = readFileSync(IN, "utf8").split(/\r?\n/);
const entries = lines.map(parseLine).filter(Boolean);

// Build lookup: package-name (lowercased) -> maximum allowed version
// If the input lists the same package multiple times, we keep the highest version
// so that "repoVersion <= maxInputVersionForThatPackage" will match.
const wantedMaxVersion = new Map(); // nameLower -> version
for (const { name, version } of entries) {
  if (!semver.valid(version)) continue; // skip non-semver inputs
  const key = name.toLowerCase();
  const prev = wantedMaxVersion.get(key);
  if (!prev || semver.gt(version, prev)) {
    wantedMaxVersion.set(key, version);
  }
}

// -------------------- Octokit --------------------
const octokit = new Octokit({
  auth: process.env.GITHUB_TOKEN,
  // Explicit API version header recommended by docs
  defaults: {
    headers: { "X-GitHub-Api-Version": "2022-11-28" },
  },
});

// -------------------- Repo list --------------------
const repos = await octokit.paginate("GET /orgs/{org}/repos", {
  org: ORG,
  per_page: 100,
  type: "all",
});

const reposToScan = repos.filter((r) => {
  if (!INCLUDE_FORKS && r.fork) return false;
  if (!INCLUDE_ARCHIVED && r.archived) return false;
  return true;
});

// -------------------- Scan SBOMs --------------------
const affectedMap = new Map(); // key = "name@version" => Set of "org/repo"

await pool(reposToScan, CONCURRENCY, async (repo) => {
  const full = repo.full_name || `${ORG}/${repo.name}`;
  try {
    // SBOM for default branch head (SPDX JSON)
    const res = await octokit.request(
      "GET /repos/{owner}/{repo}/dependency-graph/sbom",
      { owner: ORG, repo: repo.name },
    );
    const sbom = res.data?.sbom;
    const pkgs = Array.isArray(sbom?.packages) ? sbom.packages : [];

    // Build set of matches in this repo to avoid dupes
    const foundPairs = new Set();

    for (const p of pkgs) {
      const nv = parsePkgNameVersionFromSpdx(p);
      if (!nv) continue;
      const nameLower = nv.name.toLowerCase();
      const maxAllowed = wantedMaxVersion.get(nameLower);
      if (!maxAllowed) continue; // not a package we care about
      // Match if repo's version <= input version
      if (semver.lte(nv.version, maxAllowed)) {
        foundPairs.add(keyNameVersion(nv.name, nv.version));
      }
    }

    for (const pair of foundPairs) {
      if (!affectedMap.has(pair)) affectedMap.set(pair, new Set());
      affectedMap.get(pair).add(full);
    }
  } catch (e) {
    // Common: 403 if dependency graph unavailable, or 404 if repo disabled/empty
    const msg = e?.status ? `${e.status}` : e?.message || "error";
    console.error(`SBOM fetch failed for ${full}: ${msg}`);
    // brief backoff on abuse/rate limit
    if (
      e?.status === 429 ||
      (e?.response && e.response.headers?.["retry-after"])
    ) {
      await sleep(1000);
    }
  }
});

// -------------------- Build output --------------------
const matches = [];
for (const [pair, setRepos] of affectedMap.entries()) {
  // recover package + version from key
  const at = pair.lastIndexOf("@");
  const pkg = pair.slice(0, at);
  const ver = pair.slice(at + 1);
  matches.push({
    package: pkg,
    version: ver,
    repositories: Array.from(setRepos).sort(),
  });
}
matches.sort((a, b) =>
  a.package === b.package
    ? a.version.localeCompare(b.version)
    : a.package.localeCompare(b.package),
);

const out = {
  org: ORG,
  generated_at: new Date().toISOString(),
  input_entries: entries.length,
  repos_scanned: reposToScan.length,
  matches, // only entries with hits
  host: os.hostname(),
};

writeFileSync(OUT, JSON.stringify(out, null, 2), "utf8");
console.log(
  `Wrote ${OUT} with ${matches.length} distinct package@version matches across ${reposToScan.length} repos.`,
);
