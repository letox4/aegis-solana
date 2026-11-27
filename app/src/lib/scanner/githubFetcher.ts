import {
  MAX_SCAN_CODE_BYTES,
  MULTI_FILE_MARKER_PREFIX,
  MULTI_FILE_MARKER_SUFFIX,
} from "./solanaRules";

export interface FetchedGithubRepo {
  owner: string;
  repo: string;
  branch: string;
  repoUrl: string;
  detectedProgramId: string | null;
  files: Array<{ path: string; bytes: number; lines: number }>;
  combinedCode: string;
  totalBytes: number;
  truncatedFileCount: number;
}

const GITHUB_URL_REGEX =
  /^https?:\/\/(?:www\.)?github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?(?:\/(?:tree|blob)\/([A-Za-z0-9_./-]+))?\/?$/;

const SAFE_GITHUB_SLUG_REGEX = /^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?$/;
const SAFE_GITHUB_REF_REGEX = /^[A-Za-z0-9_./-]+$/;

const MAX_FILES_TO_FETCH = 8;
const MAX_COMBINED_BYTES = MAX_SCAN_CODE_BYTES - 4_000;

function hasTraversalSegment(pathOrRef: string): boolean {
  if (!pathOrRef || pathOrRef.includes("..") || pathOrRef.includes("\\")) return true;
  if (pathOrRef.startsWith("/")) return true;
  return pathOrRef.split("/").some((seg) => seg === "" || seg === "." || seg === "..");
}

function assertSafeGithubSlug(value: string, label: string) {
  if (
    !value ||
    value === "." ||
    value === ".." ||
    value.includes("..") ||
    !SAFE_GITHUB_SLUG_REGEX.test(value)
  ) {
    throw new Error(`Invalid GitHub ${label}: path traversal or disallowed characters detected.`);
  }
}

function githubHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "AEGIS-Solana-Security-Scanner/2.5",
  };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  return headers;
}

async function fetchDefaultBranch(
  owner: string,
  repo: string,
  signal: AbortSignal
): Promise<string> {
  const metaRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
    headers: githubHeaders(),
    signal,
    cache: "no-store",
  });
  if (!metaRes.ok) {
    const msg =
      metaRes.status === 404
        ? `Repository ${owner}/${repo} not found or is private.`
        : metaRes.status === 403
        ? "GitHub API rate limit reached. Try again shortly or paste Rust code directly."
        : `GitHub API returned HTTP ${metaRes.status}.`;
    throw new Error(msg);
  }
  const metaJson = await metaRes.json();
  return String(metaJson.default_branch || "main");
}

async function fetchGitTree(
  owner: string,
  repo: string,
  ref: string,
  signal: AbortSignal
): Promise<Response> {
  return fetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(ref)}?recursive=1`,
    {
      headers: githubHeaders(),
      signal,
      cache: "no-store",
    }
  );
}

function scoreRustFilePriority(path: string, subpathHint?: string): number {
  const p = path.toLowerCase();
  let score = 0;
  if (subpathHint && (path === subpathHint || path.startsWith(`${subpathHint}/`))) {
    score += 200;
  }
  if (p.includes("programs/") || p.includes("program/")) score += 50;
  if (p.endsWith("/lib.rs")) score += 40;
  if (p.includes("instructions/") || p.includes("processor")) score += 30;
  if (p.includes("state")) score += 20;
  if (p.includes("src/")) score += 10;
  if (p.includes("test") || p.includes("bench") || p.includes("example") || p.includes("mock")) {
    score -= 100;
  }
  return score;
}

/**
 * SSRF-safe GitHub repository Rust program fetcher.
 * Strictly validates `github.com/{owner}/{repo}` URLs and pulls `.rs` files
 * under Solana/Anchor program trees for multi-file x402 security auditing.
 */
export async function fetchGithubSolanaRepo(rawUrl: string): Promise<FetchedGithubRepo> {
  const trimmed = rawUrl.trim();
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(trimmed);
  } catch {
    throw new Error(
      "Invalid GitHub URL. Use format: https://github.com/<owner>/<repo> (optional /tree/<branch>)."
    );
  }

  if (
    (parsedUrl.protocol !== "https:" && parsedUrl.protocol !== "http:") ||
    (parsedUrl.hostname !== "github.com" && parsedUrl.hostname !== "www.github.com") ||
    parsedUrl.username ||
    parsedUrl.password ||
    parsedUrl.port
  ) {
    throw new Error("Only public https://github.com/<owner>/<repo> URLs are permitted.");
  }

  const match = trimmed.match(GITHUB_URL_REGEX);
  if (!match) {
    throw new Error(
      "Invalid GitHub URL. Use format: https://github.com/<owner>/<repo> (optional /tree/<branch>)."
    );
  }

  const owner = match[1];
  const repo = match[2];
  assertSafeGithubSlug(owner, "owner");
  assertSafeGithubSlug(repo, "repository");

  const capturedRef = (match[3] || "").replace(/\/+$/, "");
  if (capturedRef) {
    if (!SAFE_GITHUB_REF_REGEX.test(capturedRef) || hasTraversalSegment(capturedRef)) {
      throw new Error("Invalid GitHub branch or subpath reference.");
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12_000);

  try {
    let branch = capturedRef;
    let subpathHint: string | undefined;
    let treeRes: Response;

    if (capturedRef) {
      treeRes = await fetchGitTree(owner, repo, capturedRef, controller.signal);
      if (treeRes.status === 404) {
        // Handle `/tree/<default_branch>/<subpath>` or invalid ref by falling back to default_branch
        branch = await fetchDefaultBranch(owner, repo, controller.signal);
        if (capturedRef.startsWith(`${branch}/`)) {
          subpathHint = capturedRef.slice(branch.length + 1);
        }
        treeRes = await fetchGitTree(owner, repo, branch, controller.signal);
      }
    } else {
      branch = await fetchDefaultBranch(owner, repo, controller.signal);
      treeRes = await fetchGitTree(owner, repo, branch, controller.signal);
    }

    if (!treeRes.ok) {
      const msg =
        treeRes.status === 403
          ? "GitHub API rate limit reached. Try again shortly or paste Rust code directly."
          : `Failed to list repository tree on branch '${branch}' (HTTP ${treeRes.status}).`;
      throw new Error(msg);
    }
    const treeJson = await treeRes.json();
    const allNodes: Array<{ path: string; type: string; size?: number }> = Array.isArray(
      treeJson?.tree
    )
      ? treeJson.tree
      : [];

    const rustCandidates = allNodes
      .filter(
        (n) =>
          n.type === "blob" &&
          typeof n.path === "string" &&
          !hasTraversalSegment(n.path) &&
          n.path.endsWith(".rs") &&
          !n.path.includes("target/") &&
          !n.path.includes("tests/") &&
          !n.path.includes("/test_") &&
          !n.path.endsWith("_test.rs") &&
          (n.size ?? 0) > 40 &&
          (n.size ?? 0) <= 60_000
      )
      .sort(
        (a, b) =>
          scoreRustFilePriority(b.path, subpathHint) - scoreRustFilePriority(a.path, subpathHint)
      );

    if (rustCandidates.length === 0) {
      throw new Error(
        `No Solana/Rust (.rs) source files found in ${owner}/${repo} (branch: ${branch}).`
      );
    }

    const selected = rustCandidates.slice(0, MAX_FILES_TO_FETCH);
    const encodedBranchPath = branch.split("/").map(encodeURIComponent).join("/");
    const fetched = await Promise.all(
      selected.map(async (node) => {
        const rawEndpoint = `https://raw.githubusercontent.com/${owner}/${repo}/${encodedBranchPath}/${node.path
          .split("/")
          .map(encodeURIComponent)
          .join("/")}`;
        const r = await fetch(rawEndpoint, {
          headers: { "User-Agent": "AEGIS-Solana-Security-Scanner/2.5" },
          signal: controller.signal,
          cache: "no-store",
        });
        if (!r.ok) return null;
        const content = await r.text();
        return { path: node.path, content };
      })
    );

    const filesMeta: Array<{ path: string; bytes: number; lines: number }> = [];
    const chunks: string[] = [];
    let totalBytes = 0;
    let detectedProgramId: string | null = null;

    for (const item of fetched) {
      if (!item) continue;
      const header = `${MULTI_FILE_MARKER_PREFIX}${item.path}${MULTI_FILE_MARKER_SUFFIX}\n`;
      const block = `${header}${item.content.trimEnd()}\n`;
      const blockBytes = Buffer.byteLength(block, "utf-8");
      if (totalBytes + blockBytes > MAX_COMBINED_BYTES) continue;

      if (!detectedProgramId) {
        const idMatch = item.content.match(/declare_id!\s*\(\s*"([1-9A-HJ-NP-Za-km-z]{32,44})"\s*\)/);
        if (idMatch) detectedProgramId = idMatch[1];
      }

      chunks.push(block);
      totalBytes += blockBytes;
      filesMeta.push({
        path: item.path,
        bytes: Buffer.byteLength(item.content, "utf-8"),
        lines: item.content.split(/\r?\n/).length,
      });
    }

    if (filesMeta.length === 0) {
      throw new Error("Could not download any Rust files within the 100KB x402 audit payload cap.");
    }

    return {
      owner,
      repo,
      branch,
      repoUrl: `https://github.com/${owner}/${repo}`,
      detectedProgramId,
      files: filesMeta,
      combinedCode: chunks.join("\n"),
      totalBytes,
      truncatedFileCount: Math.max(0, rustCandidates.length - filesMeta.length),
    };
  } finally {
    clearTimeout(timer);
  }
}
