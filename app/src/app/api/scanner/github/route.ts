import { NextRequest, NextResponse } from "next/server";
import { fetchGithubSolanaRepo } from "@/lib/scanner/githubFetcher";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  let body: { repoUrl?: string } = {};
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const repoUrl = body.repoUrl?.trim();
  if (!repoUrl) {
    return NextResponse.json(
      { error: "Provide a public GitHub repository URL (e.g. https://github.com/org/repo)." },
      { status: 400 }
    );
  }

  try {
    const result = await fetchGithubSolanaRepo(repoUrl);
    return NextResponse.json(result, { status: 200 });
  } catch (err: any) {
    return NextResponse.json(
      { error: err?.message || "Failed to fetch Rust files from GitHub repository." },
      { status: 400 }
    );
  }
}
