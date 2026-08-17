/**
 * THE CEI EXAM — Cloudflare edge Worker (Project A).
 *
 * Deployed as a Worker Route in front of the existing proxied Lovable origin.
 * It never builds or serves application content: recognised routes and assets
 * are passed through with `fetch(request)` untouched. Removing the Worker Route
 * fully reverts the release.
 *
 * Privacy: no request URL, query string, header or personal data is logged.
 */

import {
  CANONICAL_ORIGIN,
  WWW_HOST,
  REDIRECT_STATUS,
  isAssetLike,
  isEdgeNotFoundPath,
  isReachable,
  lookupRedirect,
  normalisePath,
} from "./routes";

const NOT_FOUND_HTML = `<!doctype html>
<html lang="en-SG">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Page not found | THE CEI EXAM</title>
    <meta name="robots" content="noindex,nofollow" />
    <style>
      body { margin: 0; background: #ffffff; color: #23406e; font-family: Inter, system-ui, sans-serif; }
      main { max-width: 34rem; margin: 0 auto; padding: 6rem 1.5rem; }
      h1 { font-size: 1.75rem; line-height: 1.25; margin: 0 0 0.75rem; }
      p { font-size: 1rem; line-height: 1.6; margin: 0 0 1.5rem; color: #3f4c63; }
      a { display: inline-block; min-height: 48px; padding: 0.85rem 1.25rem; border-radius: 0.5rem;
          background: #fc6633; color: #ffffff; font-weight: 600; text-decoration: none; }
      a:focus-visible { outline: 3px solid #23406e; outline-offset: 2px; }
    </style>
  </head>
  <body>
    <main>
      <h1>Page not found</h1>
      <p>This address is not available on THE CEI EXAM.</p>
      <a href="${CANONICAL_ORIGIN}/">Return to THE CEI EXAM</a>
    </main>
  </body>
</html>
`;

const notFound = (method: string): Response => {
  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    "x-robots-tag": "noindex,nofollow",
    "cache-control": "no-store",
  });
  const body = method === "HEAD" ? null : NOT_FOUND_HTML;
  return new Response(body, { status: 404, headers });
};

const redirect = (location: string): Response =>
  new Response(null, {
    status: REDIRECT_STATUS,
    headers: { location, "cache-control": "no-store" },
  });

/**
 * Historical provider return URLs carry `key=<reference>`; the canonical
 * purchase-status route reads `ref`, so translate at the edge. Every unrelated
 * parameter is preserved, an existing `ref` stays authoritative, and the legacy
 * `key` is removed only once it has been translated.
 */
const redirectSearch = (target: string, search: string): string => {
  if (target !== "/purchase-status" || !search) return search;

  const params = new URLSearchParams(search);
  if (!params.has("key")) return search;

  const legacy = params.get("key") ?? "";
  if (!params.get("ref") && legacy) params.set("ref", legacy);
  params.delete("key");

  const query = params.toString();
  return query ? `?${query}` : "";
};

/**
 * Optional, non-secret preview configuration. Declared locally so the committed
 * Worker types never need to capture local environment variable names.
 */
export interface EdgeEnv {
  /** Upstream origin for the workers.dev preview only; unset in production. */
  ORIGIN_BASE_URL?: string;
}

/**
 * Preview-only upstream rewrite: path, query, method, headers and body are
 * preserved. In production `ORIGIN_BASE_URL` is unset, so the original Request
 * is proxied unchanged against the configured Worker Route origin.
 */
const upstreamRequest = (request: Request, env: EdgeEnv | undefined): Request => {
  const base = env?.ORIGIN_BASE_URL;
  if (!base) return request;

  const url = new URL(request.url);
  const upstream = new URL(base);
  upstream.pathname = url.pathname;
  upstream.search = url.search;
  return new Request(upstream.toString(), request);
};

const isNavigation = (method: string): boolean => method === "GET" || method === "HEAD";

export default {
  async fetch(request: Request, env?: EdgeEnv): Promise<Response> {
    const url = new URL(request.url);

    // Canonical host: www -> apex only, preserving method, path and query. Any
    // other hostname (workers.dev preview) is exercised, never redirected.
    if (url.hostname === WWW_HOST) {
      return redirect(`${CANONICAL_ORIGIN}${url.pathname}${url.search}`);
    }

    const path = normalisePath(url.pathname);

    if (isEdgeNotFoundPath(path)) return notFound(request.method);

    const target = lookupRedirect(path);
    if (target) {
      return redirect(`${CANONICAL_ORIGIN}${target}${redirectSearch(target, url.search)}`);
    }

    if (isReachable(path)) {
      const response = await fetch(upstreamRequest(request, env));

      // A missing asset must never soft-succeed as the application shell.
      if (isAssetLike(path) && (response.headers.get("content-type") ?? "").includes("text/html")) {
        return notFound(request.method);
      }

      return response;
    }

    if (isNavigation(request.method)) return notFound(request.method);

    return fetch(upstreamRequest(request, env));
  },
} satisfies { fetch: (request: Request, env?: EdgeEnv) => Promise<Response> };

