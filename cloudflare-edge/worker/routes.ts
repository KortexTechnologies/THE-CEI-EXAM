/**
 * Edge route registry for THE CEI EXAM (Project A).
 *
 * The Worker sits in front of the existing proxied Lovable origin. It only
 * decides between three outcomes:
 *   1. a 308 edge redirect (canonical host / canonical path),
 *   2. pass-through to the origin with the original Request unchanged,
 *   3. a genuine edge 404 for unknown navigations.
 *
 * Nothing here rewrites content, so removing the Worker Route restores the
 * previous behaviour exactly.
 */

export const CANONICAL_ORIGIN = "https://theceiexam.com";
export const CANONICAL_HOST = "theceiexam.com";
export const WWW_HOST = "www.theceiexam.com";
export const REDIRECT_STATUS = 308;

/** Exact-path redirects. Query strings are always preserved by the handler. */
export const EDGE_REDIRECTS: Readonly<Record<string, string>> = Object.freeze({
  // contracts/routes.yml declared redirects
  "/programme": "/programmes",
  "/pricing": "/programmes",
  "/plans": "/programmes",
  "/passstart": "/programmes/passstart",
  "/programme/passstart": "/programmes/passstart",
  "/pass/start": "/programmes/passstart",
  "/passready": "/programmes/passready",
  "/programme/passready": "/programmes/passready",
  "/pass/ready": "/programmes/passready",
  "/passguard": "/programmes/passguard",
  "/programme/passguard": "/programmes/passguard",
  "/pass/guard": "/programmes/passguard",
  "/mock-exams": "/mock-exam",
  "/mock-test": "/mock-exam",
  "/free-check": "/knowledge-snapshot",
  "/diagnostic": "/knowledge-snapshot",
  "/faq": "/faqs",
  "/access-extension-support": "/access-extension",
  "/termsofuse": "/terms",
  "/privacypolicy": "/privacy",
  "/cookiespolicy": "/cookies",
  "/return-and-refund": "/refunds",
  "/contact": "/contact-us",
  "/checkout/success": "/purchase-status",
  "/practice-pack/success": "/purchase-status",

  // src/App.tsx compatibility redirects promoted to edge behaviour
  "/practice-pack": "/programmes",
  "/practice-pack/checkout": "/programmes",
  "/practicepack": "/programmes",
  "/pass": "/programmes",
  "/pass/passguard/guarantee": "/programmes",
  "/passguarantee": "/programmes",
  "/exam-readiness": "/programmes",
  "/assessment": "/programmes",
  "/features": "/programmes",
  "/course": "/programmes",
  "/pathway": "/programmes",
  "/track": "/programmes",
  "/scope": "/programmes",
  "/digital-access": "/programmes",
  "/the-cost-of-unpreparedness": "/programmes",
  "/tokens": "/programmes",
  "/free-tokens": "/programmes",
  "/credit": "/programmes",
  "/free-credit": "/programmes",
  "/sitemap": "/programmes",
  "/platform": "/programmes",
  "/platform-overview": "/programmes",
  "/platform-overview-about-cei": "/programmes",
  "/platform-overview-who-needs-the-cei": "/programmes",
  "/platform-overview-how-to-prepare": "/programmes",
  "/platform-overview-mock-exams-and-diagnostics": "/programmes",
  "/platform-overview-study-resources": "/programmes",
  "/platform-overview-why-the-cei-exam": "/programmes",
  "/platform-overview-for-candidates": "/programmes",
  "/platform-overview-pricing": "/programmes",
  "/modules": "/knowledge-snapshot",
  "/glossary": "/knowledge-snapshot",
  "/topics": "/knowledge-snapshot",
  "/search": "/knowledge-snapshot",
  "/infographics": "/knowledge-snapshot",
  "/what-is-efma": "/knowledge-snapshot",
  "/common-cei-mistakes": "/knowledge-snapshot",
  "/platform-overview-resources": "/knowledge-snapshot",
  "/platform-overview-insights": "/knowledge-snapshot",
  "/platform-overview-glossary": "/knowledge-snapshot",
  "/kah-eas": "/contact-us",
  "/for-agencies": "/contact-us",
  "/enterprise": "/contact-us",
  "/advisory": "/contact-us",
  "/what-is-kah-cei": "/contact-us",
  "/cei-for-employment-agencies": "/contact-us",
  "/partner-programme": "/contact-us",
  "/feature-with-us": "/contact-us",
  "/platform-overview-advisory": "/contact-us",
  "/platform-overview-for-agencies": "/contact-us",
  "/platform-overview-faq": "/contact-us",
  "/claim": "/my-passes",
  "/purchase": "/my-passes",
  "/purchases": "/my-passes",
  "/hero-preview": "/",
  "/debug": "/",
  "/purcr": "/my-passes",
  "/goodbye-to-ceiro": "/unsubscribe",
});

/** Prefix redirects mirroring React wildcard/pattern redirect routes. */
export const EDGE_PREFIX_REDIRECTS: ReadonlyArray<readonly [string, string]> = Object.freeze([
  ["/purcr/", "/my-passes"],
  ["/purchase/", "/my-passes"],
  ["/assessment/", "/programmes"],
  ["/enterprise/", "/contact-us"],
  ["/advisory/", "/contact-us"],
  ["/features/", "/programmes"],
  ["/plans/", "/programmes"],
  ["/platform-overview/", "/programmes"],
  ["/modules/", "/knowledge-snapshot"],
  ["/topics/", "/knowledge-snapshot"],
  ["/debug/", "/"],
] as const);

/**
 * Every currently registered, non-catchall React application route that must
 * remain reachable through origin pass-through.
 */
export const REACHABLE_ROUTES: ReadonlyArray<string> = Object.freeze([
  "/",
  "/programmes",
  "/mock-exam",
  "/practitioner-review",
  "/access-extension",
  "/insights",
  "/faqs",
  "/knowledge-snapshot",
  "/how-it-works",
  "/free-resources",
  "/how-to-prepare-for-cei",
  "/how-to-register-for-cei-exam",
  "/cei-vs-basic",
  "/contact-us",
  "/contact-us/confirmation",
  "/checkout",
  "/purchase-status",
  "/receipt",
  "/member-add-on",
  "/dashboard",
  "/dashboard/professional",
  "/dashboard/corporate",
  "/my-passes",
  "/signin",
  "/.lovable/oauth/consent",
  "/dev/gcr-preview",
  "/terms",
  "/privacy",
  "/cookies",
  "/cybersecurity",
  "/refunds",
  "/unsubscribe",
]);

/**
 * Paths that must answer with the genuine edge 404 contract rather than proxy
 * the application soft-404 shell.
 */
export const EDGE_NOT_FOUND_PATHS: ReadonlyArray<string> = Object.freeze(["/404"]);

export const isEdgeNotFoundPath = (pathname: string): boolean =>
  EDGE_NOT_FOUND_PATHS.includes(normalisePath(pathname));

/** Dynamic/pattern application routes that must proxy. */
export const REACHABLE_PATTERNS: ReadonlyArray<RegExp> = Object.freeze([
  /^\/programmes\/[^/]+$/,
]);

/**
 * Manual escape hatch for origin-served root files. Intentionally empty: every
 * reachable root file must be a real committed file under `public/`, guarded by
 * src/test/worker-route-registry-drift.test.ts.
 */
export const REACHABLE_ROOT_FILES: ReadonlyArray<string> = Object.freeze([]);

/**
 * Exact real files committed under source `public/`. These are served verbatim by
 * the origin and must always proxy — including HTML verification files, whose
 * content type must not be mistaken for an application-shell soft fallback.
 *
 * Guarded by src/test/worker-route-registry-drift.test.ts, which enumerates
 * public/** recursively so a new file cannot silently fall out of the registry.
 */
export const PUBLIC_FILES: ReadonlyArray<string> = Object.freeze([
  "/3836a2f5d2537b83888a89d3fc9ebf60.txt",
  "/_headers",
  "/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.txt",
  "/apple-touch-icon.png",
  "/brand/focused-preparation-stronger-results.jpg",
  "/ceiro-mascot-banner.jpeg",
  "/downloads/2026_EARF_Navigating_New_Statutory_Landscape.pdf",
  "/downloads/2026_Enterprise_Compliance.pdf",
  "/downloads/2026_Singapore_Employment_Compliance_Landscape.pdf",
  "/downloads/2026_Singapore_Recruiter_Strategy_Guide.pdf",
  "/downloads/7-day-cei-cheat-sheet.pdf",
  "/downloads/TheCEIExam-Capability-Brief.pdf",
  "/downloads/cei-variants-routing-reference.pdf",
  "/downloads/obsidian-mindmap.csv",
  "/favicon.png",
  "/fonts/Inter.woff2",
  "/google-merchant-feed.txt",
  "/googlecdf1242f06042cf8.html",
  "/hero-readiness-mobile.webp",
  "/hero-readiness.png",
  "/hero-readiness.webp",
  "/know-where-you-stand.jpg",
  "/lighthouse-metrics.json",
  "/lighthouse-report.pdf",
  "/llms.txt",
  "/marketing/cei-banner-prepare-smarter.jpeg",
  "/merchant/PassGuard_ProductCard_THECEIEXAM.png",
  "/merchant/PassReady_ProductCard_THECEIEXAM.png",
  "/merchant/PassStart_ProductCard_THECEIEXAM.png",
  "/merchant/PracticePack_ProductCard_THECEIEXAM.png",
  "/meta/interface-contract.json",
  "/meta/product-contract.json",
  "/og-card.png",
  "/og-logo.png",
  "/og/algorithmic-pedagogy-cei-preparation.png",
  "/og/basic-vs-kah.png",
  "/og/cei-exam-study-plan-7-days.png",
  "/og/cei-variants-routing-reference-ea-owners-kahs.png",
  "/og/choose-training-provider.png",
  "/og/knowledge-snapshot.png",
  "/og/mock-exam.png",
  "/og/singapore-foreign-workforce-policies-2026.png",
  "/og/the-cost-of-unpreparedness.png",
  "/placeholder.svg",
  "/robots.txt",
  "/sitemap.xml",
  "/uploads/cei-banner.jpeg",
  "/videos/platform-preview.mp4",
]);

/**
 * Prefixes whose contents are generated or uploaded at runtime, so they cannot
 * be enumerated at build time. A miss under these prefixes must degrade to the
 * edge 404 rather than a soft HTML 200.
 */
export const DYNAMIC_ASSET_PREFIXES: ReadonlyArray<string> = Object.freeze([
  "/assets/",
  "/lovable-uploads/",
  "/.well-known/",
]);

export const normalisePath = (pathname: string): string => {
  if (pathname.length > 1 && pathname.endsWith("/")) return pathname.replace(/\/+$/, "") || "/";
  return pathname;
};

export const lookupRedirect = (pathname: string): string | null => {
  const path = normalisePath(pathname);
  const exact = EDGE_REDIRECTS[path];
  if (exact) return exact;
  for (const [prefix, target] of EDGE_PREFIX_REDIRECTS) {
    if (path.startsWith(prefix)) return target;
  }
  return null;
};

/** True when the path is an exact, known real file under source `public/`. */
export const isPublicFile = (pathname: string): boolean => PUBLIC_FILES.includes(normalisePath(pathname));

/** True when the path sits under a runtime-generated static prefix. */
export const isDynamicAssetPath = (pathname: string): boolean =>
  DYNAMIC_ASSET_PREFIXES.some((prefix) => normalisePath(pathname).startsWith(prefix));

export const isReachable = (pathname: string): boolean => {
  const path = normalisePath(pathname);
  if (REACHABLE_ROUTES.includes(path)) return true;
  if (isPublicFile(path)) return true;
  if (REACHABLE_ROOT_FILES.includes(path)) return true;
  if (REACHABLE_PATTERNS.some((pattern) => pattern.test(path))) return true;
  return isDynamicAssetPath(path);
};

/**
 * Requests that look like a file and are not a known real public file, so an
 * HTML response from the origin can only be a soft application-shell fallback.
 */
export const isAssetLike = (pathname: string): boolean => {
  const path = normalisePath(pathname);
  if (isPublicFile(path)) return false;
  return isDynamicAssetPath(path) || /\.[a-z0-9]{2,5}$/i.test(path);
};

