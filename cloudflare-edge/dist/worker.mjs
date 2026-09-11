// worker/routes.ts
var CANONICAL_ORIGIN = "https://theceiexam.com";
var WWW_HOST = "www.theceiexam.com";
var REDIRECT_STATUS = 301;
var EDGE_REDIRECTS = Object.freeze({
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
  "/goodbye-to-ceiro": "/unsubscribe"
});
var EDGE_PREFIX_REDIRECTS = Object.freeze([
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
  ["/debug/", "/"]
]);
var REACHABLE_ROUTES = Object.freeze([
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
  "/unsubscribe"
]);
var EDGE_NOT_FOUND_PATHS = Object.freeze(["/404"]);
var isEdgeNotFoundPath = (pathname) => EDGE_NOT_FOUND_PATHS.includes(normalisePath(pathname));
var REACHABLE_PATTERNS = Object.freeze([
  /^\/programmes\/[^/]+$/
]);
var REACHABLE_ROOT_FILES = Object.freeze([]);
var PUBLIC_FILES = Object.freeze([
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
  "/videos/platform-preview.mp4"
]);
var DYNAMIC_ASSET_PREFIXES = Object.freeze([
  "/assets/",
  "/lovable-uploads/",
  "/.well-known/"
]);
var normalisePath = (pathname) => {
  if (pathname.length > 1 && pathname.endsWith("/")) return pathname.replace(/\/+$/, "") || "/";
  return pathname;
};
var lookupRedirect = (pathname) => {
  const path = normalisePath(pathname);
  const exact = EDGE_REDIRECTS[path];
  if (exact) return exact;
  for (const [prefix, target] of EDGE_PREFIX_REDIRECTS) {
    if (path.startsWith(prefix)) return target;
  }
  return null;
};
var isPublicFile = (pathname) => PUBLIC_FILES.includes(normalisePath(pathname));
var isDynamicAssetPath = (pathname) => DYNAMIC_ASSET_PREFIXES.some((prefix) => normalisePath(pathname).startsWith(prefix));
var isReachable = (pathname) => {
  const path = normalisePath(pathname);
  if (REACHABLE_ROUTES.includes(path)) return true;
  if (isPublicFile(path)) return true;
  if (REACHABLE_ROOT_FILES.includes(path)) return true;
  if (REACHABLE_PATTERNS.some((pattern) => pattern.test(path))) return true;
  return isDynamicAssetPath(path);
};
var isAssetLike = (pathname) => {
  const path = normalisePath(pathname);
  if (isPublicFile(path)) return false;
  return isDynamicAssetPath(path) || /\.[a-z0-9]{2,5}$/i.test(path);
};
var DASHBOARD_CANONICAL_ORIGIN = "https://dashboard.theceiexam.com";
var DASHBOARD_CANONICAL_HOST = "dashboard.theceiexam.com";
var DASHBOARD_WWW_HOST = "www.dashboard.theceiexam.com";
var DASHBOARD_REDIRECT_STATUS = 301;
var DASHBOARD_REACHABLE_ROUTES = Object.freeze([
  "/",
  "/signin",
  "/login",
  "/signin-password",
  "/access-status",
  "/sso",
  "/.lovable/oauth/consent",
  "/sso-callback",
  "/sso-status",
  "/unsubscribe",
  "/auth",
  "/auth-sign-in",
  "/signup",
  "/auth-sign-up",
  "/claim",
  "/dashboard",
  "/practice",
  "/section-practice",
  "/module-practice",
  "/practise",
  "/section-practise",
  "/module-practise",
  "/practice-set",
  "/practice/pack",
  "/practice-pack",
  "/mock-exams",
  "/mock-exam",
  "/review",
  "/review-requests",
  "/progress",
  "/performance",
  "/activity",
  "/programme",
  "/material",
  "/notes",
  "/study-materials",
  "/flashcards",
  "/flashcard",
  "/support",
  "/contact-support",
  "/account",
  "/profile",
  "/pass",
  "/learning-wallet",
  "/purchase-success",
  "/purchase-status",
  "/reviewer",
  "/admin/sign-in",
  "/admin",
  "/admin/candidates",
  "/admin/access-sync",
  "/admin/content-review",
  "/admin/support",
  "/admin/review-requests",
  "/admin/practitioner-review",
  "/admin/material-access",
  "/admin/practice-pack",
  "/practice-pack/admin",
  "/onboarding",
  "/change-password",
  "/reset-password",
  "/code-of-conduct",
  "/feedback",
  "/terms-of-service",
  "/terms",
  "/privacy-policy",
  "/privacy",
  "/cookies",
  "/cookie-policy",
  "/refunds",
  "/refund-policy",
  "/Terms-of-Service",
  "/Privacy-Policy",
  "/variant-b",
  "/platform-overview",
  "/regulatory-frameworks",
  "/scenario-simulation",
  "/readiness-diagnostics",
  "/error-analysis",
  "/question-bank",
  "/learning-analytics",
  "/technology-architecture",
  "/use-cases",
  "/platform-metrics",
  "/approach",
  "/demo",
  "/video",
  "/Knowledge-diagnostic",
  "/cei-diagnostic",
  "/marketing-embed",
  "/case-scenario",
  "/module-focus",
  "/practice/module-focus"
]);
var DASHBOARD_REACHABLE_PATTERNS = Object.freeze([
  /^\/mock-exams\/[^/]+$/,
  /^\/mock-exam\/[^/]+$/,
  /^\/admin\/candidates\/[^/]+$/,
  /^\/Knowledge-diagnostic\/.*$/,
  /^\/cei-diagnostic\/.*$/
]);
var isDashboardReachable = (pathname) => {
  const path = normalisePath(pathname);
  return DASHBOARD_REACHABLE_ROUTES.includes(path) || DASHBOARD_REACHABLE_PATTERNS.some((pattern) => pattern.test(path)) || isAssetLike(path);
};

// worker/index.ts
var NOT_FOUND_HTML = `<!doctype html>
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
var notFound = (method, returnOrigin = CANONICAL_ORIGIN) => {
  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    "x-robots-tag": "noindex,nofollow",
    "cache-control": "no-store"
  });
  const html = NOT_FOUND_HTML.replace(`${CANONICAL_ORIGIN}/`, `${returnOrigin}/`);
  const body = method === "HEAD" ? null : html;
  return new Response(body, { status: 404, headers });
};
var redirect = (location, status = REDIRECT_STATUS) => new Response(null, {
  status,
  headers: { location, "cache-control": "no-store" }
});
var redirectSearch = (target, search) => {
  if (target !== "/purchase-status" || !search) return search;
  const params = new URLSearchParams(search);
  if (!params.has("key")) return search;
  const legacy = params.get("key") ?? "";
  if (!params.get("ref") && legacy) params.set("ref", legacy);
  params.delete("key");
  const query = params.toString();
  return query ? `?${query}` : "";
};
var upstreamRequest = (request, env) => {
  const base = env?.ORIGIN_BASE_URL;
  if (!base) return request;
  const url = new URL(request.url);
  const upstream = new URL(base);
  upstream.pathname = url.pathname;
  upstream.search = url.search;
  return new Request(upstream.toString(), request);
};
var isNavigation = (method) => method === "GET" || method === "HEAD";
var index_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.hostname === DASHBOARD_WWW_HOST) {
      return redirect(
        `${DASHBOARD_CANONICAL_ORIGIN}${url.pathname}${url.search}`,
        DASHBOARD_REDIRECT_STATUS
      );
    }
    if (url.hostname === DASHBOARD_CANONICAL_HOST) {
      const dashboardPath = normalisePath(url.pathname);
      if (isDashboardReachable(dashboardPath)) {
        const response = await fetch(upstreamRequest(request, env));
        if (isAssetLike(dashboardPath) && (response.headers.get("content-type") ?? "").includes("text/html")) {
          return notFound(request.method, DASHBOARD_CANONICAL_ORIGIN);
        }
        return response;
      }
      if (isNavigation(request.method)) {
        return notFound(request.method, DASHBOARD_CANONICAL_ORIGIN);
      }
      return fetch(upstreamRequest(request, env));
    }
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
      if (isAssetLike(path) && (response.headers.get("content-type") ?? "").includes("text/html")) {
        return notFound(request.method);
      }
      return response;
    }
    if (isNavigation(request.method)) return notFound(request.method);
    return fetch(upstreamRequest(request, env));
  }
};
export {
  index_default as default
};
