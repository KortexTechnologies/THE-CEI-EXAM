import assert from "node:assert/strict";

const { default: worker } = await import("./dist/worker.mjs");

const originFetch = globalThis.fetch;
const seen = [];
globalThis.fetch = async (request) => {
  seen.push(request);
  const url = new URL(request.url);
  if (url.pathname === "/assets/missing") {
    return new Response("<!doctype html><title>app shell</title>", {
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }
  return new Response("origin", {
    status: 200,
    headers: { "content-type": url.pathname.endsWith(".html") ? "text/html" : "text/plain" },
  });
};

try {
  const unknown = await worker.fetch(new Request("https://theceiexam.com/unknown-path"));
  assert.equal(unknown.status, 404);
  assert.equal(unknown.headers.get("x-robots-tag"), "noindex,nofollow");
  assert.equal(unknown.headers.get("cache-control"), "no-store");
  assert.match(await unknown.text(), /Page not found/);

  const unknownHead = await worker.fetch(new Request("https://theceiexam.com/unknown-path", { method: "HEAD" }));
  assert.equal(unknownHead.status, 404);
  assert.equal(await unknownHead.text(), "");

  const programme = await worker.fetch(new Request("https://theceiexam.com/programme?utm_source=test"));
  assert.equal(programme.status, 308);
  assert.equal(programme.headers.get("location"), "https://theceiexam.com/programmes?utm_source=test");

  const www = await worker.fetch(new Request("https://www.theceiexam.com/?utm_source=test"));
  assert.equal(www.status, 308);
  assert.equal(www.headers.get("location"), "https://theceiexam.com/?utm_source=test");

  const legacyReturn = await worker.fetch(
    new Request("https://theceiexam.com/checkout/success?key=legacy&campaign=keep"),
  );
  assert.equal(legacyReturn.status, 308);
  const legacyLocation = new URL(legacyReturn.headers.get("location"));
  assert.equal(legacyLocation.pathname, "/purchase-status");
  assert.equal(legacyLocation.searchParams.get("ref"), "legacy");
  assert.equal(legacyLocation.searchParams.get("campaign"), "keep");
  assert.equal(legacyLocation.searchParams.has("key"), false);

  const known = await worker.fetch(new Request("https://theceiexam.com/programmes"));
  assert.equal(known.status, 200);
  assert.equal(await known.text(), "origin");
  assert.equal(new URL(seen.at(-1).url).pathname, "/programmes");

  const missingAsset = await worker.fetch(new Request("https://theceiexam.com/assets/missing"));
  assert.equal(missingAsset.status, 404);

  const publicHtml = await worker.fetch(
    new Request("https://theceiexam.com/googlecdf1242f06042cf8.html"),
  );
  assert.equal(publicHtml.status, 200);

  const unknownPost = await worker.fetch(
    new Request("https://theceiexam.com/unknown-api", { method: "POST", body: "x" }),
  );
  assert.equal(unknownPost.status, 200);

  const preview = await worker.fetch(
    new Request("https://theceiexam-edge.workers.dev/programmes?preview=1"),
    { ORIGIN_BASE_URL: "https://theceiexam.lovable.app" },
  );
  assert.equal(preview.status, 200);
  assert.equal(seen.at(-1).url, "https://theceiexam.lovable.app/programmes?preview=1");

  console.log("edge verification: 9 scenarios passed");
} finally {
  globalThis.fetch = originFetch;
}
