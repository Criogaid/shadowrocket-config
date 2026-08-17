import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const source = readFileSync(new URL("../vendor/scripts/bilibili-ads.js", import.meta.url), "utf8");

function transform(url, body) {
  const calls = [];
  vm.runInNewContext(source, {
    $request: { url },
    $response: { body },
    $done: (value) => calls.push(value),
    console: { log() {} },
  });
  assert.equal(calls.length, 1, "transformer must finish exactly once");
  return calls[0].body;
}

for (const endpoint of ["list", "show"]) {
  const splash = JSON.stringify({ data: { show: { id: 1 }, keep: true } });
  assert.deepEqual(
    JSON.parse(transform(`https://app.bilibili.com/x/v2/splash/${endpoint}?version=1`, splash)),
    { data: { keep: true } },
  );
}

const adDestinations = ["ad_web_s", "ad_av", "ad_web_gif", "ad_player", "ad_inline_3d", "ad_inline_eggs"];
const feed = {
  data: {
    items: [
      { id: "normal", card_type: "small_cover_v2", card_goto: "av" },
      ...adDestinations.map((card_goto) => ({ id: card_goto, card_type: "cm_v2", card_goto })),
      { id: "double", card_type: "cm_double_v9", card_goto: "ad_inline_av" },
      { id: "banner", card_type: "banner_v8", card_goto: "banner", banner_item: [{ type: "ad" }] },
      { id: "editorial-banner", card_type: "banner_v8", card_goto: "banner", banner_item: [{ type: "topic" }] },
      { id: "non-ad-commercial", card_type: "cm_v2", card_goto: "av" },
    ],
  },
};
const feedBody = JSON.stringify(feed);
const transformedFeed = JSON.parse(transform("https://app.bilibili.com/x/v2/feed/index?idx=1", feedBody));
assert.deepEqual(transformedFeed.data.items.map((item) => item.id), ["normal", "editorial-banner", "non-ad-commercial"]);

for (const url of [
  "https://app.bilibili.com/x/v2/feed/index-old",
  "https://app.bilibili.com/x/v2/splash/showcase",
  "https://app.bilibili.com/x/v2/unmatched",
  "https://other.example/x/v2/feed/index",
]) {
  assert.equal(transform(url, feedBody), feedBody, `must not transform ${url}`);
}

const malformed = "{not-json";
assert.equal(transform("https://app.bilibili.com/x/v2/feed/index", malformed), malformed);

console.log("script fixtures passed: endpoint boundaries, every ad branch, and fail-open behavior");
