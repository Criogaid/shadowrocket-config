// Derived from app2smile/rules js/bilibili-json.js (MIT), reviewed 2026-08-17.
// Local changes retain only splash and feed advertising removal.
(() => {
  const original = $response.body;
  let output = original;

  try {
    const body = JSON.parse(original);
    const path = $request.url.replace(/^https:\/\/app\.bilibili\.com/, "");

    if (/^\/x\/v2\/splash\/(?:list|show)(?:\?|$)/.test(path) && body?.data?.show) {
      delete body.data.show;
      output = JSON.stringify(body);
    } else if (/^\/x\/v2\/feed\/index(?:\?|$)/.test(path) && Array.isArray(body?.data?.items)) {
      body.data.items = body.data.items.filter((item) => {
        if (item?.card_type === "banner_v8" && item?.card_goto === "banner") {
          return !item.banner_item?.some((banner) => banner?.type === "ad");
        }
        if (item?.card_type === "cm_v2") {
          return !["ad_web_s", "ad_av", "ad_web_gif", "ad_player", "ad_inline_3d", "ad_inline_eggs"].includes(item.card_goto);
        }
        return !(item?.card_type === "cm_double_v9" && item?.card_goto === "ad_inline_av");
      });
      output = JSON.stringify(body);
    }
  } catch (error) {
    console.log(`bilibili-ads: unchanged malformed response (${error.name})`);
  }

  $done({ body: output });
})();
