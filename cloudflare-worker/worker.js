// Single Cloudflare Worker / Pages Function for the "MedoVPN" Go client.
// Replaces BOTH the old Gateway worker and the private Fetch worker.
//
//   GET  /health -> "MedoVPN Gateway is online."   (used by the app's health check)
//   POST /relay  -> {k,u,m,h,b,r}  =>  {s,h,b}  or  {e}
//   everything else -> a decoy static page, so active probing (GFW/Iranian-DPI style
//                      "connect to this host and see if it looks like a real website")
//                      doesn't fingerprint this domain as proxy infrastructure.
//
// Password: edit AUTH_KEY below, then paste this whole file into the Cloudflare dashboard.
// It must be the same text you type as the "Gateway password" in the Go app.

// ===== PUT YOUR PASSWORD HERE (between the quotes) =====
const AUTH_KEY = "PUT_YOUR_PASSWORD_HERE";
// =======================================================

const HEALTH_TEXT = "MedoVPN Gateway is online.";
const MAX_REQUEST_BODY = 10 * 1024 * 1024;   // matches the Go client's 10 MiB limit
const MAX_RESPONSE_BODY = 24 * 1024 * 1024;  // below the client's 32 MiB cap; base64 adds ~33%
const UPSTREAM_TIMEOUT_MS = 60000;

const REQUEST_SKIP = new Set([
    "host", "connection", "content-length", "transfer-encoding", "keep-alive",
    "proxy-authenticate", "proxy-authorization", "proxy-connection", "te",
    "trailer", "upgrade", "expect", "accept-encoding",
    "x-medo-relay-token", "x-relay-hop", "x-fwd-hop",
]);

// The runtime already decodes gzip/br bodies when we read them, so content-encoding
// and content-length from the origin no longer describe the bytes we send back.
const RESPONSE_SKIP = new Set([
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
    "content-encoding", "content-length", "set-cookie",
]);

async function handle(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/health" && (request.method === "GET" || request.method === "HEAD")) {
        return new Response(request.method === "HEAD" ? null : HEALTH_TEXT + "\n", {
            status: 200,
            headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
        });
    }

    if (url.pathname === "/relay") {
        if (request.method !== "POST") return json({ e: "Method not allowed" }, 405);
        const key = (env && env.CLIENT_AUTH_KEY) || AUTH_KEY;
        if (!key || key === "PUT_YOUR_PASSWORD_HERE") {
            return json({ e: "Gateway is not configured (set AUTH_KEY in worker.js)" }, 503);
        }
        let req;
        try { req = await request.json(); } catch { return json({ e: "invalid JSON" }, 400); }
        if (!req || !safeEqual(req.k, key)) return json({ e: "unauthorized" }, 401);
        try {
            return json(await relay(req, url.hostname));
        } catch (err) {
            return json({ e: String((err && err.message) || err) }, 502);
        }
    }

    // Everything else: serve the decoy site so active probing and casual
    // inspection see an ordinary small website, not bare proxy infrastructure.
    return decoyResponse(url);
}

async function relay(req, selfHost) {
    if (typeof req.u !== "string") throw new Error("missing url");
    let target;
    try { target = new URL(req.u); } catch { throw new Error("bad url"); }
    if ((target.protocol !== "http:" && target.protocol !== "https:") || target.username || target.password) {
        throw new Error("bad url");
    }
    if (target.hostname === selfHost) throw new Error("self-fetch blocked");

    const method = String(req.m || "GET").toUpperCase();
    if (!/^[A-Z]+$/.test(method) || method === "CONNECT" || method === "TRACE") throw new Error("bad method");

    const headers = new Headers();
    if (req.h && typeof req.h === "object") {
        for (const [k, v] of Object.entries(req.h)) {
            if (!REQUEST_SKIP.has(k.toLowerCase())) headers.set(k, String(v));
        }
    }
    headers.set("accept-encoding", "identity");

    const init = {
        method,
        headers,
        // The Go client sends r:false and lets the browser follow redirects itself.
        redirect: req.r === true ? "follow" : "manual",
        signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    };
    if (req.b && method !== "GET" && method !== "HEAD") {
        const body = Uint8Array.from(atob(req.b), (c) => c.charCodeAt(0));
        if (body.length > MAX_REQUEST_BODY) throw new Error("request body too large");
        init.body = body;
    }

    const resp = await fetch(target.toString(), init);
    const bytes = method === "HEAD" ? new Uint8Array(0) : await readLimited(resp);

    const h = {};
    resp.headers.forEach((v, k) => {
        const lower = k.toLowerCase();
        if (!RESPONSE_SKIP.has(lower)) h[lower] = v;
    });
    if (method === "HEAD") {
        const cl = resp.headers.get("content-length");
        if (cl) h["content-length"] = cl;
    }
    const cookies = typeof resp.headers.getSetCookie === "function" ? resp.headers.getSetCookie() : [];
    if (cookies.length) h["set-cookie"] = cookies;

    return { s: resp.status, h, b: bytesToBase64(bytes) };
}

async function readLimited(resp) {
    if (!resp.body) return new Uint8Array(0);
    const reader = resp.body.getReader();
    const chunks = [];
    let total = 0;
    for (; ;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.length;
        if (total > MAX_RESPONSE_BODY) {
            await reader.cancel();
            throw new Error("response body exceeds the " + (MAX_RESPONSE_BODY >> 20) + " MiB relay limit");
        }
        chunks.push(value);
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) { out.set(c, offset); offset += c.length; }
    return out;
}

function bytesToBase64(bytes) {
    const parts = [];
    const CHUNK = 0x6000; // divisible by 3, so chunks concatenate cleanly
    for (let i = 0; i < bytes.length; i += CHUNK) {
        parts.push(btoa(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK))));
    }
    return parts.join("");
}

function safeEqual(a, b) {
    if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}

function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
        status,
        headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
}

// ===================== Decoy site =====================
// Original content only — no real brand, no copied markup. Boring on purpose:
// a generic small-business/news-aggregator look with more than one resource
// (HTML + CSS + a tiny JS file + favicon + robots.txt), served with ordinary
// static-site headers, so it doesn't read as an API/proxy backend to either
// an automated prober or a human glancing at the domain.

const DECOY_PAGES = {
    "/": decoyHTML(),
    "/favicon.ico": null, // handled specially below (binary)
    "/robots.txt": "User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n",
    "/sitemap.xml": decoySitemap(),
    "/static/site.css": decoyCSS(),
    "/static/site.js": decoyJS(),
    "/about": decoyAboutHTML(),
    "/contact": decoyContactHTML(),
};

function decoyResponse(url) {
    const path = url.pathname === "" ? "/" : url.pathname;

    if (path === "/favicon.ico") {
        return new Response(decoyFaviconBytes(), {
            status: 200,
            headers: { "content-type": "image/x-icon", "cache-control": "public, max-age=86400" },
        });
    }

    const body = DECOY_PAGES[path];
    if (body !== undefined && body !== null) {
        const contentType = path.endsWith(".css")
            ? "text/css; charset=utf-8"
            : path.endsWith(".js")
                ? "text/javascript; charset=utf-8"
                : path.endsWith(".xml")
                    ? "application/xml; charset=utf-8"
                    : path.endsWith(".txt")
                        ? "text/plain; charset=utf-8"
                        : "text/html; charset=utf-8";
        return new Response(body, {
            status: 200,
            headers: {
                "content-type": contentType,
                "cache-control": path.endsWith(".html") || contentType.startsWith("text/html")
                    ? "public, max-age=300"
                    : "public, max-age=86400",
            },
        });
    }

    // Unknown path: themed 404 within the decoy site, not a bare "Not found".
    return new Response(decoy404HTML(), {
        status: 404,
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
    });
}

function decoyShell(title, bodyHTML) {
    return `<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<meta name="description" content="یادداشت‌ها و مطالب کوتاه درباره فناوری، شبکه و زندگی روزمره.">
<link rel="icon" href="/favicon.ico">
<link rel="stylesheet" href="/static/site.css">
</head>
<body>
<header class="site-header">
  <a class="brand" href="/">دفترچه</a>
  <nav>
    <a href="/">خانه</a>
    <a href="/about">درباره</a>
    <a href="/contact">تماس</a>
  </nav>
</header>
<main>
${bodyHTML}
</main>
<footer class="site-footer">
  <p>© ${new Date().getFullYear()} دفترچه — همه حقوق محفوظ است.</p>
</footer>
<script src="/static/site.js"></script>
</body>
</html>`;
}

function decoyHTML() {
    const posts = [
        { title: "چند نکته درباره مدیریت زمان", excerpt: "روش‌های ساده‌ای که در هفته‌های اخیر امتحان کردم و نتیجه گرفتم.", date: "۱۴۰۳/۰۸/۱۰" },
        { title: "یادداشتی کوتاه درباره کتاب‌خوانی", excerpt: "چرا خواندن روزی نیم ساعت بیشتر از خواندن یک‌باره در آخر هفته جواب می‌دهد.", date: "۱۴۰۳/۰۷/۲۲" },
        { title: "سفر یک‌روزه به شمال", excerpt: "گزارش کوتاه یک سفر کوتاه، بدون برنامه‌ریزی قبلی.", date: "۱۴۰۳/۰۶/۰۳" },
    ];
    const items = posts.map(p => `
  <article class="post-card">
    <h2>${p.title}</h2>
    <p class="meta">${p.date}</p>
    <p>${p.excerpt}</p>
  </article>`).join("\n");
    return decoyShell("دفترچه — یادداشت‌های کوتاه", `
  <section class="hero">
    <h1>دفترچه</h1>
    <p>یادداشت‌های کوتاه و پراکنده؛ بدون قاعده‌ی مشخص برای انتشار.</p>
  </section>
  <section class="posts">
  ${items}
  </section>`);
}

function decoyAboutHTML() {
    return decoyShell("درباره — دفترچه", `
  <section class="page">
    <h1>درباره</h1>
    <p>این صفحه فقط چند خط درباره‌ی این وبلاگ کوچک است. محتوای تازه هر چند وقت یک‌بار اضافه می‌شود.</p>
  </section>`);
}

function decoyContactHTML() {
    return decoyShell("تماس — دفترچه", `
  <section class="page">
    <h1>تماس</h1>
    <p>برای پیام دادن می‌توانید از فرم زیر استفاده کنید.</p>
    <form class="contact-form" onsubmit="return false;">
      <label>نام<input type="text" name="name"></label>
      <label>ایمیل<input type="email" name="email"></label>
      <label>پیام<textarea name="message" rows="4"></textarea></label>
      <button type="submit">ارسال</button>
    </form>
  </section>`);
}

function decoy404HTML() {
    return decoyShell("صفحه پیدا نشد — دفترچه", `
  <section class="page">
    <h1>۴۰۴</h1>
    <p>صفحه‌ای که دنبالش بودید پیدا نشد.</p>
    <p><a href="/">بازگشت به خانه</a></p>
  </section>`);
}

function decoyCSS() {
    return `:root{--bg:#faf9f7;--fg:#222;--muted:#6b6b6b;--accent:#8a5a44;--card:#fff;--border:#e7e3df}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:Tahoma,"Vazirmatn",sans-serif;line-height:1.7}
.site-header{display:flex;justify-content:space-between;align-items:center;padding:1rem 1.5rem;border-bottom:1px solid var(--border)}
.site-header .brand{font-weight:bold;font-size:1.2rem;color:var(--accent);text-decoration:none}
.site-header nav a{margin-inline-start:1rem;color:var(--fg);text-decoration:none}
.site-header nav a:hover{color:var(--accent)}
main{max-width:720px;margin:0 auto;padding:1.5rem}
.hero{padding:2rem 0}
.hero h1{margin:0 0 .25rem;font-size:2rem}
.hero p{color:var(--muted);margin:0}
.post-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem 1.25rem;margin-bottom:1rem}
.post-card h2{margin:0 0 .25rem;font-size:1.1rem}
.post-card .meta{color:var(--muted);font-size:.85rem;margin:0 0 .5rem}
.page h1{font-size:1.5rem}
.contact-form{display:flex;flex-direction:column;gap:.75rem;max-width:360px}
.contact-form label{display:flex;flex-direction:column;gap:.25rem;font-size:.9rem;color:var(--muted)}
.contact-form input,.contact-form textarea{padding:.5rem;border:1px solid var(--border);border-radius:6px;font-family:inherit}
.contact-form button{align-self:flex-start;padding:.5rem 1.25rem;background:var(--accent);color:#fff;border:0;border-radius:6px;cursor:pointer}
.site-footer{text-align:center;color:var(--muted);font-size:.85rem;padding:2rem 1rem}`;
}

function decoyJS() {
    return `document.addEventListener('DOMContentLoaded',function(){
  var f=document.querySelector('.contact-form');
  if(f){f.addEventListener('submit',function(e){e.preventDefault();});}
});`;
}

function decoySitemap() {
    return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>/</loc></url>
<url><loc>/about</loc></url>
<url><loc>/contact</loc></url>
</urlset>`;
}

// Minimal valid 16x16 ICO (single-color), generated once as a byte literal
// so there's no build step. Keeps the favicon request from 404ing.
function decoyFaviconBytes() {
    const b64 =
        "AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
        "AAAAAAAAAAD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/" +
        "//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//" +
        "/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////" +
        "AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A" +
        "////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/" +
        "//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//" +
        "/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////" +
        "AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A" +
        "////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/" +
        "//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//" +
        "/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////" +
        "AP///wD///8A";
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

export default { fetch: handle };