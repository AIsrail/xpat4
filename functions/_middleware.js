// Cloudflare Pages Function — runs at the edge before any static file is served.
// Gates /admin so it can no longer be reached by anyone who just requests the URL:
// the old check lived entirely in admin.html's client-side JS, which can never be a
// real security boundary on a static site (the "password" is just text in a public
// HTML file, and the "logged in" flag is a sessionStorage key anyone can set from
// the browser console).
//
// Set the real password as a Cloudflare Pages secret named ADMIN_PASSWORD:
// Pages project → Settings → Environment variables → add ADMIN_PASSWORD (encrypt)
// for both Production and Preview. Without it configured, admin access fails closed.
export async function onRequest(context) {
  const { request, next, env } = context;
  const path = new URL(request.url).pathname;

  const isAdminRoute = path === "/admin" || path === "/admin.html" || path === "/admin/";
  if (!isAdminRoute) return next();

  const expected = env.ADMIN_PASSWORD;
  if (!expected) {
    return new Response("Admin access is not configured.", { status: 503 });
  }

  const authHeader = request.headers.get("Authorization") || "";
  const [scheme, encoded] = authHeader.split(" ");
  if (scheme === "Basic" && encoded) {
    let decoded = "";
    try {
      decoded = atob(encoded);
    } catch {
      decoded = "";
    }
    const sep = decoded.indexOf(":");
    const password = sep >= 0 ? decoded.slice(sep + 1) : "";
    if (password.length === expected.length && timingSafeEqual(password, expected)) {
      return next();
    }
  }

  return new Response("Authentication required.", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="xpat4 admin", charset="UTF-8"' },
  });
}

function timingSafeEqual(a, b) {
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
