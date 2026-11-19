const COOKIE_NAME = "netlify_site_auth";

async function makeToken(secret: string): Promise<string> {
  const data = new TextEncoder().encode(`auth:${secret}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function getCookie(request: Request, name: string): string | null {
  const cookieHeader = request.headers.get("cookie") || "";
  const parts = cookieHeader.split(";").map((part) => part.trim());
  for (const part of parts) {
    if (part.startsWith(`${name}=`)) {
      return decodeURIComponent(part.slice(name.length + 1));
    }
  }
  return null;
}

function loginPage(error = false): Response {
  const html = `<!doctype html>
<html lang="uk">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Вхід за паролем</title>
  <style>
    body { font-family: system-ui, sans-serif; display: grid; place-items: center; min-height: 100vh; margin: 0; background: #111; color: #f5f5f5; }
    form { display: flex; flex-direction: column; gap: 12px; width: 100%; max-width: 320px; padding: 24px; border-radius: 12px; background: #1c1c1c; }
    input, button { padding: 10px 12px; border-radius: 8px; border: 1px solid #333; font-size: 16px; }
    input { background: #111; color: #fff; }
    button { background: #00ad9f; color: #000; font-weight: 600; border: none; cursor: pointer; }
    .err { color: #ff6b6b; font-size: 14px; margin: 0; }
  </style>
</head>
<body>
  <form method="POST" action="/__login">
    <h2 style="margin:0 0 4px">Доступ обмежено</h2>
    ${error ? '<p class="err">Невірний пароль</p>' : ""}
    <input type="password" name="password" placeholder="Введіть пароль" required autofocus />
    <button type="submit">Увійти</button>
  </form>
</body>
</html>`;

  return new Response(html, {
    status: 401,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

export default async function handler(request: Request, context: { next: () => Promise<Response> }) {
  const expectedPassword = Deno.env.get("SITE_PASSWORD");
  if (!expectedPassword) {
    return new Response("SITE_PASSWORD is not configured", { status: 500 });
  }

  const validToken = await makeToken(expectedPassword);
  const url = new URL(request.url);

  if (url.pathname === "/__login" && request.method === "POST") {
    const formData = await request.formData();
    const submitted = String(formData.get("password") ?? "");

    if (submitted === expectedPassword) {
      const headers = new Headers({
        Location: "/",
        "Set-Cookie": `${COOKIE_NAME}=${encodeURIComponent(validToken)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`,
      });
      return new Response(null, { status: 302, headers });
    }
    return loginPage(true);
  }

  const currentToken = getCookie(request, COOKIE_NAME);
  if (currentToken === validToken) {
    return context.next();
  }

  return loginPage(false);
}
