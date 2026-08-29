export function getCookie(request, name) {
  const cookie = request.headers.get("Cookie");

  if (!cookie) {
    return null;
  }

  const parts = cookie.split(";");

  for (const part of parts) {
    const item = part.trim();

    if (item.startsWith(name + "=")) {
      return decodeURIComponent(
        item.substring(name.length + 1)
      );
    }
  }

  return null;
}

export function cookieHeader(token) {
  return (
    "meant_session=" +
    encodeURIComponent(token) +
    "; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax"
  );
}

export function clearCookieHeader() {
  return (
    "meant_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
  );
}
