import {
  sha256Base64,
  createToken
} from "./crypto.js";

const SESSION_DAYS = 30;

/* =========================================================
   COOKIE
========================================================= */

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

/* =========================================================
   CREATE SESSION
========================================================= */

export async function createSession(env, accountId) {
  if (!env.DB) {
    throw new Error("DB binding не найден");
  }

  if (!accountId) {
    throw new Error("accountId не указан");
  }

  const token = createToken();

  const tokenHash =
    await sha256Base64(token);

  const sessionId =
    crypto.randomUUID();

  const expires =
    new Date(
      Date.now() +
        SESSION_DAYS *
        24 *
        60 *
        60 *
        1000
    ).toISOString();

  await env.DB
    .prepare(`
      INSERT INTO sessions
      (
        id,
        account_id,
        token_hash,
        expires_at
      )
      VALUES (?, ?, ?, ?)
    `)
    .bind(
      sessionId,
      accountId,
      tokenHash,
      expires
    )
    .run();

  return {
    token,
    expires
  };
}

/* =========================================================
   GET SESSION ACCOUNT
========================================================= */

export async function getSessionAccount(
  request,
  env
) {
  if (!env.DB) {
    throw new Error("DB binding не найден");
  }

  const token =
    getCookie(
      request,
      "meant_session"
    );

  if (!token) {
    return null;
  }

  const tokenHash =
    await sha256Base64(token);

  const row =
    await env.DB
      .prepare(`
        SELECT
          accounts.id,
          accounts.username,
          accounts.balance,
          accounts.email,

          sessions.id AS session_id,
          sessions.expires_at

        FROM sessions

        INNER JOIN accounts
          ON accounts.id =
             sessions.account_id

        WHERE
          sessions.token_hash = ?

        LIMIT 1
      `)
      .bind(tokenHash)
      .first();

  if (!row) {
    return null;
  }

  /* =======================================================
     SESSION EXPIRED
  ======================================================= */

  if (
    !row.expires_at ||
    new Date(
      row.expires_at
    ).getTime() <= Date.now()
  ) {
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE token_hash = ?
      `)
      .bind(tokenHash)
      .run();

    return null;
  }

  return row;
}

/* =========================================================
   DELETE SESSION
========================================================= */

export async function deleteSession(
  request,
  env
) {
  if (!env.DB) {
    throw new Error("DB binding не найден");
  }

  const token =
    getCookie(
      request,
      "meant_session"
    );

  if (!token) {
    return;
  }

  const tokenHash =
    await sha256Base64(token);

  await env.DB
    .prepare(`
      DELETE FROM sessions
      WHERE token_hash = ?
    `)
    .bind(tokenHash)
    .run();
}

/* =========================================================
   DELETE ALL USER SESSIONS
========================================================= */

export async function deleteAllSessions(
  env,
  accountId
) {
  if (!env.DB) {
    throw new Error("DB binding не найден");
  }

  if (!accountId) {
    return;
  }

  await env.DB
    .prepare(`
      DELETE FROM sessions
      WHERE account_id = ?
    `)
    .bind(accountId)
    .run();
}

/* =========================================================
   CLEAN EXPIRED SESSIONS
========================================================= */

export async function cleanupExpiredSessions(env) {
  if (!env.DB) {
    throw new Error("DB binding не найден");
  }

  await env.DB
    .prepare(`
      DELETE FROM sessions
      WHERE expires_at <= CURRENT_TIMESTAMP
    `)
    .run();
}
