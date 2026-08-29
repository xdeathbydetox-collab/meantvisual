const SESSION_DAYS = 30;
const SESSION_COOKIE_NAME = "meant_session";

/* =========================================================
   TOKEN
========================================================= */

function randomBytes(length) {
  const bytes = new Uint8Array(length);

  crypto.getRandomValues(bytes);

  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function createToken() {
  return bytesToBase64(
    randomBytes(32)
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/* =========================================================
   SHA-256
========================================================= */

async function sha256Base64(value) {
  const data =
    new TextEncoder().encode(
      String(value)
    );

  const hash =
    await crypto.subtle.digest(
      "SHA-256",
      data
    );

  return bytesToBase64(
    new Uint8Array(hash)
  );
}

/* =========================================================
   COOKIE
========================================================= */

function getCookie(request, name) {
  const cookie =
    request.headers.get("Cookie");

  if (!cookie) {
    return null;
  }

  const parts =
    cookie.split(";");

  for (const part of parts) {
    const item =
      part.trim();

    if (
      item.startsWith(
        name + "="
      )
    ) {
      const value =
        item.substring(
          name.length + 1
        );

      try {
        return decodeURIComponent(
          value
        );
      } catch {
        return value;
      }
    }
  }

  return null;
}

function createCookie(token) {
  const maxAge =
    SESSION_DAYS *
    24 *
    60 *
    60;

  return (
    SESSION_COOKIE_NAME +
    "=" +
    encodeURIComponent(token) +
    "; Path=/; Max-Age=" +
    maxAge +
    "; HttpOnly; Secure; SameSite=Lax"
  );
}

export function clearSessionCookie() {
  return (
    SESSION_COOKIE_NAME +
    "=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
  );
}

/* =========================================================
   CREATE SESSION
========================================================= */

export async function createSession(
  env,
  accountId
) {
  if (!env || !env.DB) {
    throw new Error(
      "DB binding не найден"
    );
  }

  if (!accountId) {
    throw new Error(
      "accountId не указан"
    );
  }

  const token =
    createToken();

  const tokenHash =
    await sha256Base64(
      token
    );

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
    id: sessionId,
    token,
    expires,
    cookie: createCookie(token)
  };
}

/* =========================================================
   GET SESSION TOKEN
========================================================= */

export function getSessionToken(request) {
  return getCookie(
    request,
    SESSION_COOKIE_NAME
  );
}

/* =========================================================
   GET SESSION
========================================================= */

export async function getSession(
  request,
  env
) {
  const token =
    getSessionToken(request);

  if (!token) {
    return null;
  }

  if (!env || !env.DB) {
    throw new Error(
      "DB binding не найден"
    );
  }

  const tokenHash =
    await sha256Base64(
      token
    );

  const session =
    await env.DB
      .prepare(`
        SELECT
          id,
          account_id,
          token_hash,
          expires_at,
          created_at
        FROM sessions
        WHERE token_hash = ?
        LIMIT 1
      `)
      .bind(tokenHash)
      .first();

  if (!session) {
    return null;
  }

  /* -------------------------
     CHECK EXPIRATION
  ------------------------- */

  if (
    !session.expires_at ||
    new Date(
      session.expires_at
    ).getTime() <= Date.now()
  ) {
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE id = ?
      `)
      .bind(
        session.id
      )
      .run();

    return null;
  }

  return session;
}

/* =========================================================
   GET SESSION ACCOUNT
========================================================= */

export async function getSessionAccount(
  request,
  env
) {
  const token =
    getSessionToken(request);

  if (!token) {
    return null;
  }

  if (!env || !env.DB) {
    throw new Error(
      "DB binding не найден"
    );
  }

  const tokenHash =
    await sha256Base64(
      token
    );

  const row =
    await env.DB
      .prepare(`
        SELECT
          accounts.id,
          accounts.username,
          accounts.email,
          accounts.balance,

          sessions.id AS session_id,
          sessions.expires_at AS session_expires_at

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

  /* -------------------------
     CHECK SESSION EXPIRATION
  ------------------------- */

  if (
    !row.session_expires_at ||
    new Date(
      row.session_expires_at
    ).getTime() <= Date.now()
  ) {
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE id = ?
      `)
      .bind(
        row.session_id
      )
      .run();

    return null;
  }

  return {
    id: row.id,
    username: row.username,
    email: row.email,
    balance:
      Number(
        row.balance || 0
      ),

    session_id:
      row.session_id,

    session_expires_at:
      row.session_expires_at
  };
}

/* =========================================================
   DELETE CURRENT SESSION
========================================================= */

export async function deleteSession(
  request,
  env
) {
  const token =
    getSessionToken(request);

  if (!token) {
    return false;
  }

  if (!env || !env.DB) {
    throw new Error(
      "DB binding не найден"
    );
  }

  const tokenHash =
    await sha256Base64(
      token
    );

  const result =
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE token_hash = ?
      `)
      .bind(tokenHash)
      .run();

  return (
    Number(
      result?.meta?.changes || 0
    ) > 0
  );
}

/* =========================================================
   DELETE SESSION BY TOKEN
========================================================= */

export async function deleteSessionByToken(
  env,
  token
) {
  if (!token) {
    return false;
  }

  if (!env || !env.DB) {
    throw new Error(
      "DB binding не найден"
    );
  }

  const tokenHash =
    await sha256Base64(
      token
    );

  const result =
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE token_hash = ?
      `)
      .bind(tokenHash)
      .run();

  return (
    Number(
      result?.meta?.changes || 0
    ) > 0
  );
}

/* =========================================================
   DELETE ALL ACCOUNT SESSIONS
========================================================= */

export async function deleteAllSessions(
  env,
  accountId
) {
  if (!accountId) {
    return false;
  }

  if (!env || !env.DB) {
    throw new Error(
      "DB binding не найден"
    );
  }

  const result =
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE account_id = ?
      `)
      .bind(accountId)
      .run();

  return (
    Number(
      result?.meta?.changes || 0
    ) > 0
  );
}

/* =========================================================
   CLEAN EXPIRED SESSIONS
========================================================= */

export async function cleanExpiredSessions(
  env
) {
  if (!env || !env.DB) {
    throw new Error(
      "DB binding не найден"
    );
  }

  const result =
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE expires_at <= CURRENT_TIMESTAMP
      `)
      .run();

  return Number(
    result?.meta?.changes || 0
  );
}
