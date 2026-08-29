/* =========================================================
   SESSION.JS
   MEANT SHOP
========================================================= */

const SESSION_DAYS = 30;

const PBKDF2_ITERATIONS = 100000;
const HASH_BYTES = 32;

/* =========================================================
   RANDOM
========================================================= */

function randomBytes(length) {
  const bytes = new Uint8Array(length);

  crypto.getRandomValues(bytes);

  return bytes;
}

/* =========================================================
   BASE64
========================================================= */

function bytesToBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);

  const bytes =
    new Uint8Array(binary.length);

  for (
    let i = 0;
    i < binary.length;
    i++
  ) {
    bytes[i] =
      binary.charCodeAt(i);
  }

  return bytes;
}

/* =========================================================
   SHA-256
========================================================= */

export async function sha256Base64(value) {
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
   PASSWORD HASH
========================================================= */

async function hashPassword(password) {
  const salt =
    randomBytes(16);

  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(
        String(password)
      ),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations:
          PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      key,
      HASH_BYTES * 8
    );

  return {
    hash:
      bytesToBase64(
        new Uint8Array(bits)
      ),

    salt:
      bytesToBase64(
        salt
      )
  };
}

/* =========================================================
   CREATE PASSWORD HASH
========================================================= */

export async function createPasswordHash(
  password
) {
  const result =
    await hashPassword(
      password
    );

  return (
    result.salt +
    "$" +
    result.hash
  );
}

/* =========================================================
   VERIFY PASSWORD
========================================================= */

export async function verifyPassword(
  password,
  stored
) {
  try {
    if (!stored) {
      return false;
    }

    const parts =
      String(stored).split("$");

    if (
      parts.length !== 2
    ) {
      return false;
    }

    const salt =
      base64ToBytes(
        parts[0]
      );

    const expected =
      base64ToBytes(
        parts[1]
      );

    const key =
      await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(
          String(password)
        ),
        "PBKDF2",
        false,
        ["deriveBits"]
      );

    const bits =
      await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt,
          iterations:
            PBKDF2_ITERATIONS,
          hash: "SHA-256"
        },
        key,
        HASH_BYTES * 8
      );

    const actual =
      new Uint8Array(bits);

    if (
      actual.length !==
      expected.length
    ) {
      return false;
    }

    let difference = 0;

    for (
      let i = 0;
      i < actual.length;
      i++
    ) {
      difference |=
        actual[i] ^
        expected[i];
    }

    return difference === 0;

  } catch {
    return false;
  }
}

/* =========================================================
   TOKEN
========================================================= */

export function createToken() {
  return bytesToBase64(
    randomBytes(32)
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/* =========================================================
   COOKIE
========================================================= */

export function getCookie(
  request,
  name
) {
  const cookie =
    request.headers.get(
      "Cookie"
    );

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
      return decodeURIComponent(
        item.substring(
          name.length + 1
        )
      );
    }
  }

  return null;
}

/* =========================================================
   SESSION COOKIE
========================================================= */

export function cookieHeader(
  token
) {
  return (
    "meant_session=" +
    encodeURIComponent(token) +
    "; Path=/; Max-Age=" +
    (
      SESSION_DAYS *
      24 *
      60 *
      60
    ) +
    "; HttpOnly; Secure; SameSite=Lax"
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

export async function createSession(
  env,
  accountId
) {
  if (
    !env ||
    !env.DB
  ) {
    throw new Error(
      "DB binding не найден"
    );
  }

  if (!accountId) {
    throw new Error(
      "Не указан accountId"
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
    id:
      sessionId,

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
  const token =
    getCookie(
      request,
      "meant_session"
    );

  if (!token) {
    return null;
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
          sessions.expires_at

        FROM sessions

        INNER JOIN accounts
          ON accounts.id =
             sessions.account_id

        WHERE sessions.token_hash = ?

        LIMIT 1
      `)
      .bind(
        tokenHash
      )
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
    ).getTime() <=
      Date.now()
  ) {
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE token_hash = ?
      `)
      .bind(
        tokenHash
      )
      .run();

    return null;
  }

  return row;
}

/* =========================================================
   DELETE CURRENT SESSION
========================================================= */

export async function deleteSession(
  request,
  env
) {
  const token =
    getCookie(
      request,
      "meant_session"
    );

  if (!token) {
    return false;
  }

  const tokenHash =
    await sha256Base64(
      token
    );

  await env.DB
    .prepare(`
      DELETE FROM sessions
      WHERE token_hash = ?
    `)
    .bind(
      tokenHash
    )
    .run();

  return true;
}

/* =========================================================
   DELETE ALL ACCOUNT SESSIONS
========================================================= */

export async function deleteAccountSessions(
  env,
  accountId
) {
  if (!accountId) {
    return false;
  }

  await env.DB
    .prepare(`
      DELETE FROM sessions
      WHERE account_id = ?
    `)
    .bind(
      accountId
    )
    .run();

  return true;
}
