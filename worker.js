const PBKDF2_ITERATIONS = 100000;
const HASH_BYTES = 32;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      ...extraHeaders
    }
  });
}

function optionsResponse() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Credentials": "true"
    }
  });
}

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

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

async function sha256Base64(value) {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", data);

  return bytesToBase64(new Uint8Array(hash));
}

async function createPasswordHash(password) {
  const salt = randomBytes(16);

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    HASH_BYTES * 8
  );

  return (
    bytesToBase64(salt) +
    "$" +
    bytesToBase64(new Uint8Array(bits))
  );
}

async function verifyPassword(password, stored) {
  try {
    const parts = String(stored || "").split("$");

    if (parts.length !== 2) {
      return false;
    }

    const salt = base64ToBytes(parts[0]);
    const expected = base64ToBytes(parts[1]);

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      key,
      HASH_BYTES * 8
    );

    const actual = new Uint8Array(bits);

    if (actual.length !== expected.length) {
      return false;
    }

    let difference = 0;

    for (let i = 0; i < actual.length; i++) {
      difference |= actual[i] ^ expected[i];
    }

    return difference === 0;

  } catch {
    return false;
  }
}

function createToken() {
  return bytesToBase64(randomBytes(32))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie");

  if (!cookie) {
    return null;
  }

  for (const part of cookie.split(";")) {
    const item = part.trim();

    if (item.startsWith(name + "=")) {
      return decodeURIComponent(
        item.slice(name.length + 1)
      );
    }
  }

  return null;
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

async function createSession(env, accountId) {
  const token = createToken();

  const tokenHash = await sha256Base64(token);

  const sessionId = crypto.randomUUID();

  const expires = new Date(
    Date.now() + 30 * 24 * 60 * 60 * 1000
  ).toISOString();

  await env.DB.prepare(`
    INSERT INTO sessions
    (id, account_id, token_hash, expires_at)
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

async function getCurrentAccount(request, env) {
  const token = getCookie(
    request,
    "meant_session"
  );

  if (!token) {
    return null;
  }

  const tokenHash = await sha256Base64(token);

  const row = await env.DB.prepare(`
    SELECT
      accounts.id,
      accounts.username,
      accounts.balance,
      sessions.expires_at
    FROM sessions
    INNER JOIN accounts
      ON accounts.id = sessions.account_id
    WHERE sessions.token_hash = ?
    LIMIT 1
  `)
    .bind(tokenHash)
    .first();

  if (!row) {
    return null;
  }

  if (
    !row.expires_at ||
    new Date(row.expires_at).getTime() <= Date.now()
  ) {
    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE token_hash = ?
    `)
      .bind(tokenHash)
      .run();

    return null;
  }

  return row;
}

function sessionCookie(token, maxAge = 2592000) {
  return (
    "meant_session=" +
    encodeURIComponent(token) +
    `; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`
  );
}

async function register(request, env) {
  const body = await readJson(request);

  if (!body) {
    return json({
      error: "Неверный JSON"
    }, 400);
  }

  const username = String(
    body.username || ""
  ).trim();

  const password = String(
    body.password || ""
  );

  if (!username) {
    return json({
      error: "Введите никнейм"
    }, 400);
  }

  if (username.length < 3) {
    return json({
      error: "Никнейм должен содержать минимум 3 символа"
    }, 400);
  }

  if (username.length > 24) {
    return json({
      error: "Никнейм слишком длинный"
    }, 400);
  }

  if (!password) {
    return json({
      error: "Введите пароль"
    }, 400);
  }

  if (password.length < 8) {
    return json({
      error: "Пароль должен содержать минимум 8 символов"
    }, 400);
  }

  const existing = await env.DB.prepare(`
    SELECT id
    FROM accounts
    WHERE LOWER(username) = LOWER(?)
    LIMIT 1
  `)
    .bind(username)
    .first();

  if (existing) {
    return json({
      error: "Этот никнейм уже занят"
    }, 409);
  }

  const accountId = crypto.randomUUID();

  const passwordHash =
    await createPasswordHash(password);

  try {

    /*
      ВАЖНО:

      Здесь 3 вопросительных знака:
      (?, ?, ?)

      И здесь ровно 3 значения:
      accountId, username, 0
    */

    await env.DB.prepare(`
      INSERT INTO accounts
      (id, username, balance)
      VALUES (?, ?, ?)
    `)
      .bind(
        accountId,
        username,
        0
      )
      .run();

    await env.DB.prepare(`
      INSERT INTO credentials
      (account_id, password_hash)
      VALUES (?, ?)
    `)
      .bind(
        accountId,
        passwordHash
      )
      .run();

  } catch (error) {

    try {
      await env.DB.prepare(`
        DELETE FROM credentials
        WHERE account_id = ?
      `)
        .bind(accountId)
        .run();
    } catch {}

    try {
      await env.DB.prepare(`
        DELETE FROM accounts
        WHERE id = ?
      `)
        .bind(accountId)
        .run();
    } catch {}

    return json({
      error:
        "Ошибка базы данных: " +
        (error?.message || String(error))
    }, 500);
  }

  try {

    const session =
      await createSession(
        env,
        accountId
      );

    return json(
      {
        success: true,

        account: {
          id: accountId,
          username,
          balance: 0
        }
      },

      200,

      {
        "Set-Cookie":
          sessionCookie(
            session.token
          )
      }
    );

  } catch (error) {

    return json({
      error:
        "Аккаунт создан, но не удалось создать сессию: " +
        (error?.message || String(error))
    }, 500);
  }
}

async function login(request, env) {
  const body = await readJson(request);

  if (!body) {
    return json({
      error: "Неверный JSON"
    }, 400);
  }

  const username = String(
    body.username || ""
  ).trim();

  const password = String(
    body.password || ""
  );

  if (!username || !password) {
    return json({
      error: "Введите никнейм и пароль"
    }, 400);
  }

  const account = await env.DB.prepare(`
    SELECT
      accounts.id,
      accounts.username,
      accounts.balance,
      credentials.password_hash
    FROM accounts
    INNER JOIN credentials
      ON credentials.account_id = accounts.id
    WHERE LOWER(accounts.username) = LOWER(?)
    LIMIT 1
  `)
    .bind(username)
    .first();

  if (!account) {
    return json({
      error: "Неверный никнейм или пароль"
    }, 401);
  }

  const valid =
    await verifyPassword(
      password,
      account.password_hash
    );

  if (!valid) {
    return json({
      error: "Неверный никнейм или пароль"
    }, 401);
  }

  try {

    const session =
      await createSession(
        env,
        account.id
      );

    return json(
      {
        success: true,

        account: {
          id: account.id,
          username: account.username,
          balance: Number(
            account.balance || 0
          )
        }
      },

      200,

      {
        "Set-Cookie":
          sessionCookie(
            session.token
          )
      }
    );

  } catch (error) {

    return json({
      error:
        "Не удалось создать сессию: " +
        (error?.message || String(error))
    }, 500);
  }
}

async function me(request, env) {
  const account =
    await getCurrentAccount(
      request,
      env
    );

  if (!account) {
    return json({
      authenticated: false
    }, 401);
  }

  return json({
    authenticated: true,

    account: {
      id: account.id,
      username: account.username,
      balance: Number(
        account.balance || 0
      )
    }
  });
}

async function logout(request, env) {
  const token =
    getCookie(
      request,
      "meant_session"
    );

  if (token) {

    const tokenHash =
      await sha256Base64(token);

    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE token_hash = ?
    `)
      .bind(tokenHash)
      .run();
  }

  return json(
    {
      success: true
    },

    200,

    {
      "Set-Cookie":
        sessionCookie("", 0)
    }
  );
}

async function health(env) {
  try {

    await env.DB
      .prepare("SELECT 1")
      .first();

    const accounts =
      await env.DB
        .prepare(
          "SELECT COUNT(*) AS count FROM accounts"
        )
        .first();

    return json({
      success: true,
      database: true,
      accounts: Number(
        accounts?.count || 0
      )
    });

  } catch (error) {

    return json({
      success: false,
      database: false,
      error:
        error?.message ||
        String(error)
    }, 500);
  }
}

export default {

  async fetch(request, env) {

    if (request.method === "OPTIONS") {
      return optionsResponse();
    }

    const url =
      new URL(request.url);

    const path =
      url.pathname;

    try {

      if (
        path === "/api/auth/register" &&
        request.method === "POST"
      ) {
        return await register(
          request,
          env
        );
      }

      if (
        path === "/api/auth/login" &&
        request.method === "POST"
      ) {
        return await login(
          request,
          env
        );
      }

      if (
        path === "/api/auth/me" &&
        request.method === "GET"
      ) {
        return await me(
          request,
          env
        );
      }

      if (
        path === "/api/auth/logout" &&
        request.method === "POST"
      ) {
        return await logout(
          request,
          env
        );
      }

      if (
        path === "/api/health" &&
        request.method === "GET"
      ) {
        return await health(env);
      }

      if (env.ASSETS) {
        return env.ASSETS.fetch(
          request
        );
      }

      return new Response(
        "Not Found",
        {
          status: 404
        }
      );

    } catch (error) {

      console.error(error);

      return json({
        error:
          error?.message ||
          String(error)
      }, 500);
    }
  }
};
