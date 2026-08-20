// ============================================================
// MEANT SHOP - Cloudflare Worker
// Авторизация + регистрация + D1
// ============================================================

const PBKDF2_ITERATIONS = 100000;
const PASSWORD_SALT_BYTES = 16;
const PASSWORD_HASH_BYTES = 32;

// ------------------------------------------------------------
// CORS
// ------------------------------------------------------------

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Content-Type": "application/json; charset=utf-8"
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders()
  });
}

// ------------------------------------------------------------
// OPTIONS
// ------------------------------------------------------------

function handleOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization"
    }
  });
}

// ------------------------------------------------------------
// RANDOM
// ------------------------------------------------------------

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

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

// ------------------------------------------------------------
// PASSWORD HASH
// ------------------------------------------------------------

async function hashPassword(password) {
  const salt = randomBytes(PASSWORD_SALT_BYTES);

  const encoder = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    keyMaterial,
    PASSWORD_HASH_BYTES * 8
  );

  return {
    salt: bytesToBase64(salt),
    hash: bytesToBase64(new Uint8Array(derivedBits))
  };
}

// ------------------------------------------------------------
// PASSWORD CHECK
// ------------------------------------------------------------

async function verifyPassword(password, saltBase64, hashBase64) {
  const salt = base64ToBytes(saltBase64);
  const expectedHash = base64ToBytes(hashBase64);

  const encoder = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    keyMaterial,
    PASSWORD_HASH_BYTES * 8
  );

  const actualHash = new Uint8Array(derivedBits);

  if (actualHash.length !== expectedHash.length) {
    return false;
  }

  let difference = 0;

  for (let i = 0; i < actualHash.length; i++) {
    difference |= actualHash[i] ^ expectedHash[i];
  }

  return difference === 0;
}

// ------------------------------------------------------------
// SESSION TOKEN
// ------------------------------------------------------------

function createToken() {
  return bytesToBase64(randomBytes(32))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// ------------------------------------------------------------
// REQUEST BODY
// ------------------------------------------------------------

async function getBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

// ------------------------------------------------------------
// REGISTER
// ------------------------------------------------------------

async function register(request, env) {
  const body = await getBody(request);

  if (!body) {
    return json({
      error: "Неверный JSON"
    }, 400);
  }

  const nickname = String(body.nickname || "").trim();
  const password = String(body.password || "");
  const passwordRepeat = String(
    body.passwordRepeat ??
    body.confirmPassword ??
    body.password2 ??
    ""
  );

  if (!nickname) {
    return json({
      error: "Введите никнейм"
    }, 400);
  }

  if (nickname.length < 3) {
    return json({
      error: "Никнейм должен содержать минимум 3 символа"
    }, 400);
  }

  if (nickname.length > 32) {
    return json({
      error: "Никнейм слишком длинный"
    }, 400);
  }

  if (!password) {
    return json({
      error: "Введите пароль"
    }, 400);
  }

  if (password.length < 6) {
    return json({
      error: "Пароль должен содержать минимум 6 символов"
    }, 400);
  }

  if (password !== passwordRepeat) {
    return json({
      error: "Пароли не совпадают"
    }, 400);
  }

  // Проверяем существующий аккаунт
  const existing = await env.DB.prepare(
    "SELECT id FROM accounts WHERE LOWER(nickname) = LOWER(?) LIMIT 1"
  )
    .bind(nickname)
    .first();

  if (existing) {
    return json({
      error: "Этот никнейм уже занят"
    }, 409);
  }

  const passwordData = await hashPassword(password);

  const id = crypto.randomUUID();

  try {
    await env.DB.prepare(`
      INSERT INTO accounts
      (id, nickname, password_hash, password_salt, balance)
      VALUES (?, ?, ?, ?, ?)
    `)
      .bind(
        id,
        nickname,
        passwordData.hash,
        passwordData.salt,
        0
      )
      .run();
  } catch (error) {
    return json({
      error: "Ошибка базы данных: " + String(error.message || error)
    }, 500);
  }

  const token = createToken();

  const expiresAt = Date.now() + 1000 * 60 * 60 * 24 * 30;

  await env.DB.prepare(`
    INSERT INTO sessions
    (token, account_id, expires_at)
    VALUES (?, ?, ?)
  `)
    .bind(token, id, expiresAt)
    .run();

  return json({
    success: true,
    token,
    user: {
      id,
      nickname,
      balance: 0
    }
  });
}

// ------------------------------------------------------------
// LOGIN
// ------------------------------------------------------------

async function login(request, env) {
  const body = await getBody(request);

  if (!body) {
    return json({
      error: "Неверный JSON"
    }, 400);
  }

  const nickname = String(body.nickname || "").trim();
  const password = String(body.password || "");

  if (!nickname || !password) {
    return json({
      error: "Введите никнейм и пароль"
    }, 400);
  }

  const account = await env.DB.prepare(`
    SELECT
      id,
      nickname,
      password_hash,
      password_salt,
      balance
    FROM accounts
    WHERE LOWER(nickname) = LOWER(?)
    LIMIT 1
  `)
    .bind(nickname)
    .first();

  if (!account) {
    return json({
      error: "Неверный никнейм или пароль"
    }, 401);
  }

  const valid = await verifyPassword(
    password,
    account.password_salt,
    account.password_hash
  );

  if (!valid) {
    return json({
      error: "Неверный никнейм или пароль"
    }, 401);
  }

  const token = createToken();

  const expiresAt = Date.now() + 1000 * 60 * 60 * 24 * 30;

  await env.DB.prepare(`
    INSERT INTO sessions
    (token, account_id, expires_at)
    VALUES (?, ?, ?)
  `)
    .bind(
      token,
      account.id,
      expiresAt
    )
    .run();

  return json({
    success: true,
    token,
    user: {
      id: account.id,
      nickname: account.nickname,
      balance: Number(account.balance || 0)
    }
  });
}

// ------------------------------------------------------------
// GET TOKEN
// ------------------------------------------------------------

function getToken(request) {
  const authorization = request.headers.get("Authorization");

  if (!authorization) {
    return null;
  }

  if (!authorization.startsWith("Bearer ")) {
    return null;
  }

  return authorization.slice(7).trim();
}

// ------------------------------------------------------------
// CURRENT USER
// ------------------------------------------------------------

async function getMe(request, env) {
  const token = getToken(request);

  if (!token) {
    return json({
      authenticated: false
    }, 401);
  }

  const session = await env.DB.prepare(`
    SELECT
      sessions.token,
      sessions.expires_at,
      accounts.id,
      accounts.nickname,
      accounts.balance
    FROM sessions
    JOIN accounts
      ON accounts.id = sessions.account_id
    WHERE sessions.token = ?
    LIMIT 1
  `)
    .bind(token)
    .first();

  if (!session) {
    return json({
      authenticated: false
    }, 401);
  }

  if (Number(session.expires_at) < Date.now()) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE token = ?"
    )
      .bind(token)
      .run();

    return json({
      authenticated: false
    }, 401);
  }

  return json({
    authenticated: true,
    user: {
      id: session.id,
      nickname: session.nickname,
      balance: Number(session.balance || 0)
    }
  });
}

// ------------------------------------------------------------
// LOGOUT
// ------------------------------------------------------------

async function logout(request, env) {
  const token = getToken(request);

  if (token) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE token = ?"
    )
      .bind(token)
      .run();
  }

  return json({
    success: true
  });
}

// ------------------------------------------------------------
// HEALTH CHECK
// ------------------------------------------------------------

async function health(env) {
  try {
    await env.DB.prepare(
      "SELECT 1"
    ).first();

    return json({
      success: true,
      database: true,
      message: "MEANT SHOP Worker работает"
    });
  } catch (error) {
    return json({
      success: false,
      database: false,
      error: String(error.message || error)
    }, 500);
  }
}

// ------------------------------------------------------------
// MAIN
// ------------------------------------------------------------

export default {
  async fetch(request, env) {

    if (request.method === "OPTIONS") {
      return handleOptions();
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {

      // API
      if (path === "/api/register" && request.method === "POST") {
        return await register(request, env);
      }

      if (path === "/api/login" && request.method === "POST") {
        return await login(request, env);
      }

      if (path === "/api/me" && request.method === "GET") {
        return await getMe(request, env);
      }

      if (path === "/api/logout" && request.method === "POST") {
        return await logout(request, env);
      }

      if (path === "/api/health" && request.method === "GET") {
        return await health(env);
      }

      // ------------------------------------------------------
      // STATIC FILES
      // ------------------------------------------------------

      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return new Response("Not Found", {
        status: 404
      });

    } catch (error) {

      console.error(error);

      return json({
        error: String(error.message || error)
      }, 500);
    }
  }
};
