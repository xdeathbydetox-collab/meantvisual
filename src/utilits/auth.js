import {
  createPasswordHash,
  verifyPassword,
  createSession,
  getSessionAccount,
  deleteSession
} from "./session.js";

import {
  json
} from "./response.js";

/* =========================================================
   HELPERS
========================================================= */

function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function normalizeUsername(value) {
  return String(value || "").trim();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validUsername(username) {
  return /^[a-zA-Z0-9_.-]{3,24}$/.test(username);
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

/* =========================================================
   REGISTER
   POST /api/auth/register
========================================================= */

export async function register(request, env) {
  const body = await readJson(request);

  if (!body) {
    return json({
      error: "Неверный JSON"
    }, 400);
  }

  const username = normalizeUsername(
    body.username
  );

  const email = normalizeEmail(
    body.email
  );

  const password = String(
    body.password || ""
  );

  /* -------------------------
     VALIDATION
  ------------------------- */

  if (!username) {
    return json({
      error: "Введите никнейм"
    }, 400);
  }

  if (!validUsername(username)) {
    return json({
      error:
        "Никнейм должен содержать 3-24 символа: буквы, цифры, _, -, ."
    }, 400);
  }

  if (!email) {
    return json({
      error: "Введите email"
    }, 400);
  }

  if (!validEmail(email)) {
    return json({
      error: "Некорректный email"
    }, 400);
  }

  if (!password) {
    return json({
      error: "Введите пароль"
    }, 400);
  }

  if (password.length < 8) {
    return json({
      error:
        "Пароль должен содержать минимум 8 символов"
    }, 400);
  }

  /* -------------------------
     CHECK USERNAME
  ------------------------- */

  const existingUsername =
    await env.DB
      .prepare(`
        SELECT id
        FROM accounts
        WHERE LOWER(username) = LOWER(?)
        LIMIT 1
      `)
      .bind(username)
      .first();

  if (existingUsername) {
    return json({
      error: "Этот никнейм уже занят"
    }, 409);
  }

  /* -------------------------
     CHECK EMAIL
  ------------------------- */

  const existingEmail =
    await env.DB
      .prepare(`
        SELECT id
        FROM accounts
        WHERE LOWER(email) = LOWER(?)
        LIMIT 1
      `)
      .bind(email)
      .first();

  if (existingEmail) {
    return json({
      error: "Этот email уже используется"
    }, 409);
  }

  /* -------------------------
     CREATE ACCOUNT
  ------------------------- */

  const accountId =
    crypto.randomUUID();

  const passwordHash =
    await createPasswordHash(password);

  try {
    await env.DB
      .prepare(`
        INSERT INTO accounts
        (
          id,
          username,
          email,
          balance
        )
        VALUES (?, ?, ?, 0)
      `)
      .bind(
        accountId,
        username,
        email
      )
      .run();

    await env.DB
      .prepare(`
        INSERT INTO credentials
        (
          account_id,
          password_hash
        )
        VALUES (?, ?)
      `)
      .bind(
        accountId,
        passwordHash
      )
      .run();

  } catch (error) {

    /* rollback */

    try {
      await env.DB
        .prepare(`
          DELETE FROM credentials
          WHERE account_id = ?
        `)
        .bind(accountId)
        .run();
    } catch {}

    try {
      await env.DB
        .prepare(`
          DELETE FROM accounts
          WHERE id = ?
        `)
        .bind(accountId)
        .run();
    } catch {}

    console.error(
      "REGISTER ERROR:",
      error
    );

    return json({
      error:
        "Ошибка базы данных: " +
        (
          error?.message ||
          String(error)
        )
    }, 500);
  }

  /* -------------------------
     CREATE SESSION
  ------------------------- */

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
        email,
        balance: 0
      }
    },
    201,
    {
      "Set-Cookie":
        session.cookie
    }
  );
}

/* =========================================================
   LOGIN
   POST /api/auth/login
========================================================= */

export async function login(request, env) {
  const body = await readJson(request);

  if (!body) {
    return json({
      error: "Неверный JSON"
    }, 400);
  }

  /*
    Можно отправлять:

    {
      "login": "nickname",
      "password": "12345678"
    }

    или

    {
      "username": "nickname",
      "password": "12345678"
    }

    или

    {
      "email": "mail@example.com",
      "password": "12345678"
    }
  */

  const loginValue =
    String(
      body.login ??
      body.username ??
      body.email ??
      ""
    ).trim();

  const password =
    String(
      body.password || ""
    );

  if (!loginValue || !password) {
    return json({
      error:
        "Введите логин/email и пароль"
    }, 400);
  }

  /* -------------------------
     FIND ACCOUNT
  ------------------------- */

  const account =
    await env.DB
      .prepare(`
        SELECT
          accounts.id,
          accounts.username,
          accounts.email,
          accounts.balance,
          credentials.password_hash
        FROM accounts
        INNER JOIN credentials
          ON credentials.account_id =
             accounts.id
        WHERE
          LOWER(accounts.username) =
            LOWER(?)
          OR
          LOWER(accounts.email) =
            LOWER(?)
        LIMIT 1
      `)
      .bind(
        loginValue,
        loginValue
      )
      .first();

  if (!account) {
    return json({
      error:
        "Неверный логин/email или пароль"
    }, 401);
  }

  /* -------------------------
     VERIFY PASSWORD
  ------------------------- */

  const valid =
    await verifyPassword(
      password,
      account.password_hash
    );

  if (!valid) {
    return json({
      error:
        "Неверный логин/email или пароль"
    }, 401);
  }

  /* -------------------------
     CREATE SESSION
  ------------------------- */

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
        email: account.email,
        balance:
          Number(
            account.balance || 0
          )
      }
    },
    200,
    {
      "Set-Cookie":
        session.cookie
    }
  );
}

/* =========================================================
   ME
   GET /api/auth/me
========================================================= */

export async function me(request, env) {
  const account =
    await getSessionAccount(
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
      email: account.email,
      balance:
        Number(
          account.balance || 0
        )
    }
  });
}

/* =========================================================
   LOGOUT
   POST /api/auth/logout
========================================================= */

export async function logout(request, env) {
  const account =
    await getSessionAccount(
      request,
      env
    );

  /*
    Даже если сессия уже отсутствует,
    logout всё равно успешный.
  */

  if (account) {
    await deleteSession(
      request,
      env
    );
  }

  return json(
    {
      success: true
    },
    200,
    {
      "Set-Cookie":
        "meant_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
    }
  );
}
