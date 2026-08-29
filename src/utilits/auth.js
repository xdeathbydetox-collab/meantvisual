import {
  createPasswordHash,
  verifyPassword
} from "./crypto.js";

import {
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

function normalizeUsername(value) {
  return String(value || "").trim();
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

   НИК + ПАРОЛЬ
   БЕЗ EMAIL
========================================================= */

export async function register(
  request,
  env
) {

  const body =
    await readJson(request);

  if (!body) {
    return json({
      success: false,
      error: "Неверный JSON"
    }, 400);
  }


  const username =
    normalizeUsername(
      body.username
    );

  const password =
    String(
      body.password || ""
    );


  /* -------------------------
     VALIDATION
  ------------------------- */

  if (!username) {
    return json({
      success: false,
      error: "Введите никнейм"
    }, 400);
  }


  if (!validUsername(username)) {
    return json({
      success: false,
      error:
        "Никнейм должен содержать 3-24 символа: буквы, цифры, _, -, ."
    }, 400);
  }


  if (!password) {
    return json({
      success: false,
      error: "Введите пароль"
    }, 400);
  }


  if (password.length < 8) {
    return json({
      success: false,
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
        WHERE LOWER(username) =
              LOWER(?)
        LIMIT 1
      `)
      .bind(username)
      .first();


  if (existingUsername) {
    return json({
      success: false,
      error:
        "Этот никнейм уже занят"
    }, 409);
  }


  /* -------------------------
     ACCOUNT
  ------------------------- */

  const accountId =
    crypto.randomUUID();


  const passwordHash =
    await createPasswordHash(
      password
    );


  try {

    /* ACCOUNT */

    await env.DB
      .prepare(`
        INSERT INTO accounts
        (
          id,
          username,
          balance
        )
        VALUES (?, ?, 0)
      `)
      .bind(
        accountId,
        username
      )
      .run();


    /* PASSWORD */

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

    /* -------------------------
       ROLLBACK
    ------------------------- */

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
      success: false,
      error:
        "Ошибка базы данных: " +
        (
          error?.message ||
          String(error)
        )
    }, 500);
  }


  /* -------------------------
     SESSION
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

   НИК + ПАРОЛЬ
========================================================= */

export async function login(
  request,
  env
) {

  const body =
    await readJson(request);


  if (!body) {
    return json({
      success: false,
      error:
        "Неверный JSON"
    }, 400);
  }


  const loginValue =
    normalizeUsername(
      body.login ??
      body.username
    );


  const password =
    String(
      body.password || ""
    );


  if (
    !loginValue ||
    !password
  ) {

    return json({
      success: false,
      error:
        "Введите ник и пароль"
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
          accounts.balance,
          credentials.password_hash

        FROM accounts

        INNER JOIN credentials
          ON credentials.account_id =
             accounts.id

        WHERE
          LOWER(accounts.username) =
            LOWER(?)

        LIMIT 1
      `)
      .bind(
        loginValue
      )
      .first();


  if (!account) {

    return json({
      success: false,
      error:
        "Неверный ник или пароль"
    }, 401);

  }


  /* -------------------------
     PASSWORD
  ------------------------- */

  const valid =
    await verifyPassword(
      password,
      account.password_hash
    );


  if (!valid) {

    return json({
      success: false,
      error:
        "Неверный ник или пароль"
    }, 401);

  }


  /* -------------------------
     SESSION
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
        id:
          account.id,

        username:
          account.username,

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

export async function me(
  request,
  env
) {

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

      id:
        account.id,

      username:
        account.username,

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

export async function logout(
  request,
  env
) {

  await deleteSession(
    request,
    env
  );


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
