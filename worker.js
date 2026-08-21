const PBKDF2_ITERATIONS = 100000;
const HASH_BYTES = 32;

/* =========================================================
   RESPONSE
========================================================= */

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Credentials": "true",
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
      "Access-Control-Allow-Headers": "Content-Type, Accept",
      "Access-Control-Allow-Credentials": "true"
    }
  });
}

/* =========================================================
   CRYPTO
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
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      key,
      HASH_BYTES * 8
    );

  return {
    hash: bytesToBase64(
      new Uint8Array(bits)
    ),

    salt: bytesToBase64(
      salt
    )
  };
}

async function verifyPassword(
  password,
  stored
) {

  try {

    const parts =
      stored.split("$");

    if (parts.length !== 2) {
      return false;
    }

    const salt =
      base64ToBytes(parts[0]);

    const expected =
      base64ToBytes(parts[1]);

    const key =
      await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
      );

    const bits =
      await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt,
          iterations: PBKDF2_ITERATIONS,
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
        actual[i] ^ expected[i];

    }

    return difference === 0;

  } catch {

    return false;

  }
}

async function createPasswordHash(
  password
) {

  const result =
    await hashPassword(password);

  return (
    result.salt +
    "$" +
    result.hash
  );
}

/* =========================================================
   SESSION
========================================================= */

function createToken() {

  return bytesToBase64(
    randomBytes(32)
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

}

function createSessionId() {

  return crypto.randomUUID();

}

function getCookie(
  request,
  name
) {

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

      return decodeURIComponent(
        item.substring(
          name.length + 1
        )
      );

    }

  }

  return null;
}

async function readJson(
  request
) {

  try {

    return await request.json();

  } catch {

    return null;

  }
}

async function createSession(
  env,
  accountId
) {

  const token =
    createToken();

  const tokenHash =
    await sha256Base64(token);

  const sessionId =
    createSessionId();

  const expires =
    new Date(
      Date.now() +
      30 *
      24 *
      60 *
      60 *
      1000
    ).toISOString();

  await env.DB
    .prepare(`
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

async function getCurrentAccount(
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
    await sha256Base64(token);

  const row =
    await env.DB
      .prepare(`
        SELECT
          accounts.id,
          accounts.username,
          accounts.balance,
          sessions.expires_at
        FROM sessions
        INNER JOIN accounts
          ON accounts.id =
             sessions.account_id
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
   REGISTER
========================================================= */

async function register(
  request,
  env
) {

  const body =
    await readJson(request);

  if (!body) {

    return json({
      error: "Неверный JSON"
    }, 400);

  }

  const username =
    String(
      body.username || ""
    ).trim();

  const password =
    String(
      body.password || ""
    );

  if (!username) {

    return json({
      error: "Введите никнейм"
    }, 400);

  }

  if (username.length < 3) {

    return json({
      error:
        "Никнейм должен содержать минимум 3 символа"
    }, 400);

  }

  if (username.length > 24) {

    return json({
      error:
        "Никнейм слишком длинный"
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

  const existing =
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

  if (existing) {

    return json({
      error:
        "Этот никнейм уже занят"
    }, 409);

  }

  const accountId =
    crypto.randomUUID();

  const passwordHash =
    await createPasswordHash(
      password
    );

  try {

    await env.DB
      .prepare(`
        INSERT INTO accounts
        (id, username, balance)
        VALUES (?, ?, 0)
      `)
      .bind(
        accountId,
        username
      )
      .run();

    await env.DB
      .prepare(`
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

      await env.DB
        .prepare(`
          DELETE FROM credentials
          WHERE account_id = ?
        `)
        .bind(accountId)
        .run();

      await env.DB
        .prepare(`
          DELETE FROM accounts
          WHERE id = ?
        `)
        .bind(accountId)
        .run();

    } catch {}

    return json({
      error:
        "Ошибка базы данных: " +
        (
          error?.message ||
          String(error)
        )
    }, 500);

  }

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
        "meant_session=" +
        encodeURIComponent(
          session.token
        ) +
        "; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax"
    }
  );
}

/* =========================================================
   LOGIN
========================================================= */

async function login(
  request,
  env
) {

  const body =
    await readJson(request);

  if (!body) {

    return json({
      error: "Неверный JSON"
    }, 400);

  }

  const username =
    String(
      body.username || ""
    ).trim();

  const password =
    String(
      body.password || ""
    );

  if (
    !username ||
    !password
  ) {

    return json({
      error:
        "Введите никнейм и пароль"
    }, 400);

  }

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
        WHERE LOWER(accounts.username) =
              LOWER(?)
        LIMIT 1
      `)
      .bind(username)
      .first();

  if (!account) {

    return json({
      error:
        "Неверный никнейм или пароль"
    }, 401);

  }

  const valid =
    await verifyPassword(
      password,
      account.password_hash
    );

  if (!valid) {

    return json({
      error:
        "Неверный никнейм или пароль"
    }, 401);

  }

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
        balance:
          Number(
            account.balance || 0
          )
      }
    },
    200,
    {
      "Set-Cookie":
        "meant_session=" +
        encodeURIComponent(
          session.token
        ) +
        "; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax"
    }
  );
}

/* =========================================================
   ME
========================================================= */

async function me(
  request,
  env
) {

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
      balance:
        Number(
          account.balance || 0
        )
    }
  });
}

/* =========================================================
   LOGOUT
========================================================= */

async function logout(
  request,
  env
) {

  const token =
    getCookie(
      request,
      "meant_session"
    );

  if (token) {

    const tokenHash =
      await sha256Base64(
        token
      );

    await env.DB
      .prepare(`
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
        "meant_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
    }
  );
}

/* =========================================================
   TEBEX HELPERS
========================================================= */

function getTebexAuth(
  env
) {

  if (
    !env.TEBEX_PUBLIC_TOKEN ||
    !env.TEBEX_PRIVATE_KEY
  ) {

    return null;

  }

  return btoa(
    env.TEBEX_PUBLIC_TOKEN +
    ":" +
    env.TEBEX_PRIVATE_KEY
  );
}

async function tebexRequest(
  env,
  url,
  options = {}
) {

  const auth =
    getTebexAuth(env);

  if (!auth) {

    throw new Error(
      "Не настроены TEBEX_PUBLIC_TOKEN и TEBEX_PRIVATE_KEY"
    );

  }

  const headers =
    new Headers(
      options.headers || {}
    );

  headers.set(
    "Authorization",
    "Basic " + auth
  );

  headers.set(
    "Content-Type",
    "application/json"
  );

  headers.set(
    "Accept",
    "application/json"
  );

  const response =
    await fetch(
      url,
      {
        ...options,
        headers
      }
    );

  const raw =
    await response.text();

  let data = null;

  if (raw.trim()) {

    try {

      data =
        JSON.parse(raw);

    } catch {

      data = {
        raw
      };

    }

  }

  if (!response.ok) {

    let message =
      "Tebex HTTP " +
      response.status;

    if (
      data?.detail
    ) {

      message =
        data.detail;

    } else if (
      data?.error
    ) {

      message =
        data.error;

    } else if (
      data?.message
    ) {

      message =
        data.message;

    }

    throw new Error(
      message
    );

  }

  return data;
}

/* =========================================================
   PRODUCT -> TEBEX PACKAGE
========================================================= */

function getTebexPackageId(
  env,
  productId
) {

  if (
    productId ===
    "30-days"
  ) {

    return env.TEBEX_PACKAGE_30_DAYS;

  }

  if (
    productId ===
    "90-days"
  ) {

    return env.TEBEX_PACKAGE_90_DAYS;

  }

  if (
    productId ===
    "forever"
  ) {

    return env.TEBEX_PACKAGE_FOREVER;

  }

  return null;
}

/* =========================================================
   CHECKOUT
========================================================= */

async function checkout(
  request,
  env
) {

  /*
    1. Проверяем авторизацию.
  */

  const account =
    await getCurrentAccount(
      request,
      env
    );

  if (!account) {

    return json({
      error:
        "Сначала войдите в аккаунт"
    }, 401);

  }

  /*
    2. Проверяем Tebex secrets.
  */

  if (
    !env.TEBEX_PUBLIC_TOKEN ||
    !env.TEBEX_PRIVATE_KEY
  ) {

    return json({
      error:
        "Не настроены TEBEX_PUBLIC_TOKEN и TEBEX_PRIVATE_KEY"
    }, 500);

  }

  /*
    3. Читаем корзину.
  */

  const body =
    await readJson(request);

  if (!body) {

    return json({
      error:
        "Неверный JSON"
    }, 400);

  }

  if (
    !Array.isArray(
      body.items
    ) ||
    body.items.length === 0
  ) {

    return json({
      error:
        "Корзина пуста"
    }, 400);

  }

  /*
    На этом этапе разрешаем
    только один товар за одну оплату.

    Это безопаснее для нашей
    первой версии магазина.
  */

  if (
    body.items.length !== 1
  ) {

    return json({
      error:
        "За одну оплату можно купить только один товар"
    }, 400);

  }

  const item =
    body.items[0];

  const productId =
    String(
      item.productId || ""
    );

  const quantity =
    Number(
      item.qty || 1
    );

  if (
    !productId
  ) {

    return json({
      error:
        "Не указан товар"
    }, 400);

  }

  if (
    !Number.isInteger(quantity) ||
    quantity !== 1
  ) {

    return json({
      error:
        "Некорректное количество товара"
    }, 400);

  }

  /*
    4. Получаем настоящий Tebex package ID
       только из Worker secrets.

    Пользователь не может передать
    произвольный package ID.
  */

  const packageId =
    getTebexPackageId(
      env,
      productId
    );

  if (!packageId) {

    return json({
      error:
        "Не настроен Tebex Package ID для товара: " +
        productId
    }, 500);

  }

  /*
    5. URL возврата.
  */

  const requestUrl =
    new URL(
      request.url
    );

  const origin =
    requestUrl.origin;

  const completeUrl =
    origin +
    "/shop.html?payment=success";

  const cancelUrl =
    origin +
    "/shop.html?payment=cancel";

  /*
    6. Получаем IP пользователя.
  */

  const ip =
    request.headers.get(
      "CF-Connecting-IP"
    ) ||
    request.headers.get(
      "X-Forwarded-For"
    )?.split(",")[0]
      ?.trim() ||
    "";

  /*
    7. Создаём Tebex basket.
  */

  let basket;

  try {

    basket =
      await tebexRequest(
        env,
        "https://headless.tebex.io/api/accounts/" +
          encodeURIComponent(
            env.TEBEX_PUBLIC_TOKEN
          ) +
          "/baskets",
        {
          method: "POST",

          body: JSON.stringify({

            complete_url:
              completeUrl,

            cancel_url:
              cancelUrl,

            complete_auto_redirect:
              true,

            custom: {

              meant_account_id:
                account.id,

              meant_username:
                account.username,

              meant_product_id:
                productId

            },

            ...(ip
              ? {
                  ip_address: ip
                }
              : {})

          })
        }
      );

  } catch (error) {

    console.error(
      "Tebex basket error:",
      error
    );

    return json({
      error:
        "Tebex не смог создать корзину: " +
        (
          error?.message ||
          String(error)
        )
    }, 502);

  }

  /*
    Tebex может вернуть basket
    непосредственно или внутри data.
  */

  const basketData =
    basket?.data ||
    basket;

  const basketIdent =
    basketData?.ident;

  if (!basketIdent) {

    console.error(
      "Tebex basket response:",
      basket
    );

    return json({
      error:
        "Tebex не вернул идентификатор корзины"
    }, 502);

  }

  /*
    8. Добавляем package.
  */

  let updatedBasket;

  try {

    updatedBasket =
      await tebexRequest(
        env,
        "https://headless.tebex.io/api/baskets/" +
          encodeURIComponent(
            basketIdent
          ) +
          "/packages",
        {
          method: "POST",

          body: JSON.stringify({

            package_id:
              String(packageId),

            quantity: 1

          })
        }
      );

  } catch (error) {

    console.error(
      "Tebex package error:",
      error
    );

    return json({
      error:
        "Tebex не смог добавить товар в корзину: " +
        (
          error?.message ||
          String(error)
        )
    }, 502);

  }

  /*
    9. Ищем ссылку checkout.
  */

  const checkoutUrl =
    updatedBasket?.links?.checkout ||
    updatedBasket?.data?.links?.checkout ||
    basketData?.links?.checkout;

  if (!checkoutUrl) {

    console.error(
      "Tebex checkout response:",
      updatedBasket
    );

    return json({
      error:
        "Tebex не вернул ссылку на оплату"
    }, 502);

  }

  /*
    10. Сохраняем информацию
        о попытке покупки.

    Пока transaction_id неизвестен.
    После оплаты его обработает webhook.
  */

  try {

    await env.DB
      .prepare(`
        INSERT INTO transactions
        (
          account_id,
          type,
          amount,
          balance_after,
          tebex_transaction_id,
          webhook_id,
          product_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        account.id,
        "purchase_pending",
        0,
        Number(
          account.balance || 0
        ),
        null,
        null,
        productId
      )
      .run();

  } catch (error) {

    console.error(
      "Pending transaction DB error:",
      error
    );

    /*
      Сам checkout всё равно можно
      продолжить — Tebex уже создал
      корзину.
    */

  }

  /*
    11. Возвращаем shop.html
        нормальный JSON.
  */

  return json({
    success: true,

    checkout_url:
      checkoutUrl,

    basket_ident:
      basketIdent,

    product_id:
      productId
  });

}

/* =========================================================
   HEALTH
========================================================= */

async function health(
  env
) {

  try {

    await env.DB
      .prepare(
        "SELECT 1"
      )
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

      accounts:
        Number(
          accounts?.count || 0
        ),

      tebex:
        Boolean(
          env.TEBEX_PUBLIC_TOKEN &&
          env.TEBEX_PRIVATE_KEY
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

/* =========================================================
   MAIN WORKER
========================================================= */

export default {

  async fetch(
    request,
    env
  ) {

    if (
      request.method ===
      "OPTIONS"
    ) {

      return optionsResponse();

    }

    const url =
      new URL(
        request.url
      );

    const path =
      url.pathname;

    try {

      /* REGISTER */

      if (
        path ===
        "/api/auth/register" &&
        request.method ===
        "POST"
      ) {

        return await register(
          request,
          env
        );

      }

      /* LOGIN */

      if (
        path ===
        "/api/auth/login" &&
        request.method ===
        "POST"
      ) {

        return await login(
          request,
          env
        );

      }

      /* ME */

      if (
        path ===
        "/api/auth/me" &&
        request.method ===
        "GET"
      ) {

        return await me(
          request,
          env
        );

      }

      /* LOGOUT */

      if (
        path ===
        "/api/auth/logout" &&
        request.method ===
        "POST"
      ) {

        return await logout(
          request,
          env
        );

      }

      /* CHECKOUT */

      if (
        path ===
        "/api/checkout" &&
        request.method ===
        "POST"
      ) {

        return await checkout(
          request,
          env
        );

      }

      /* HEALTH */

      if (
        path ===
        "/api/health" &&
        request.method ===
        "GET"
      ) {

        return await health(
          env
        );

      }

      /*
        Если это обычная страница,
        картинка, CSS, JS и т.д.
      */

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

      console.error(
        error
      );

      return json({

        error:
          error?.message ||
          String(error)

      }, 500);

    }

  }

};
