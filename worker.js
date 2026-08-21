const PBKDF2_ITERATIONS = 100000;
const HASH_BYTES = 32;

/* =========================================================
   JSON
========================================================= */

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      ...extraHeaders
    }
  });
}


/* =========================================================
   CORS
========================================================= */

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
   RANDOM / BASE64
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


/* =========================================================
   SHA256
========================================================= */

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
  const salt = randomBytes(16);

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
    salt: bytesToBase64(salt)
  };
}


async function createPasswordHash(password) {
  const result =
    await hashPassword(password);

  return (
    result.salt +
    "$" +
    result.hash
  );
}


async function verifyPassword(password, stored) {
  try {
    const parts =
      String(stored).split("$");

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


/* =========================================================
   TOKEN
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
    const item = part.trim();

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
   REQUEST JSON
========================================================= */

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}


/* =========================================================
   SESSION
========================================================= */

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

  await env.DB.prepare(`
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
    await env.DB.prepare(`
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
    await env.DB.prepare(`
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

    await env.DB.prepare(`
      INSERT INTO accounts
      (
        id,
        username,
        balance
      )
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

    try {

      await env.DB.prepare(`
        DELETE FROM credentials
        WHERE account_id = ?
      `)
        .bind(accountId)
        .run();

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
    await env.DB.prepare(`
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
        "meant_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
    }
  );
}


/* =========================================================
   HEALTH
========================================================= */

async function health(env) {
  try {

    await env.DB.prepare(
      "SELECT 1"
    ).first();

    const accounts =
      await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM accounts"
      ).first();

    return json({
      success: true,
      database: true,
      accounts:
        Number(
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


/* =========================================================
   TEBEX AUTH
========================================================= */

function getTebexAuth(env) {

  const publicToken =
    String(
      env.TEBEX_PUBLIC_TOKEN || ""
    ).trim();

  const privateKey =
    String(
      env.TEBEX_PRIVATE_KEY || ""
    ).trim();

  if (
    !publicToken ||
    !privateKey
  ) {
    throw new Error(
      "Не настроены TEBEX_PUBLIC_TOKEN и TEBEX_PRIVATE_KEY"
    );
  }

  return (
    "Basic " +
    btoa(
      publicToken +
      ":" +
      privateKey
    )
  );
}


/* =========================================================
   TEBEX REQUEST
========================================================= */

async function tebexRequest(
  env,
  url,
  options = {}
) {

  const headers = {
    "Authorization":
      getTebexAuth(env),

    "Content-Type":
      "application/json",

    "Accept":
      "application/json",

    ...(options.headers || {})
  };

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
      data = null;
    }
  }

  if (!response.ok) {

    let message =
      "Tebex HTTP " +
      response.status;

    if (data) {

      if (
        typeof data.error ===
        "string"
      ) {
        message =
          data.error;
      }

      else if (
        typeof data.message ===
        "string"
      ) {
        message =
          data.message;
      }

      else if (
        typeof data.detail ===
        "string"
      ) {
        message =
          data.detail;
      }
    }

    throw new Error(
      message
    );
  }

  return data;
}


/* =========================================================
   FIND TEBEX PACKAGE
========================================================= */

async function findTebexPackage(
  env,
  productId
) {

  const token =
    String(
      env.TEBEX_PUBLIC_TOKEN || ""
    ).trim();

  if (!token) {
    throw new Error(
      "TEBEX_PUBLIC_TOKEN не настроен"
    );
  }

  const url =
    "https://headless.tebex.io/api/accounts/" +
    encodeURIComponent(token) +
    "/packages";

  const data =
    await tebexRequest(
      env,
      url,
      {
        method: "GET"
      }
    );

  const packages =
    Array.isArray(data?.data)
      ? data.data
      : [];

  /*
    Можно указать реальные ID пакетов
    через Worker Variables.

    Если ID не указаны,
    используем поиск по названию.
  */

  const envNames = {
    "30-days":
      "TEBEX_PACKAGE_30_DAYS",

    "90-days":
      "TEBEX_PACKAGE_90_DAYS",

    "forever":
      "TEBEX_PACKAGE_FOREVER"
  };

  const envName =
    envNames[productId];

  const configuredId =
    envName
      ? String(
          env[envName] || ""
        ).trim()
      : "";

  if (configuredId) {

    const found =
      packages.find(
        pkg =>
          String(pkg.id) ===
          configuredId
      );

    if (found) {
      return found;
    }

    /*
      Даже если пакет не попал
      в список packages, его ID
      можно использовать напрямую.
    */

    return {
      id: configuredId,
      name: productId
    };
  }


  const names = {

    "30-days": [
      "30 дней",
      "30 days",
      "30 Days"
    ],

    "90-days": [
      "90 дней",
      "90 days",
      "90 Days"
    ],

    "forever": [
      "Навсегда",
      "Forever",
      "Lifetime",
      "Lifetime Access"
    ]

  };

  const wanted =
    names[productId] || [];

  const found =
    packages.find(pkg => {

      const packageName =
        String(
          pkg.name || ""
        )
          .trim()
          .toLowerCase();

      return wanted.some(
        name =>
          packageName ===
          String(
            name
          ).toLowerCase()
      );
    });

  if (!found) {

    throw new Error(
      "Товар Tebex не найден: " +
      productId +
      ". Укажи его ID через переменную Worker " +
      (envName || "")
    );
  }

  return found;
}


/* =========================================================
   CHECKOUT
========================================================= */

async function checkout(
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
      error:
        "Сначала войдите в аккаунт"
    }, 401);

  }


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
    Разрешаем только наши
    известные товары.
  */

  const allowedProducts = new Set([
    "30-days",
    "90-days",
    "forever"
  ]);


  const requestedItems =
    body.items;


  /*
    Защита от покупки
    произвольного Tebex package ID.
  */

  for (
    const item of requestedItems
  ) {

    if (
      !item ||
      !allowedProducts.has(
        String(
          item.productId || ""
        )
      )
    ) {

      return json({
        error:
          "Неизвестный товар"
      }, 400);

    }

    const qty =
      Number(
        item.qty || 1
      );

    if (
      !Number.isInteger(qty) ||
      qty < 1 ||
      qty > 1
    ) {

      return json({
        error:
          "Количество товара должно быть 1"
      }, 400);

    }

  }


  try {

    /*
      -------------------------------------------------------
      1. СОЗДАЁМ TEBEX BASKET
      -------------------------------------------------------
    */

    const origin =
      new URL(
        request.url
      ).origin;


    const basketUrl =
      "https://headless.tebex.io/api/accounts/" +
      encodeURIComponent(
        String(
          env.TEBEX_PUBLIC_TOKEN
        )
      ) +
      "/baskets";


    const basketData =
      await tebexRequest(
        env,
        basketUrl,
        {
          method: "POST",

          body: JSON.stringify({

            complete_url:
              origin +
              "/shop.html?payment=success",

            cancel_url:
              origin +
              "/shop.html?payment=cancel",

            complete_auto_redirect:
              true,

            custom: {

              account_id:
                account.id,

              username:
                account.username,

              source:
                "meant-shop",

              version:
                1

            }

          })
        }
      );


    const basket =
      basketData?.data ||
      basketData;


    const basketIdent =
      basket?.ident;


    if (!basketIdent) {

      throw new Error(
        "Tebex не вернул basket ident"
      );

    }


    /*
      -------------------------------------------------------
      2. ДОБАВЛЯЕМ ТОВАРЫ
      -------------------------------------------------------
    */

    for (
      const item of requestedItems
    ) {

      const productId =
        String(
          item.productId
        );

      const quantity =
        Number(
          item.qty || 1
        );


      const tebexPackage =
        await findTebexPackage(
          env,
          productId
        );


      const packageUrl =
        "https://headless.tebex.io/api/baskets/" +
        encodeURIComponent(
          basketIdent
        ) +
        "/packages";


      await tebexRequest(
        env,
        packageUrl,
        {
          method: "POST",

          body: JSON.stringify({

            package_id:
              String(
                tebexPackage.id
              ),

            quantity

          })
        }
      );

    }


    /*
      -------------------------------------------------------
      3. ПОЛУЧАЕМ ОБНОВЛЁННУЮ КОРЗИНУ
      -------------------------------------------------------
    */

    const finalUrl =
      "https://headless.tebex.io/api/accounts/" +
      encodeURIComponent(
        String(
          env.TEBEX_PUBLIC_TOKEN
        )
      ) +
      "/baskets/" +
      encodeURIComponent(
        basketIdent
      );


    const finalData =
      await tebexRequest(
        env,
        finalUrl,
        {
          method: "GET"
        }
      );


    const finalBasket =
      finalData?.data ||
      finalData;


    const checkoutUrl =
      finalBasket?.links?.checkout;


    if (!checkoutUrl) {

      throw new Error(
        "Tebex не вернул ссылку на оплату"
      );

    }


    /*
      -------------------------------------------------------
      4. СОХРАНЯЕМ ИНФОРМАЦИЮ О ПОКУПКЕ
      -------------------------------------------------------
    */

    /*
      В текущей схеме нет отдельной
      таблицы baskets/orders.

      Поэтому пока просто
      возвращаем checkout URL.

      Позже, когда сделаем webhook,
      webhook_events + entitlements
      будут использовать custom.account_id.
    */


    return json({
      success: true,

      checkout_url:
        checkoutUrl,

      basket_ident:
        basketIdent

    });


  } catch (error) {

    console.error(
      "Tebex checkout error:",
      error
    );


    return json({
      error:
        error?.message ||
        "Не удалось создать оплату"
    }, 500);

  }

}


/* =========================================================
   MAIN
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


      /* SHOP CHECKOUT */

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


      /* ASSETS */

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
