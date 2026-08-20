const PRODUCTS = {
  "30-days": {
    name: "30 дней",
    price: 99,
    grant: "access",
    days: 30
  },
  "90-days": {
    name: "90 дней",
    price: 159,
    grant: "access",
    days: 90
  },
  "forever": {
    name: "Навсегда",
    price: 499,
    grant: "access",
    days: null
  },
  "topup-50": {
    name: "Пополнение 50 ₽",
    price: 50,
    grant: "balance",
    amount: 50
  },
  "topup-100": {
    name: "Пополнение 100 ₽",
    price: 100,
    grant: "balance",
    amount: 100
  },
  "topup-200": {
    name: "Пополнение 200 ₽",
    price: 200,
    grant: "balance",
    amount: 200
  },
  "topup-400": {
    name: "Пополнение 400 ₽",
    price: 400,
    grant: "balance",
    amount: 400
  },
  "topup-500": {
    name: "Пополнение 500 ₽ + 50 ₽",
    price: 500,
    grant: "balance",
    amount: 550
  },
  "topup-800": {
    name: "Пополнение 800 ₽ + 80 ₽",
    price: 800,
    grant: "balance",
    amount: 880
  }
};

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "content-type",
  "access-control-max-age": "86400"
};

function json(data, status = 200, extra = {}) {
  const headers = new Headers({
    "content-type": "application/json; charset=UTF-8",
    "cache-control": "no-store",
    ...CORS,
    ...extra
  });

  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}

function text(message, status = 200) {
  return new Response(message, {
    status,
    headers: {
      "content-type": "text/plain; charset=UTF-8",
      ...CORS
    }
  });
}

function randomId(bytes = 32) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);

  return [...a]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function b64(bytes) {
  let s = "";

  for (const b of bytes) {
    s += String.fromCharCode(b);
  }

  return btoa(s);
}

function fromB64(value) {
  const raw = atob(value);
  const out = new Uint8Array(raw.length);

  for (let i = 0; i < raw.length; i++) {
    out[i] = raw.charCodeAt(i);
  }

  return out;
}

async function digestHex(text) {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", data);

  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function safeEqual(a, b) {
  if (!a || !b || a.length !== b.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

async function hmacHex(body, secret) {
  const bodyHash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(body)
  );

  const bodyHashHex = [...new Uint8Array(bodyHash)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(bodyHashHex)
  );

  return [...new Uint8Array(signature)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}


/* =========================
   AUTH
========================= */

const SESSION_DAYS = 30;
const PBKDF2_ITERATIONS = 120000;
const COOKIE_NAME = "meant_session";

function cookie(name, value, maxAge) {
  return `${name}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function clearCookie(name) {
  return `${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function getCookie(req, name) {
  const raw = req.headers.get("Cookie") || "";

  for (const part of raw.split(";")) {
    const [key, ...value] = part.trim().split("=");

    if (key === name) {
      return value.join("=");
    }
  }

  return null;
}

async function passwordHash(password, saltB64) {
  const salt = saltB64
    ? fromB64(saltB64)
    : crypto.getRandomValues(new Uint8Array(16));

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
    256
  );

  return {
    salt: b64(salt),
    hash: b64(new Uint8Array(bits))
  };
}

async function verifyPassword(password, stored) {
  const parts = String(stored || "").split("$");

  if (parts.length !== 4) {
    return false;
  }

  const [scheme, iterations, salt, hash] = parts;

  if (
    scheme !== "pbkdf2-sha256" ||
    Number(iterations) !== PBKDF2_ITERATIONS ||
    !salt ||
    !hash
  ) {
    return false;
  }

  const result = await passwordHash(password, salt);

  return safeEqual(result.hash, hash);
}

async function currentAccount(env, req) {
  const token = getCookie(req, COOKIE_NAME);

  if (!token) {
    return null;
  }

  const tokenHash = await digestHex(token);

  const row = await env.DB
    .prepare(`
      SELECT
        a.id,
        a.username,
        a.balance,
        a.created_at,
        a.updated_at,
        s.expires_at
      FROM sessions s
      JOIN accounts a ON a.id = s.account_id
      WHERE s.token_hash = ?
        AND s.expires_at > CURRENT_TIMESTAMP
    `)
    .bind(tokenHash)
    .first();

  return row || null;
}

async function createSession(env, accountId) {
  const token = randomId(32);
  const tokenHash = await digestHex(token);

  const expires = new Date(
    Date.now() + SESSION_DAYS * 86400000
  ).toISOString();

  await env.DB
    .prepare(`
      DELETE FROM sessions
      WHERE account_id = ?
         OR expires_at <= CURRENT_TIMESTAMP
    `)
    .bind(accountId)
    .run();

  await env.DB
    .prepare(`
      INSERT INTO sessions
        (id, account_id, token_hash, expires_at)
      VALUES (?, ?, ?, ?)
    `)
    .bind(
      randomId(16),
      accountId,
      tokenHash,
      expires
    )
    .run();

  return token;
}

async function authApi(env, req, url) {

  /* REGISTER */

  if (
    url.pathname === "/api/auth/register" &&
    req.method === "POST"
  ) {
    let body;

    try {
      body = await req.json();
    } catch {
      return json(
        { error: "Некорректный JSON" },
        400
      );
    }

    const username = String(body?.username || "").trim();
    const password = String(body?.password || "");

    if (
      !/^[A-Za-zА-Яа-яЁё0-9_]{3,24}$/.test(username)
    ) {
      return json(
        {
          error:
            "Никнейм: 3–24 символа, только буквы, цифры и _"
        },
        400
      );
    }

    if (
      password.length < 8 ||
      password.length > 128
    ) {
      return json(
        {
          error:
            "Пароль должен содержать от 8 до 128 символов"
        },
        400
      );
    }

    const exists = await env.DB
      .prepare(`
        SELECT id
        FROM accounts
        WHERE lower(username) = lower(?)
      `)
      .bind(username)
      .first();

    if (exists) {
      return json(
        {
          error: "Такой никнейм уже занят"
        },
        409
      );
    }

    const accountId = randomId(16);

    const passwordData =
      await passwordHash(password);

    const storedPassword =
      `pbkdf2-sha256$${PBKDF2_ITERATIONS}$${passwordData.salt}$${passwordData.hash}`;

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
          storedPassword
        )
        .run();

      const token =
        await createSession(
          env,
          accountId
        );

      return json(
        {
          ok: true,
          account: {
            id: accountId,
            username,
            balance: 0
          }
        },
        201,
        {
          "set-cookie": cookie(
            COOKIE_NAME,
            token,
            SESSION_DAYS * 86400
          )
        }
      );

    } catch (error) {
      return json(
        {
          error:
            error?.message ||
            "Не удалось создать аккаунт"
        },
        500
      );
    }
  }


  /* LOGIN */

  if (
    url.pathname === "/api/auth/login" &&
    req.method === "POST"
  ) {
    let body;

    try {
      body = await req.json();
    } catch {
      return json(
        { error: "Некорректный JSON" },
        400
      );
    }

    const username =
      String(body?.username || "").trim();

    const password =
      String(body?.password || "");

    try {
      const row = await env.DB
        .prepare(`
          SELECT
            a.id,
            a.username,
            a.balance,
            c.password_hash
          FROM accounts a
          JOIN credentials c
            ON c.account_id = a.id
          WHERE lower(a.username) = lower(?)
        `)
        .bind(username)
        .first();

      if (
        !row ||
        !(await verifyPassword(
          password,
          row.password_hash
        ))
      ) {
        return json(
          {
            error:
              "Неверный никнейм или пароль"
          },
          401
        );
      }

      const token =
        await createSession(
          env,
          row.id
        );

      return json(
        {
          ok: true,
          account: {
            id: row.id,
            username: row.username,
            balance: row.balance
          }
        },
        200,
        {
          "set-cookie": cookie(
            COOKIE_NAME,
            token,
            SESSION_DAYS * 86400
          )
        }
      );

    } catch (error) {
      return json(
        {
          error:
            error?.message ||
            "Ошибка входа"
        },
        500
      );
    }
  }


  /* CURRENT ACCOUNT */

  if (
    url.pathname === "/api/auth/me" &&
    req.method === "GET"
  ) {
    try {
      const account =
        await currentAccount(
          env,
          req
        );

      if (!account) {
        return json(
          {
            authenticated: false
          },
          401
        );
      }

      return json({
        authenticated: true,
        account
      });

    } catch (error) {
      return json(
        {
          error:
            error?.message ||
            "Ошибка авторизации"
        },
        500
      );
    }
  }


  /* LOGOUT */

  if (
    url.pathname === "/api/auth/logout" &&
    req.method === "POST"
  ) {
    try {
      const token =
        getCookie(
          req,
          COOKIE_NAME
        );

      if (token) {
        const tokenHash =
          await digestHex(token);

        await env.DB
          .prepare(`
            DELETE FROM sessions
            WHERE token_hash = ?
          `)
          .bind(tokenHash)
          .run();
      }

      return json(
        { ok: true },
        200,
        {
          "set-cookie":
            clearCookie(COOKIE_NAME)
        }
      );

    } catch (error) {
      return json(
        {
          error:
            error?.message ||
            "Ошибка выхода"
        },
        500
      );
    }
  }

  return null;
}


/* =========================
   ACCOUNT
========================= */

async function getAccount(env, id) {
  let account = await env.DB
    .prepare(`
      SELECT
        id,
        username,
        balance,
        created_at,
        updated_at
      FROM accounts
      WHERE id = ?
    `)
    .bind(id)
    .first();

  if (!account) {
    await env.DB
      .prepare(`
        INSERT INTO accounts
          (id, username, balance)
        VALUES (?, ?, 0)
      `)
      .bind(
        id,
        id
      )
      .run();

    account = await env.DB
      .prepare(`
        SELECT
          id,
          username,
          balance,
          created_at,
          updated_at
        FROM accounts
        WHERE id = ?
      `)
      .bind(id)
      .first();
  }

  return account;
}


/* =========================
   TEBEX CHECKOUT
========================= */

async function tebexCheckout(
  env,
  accountId,
  items,
  origin
) {
  if (
    !env.TEBEX_PROJECT_ID ||
    !env.TEBEX_PRIVATE_KEY
  ) {
    throw new Error(
      "Tebex credentials are not configured"
    );
  }

  const basket = {
    first_name: "MEANT",
    last_name: "User",
    return_url:
      `${origin}/shop.html`,
    complete_url:
      `${origin}/profile.html?payment=complete`,
    complete_auto_redirect: true,
    custom: {
      meant_account_id:
        accountId,
      source: "meant-shop"
    }
  };

  const checkoutItems =
    items.map(
      ({
        productId,
        qty = 1
      }) => {
        const product =
          PRODUCTS[productId];

        if (!product) {
          throw new Error(
            `Unknown product: ${productId}`
          );
        }

        return {
          package: {
            name: product.name,
            price: product.price,
            type: "single",
            qty: 1,
            custom: {
              meant_product_id:
                productId
            }
          },
          qty,
          type: "single"
        };
      }
    );

  const auth =
    btoa(
      `${env.TEBEX_PROJECT_ID}:${env.TEBEX_PRIVATE_KEY}`
    );

  const response =
    await fetch(
      "https://checkout.tebex.io/api/checkout",
      {
        method: "POST",
        headers: {
          Authorization:
            `Basic ${auth}`,
          "Content-Type":
            "application/json"
        },
        body: JSON.stringify({
          basket,
          items: checkoutItems
        })
      }
    );

  let data;

  try {
    data = await response.json();
  } catch {
    throw new Error(
      `Tebex returned HTTP ${response.status}`
    );
  }

  if (!response.ok) {
    throw new Error(
      data?.message ||
      "Tebex checkout failed"
    );
  }

  return data;
}


/* =========================
   TEBEX WEBHOOK
========================= */

async function webhook(env, req) {
  const raw =
    await req.text();

  const signature =
    req.headers.get("X-Signature") ||
    req.headers.get(
      "X-Tebex-Signature"
    );

  if (
    !signature ||
    !env.TEBEX_WEBHOOK_SECRET
  ) {
    return text(
      "Unauthorized",
      401
    );
  }

  const expected =
    await hmacHex(
      raw,
      env.TEBEX_WEBHOOK_SECRET
    );

  if (
    !safeEqual(
      signature,
      expected
    )
  ) {
    return text(
      "Invalid signature",
      401
    );
  }

  let event;

  try {
    event =
      JSON.parse(raw);
  } catch {
    return text(
      "Bad JSON",
      400
    );
  }

  if (
    event.type ===
    "validation.webhook"
  ) {
    return json({
      id: event.id
    });
  }

  const eventId =
    event.id;

  const type =
    event.type ||
    "unknown";

  if (!eventId) {
    return text(
      "Missing event id",
      400
    );
  }

  const existing =
    await env.DB
      .prepare(`
        SELECT webhook_id
        FROM webhook_events
        WHERE webhook_id = ?
      `)
      .bind(eventId)
      .first();

  if (existing) {
    return json({
      ok: true,
      duplicate: true
    });
  }

  const subject =
    event.subject || {};

  const transactionId =
    subject.transaction_id ||
    null;

  const status =
    subject.status?.id;

  if (
    type === "payment.completed" &&
    status === 1
  ) {
    const accountId =
      subject.custom?.meant_account_id ||
      subject.customer?.username?.id ||
      subject.customer?.username?.username;

    if (!accountId) {
      return text(
        "Missing MEANT account id",
        422
      );
    }

    await getAccount(
      env,
      String(accountId)
    );

    const products =
      subject.products || [];

    for (
      const item of products
    ) {
      const productId =
        item.custom?.meant_product_id ||
        Object.keys(PRODUCTS)
          .find(
            key =>
              PRODUCTS[key].name ===
              item.name
          );

      const product =
        PRODUCTS[productId];

      if (!product) {
        continue;
      }

      const qty =
        Number(
          item.quantity || 1
        );

      if (
        product.grant ===
        "balance"
      ) {
        const amount =
          product.amount * qty;

        await env.DB
          .prepare(`
            UPDATE accounts
            SET
              balance = balance + ?,
              updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
          `)
          .bind(
            amount,
            String(accountId)
          )
          .run();

        const account =
          await getAccount(
            env,
            String(accountId)
          );

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
            String(accountId),
            "tebex_topup",
            amount,
            account.balance,
            transactionId,
            eventId,
            productId
          )
          .run();

      } else {
        let expires = null;

        if (
          product.days !== null
        ) {
          const date =
            new Date();

          date.setUTCDate(
            date.getUTCDate() +
            product.days * qty
          );

          expires =
            date.toISOString();
        }

        await env.DB
          .prepare(`
            INSERT INTO entitlements
              (
                account_id,
                product_id,
                product_name,
                expires_at,
                status,
                tebex_transaction_id
              )
            VALUES (?, ?, ?, ?, ?, ?)
          `)
          .bind(
            String(accountId),
            productId,
            product.name,
            expires,
            "active",
            transactionId
          )
          .run();

        const account =
          await getAccount(
            env,
            String(accountId)
          );

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
            String(accountId),
            "purchase",
            0,
            account.balance,
            transactionId,
            eventId,
            productId
          )
          .run();
      }
    }
  }

  if (
    [
      "payment.refunded",
      "payment.dispute.opened",
      "payment.dispute.lost"
    ].includes(type)
  ) {
    await env.DB
      .prepare(`
        UPDATE entitlements
        SET status = 'revoked'
        WHERE tebex_transaction_id = ?
      `)
      .bind(transactionId)
      .run();

    const rows =
      await env.DB
        .prepare(`
          SELECT
            account_id,
            amount,
            product_id
          FROM transactions
          WHERE tebex_transaction_id = ?
            AND type = 'tebex_topup'
        `)
        .bind(transactionId)
        .all();

    for (
      const row of
      rows.results || []
    ) {
      await env.DB
        .prepare(`
          UPDATE accounts
          SET
            balance =
              MAX(0, balance - ?),
            updated_at =
              CURRENT_TIMESTAMP
          WHERE id = ?
        `)
        .bind(
          row.amount,
          row.account_id
        )
        .run();
    }
  }

  await env.DB
    .prepare(`
      INSERT INTO webhook_events
        (
          webhook_id,
          type,
          transaction_id,
          payload
        )
      VALUES (?, ?, ?, ?)
    `)
    .bind(
      eventId,
      type,
      transactionId,
      raw
    )
    .run();

  return json({
    ok: true
  });
}


/* =========================
   API
========================= */

async function api(
  env,
  req,
  url
) {
  if (
    req.method ===
    "OPTIONS"
  ) {
    return new Response(
      null,
      {
        status: 204,
        headers: CORS
      }
    );
  }

  const auth =
    await authApi(
      env,
      req,
      url
    );

  if (auth) {
    return auth;
  }

  if (
    url.pathname ===
    "/api/health"
  ) {
    return json({
      ok: true,
      project_id:
        env.TEBEX_PROJECT_ID ||
        ""
    });
  }


  /* PROFILE / ACCOUNT */

  if (
    url.pathname ===
      "/api/me" &&
    req.method === "GET"
  ) {
    try {
      const session =
        await currentAccount(
          env,
          req
        );

      const accountId =
        session?.id ||
        url.searchParams.get(
          "accountId"
        );

      if (!accountId) {
        return json(
          {
            error:
              "Требуется авторизация"
          },
          401
        );
      }

      const account =
        await getAccount(
          env,
          accountId
        );

      const entitlements =
        await env.DB
          .prepare(`
            SELECT
              product_id,
              product_name,
              expires_at,
              status,
              created_at
            FROM entitlements
            WHERE account_id = ?
            ORDER BY created_at DESC
          `)
          .bind(accountId)
          .all();

      const history =
        await env.DB
          .prepare(`
            SELECT
              type,
              amount,
              balance_after,
              product_id,
              created_at
            FROM transactions
            WHERE account_id = ?
            ORDER BY id DESC
            LIMIT 30
          `)
          .bind(accountId)
          .all();

      return json({
        account,
        entitlements:
          entitlements.results ||
          [],
        history:
          history.results ||
          []
      });

    } catch (error) {
      return json(
        {
          error:
            error?.message ||
            "Ошибка получения профиля"
        },
        500
      );
    }
  }


  /* CHECKOUT */

  if (
    url.pathname ===
      "/api/checkout" &&
    req.method === "POST"
  ) {
    try {
      const session =
        await currentAccount(
          env,
          req
        );

      if (!session) {
        return json(
          {
            error:
              "Требуется авторизация"
          },
          401
        );
      }

      let body;

      try {
        body =
          await req.json();
      } catch {
        return json(
          {
            error:
              "Некорректный JSON"
          },
          400
        );
      }

      const items =
        Array.isArray(
          body?.items
        )
          ? body.items
          : [];

      if (!items.length) {
        return json(
          {
            error:
              "Cart is empty"
          },
          400
        );
      }

      const checkout =
        await tebexCheckout(
          env,
          String(session.id),
          items,
          url.origin
        );

      return json({
        checkout_url:
          checkout?.links?.checkout ||
          checkout?.checkout_url ||
          checkout?.links?.payment ||
          null,
        ident:
          checkout?.ident ||
          checkout?.id ||
          null
      });

    } catch (error) {
      return json(
        {
          error:
            error?.message ||
            "Ошибка создания платежа"
        },
        500
      );
    }
  }


  /* WEBHOOK */

  if (
    url.pathname ===
      "/api/tebex/webhook" &&
    req.method === "POST"
  ) {
    try {
      return await webhook(
        env,
        req
      );
    } catch (error) {
      return json(
        {
          error:
            error?.message ||
            "Webhook error"
        },
        500
      );
    }
  }


  /* IMPORTANT:
     API NEVER FALLS THROUGH
     TO HTML ASSETS
  */

  return json(
    {
      error:
        "API endpoint not found",
      path:
        url.pathname,
      method:
        req.method
    },
    404
  );
}


/* =========================
   WORKER
========================= */

export default {
  async fetch(req, env) {
    const url =
      new URL(req.url);

    try {
      if (
        url.pathname.startsWith(
          "/api/"
        )
      ) {
        return await api(
          env,
          req,
          url
        );
      }

      if (
        req.method ===
        "OPTIONS"
      ) {
        return new Response(
          null,
          {
            status: 204,
            headers: CORS
          }
        );
      }

      if (
        url.pathname === "/" ||
        url.pathname ===
          "/index.html"
      ) {
        return Response.redirect(
          new URL(
            "/visual.html",
            url
          ),
          302
        );
      }

      return env.ASSETS.fetch(
        req
      );

    } catch (error) {
      console.error(
        "Worker error:",
        error
      );

      if (
        url.pathname.startsWith(
          "/api/"
        )
      ) {
        return json(
          {
            error:
              error?.message ||
              "Internal Worker error"
          },
          500
        );
      }

      return text(
        "Internal Worker error",
        500
      );
    }
  }
};
