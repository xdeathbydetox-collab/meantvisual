/* =========================================================
   AUTH.JS — MEANT SHOP
   Первоначальная версия
   Регистрация / вход БЕЗ EMAIL
========================================================= */


/* =========================================================
   SETTINGS
========================================================= */

const SESSION_DAYS = 30;

const PBKDF2_ITERATIONS = 100000;

const COOKIE_NAME = "meant_session";


/* =========================================================
   BASE64
========================================================= */

function b64(bytes) {

    let s = "";

    for (const b of bytes) {

        s += String.fromCharCode(b);

    }

    return btoa(s);

}


function fromB64(s) {

    const raw = atob(s);

    const out =
        new Uint8Array(
            raw.length
        );

    for (
        let i = 0;
        i < raw.length;
        i++
    ) {

        out[i] =
            raw.charCodeAt(i);

    }

    return out;

}


/* =========================================================
   RANDOM ID
========================================================= */

function randomId(
    bytes = 32
) {

    const a =
        new Uint8Array(
            bytes
        );

    crypto.getRandomValues(a);

    return [...a]
        .map(
            x =>
                x
                    .toString(16)
                    .padStart(2, "0")
        )
        .join("");

}


/* =========================================================
   SHA-256
========================================================= */

async function digestHex(
    text
) {

    const data =
        new TextEncoder()
            .encode(text);


    const digest =
        await crypto.subtle.digest(
            "SHA-256",
            data
        );


    return [
        ...new Uint8Array(
            digest
        )
    ]
        .map(
            b =>
                b
                    .toString(16)
                    .padStart(2, "0")
        )
        .join("");

}


/* =========================================================
   PASSWORD HASH
========================================================= */

async function passwordHash(
    password,
    saltB64 = null
) {

    const salt =
        saltB64
            ? fromB64(saltB64)
            : crypto.getRandomValues(
                new Uint8Array(16)
            );


    const key =
        await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(
                password
            ),
            "PBKDF2",
            false,
            [
                "deriveBits"
            ]
        );


    const bits =
        await crypto.subtle.deriveBits(
            {
                name: "PBKDF2",

                salt,

                iterations:
                    PBKDF2_ITERATIONS,

                hash:
                    "SHA-256"
            },

            key,

            256
        );


    return {

        salt:
            b64(salt),

        hash:
            b64(
                new Uint8Array(
                    bits
                )
            )

    };

}


/* =========================================================
   SAFE EQUAL
========================================================= */

function safeEqual(
    a,
    b
) {

    if (
        !a ||
        !b ||
        a.length !== b.length
    ) {

        return false;

    }


    let result = 0;


    for (
        let i = 0;
        i < a.length;
        i++
    ) {

        result |=
            a.charCodeAt(i) ^
            b.charCodeAt(i);

    }


    return result === 0;

}


/* =========================================================
   VERIFY PASSWORD
========================================================= */

async function verifyPassword(
    password,
    stored
) {

    const parts =
        String(
            stored || ""
        ).split("$");


    const scheme =
        parts[0];

    const iterations =
        Number(parts[1]);

    const salt =
        parts[2];

    const hash =
        parts[3];


    if (
        scheme !==
            "pbkdf2-sha256"
    ) {

        return false;

    }


    if (
        iterations !==
            PBKDF2_ITERATIONS
    ) {

        return false;

    }


    if (
        !salt ||
        !hash
    ) {

        return false;

    }


    const calculated =
        await passwordHash(
            password,
            salt
        );


    return safeEqual(
        calculated.hash,
        hash
    );

}


/* =========================================================
   COOKIE
========================================================= */

function cookie(
    name,
    value,
    maxAge
) {

    return [
        `${name}=${value}`,
        `Max-Age=${maxAge}`,
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Lax"
    ].join("; ");

}


/* =========================================================
   CLEAR COOKIE
========================================================= */

function clearCookie(
    name
) {

    return [
        `${name}=`,
        "Max-Age=0",
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Lax"
    ].join("; ");

}


/* =========================================================
   GET COOKIE
========================================================= */

function getCookie(
    request,
    name
) {

    const raw =
        request.headers.get(
            "Cookie"
        ) || "";


    for (
        const part
        of raw.split(";")
    ) {

        const [
            key,
            ...value
        ] =
            part
                .trim()
                .split("=");


        if (
            key === name
        ) {

            return value.join("=");

        }

    }


    return null;

}


/* =========================================================
   JSON RESPONSE
========================================================= */

async function authResponse(
    data,
    status = 200,
    extraHeaders = {}
) {

    const headers =
        new Headers({

            "content-type":
                "application/json;charset=UTF-8",

            "cache-control":
                "no-store",

            ...extraHeaders

        });


    return new Response(
        JSON.stringify(data),
        {
            status,
            headers
        }
    );

}


/* =========================================================
   CURRENT ACCOUNT
========================================================= */

async function currentAccount(
    env,
    request
) {

    const token =
        getCookie(
            request,
            COOKIE_NAME
        );


    if (!token) {

        return null;

    }


    /*
     * В БД хранится только SHA-256
     * от токена сессии.
     */

    const tokenHash =
        await digestHex(
            token
        );


    const row =
        await env.DB
            .prepare(`
                SELECT
                    a.id,
                    a.username,
                    a.balance,
                    a.created_at,
                    a.updated_at,
                    s.expires_at
                FROM sessions s
                JOIN accounts a
                    ON a.id = s.account_id
                WHERE s.token_hash = ?
                  AND s.expires_at > CURRENT_TIMESTAMP
                LIMIT 1
            `)
            .bind(
                tokenHash
            )
            .first();


    return row || null;

}


/* =========================================================
   CREATE SESSION
========================================================= */

async function createSession(
    env,
    accountId
) {

    /*
     * Сам токен отдаём браузеру.
     * В БД сохраняем только его SHA-256.
     */

    const token =
        randomId(32);


    const tokenHash =
        await digestHex(
            token
        );


    const expires =
        new Date(
            Date.now() +
            SESSION_DAYS *
            86400000
        ).toISOString();


    /*
     * Удаляем старую сессию
     * пользователя и просроченные сессии.
     */

    await env.DB
        .prepare(`
            DELETE FROM sessions
            WHERE account_id = ?
               OR expires_at <= CURRENT_TIMESTAMP
        `)
        .bind(
            accountId
        )
        .run();


    /*
     * Создаём новую сессию.
     */

    await env.DB
        .prepare(`
            INSERT INTO sessions (
                id,
                account_id,
                token_hash,
                expires_at
            )
            VALUES (
                ?,
                ?,
                ?,
                ?
            )
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


/* =========================================================
   AUTH API
========================================================= */

export async function authApi(
    env,
    request,
    url
) {


    /* =====================================================
       REGISTER
    ===================================================== */

    if (
        url.pathname ===
            "/api/auth/register" &&
        request.method === "POST"
    ) {

        let body;


        try {

            body =
                await request.json();

        } catch {

            return authResponse(
                {
                    error:
                        "Некорректный JSON"
                },
                400
            );

        }


        const username =
            String(
                body.username || ""
            ).trim();


        const password =
            String(
                body.password || ""
            );


        /* -------------------------------------------------
           USERNAME
        ------------------------------------------------- */

        if (
            !/^[A-Za-zА-Яа-яЁё0-9_]{3,24}$/
                .test(username)
        ) {

            return authResponse(
                {
                    error:
                        "Никнейм: 3–24 символа, только буквы, цифры и _"
                },
                400
            );

        }


        /* -------------------------------------------------
           PASSWORD
        ------------------------------------------------- */

        if (
            password.length < 8 ||
            password.length > 128
        ) {

            return authResponse(
                {
                    error:
                        "Пароль должен содержать от 8 до 128 символов"
                },
                400
            );

        }


        /* -------------------------------------------------
           CHECK USERNAME
        ------------------------------------------------- */

        const exists =
            await env.DB
                .prepare(`
                    SELECT id
                    FROM accounts
                    WHERE lower(username)
                        = lower(?)
                    LIMIT 1
                `)
                .bind(
                    username
                )
                .first();


        if (exists) {

            return authResponse(
                {
                    error:
                        "Такой никнейм уже занят"
                },
                409
            );

        }


        /* -------------------------------------------------
           ACCOUNT ID
        ------------------------------------------------- */

        const accountId =
            randomId(16);


        /* -------------------------------------------------
           PASSWORD HASH
        ------------------------------------------------- */

        const passwordData =
            await passwordHash(
                password
            );


        const storedPassword =
            [
                "pbkdf2-sha256",
                PBKDF2_ITERATIONS,
                passwordData.salt,
                passwordData.hash
            ].join("$");


        /* -------------------------------------------------
           CREATE ACCOUNT
        ------------------------------------------------- */

        await env.DB
            .prepare(`
                INSERT INTO accounts (
                    id,
                    username,
                    balance
                )
                VALUES (
                    ?,
                    ?,
                    0
                )
            `)
            .bind(
                accountId,
                username
            )
            .run();


        /* -------------------------------------------------
           CREATE CREDENTIALS
        ------------------------------------------------- */

        await env.DB
            .prepare(`
                INSERT INTO credentials (
                    account_id,
                    password_hash
                )
                VALUES (
                    ?,
                    ?
                )
            `)
            .bind(
                accountId,
                storedPassword
            )
            .run();


        /* -------------------------------------------------
           CREATE SESSION
        ------------------------------------------------- */

        const token =
            await createSession(
                env,
                accountId
            );


        /* -------------------------------------------------
           RESPONSE
        ------------------------------------------------- */

        return authResponse(

            {
                ok: true,

                authenticated:
                    true,

                account: {

                    id:
                        accountId,

                    username:
                        username,

                    balance:
                        0

                }

            },

            201,

            {
                "set-cookie":
                    cookie(
                        COOKIE_NAME,
                        token,
                        SESSION_DAYS *
                            86400
                    )
            }

        );

    }


    /* =====================================================
       LOGIN
    ===================================================== */

    if (
        url.pathname ===
            "/api/auth/login" &&
        request.method === "POST"
    ) {

        let body;


        try {

            body =
                await request.json();

        } catch {

            return authResponse(
                {
                    error:
                        "Некорректный JSON"
                },
                400
            );

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

            return authResponse(
                {
                    error:
                        "Введите никнейм"
                },
                400
            );

        }


        if (!password) {

            return authResponse(
                {
                    error:
                        "Введите пароль"
                },
                400
            );

        }


        /* -------------------------------------------------
           FIND ACCOUNT + CREDENTIALS
        ------------------------------------------------- */

        const account =
            await env.DB
                .prepare(`
                    SELECT
                        a.id,
                        a.username,
                        a.balance,
                        a.created_at,
                        a.updated_at,
                        c.password_hash
                    FROM accounts a
                    JOIN credentials c
                        ON c.account_id = a.id
                    WHERE lower(a.username)
                        = lower(?)
                    LIMIT 1
                `)
                .bind(
                    username
                )
                .first();


        /* -------------------------------------------------
           VERIFY
        ------------------------------------------------- */

        if (
            !account ||
            !await verifyPassword(
                password,
                account.password_hash
            )
        ) {

            return authResponse(
                {
                    error:
                        "Неверный никнейм или пароль"
                },
                401
            );

        }


        /* -------------------------------------------------
           CREATE SESSION
        ------------------------------------------------- */

        const token =
            await createSession(
                env,
                account.id
            );


        /* -------------------------------------------------
           RESPONSE
        ------------------------------------------------- */

        return authResponse(

            {
                ok: true,

                authenticated:
                    true,

                account: {

                    id:
                        account.id,

                    username:
                        account.username,

                    balance:
                        Number(
                            account.balance || 0
                        ),

                    created_at:
                        account.created_at

                }

            },

            200,

            {
                "set-cookie":
                    cookie(
                        COOKIE_NAME,
                        token,
                        SESSION_DAYS *
                            86400
                    )
            }

        );

    }


    /* =====================================================
       ME
    ===================================================== */

    if (
        url.pathname ===
            "/api/auth/me" &&
        request.method === "GET"
    ) {

        const account =
            await currentAccount(
                env,
                request
            );


        if (!account) {

            return authResponse(
                {
                    authenticated:
                        false
                },
                401
            );

        }


        return authResponse(
            {
                authenticated:
                    true,

                account: {

                    id:
                        account.id,

                    username:
                        account.username,

                    balance:
                        Number(
                            account.balance || 0
                        ),

                    created_at:
                        account.created_at,

                    updated_at:
                        account.updated_at,

                    expires_at:
                        account.expires_at

                }

            }
        );

    }


    /* =====================================================
       LOGOUT
    ===================================================== */

    if (
        url.pathname ===
            "/api/auth/logout" &&
        request.method === "POST"
    ) {

        const token =
            getCookie(
                request,
                COOKIE_NAME
            );


        if (token) {

            const tokenHash =
                await digestHex(
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

        }


        return authResponse(

            {
                ok: true
            },

            200,

            {
                "set-cookie":
                    clearCookie(
                        COOKIE_NAME
                    )
            }

        );

    }


    /* =====================================================
       NO AUTH ROUTE
    ===================================================== */

    return null;

}
