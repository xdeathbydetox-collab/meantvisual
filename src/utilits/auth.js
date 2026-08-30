/* =========================================================
   AUTH.JS — MEANT SHOP
   Авторизация БЕЗ EMAIL
========================================================= */

const PBKDF2_ITERATIONS = 100000;
const HASH_BYTES = 32;
const SESSION_DAYS = 30;


/* =========================================================
   RESPONSE
========================================================= */

function json(data, status = 200, extraHeaders = {}) {

    return new Response(
        JSON.stringify(data),
        {
            status,

            headers: {
                "Content-Type":
                    "application/json; charset=utf-8",

                "Access-Control-Allow-Origin":
                    "*",

                "Access-Control-Allow-Credentials":
                    "true",

                ...extraHeaders
            }
        }
    );

}


/* =========================================================
   ACCOUNT ID
========================================================= */

function generateAccountId() {

    return crypto.randomUUID();

}


/* =========================================================
   SESSION TOKEN
========================================================= */

function generateSessionToken() {

    return (
        crypto.randomUUID() +
        "-" +
        crypto.randomUUID()
    );

}


/* =========================================================
   USERNAME
========================================================= */

function normalizeUsername(username) {

    return String(
        username ?? ""
    ).trim();

}


function validUsername(username) {

    return /^[a-zA-Z0-9_-]{3,24}$/
        .test(username);

}


/* =========================================================
   PASSWORD
========================================================= */

function normalizePassword(password) {

    return String(
        password ?? ""
    ).replace(
        /[\u200B-\u200D\uFEFF]/g,
        ""
    );

}


/* =========================================================
   HEX
========================================================= */

function bytesToHex(bytes) {

    return Array
        .from(bytes)
        .map(
            byte =>
                byte
                    .toString(16)
                    .padStart(2, "0")
        )
        .join("");

}


function hexToBytes(hex) {

    if (
        !hex ||
        hex.length % 2 !== 0
    ) {

        throw new Error(
            "Invalid hex string"
        );

    }


    const bytes =
        new Uint8Array(
            hex.length / 2
        );


    for (
        let i = 0;
        i < hex.length;
        i += 2
    ) {

        bytes[i / 2] =
            parseInt(
                hex.substring(
                    i,
                    i + 2
                ),
                16
            );

    }


    return bytes;

}


/* =========================================================
   SHA-256
========================================================= */

async function sha256(value) {

    const data =
        new TextEncoder()
            .encode(
                String(value)
            );


    const hash =
        await crypto.subtle.digest(
            "SHA-256",
            data
        );


    return bytesToHex(
        new Uint8Array(hash)
    );

}


/* =========================================================
   PASSWORD HASH
========================================================= */

async function hashPassword(
    password
) {

    const encoder =
        new TextEncoder();


    const salt =
        crypto.getRandomValues(
            new Uint8Array(16)
        );


    const key =
        await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            {
                name: "PBKDF2"
            },
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

            HASH_BYTES * 8
        );


    return [
        PBKDF2_ITERATIONS,
        bytesToHex(salt),
        bytesToHex(
            new Uint8Array(bits)
        )
    ].join("$");

}


/* =========================================================
   PASSWORD VERIFY
========================================================= */

async function verifyPassword(
    password,
    storedPassword
) {

    try {

        const parts =
            String(
                storedPassword || ""
            ).split("$");


        if (
            parts.length !== 3
        ) {

            return false;

        }


        const iterations =
            Number(parts[0]);


        const saltHex =
            parts[1];


        const storedHash =
            parts[2];


        if (
            !Number.isFinite(iterations) ||
            !saltHex ||
            !storedHash
        ) {

            return false;

        }


        const key =
            await crypto.subtle.importKey(
                "raw",

                new TextEncoder()
                    .encode(password),

                {
                    name: "PBKDF2"
                },

                false,

                [
                    "deriveBits"
                ]
            );


        const bits =
            await crypto.subtle.deriveBits(
                {
                    name: "PBKDF2",

                    salt:
                        hexToBytes(
                            saltHex
                        ),

                    iterations,

                    hash:
                        "SHA-256"
                },

                key,

                HASH_BYTES * 8
            );


        const hash =
            bytesToHex(
                new Uint8Array(bits)
            );


        return timingSafeEqual(
            hash,
            storedHash
        );

    } catch (error) {

        console.error(
            "PASSWORD VERIFY ERROR:",
            error
        );


        return false;

    }

}


/* =========================================================
   CONSTANT-TIME COMPARE
========================================================= */

function timingSafeEqual(
    a,
    b
) {

    a = String(a);
    b = String(b);


    if (
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
   COOKIE
========================================================= */

function getCookie(
    request,
    name
) {

    const cookieHeader =
        request.headers.get(
            "Cookie"
        );


    if (!cookieHeader) {

        return null;

    }


    for (
        const cookie
        of cookieHeader.split(";")
    ) {

        const index =
            cookie.indexOf("=");


        if (
            index === -1
        ) {

            continue;

        }


        const key =
            cookie
                .slice(
                    0,
                    index
                )
                .trim();


        const value =
            cookie
                .slice(
                    index + 1
                )
                .trim();


        if (
            key === name
        ) {

            return value;

        }

    }


    return null;

}


/* =========================================================
   SESSION COOKIE
========================================================= */

function sessionCookie(
    token
) {

    return [
        `session=${token}`,
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        `Max-Age=${SESSION_DAYS * 24 * 60 * 60}`
    ].join("; ");

}


/* =========================================================
   CLEAR SESSION COOKIE
========================================================= */

function clearSessionCookie() {

    return [
        "session=",
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Max-Age=0"
    ].join("; ");
    /* =========================================================
   REGISTER
========================================================= */

export async function register(
    request,
    env
) {

    try {

        const body =
            await request.json();


        const username =
            normalizeUsername(
                body?.username
            );


        const password =
            normalizePassword(
                body?.password
            );


        /* -------------------------------------------------
           USERNAME
        ------------------------------------------------- */

        if (!username) {

            return json(
                {
                    success: false,

                    error:
                        "Введите никнейм"
                },
                400
            );

        }


        if (!validUsername(username)) {

            return json(
                {
                    success: false,

                    error:
                        "Никнейм должен содержать от 3 до 24 символов: латинские буквы, цифры, _ или -"
                },
                400
            );

        }


        /* -------------------------------------------------
           PASSWORD
        ------------------------------------------------- */

        if (!password) {

            return json(
                {
                    success: false,

                    error:
                        "Введите пароль"
                },
                400
            );

        }


        if (password.length < 8) {

            return json(
                {
                    success: false,

                    error:
                        "Пароль должен быть не короче 8 символов"
                },
                400
            );

        }


        if (password.length > 128) {

            return json(
                {
                    success: false,

                    error:
                        "Пароль слишком длинный"
                },
                400
            );

        }


        /* -------------------------------------------------
           CHECK USERNAME
        ------------------------------------------------- */

        const existing =
            await env.DB
                .prepare(`
                    SELECT id
                    FROM accounts
                    WHERE LOWER(username) = LOWER(?)
                    LIMIT 1
                `)
                .bind(
                    username
                )
                .first();


        if (existing) {

            return json(
                {
                    success: false,

                    error:
                        "Этот никнейм уже занят"
                },
                409
            );

        }


        /* -------------------------------------------------
           ACCOUNT
        ------------------------------------------------- */

        const accountId =
            generateAccountId();


        await env.DB
            .prepare(`
                INSERT INTO accounts (
                    id,
                    username,
                    balance,
                    created_at,
                    updated_at
                )
                VALUES (
                    ?,
                    ?,
                    0,
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP
                )
            `)
            .bind(
                accountId,
                username
            )
            .run();


        /* -------------------------------------------------
           PASSWORD
        ------------------------------------------------- */

        const passwordHash =
            await hashPassword(
                password
            );


        await env.DB
            .prepare(`
                INSERT INTO credentials (
                    account_id,
                    password_hash,
                    created_at,
                    updated_at
                )
                VALUES (
                    ?,
                    ?,
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP
                )
            `)
            .bind(
                accountId,
                passwordHash
            )
            .run();


        /* -------------------------------------------------
           SESSION
        ------------------------------------------------- */

        const token =
            generateSessionToken();


        const tokenHash =
            await sha256(
                token
            );


        const sessionId =
            crypto.randomUUID();


        await env.DB
            .prepare(`
                INSERT INTO sessions (
                    id,
                    account_id,
                    token_hash,
                    expires_at,
                    created_at
                )
                VALUES (
                    ?,
                    ?,
                    ?,
                    datetime('now', '+30 days'),
                    CURRENT_TIMESTAMP
                )
            `)
            .bind(
                sessionId,
                accountId,
                tokenHash
            )
            .run();


        /* -------------------------------------------------
           RESPONSE
        ------------------------------------------------- */

        return json(
            {
                success: true,

                authenticated: true,

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
                "Set-Cookie":
                    sessionCookie(
                        token
                    )
            }
        );


    } catch (error) {

        console.error(
            "REGISTER ERROR:",
            error
        );


        return json(
            {
                success: false,

                error:
                    error?.message ||
                    "Ошибка регистрации"
            },
            500
        );

    }

}


/* =========================================================
   LOGIN
========================================================= */

export async function login(
    request,
    env
) {

    try {

        const body =
            await request.json();


        const username =
            normalizeUsername(
                body?.username
            );


        const password =
            normalizePassword(
                body?.password
            );


        if (!username) {

            return json(
                {
                    success: false,

                    error:
                        "Введите никнейм"
                },
                400
            );

        }


        if (!password) {

            return json(
                {
                    success: false,

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
                    LEFT JOIN credentials c
                        ON c.account_id = a.id
                    WHERE LOWER(a.username) = LOWER(?)
                    LIMIT 1
                `)
                .bind(
                    username
                )
                .first();


        if (
            !account ||
            !account.password_hash
        ) {

            return json(
                {
                    success: false,

                    error:
                        "Неверный никнейм или пароль"
                },
                401
            );

        }


        /* -------------------------------------------------
           VERIFY
        ------------------------------------------------- */

        const valid =
            await verifyPassword(
                password,
                account.password_hash
            );


        if (!valid) {

            return json(
                {
                    success: false,

                    error:
                        "Неверный никнейм или пароль"
                },
                401
            );

        }


        /* -------------------------------------------------
           SESSION
        ------------------------------------------------- */

        const token =
            generateSessionToken();


        const tokenHash =
            await sha256(
                token
            );


        const sessionId =
            crypto.randomUUID();


        await env.DB
            .prepare(`
                INSERT INTO sessions (
                    id,
                    account_id,
                    token_hash,
                    expires_at,
                    created_at
                )
                VALUES (
                    ?,
                    ?,
                    ?,
                    datetime('now', '+30 days'),
                    CURRENT_TIMESTAMP
                )
            `)
            .bind(
                sessionId,
                account.id,
                tokenHash
            )
            .run();


        /* -------------------------------------------------
           RESPONSE
        ------------------------------------------------- */

        return json(
            {
                success: true,

                authenticated: true,

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
                        account.updated_at
                }
            },
            200,
            {
                "Set-Cookie":
                    sessionCookie(
                        token
                    )
            }
        );


    } catch (error) {

        console.error(
            "LOGIN ERROR:",
            error
        );


        return json(
            {
                success: false,

                error:
                    error?.message ||
                    "Ошибка входа"
            },
            500
        );

    }

}

}
/* =========================================================
   ME
========================================================= */

export async function me(
    request,
    env
) {

    try {

        const token =
            getCookie(
                request,
                "session"
            );


        if (!token) {

            return json(
                {
                    success: false,

                    authenticated:
                        false,

                    error:
                        "Не авторизован"
                },
                401
            );

        }


        const tokenHash =
            await sha256(
                token
            );


        /* -------------------------------------------------
           SESSION
        ------------------------------------------------- */

        const session =
            await env.DB
                .prepare(`
                    SELECT
                        id,
                        account_id,
                        expires_at
                    FROM sessions
                    WHERE token_hash = ?
                    LIMIT 1
                `)
                .bind(
                    tokenHash
                )
                .first();


        if (!session) {

            return json(
                {
                    success: false,

                    authenticated:
                        false,

                    error:
                        "Сессия недействительна"
                },
                401
            );

        }


        /* -------------------------------------------------
           EXPIRATION
        ------------------------------------------------- */

        const expiresAt =
            String(
                session.expires_at || ""
            ).replace(
                " ",
                "T"
            );


        const expiresTime =
            new Date(
                expiresAt.endsWith("Z")
                    ? expiresAt
                    : expiresAt + "Z"
            ).getTime();


        if (
            Number.isFinite(
                expiresTime
            ) &&
            expiresTime <= Date.now()
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


            return json(
                {
                    success: false,

                    authenticated:
                        false,

                    error:
                        "Сессия истекла"
                },
                401,
                {
                    "Set-Cookie":
                        clearSessionCookie()
                }
            );

        }


        /* -------------------------------------------------
           ACCOUNT
        ------------------------------------------------- */

        const account =
            await env.DB
                .prepare(`
                    SELECT
                        id,
                        username,
                        balance,
                        created_at,
                        updated_at
                    FROM accounts
                    WHERE id = ?
                    LIMIT 1
                `)
                .bind(
                    session.account_id
                )
                .first();


        if (!account) {

            await env.DB
                .prepare(`
                    DELETE FROM sessions
                    WHERE id = ?
                `)
                .bind(
                    session.id
                )
                .run();


            return json(
                {
                    success: false,

                    authenticated:
                        false,

                    error:
                        "Аккаунт не найден"
                },
                404,
                {
                    "Set-Cookie":
                        clearSessionCookie()
                }
            );

        }


        /* -------------------------------------------------
           SUBSCRIPTION
        ------------------------------------------------- */

        let subscription = null;


        try {

            const entitlement =
                await env.DB
                    .prepare(`
                        SELECT
                            id,
                            product_id,
                            product_name,
                            expires_at,
                            status,
                            tebex_transaction_id,
                            created_at
                        FROM entitlements
                        WHERE account_id = ?
                          AND status = 'active'
                          AND (
                              expires_at IS NULL
                              OR expires_at = ''
                              OR datetime(expires_at)
                                 > datetime('now')
                          )
                        ORDER BY
                            CASE
                                WHEN expires_at IS NULL
                                THEN 1
                                ELSE 0
                            END DESC,
                            datetime(created_at) DESC
                        LIMIT 1
                    `)
                    .bind(
                        account.id
                    )
                    .first();


            if (entitlement) {

                subscription = {

                    active:
                        true,

                    plan:
                        entitlement.product_name,

                    product_id:
                        entitlement.product_id,

                    started_at:
                        entitlement.created_at,

                    expires_at:
                        entitlement.expires_at,

                    status:
                        entitlement.status,

                    tebex_transaction_id:
                        entitlement.tebex_transaction_id

                };

            }

        } catch (error) {

            console.error(
                "ENTITLEMENT ERROR:",
                error
            );

        }


        /* -------------------------------------------------
           RESPONSE
        ------------------------------------------------- */

        return json(
            {
                success: true,

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

                    premium:
                        subscription !== null,

                    subscription:
                        subscription

                }
            }
        );


    } catch (error) {

        console.error(
            "ME ERROR:",
            error
        );


        return json(
            {
                success: false,

                authenticated:
                    false,

                error:
                    error?.message ||
                    "Не удалось получить аккаунт"
            },
            500
        );

    }

}


/* =========================================================
   LOGOUT
========================================================= */

export async function logout(
    request,
    env
) {

    try {

        const token =
            getCookie(
                request,
                "session"
            );


        if (token) {

            const tokenHash =
                await sha256(
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


        return json(
            {
                success: true
            },
            200,
            {
                "Set-Cookie":
                    clearSessionCookie()
            }
        );


    } catch (error) {

        console.error(
            "LOGOUT ERROR:",
            error
        );


        return json(
            {
                success: false,

                error:
                    error?.message ||
                    "Ошибка выхода"
            },
            500,
            {
                "Set-Cookie":
                    clearSessionCookie()
            }
        );

    }

}
