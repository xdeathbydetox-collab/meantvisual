/* =========================================================
   AUTH.JS — MEANT SHOP
   Регистрация и вход БЕЗ EMAIL
========================================================= */


/* =========================================================
   SETTINGS
========================================================= */

const PBKDF2_ITERATIONS = 100000;
const HASH_BYTES = 32;


/* =========================================================
   RESPONSE
========================================================= */

function json(data, status = 200) {

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
                    "true"
            }
        }
    );
}


/* =========================================================
   RANDOM ID
========================================================= */

function generateAccountId() {

    return crypto.randomUUID();

}


/* =========================================================
   NORMALIZE USERNAME
========================================================= */

function normalizeUsername(username) {

    return String(
        username ?? ""
    )
        .trim();

}


/* =========================================================
   USERNAME VALIDATION
========================================================= */

function validUsername(username) {

    /*
     * Разрешаем:
     * латиницу
     * цифры
     * _
     * -
     *
     * От 3 до 24 символов.
     */

    return /^[a-zA-Z0-9_-]{3,24}$/
        .test(username);

}


/* =========================================================
   PASSWORD HASH
========================================================= */

async function hashPassword(password) {

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


    return {

        hash:
            bytesToHex(
                new Uint8Array(bits)
            ),

        salt:
            bytesToHex(
                salt
            )

    };

}


/* =========================================================
   PASSWORD VERIFY
========================================================= */

async function verifyPassword(
    password,
    storedHash,
    storedSalt
) {

    const encoder =
        new TextEncoder();


    const salt =
        hexToBytes(
            storedSalt
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


    const hash =
        bytesToHex(
            new Uint8Array(bits)
        );


    return hash === storedHash;

}


/* =========================================================
   HEX HELPERS
========================================================= */

function bytesToHex(
    bytes
) {

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


function hexToBytes(
    hex
) {

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


    const cookies =
        cookieHeader
            .split(";");


    for (
        const cookie
        of cookies
    ) {

        const [
            key,
            ...rest
        ] =
            cookie
                .trim()
                .split("=");


        if (
            key === name
        ) {

            return rest.join("=");

        }

    }


    return null;

}


/* =========================================================
   SESSION ID
========================================================= */

function generateSessionId() {

    return crypto.randomUUID();

}


/* =========================================================
   SET SESSION COOKIE
========================================================= */

function sessionCookie(
    sessionId
) {

    return [
        `session=${sessionId}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Secure",
        "Max-Age=2592000"
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
        "SameSite=Lax",
        "Secure",
        "Max-Age=0"
    ].join("; ");

}


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
                body.username
            );


        const password =
            String(
                body.password ?? ""
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
                    WHERE LOWER(username) =
                          LOWER(?)
                    LIMIT 1
                `)
                .bind(username)
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
           HASH PASSWORD
        ------------------------------------------------- */

        const passwordData =
            await hashPassword(
                password
            );


        /* -------------------------------------------------
           ACCOUNT ID
        ------------------------------------------------- */

        const accountId =
            generateAccountId();


        /* -------------------------------------------------
           CREATE ACCOUNT
        ------------------------------------------------- */

        await env.DB
            .prepare(`
                INSERT INTO accounts (
                    id,
                    username,
                    password_hash,
                    password_salt,
                    balance,
                    created_at,
                    updated_at
                )
                VALUES (
                    ?,
                    ?,
                    ?,
                    ?,
                    0,
                    datetime('now'),
                    datetime('now')
                )
            `)
            .bind(
                accountId,
                username,
                passwordData.hash,
                passwordData.salt
            )
            .run();


        /* -------------------------------------------------
           SESSION
        ------------------------------------------------- */

        const sessionId =
            generateSessionId();


        await env.DB
            .prepare(`
                INSERT INTO sessions (
                    id,
                    account_id,
                    created_at,
                    expires_at
                )
                VALUES (
                    ?,
                    ?,
                    datetime('now'),
                    datetime('now', '+30 days')
                )
            `)
            .bind(
                sessionId,
                accountId
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
                        sessionId
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
                body.username
            );


        const password =
            String(
                body.password ?? ""
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
           FIND ACCOUNT
        ------------------------------------------------- */

        const account =
            await env.DB
                .prepare(`
                    SELECT
                        id,
                        username,
                        password_hash,
                        password_salt,
                        balance,
                        created_at
                    FROM accounts
                    WHERE LOWER(username) =
                          LOWER(?)
                    LIMIT 1
                `)
                .bind(username)
                .first();


        if (!account) {

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
           VERIFY PASSWORD
        ------------------------------------------------- */

        const valid =
            await verifyPassword(
                password,
                account.password_hash,
                account.password_salt
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

        const sessionId =
            generateSessionId();


        await env.DB
            .prepare(`
                INSERT INTO sessions (
                    id,
                    account_id,
                    created_at,
                    expires_at
                )
                VALUES (
                    ?,
                    ?,
                    datetime('now'),
                    datetime('now', '+30 days')
                )
            `)
            .bind(
                sessionId,
                account.id
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
                        account.created_at
                }
            },
            200,
            {
                "Set-Cookie":
                    sessionCookie(
                        sessionId
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


/* =========================================================
   ME
========================================================= */

export async function me(
    request,
    env
) {

    try {

        const sessionId =
            getCookie(
                request,
                "session"
            );


        if (!sessionId) {

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


        /* -------------------------------------------------
           FIND SESSION
        ------------------------------------------------- */

        const session =
            await env.DB
                .prepare(`
                    SELECT
                        s.id,
                        s.account_id,
                        s.expires_at
                    FROM sessions s
                    WHERE s.id = ?
                    LIMIT 1
                `)
                .bind(
                    sessionId
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
           CHECK SESSION EXPIRATION
        ------------------------------------------------- */

        const expiresAt =
            new Date(
                session.expires_at
            ).getTime();


        if (
            Number.isFinite(
                expiresAt
            ) &&
            expiresAt <= Date.now()
        ) {

            await env.DB
                .prepare(`
                    DELETE FROM sessions
                    WHERE id = ?
                `)
                .bind(
                    sessionId
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
                401
            );

        }


        /* -------------------------------------------------
           FIND ACCOUNT
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

            return json(
                {
                    success: false,

                    authenticated:
                        false,

                    error:
                        "Аккаунт не найден"
                },
                404
            );

        }


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

        const sessionId =
            getCookie(
                request,
                "session"
            );


        if (sessionId) {

            await env.DB
                .prepare(`
                    DELETE FROM sessions
                    WHERE id = ?
                `)
                .bind(
                    sessionId
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
