/* =========================================================
   ADMIN.JS — MEANT SHOP
   ОТДЕЛЬНАЯ СИСТЕМА АДМИНИСТРАТОРОВ

   НЕ ИСПОЛЬЗУЕТ:
   - auth.js
   - accounts
   - credentials
   - обычные sessions

   ИСПОЛЬЗУЕТ:
   - admin_accounts
   - admin_sessions
========================================================= */


/* =========================================================
   SETTINGS
========================================================= */

const PBKDF2_ITERATIONS = 100000;
const HASH_BYTES = 32;

const ADMIN_SESSION_DAYS = 7;


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
   RANDOM ID
========================================================= */

function generateId() {

    return crypto.randomUUID();

}


/* =========================================================
   NORMALIZE USERNAME
========================================================= */

function normalizeUsername(username) {

    return String(
        username ?? ""
    ).trim();

}


/* =========================================================
   VALIDATE ADMIN USERNAME
========================================================= */

function validUsername(username) {

    return /^[a-zA-Z0-9_-]{3,32}$/
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
        cookieHeader.split(";");


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
   ADMIN SESSION COOKIE
========================================================= */

function adminSessionCookie(
    sessionId
) {

    return [
        `admin_session=${sessionId}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Secure",
        "Max-Age=604800"
    ].join("; ");

}


/* =========================================================
   CLEAR ADMIN SESSION COOKIE
========================================================= */

function clearAdminSessionCookie() {

    return [
        "admin_session=",
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Secure",
        "Max-Age=0"
    ].join("; ");

}


/* =========================================================
   REGISTER ADMIN
=========================================================

   Для создания первого/нового администратора
   требуется ADMIN_REGISTER_KEY.

   Ключ НЕ хранится в HTML.

   Он должен находиться в Cloudflare Secret:
   ADMIN_REGISTER_KEY
========================================================= */

export async function registerAdmin(
    request,
    env
) {

    try {

        const body =
            await request.json();


        /* -------------------------------------------------
           REGISTER KEY
        ------------------------------------------------- */

        const registerKey =
            String(
                body.registerKey ?? ""
            );


        if (
            !env.ADMIN_REGISTER_KEY
        ) {

            return json(
                {
                    success: false,

                    error:
                        "ADMIN_REGISTER_KEY не настроен на сервере"
                },
                500
            );

        }


        if (
            !registerKey ||
            registerKey !==
                env.ADMIN_REGISTER_KEY
        ) {

            return json(
                {
                    success: false,

                    error:
                        "Неверный ключ регистрации администратора"
                },
                403
            );

        }


        /* -------------------------------------------------
           DATA
        ------------------------------------------------- */

        const username =
            normalizeUsername(
                body.username
            );


        const password =
            String(
                body.password ?? ""
            );


        const role =
            String(
                body.role ?? "ADMIN"
            )
                .trim()
                .toUpperCase();


        /* -------------------------------------------------
           USERNAME
        ------------------------------------------------- */

        if (!username) {

            return json(
                {
                    success: false,

                    error:
                        "Введите логин администратора"
                },
                400
            );

        }


        if (!validUsername(username)) {

            return json(
                {
                    success: false,

                    error:
                        "Логин должен содержать от 3 до 32 символов: латинские буквы, цифры, _ или -"
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
           ROLE
        ------------------------------------------------- */

        const allowedRoles = [
            "OWNER",
            "ADMIN"
        ];


        if (
            !allowedRoles.includes(
                role
            )
        ) {

            return json(
                {
                    success: false,

                    error:
                        "Недопустимая роль"
                },
                400
            );

        }


        /* -------------------------------------------------
           CHECK EXISTING
        ------------------------------------------------- */

        const existing =
            await env.DB
                .prepare(`
                    SELECT id
                    FROM admin_accounts
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
                        "Этот логин администратора уже занят"
                },
                409
            );

        }


        /* -------------------------------------------------
           HASH
        ------------------------------------------------- */

        const passwordData =
            await hashPassword(
                password
            );


        /* -------------------------------------------------
           ID
        ------------------------------------------------- */

        const adminId =
            generateId();


        /* -------------------------------------------------
           CREATE ADMIN
        ------------------------------------------------- */

        await env.DB
            .prepare(`
                INSERT INTO admin_accounts (
                    id,
                    username,
                    password_hash,
                    password_salt,
                    role,
                    created_at,
                    updated_at
                )
                VALUES (
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    datetime('now'),
                    datetime('now')
                )
            `)
            .bind(
                adminId,
                username,
                passwordData.hash,
                passwordData.salt,
                role
            )
            .run();


        /* -------------------------------------------------
           RESPONSE
        ------------------------------------------------- */

        return json(
            {
                success: true,

                admin: {
                    id:
                        adminId,

                    username:
                        username,

                    role:
                        role
                }
            },
            201
        );


    } catch (error) {

        console.error(
            "ADMIN REGISTER ERROR:",
            error
        );


        return json(
            {
                success: false,

                error:
                    error?.message ||
                    "Ошибка регистрации администратора"
            },
            500
        );

    }

}


/* =========================================================
   ADMIN LOGIN
========================================================= */

export async function loginAdmin(
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
                        "Введите логин"
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
           FIND ADMIN
        ------------------------------------------------- */

        const admin =
            await env.DB
                .prepare(`
                    SELECT
                        id,
                        username,
                        password_hash,
                        password_salt,
                        role,
                        created_at
                    FROM admin_accounts
                    WHERE LOWER(username) =
                          LOWER(?)
                    LIMIT 1
                `)
                .bind(username)
                .first();


        if (!admin) {

            return json(
                {
                    success: false,

                    error:
                        "Неверный логин или пароль"
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
                admin.password_hash,
                admin.password_salt
            );


        if (!valid) {

            return json(
                {
                    success: false,

                    error:
                        "Неверный логин или пароль"
                },
                401
            );

        }


        /* -------------------------------------------------
           SESSION
        ------------------------------------------------- */

        const sessionId =
            generateId();


        await env.DB
            .prepare(`
                INSERT INTO admin_sessions (
                    id,
                    admin_id,
                    expires_at,
                    created_at
                )
                VALUES (
                    ?,
                    ?,
                    datetime('now', '+7 days'),
                    datetime('now')
                )
            `)
            .bind(
                sessionId,
                admin.id
            )
            .run();


        /* -------------------------------------------------
           RESPONSE
        ------------------------------------------------- */

        return json(
            {
                success: true,

                authenticated: true,

                admin: {
                    id:
                        admin.id,

                    username:
                        admin.username,

                    role:
                        admin.role,

                    created_at:
                        admin.created_at
                }
            },
            200,
            {
                "Set-Cookie":
                    adminSessionCookie(
                        sessionId
                    )
            }
        );


    } catch (error) {

        console.error(
            "ADMIN LOGIN ERROR:",
            error
        );


        return json(
            {
                success: false,

                error:
                    error?.message ||
                    "Ошибка входа администратора"
            },
            500
        );

    }

}


/* =========================================================
   ADMIN ME
========================================================= */

export async function adminMe(
    request,
    env
) {

    try {

        const sessionId =
            getCookie(
                request,
                "admin_session"
            );


        if (!sessionId) {

            return json(
                {
                    success: false,

                    authenticated:
                        false,

                    error:
                        "Администратор не авторизован"
                },
                401
            );

        }


        /* -------------------------------------------------
           SESSION
        ------------------------------------------------- */

        const session =
            await env.DB
                .prepare(`
                    SELECT
                        id,
                        admin_id,
                        expires_at
                    FROM admin_sessions
                    WHERE id = ?
                    LIMIT 1
                `)
                .bind(sessionId)
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
                    DELETE FROM admin_sessions
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
           ADMIN
        ------------------------------------------------- */

        const admin =
            await env.DB
                .prepare(`
                    SELECT
                        id,
                        username,
                        role,
                        created_at,
                        updated_at
                    FROM admin_accounts
                    WHERE id = ?
                    LIMIT 1
                `)
                .bind(
                    session.admin_id
                )
                .first();


        if (!admin) {

            return json(
                {
                    success: false,

                    authenticated:
                        false,

                    error:
                        "Администратор не найден"
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

                admin: {
                    id:
                        admin.id,

                    username:
                        admin.username,

                    role:
                        admin.role,

                    created_at:
                        admin.created_at,

                    updated_at:
                        admin.updated_at
                }
            }
        );


    } catch (error) {

        console.error(
            "ADMIN ME ERROR:",
            error
        );


        return json(
            {
                success: false,

                authenticated:
                    false,

                error:
                    error?.message ||
                    "Не удалось получить администратора"
            },
            500
        );

    }

}


/* =========================================================
   ADMIN LOGOUT
========================================================= */

export async function logoutAdmin(
    request,
    env
) {

    try {

        const sessionId =
            getCookie(
                request,
                "admin_session"
            );


        if (sessionId) {

            await env.DB
                .prepare(`
                    DELETE FROM admin_sessions
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
                    clearAdminSessionCookie()
            }
        );


    } catch (error) {

        console.error(
            "ADMIN LOGOUT ERROR:",
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
                    clearAdminSessionCookie()
            }
        );

    }

}
