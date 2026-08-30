/* AUTH.JS — MEANT SHOP
   D1 schema: accounts + credentials + sessions
   Registration/login by username and password only.
*/

const PBKDF2_ITERATIONS = 100000;
const HASH_BYTES = 32;
const SESSION_MAX_AGE = 60 * 60 * 24 * 30;

function json(data, status = 200, headers = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            ...headers
        }
    });
}

function normalizeUsername(value) {
    return String(value ?? "").trim();
}

function validUsername(value) {
    return /^[a-zA-Z0-9_-]{3,24}$/.test(value);
}

function bytesToHex(bytes) {
    return Array
        .from(bytes)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function hexToBytes(hex) {
    if (!hex || hex.length % 2) {
        throw new Error("Некорректный salt");
    }

    const out = new Uint8Array(hex.length / 2);

    for (let i = 0; i < hex.length; i += 2) {
        out[i / 2] = parseInt(
            hex.slice(i, i + 2),
            16
        );
    }

    return out;
}

async function hashPassword(password) {
    const encoder = new TextEncoder();

    const salt = crypto.getRandomValues(
        new Uint8Array(16)
    );

    const key = await crypto.subtle.importKey(
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

    const bits = await crypto.subtle.deriveBits(
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
        hash: bytesToHex(
            new Uint8Array(bits)
        ),

        salt: bytesToHex(
            salt
        )
    };
}

async function verifyPassword(
    password,
    storedHash,
    storedSalt
) {
    if (!storedHash || !storedSalt) {
        return false;
    }

    const encoder = new TextEncoder();

    const key = await crypto.subtle.importKey(
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

    const bits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: hexToBytes(storedSalt),
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        key,
        HASH_BYTES * 8
    );

    return (
        bytesToHex(
            new Uint8Array(bits)
        ) === storedHash
    );
}

async function hashSessionToken(token) {
    const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(token)
    );

    return bytesToHex(
        new Uint8Array(digest)
    );
}

function generateToken() {
    return bytesToHex(
        crypto.getRandomValues(
            new Uint8Array(32)
        )
    );
}

function getCookie(request, name) {
    const header = request.headers.get("Cookie");

    if (!header) {
        return null;
    }

    for (const part of header.split(";")) {
        const trimmed = part.trim();
        const index = trimmed.indexOf("=");

        if (index < 0) {
            continue;
        }

        const key = trimmed.slice(0, index);

        if (key === name) {
            return decodeURIComponent(
                trimmed.slice(index + 1)
            );
        }
    }

    return null;
}

function sessionCookie(token) {
    return [
        `session=${encodeURIComponent(token)}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Secure",
        `Max-Age=${SESSION_MAX_AGE}`
    ].join("; ");
}

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

async function createSession(accountId, env) {
    const token = generateToken();

    const tokenHash =
        await hashSessionToken(token);

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
                datetime('now')
            )
        `)
        .bind(
            crypto.randomUUID(),
            accountId,
            tokenHash
        )
        .run();

    return token;
}

async function currentAccount(
    request,
    env
) {
    const token =
        getCookie(
            request,
            "session"
        );

    if (!token) {
        return null;
    }

    const tokenHash =
        await hashSessionToken(
            token
        );

    return await env.DB
        .prepare(`
            SELECT
                a.id,
                a.username,
                a.balance,
                a.created_at,
                a.updated_at
            FROM sessions s
            JOIN accounts a
                ON a.id = s.account_id
            WHERE
                s.token_hash = ?
                AND s.expires_at > datetime('now')
            LIMIT 1
        `)
        .bind(
            tokenHash
        )
        .first();
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

        if (!username) {
            return json(
                {
                    success: false,
                    error: "Введите никнейм"
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

        if (!password) {
            return json(
                {
                    success: false,
                    error: "Введите пароль"
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

        const existing =
            await env.DB
                .prepare(`
                    SELECT id
                    FROM accounts
                    WHERE LOWER(username) =
                          LOWER(?)
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

        const accountId =
            crypto.randomUUID();

        const pass =
            await hashPassword(
                password
            );

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

        try {
            /*
             * В первоначальной D1-схеме
             * credentials содержит:
             *
             * account_id
             * password_hash
             *
             * Поэтому hash и salt
             * сохраняем вместе:
             *
             * hash:salt
             */

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
                    `${pass.hash}:${pass.salt}`
                )
                .run();

        } catch (error) {

            await env.DB
                .prepare(`
                    DELETE FROM accounts
                    WHERE id = ?
                `)
                .bind(
                    accountId
                )
                .run();

            throw error;
        }

        const token =
            await createSession(
                accountId,
                env
            );

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
                    WHERE
                        LOWER(a.username) =
                        LOWER(?)
                    LIMIT 1
                `)
                .bind(
                    username
                )
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

        const stored =
            String(
                account.password_hash || ""
            );

        const separator =
            stored.indexOf(":");

        if (separator < 0) {
            return json(
                {
                    success: false,
                    error:
                        "Данные пароля аккаунта повреждены"
                },
                500
            );
        }

        const storedHash =
            stored.slice(
                0,
                separator
            );

        const storedSalt =
            stored.slice(
                separator + 1
            );

        const valid =
            await verifyPassword(
                password,
                storedHash,
                storedSalt
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

        const token =
            await createSession(
                account.id,
                env
            );

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


/* =========================================================
   ME
========================================================= */

export async function me(
    request,
    env
) {
    try {

        const account =
            await currentAccount(
                request,
                env
            );

        if (!account) {
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

        const token =
            getCookie(
                request,
                "session"
            );

        if (token) {

            const tokenHash =
                await hashSessionToken(
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
                success: true,

                authenticated:
                    false
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
