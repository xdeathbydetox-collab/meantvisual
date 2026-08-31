const PBKDF2_ITERATIONS = 100000;
const HASH_BYTES = 32;
const ADMIN_SESSION_DAYS = 7;

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

function generateId() {
    return crypto.randomUUID();
}

function normalizeUsername(username) {
    return String(username ?? "").trim();
}

function validUsername(username) {
    return /^[a-zA-Z0-9_-]{3,32}$/.test(username);
}

async function hashPassword(password) {
    const encoder = new TextEncoder();

    const salt = crypto.getRandomValues(
        new Uint8Array(16)
    );

    const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
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
        HASH_BYTES * 8
    );

    return {
        hash: bytesToHex(new Uint8Array(bits)),
        salt: bytesToHex(salt)
    };
}

async function verifyPassword(password, storedHash, storedSalt) {
    if (!storedHash || !storedSalt) {
        return false;
    }

    const encoder = new TextEncoder();
    const salt = hexToBytes(storedSalt);

    const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
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
        HASH_BYTES * 8
    );

    const hash = bytesToHex(new Uint8Array(bits));

    return hash === storedHash;
}

function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

function hexToBytes(hex) {
    if (
        typeof hex !== "string" ||
        hex.length % 2 !== 0
    ) {
        return new Uint8Array();
    }

    const bytes = new Uint8Array(hex.length / 2);

    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(
            hex.substring(i, i + 2),
            16
        );
    }

    return bytes;
}

function getCookie(request, name) {
    const cookieHeader = request.headers.get("Cookie");

    if (!cookieHeader) {
        return null;
    }

    const cookies = cookieHeader.split(";");

    for (const cookie of cookies) {
        const [key, ...rest] = cookie.trim().split("=");

        if (key === name) {
            return rest.join("=");
        }
    }

    return null;
}

function adminSessionCookie(sessionId) {
    return [
        `admin_session=${sessionId}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Secure",
        "Max-Age=604800"
    ].join("; ");
}

function clearAdminSessionCookie() {
    return [
        "admin_session=",
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Secure",
        "Max-Age=0"
    ].join("; ");
}export async function adminRegister(request, env) {
    try {
        const body = await request.json();

        const registerKey = String(body.registerKey ?? "");
        const username = normalizeUsername(body.username);
        const password = String(body.password ?? "");
        const role = String(body.role ?? "ADMIN")
            .trim()
            .toUpperCase();

        if (!env.ADMIN_REGISTER_KEY) {
            return json({
                success: false,
                error: "ADMIN_REGISTER_KEY не настроен на сервере"
            }, 500);
        }

        if (!registerKey || registerKey !== env.ADMIN_REGISTER_KEY) {
            return json({
                success: false,
                error: "Неверный ключ регистрации администратора"
            }, 403);
        }

        if (!username) {
            return json({
                success: false,
                error: "Введите логин администратора"
            }, 400);
        }

        if (!validUsername(username)) {
            return json({
                success: false,
                error: "Логин должен содержать от 3 до 32 символов: латинские буквы, цифры, _ или -"
            }, 400);
        }

        if (password.length < 8) {
            return json({
                success: false,
                error: "Пароль должен быть не короче 8 символов"
            }, 400);
        }

        if (password.length > 128) {
            return json({
                success: false,
                error: "Пароль слишком длинный"
            }, 400);
        }

        if (!["OWNER", "ADMIN"].includes(role)) {
            return json({
                success: false,
                error: "Недопустимая роль"
            }, 400);
        }

        const existing = await env.DB
            .prepare(`
                SELECT id
                FROM admin_accounts
                WHERE LOWER(username) = LOWER(?)
                LIMIT 1
            `)
            .bind(username)
            .first();

        if (existing) {
            return json({
                success: false,
                error: "Этот логин администратора уже занят"
            }, 409);
        }

        const passwordData = await hashPassword(password);
        const adminId = generateId();

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

        return json({
            success: true,
            admin: {
                id: adminId,
                username,
                role
            }
        }, 201);

    } catch (error) {
        console.error("ADMIN REGISTER ERROR:", error);

        return json({
            success: false,
            error: error?.message || "Ошибка регистрации администратора"
        }, 500);
    }
}


export async function adminLogin(request, env) {
    try {
        const body = await request.json();

        const username = normalizeUsername(body.username);
        const password = String(body.password ?? "");

        if (!username) {
            return json({
                success: false,
                error: "Введите логин"
            }, 400);
        }

        if (!password) {
            return json({
                success: false,
                error: "Введите пароль"
            }, 400);
        }

        const admin = await env.DB
            .prepare(`
                SELECT
                    id,
                    username,
                    password_hash,
                    password_salt,
                    role,
                    created_at
                FROM admin_accounts
                WHERE LOWER(username) = LOWER(?)
                LIMIT 1
            `)
            .bind(username)
            .first();

        if (!admin) {
            return json({
                success: false,
                error: "Неверный логин или пароль"
            }, 401);
        }

        const valid = await verifyPassword(
            password,
            admin.password_hash,
            admin.password_salt
        );

        if (!valid) {
            return json({
                success: false,
                error: "Неверный логин или пароль"
            }, 401);
        }

        const sessionId = generateId();

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

        return json({
            success: true,
            authenticated: true,
            admin: {
                id: admin.id,
                username: admin.username,
                role: admin.role,
                created_at: admin.created_at
            }
        }, 200, {
            "Set-Cookie": adminSessionCookie(sessionId)
        });

    } catch (error) {
        console.error("ADMIN LOGIN ERROR:", error);

        return json({
            success: false,
            error: error?.message || "Ошибка входа администратора"
        }, 500);
    }
}


export async function adminMe(request, env) {
    try {
        const sessionId = getCookie(
            request,
            "admin_session"
        );

        if (!sessionId) {
            return json({
                success: false,
                authenticated: false,
                error: "Администратор не авторизован"
            }, 401);
        }

        const session = await env.DB
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
            return json({
                success: false,
                authenticated: false,
                error: "Сессия недействительна"
            }, 401);
        }

        const expiresAt = new Date(
            session.expires_at
        ).getTime();

        if (
            Number.isFinite(expiresAt) &&
            expiresAt <= Date.now()
        ) {
            await env.DB
                .prepare(`
                    DELETE FROM admin_sessions
                    WHERE id = ?
                `)
                .bind(sessionId)
                .run();

            return json({
                success: false,
                authenticated: false,
                error: "Сессия истекла"
            }, 401);
        }

        const admin = await env.DB
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
            .bind(session.admin_id)
            .first();

        if (!admin) {
            return json({
                success: false,
                authenticated: false,
                error: "Администратор не найден"
            }, 404);
        }

        return json({
            success: true,
            authenticated: true,
            admin: {
                id: admin.id,
                username: admin.username,
                role: admin.role,
                created_at: admin.created_at,
                updated_at: admin.updated_at
            }
        });

    } catch (error) {
        console.error("ADMIN ME ERROR:", error);

        return json({
            success: false,
            authenticated: false,
            error: error?.message ||
                "Не удалось получить администратора"
        }, 500);
    }
}


export async function adminLogout(request, env) {
    try {
        const sessionId = getCookie(
            request,
            "admin_session"
        );

        if (sessionId) {
            await env.DB
                .prepare(`
                    DELETE FROM admin_sessions
                    WHERE id = ?
                `)
                .bind(sessionId)
                .run();
        }

        return json({
            success: true
        }, 200, {
            "Set-Cookie":
                clearAdminSessionCookie()
        });

    } catch (error) {
        console.error("ADMIN LOGOUT ERROR:", error);

        return json({
            success: false,
            error: error?.message || "Ошибка выхода"
        }, 500, {
            "Set-Cookie":
                clearAdminSessionCookie()
        });
    }
}
/* =========================================================
   ADMIN ACCESS
   Выдача / снятие доступа обычным аккаунтам
   по ID или НИКУ
========================================================= */


/* =========================================================
   CHECK ADMIN SESSION
========================================================= */

async function requireAdmin(request, env) {

    const sessionId = getCookie(
        request,
        "admin_session"
    );

    if (!sessionId) {
        return {
            ok: false,
            response: json({
                success: false,
                error: "Администратор не авторизован"
            }, 401)
        };
    }

    const session = await env.DB
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
        return {
            ok: false,
            response: json({
                success: false,
                error: "Сессия администратора недействительна"
            }, 401)
        };
    }

    const expiresAt =
        new Date(session.expires_at).getTime();

    if (
        Number.isFinite(expiresAt) &&
        expiresAt <= Date.now()
    ) {

        await env.DB
            .prepare(`
                DELETE FROM admin_sessions
                WHERE id = ?
            `)
            .bind(sessionId)
            .run();

        return {
            ok: false,
            response: json({
                success: false,
                error: "Сессия администратора истекла"
            }, 401)
        };
    }

    const admin = await env.DB
        .prepare(`
            SELECT
                id,
                username,
                role
            FROM admin_accounts
            WHERE id = ?
            LIMIT 1
        `)
        .bind(session.admin_id)
        .first();

    if (!admin) {
        return {
            ok: false,
            response: json({
                success: false,
                error: "Администратор не найден"
            }, 404)
        };
    }

    return {
        ok: true,
        admin
    };
}


/* =========================================================
   REQUIRE OWNER / ADMIN
========================================================= */

function canManageAccess(admin) {

    return (
        admin.role === "OWNER" ||
        admin.role === "ADMIN"
    );

}


/* =========================================================
   FIND ACCOUNT
   Можно передать:
   {
       "id": "..."
   }

   или:

   {
       "username": "detox"
   }

   или:

   {
       "query": "detox"
   }
========================================================= */

async function findAccount(env, body) {

    const id =
        String(body.id ?? "").trim();

    const username =
        String(body.username ?? "").trim();

    const query =
        String(body.query ?? "").trim();

    const searchValue =
        id || username || query;

    if (!searchValue) {
        return {
            account: null,
            error: "Введите ID или ник пользователя"
        };
    }


    /* -----------------------------------------------------
       SEARCH BY ID
    ----------------------------------------------------- */

    if (id) {

        const account = await env.DB
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
            .bind(id)
            .first();

        return {
            account: account || null
        };
    }


    /* -----------------------------------------------------
       SEARCH BY USERNAME
    ----------------------------------------------------- */

    const account = await env.DB
        .prepare(`
            SELECT
                id,
                username,
                balance,
                created_at,
                updated_at
            FROM accounts
            WHERE LOWER(username) = LOWER(?)
            LIMIT 1
        `)
        .bind(searchValue)
        .first();

    return {
        account: account || null
    };
}


/* =========================================================
   GET ACCOUNT ACCESS
========================================================= */

export async function adminGetAccess(
    request,
    env
) {

    try {

        const auth =
            await requireAdmin(
                request,
                env
            );

        if (!auth.ok) {
            return auth.response;
        }


        if (!canManageAccess(auth.admin)) {
            return json({
                success: false,
                error: "Недостаточно прав"
            }, 403);
        }


        const body =
            await request.json();


        const result =
            await findAccount(
                env,
                body
            );


        if (result.error) {
            return json({
                success: false,
                error: result.error
            }, 400);
        }


        if (!result.account) {
            return json({
                success: false,
                error: "Пользователь не найден"
            }, 404);
        }


        const access =
            await env.DB
                .prepare(`
                    SELECT
                        id,
                        account_id,
                        enabled,
                        created_at,
                        updated_at
                    FROM admin_access
                    WHERE account_id = ?
                    LIMIT 1
                `)
                .bind(
                    result.account.id
                )
                .first();


        return json({
            success: true,

            account: {
                id:
                    result.account.id,

                username:
                    result.account.username,

                balance:
                    Number(
                        result.account.balance || 0
                    ),

                created_at:
                    result.account.created_at,

                updated_at:
                    result.account.updated_at
            },

            access: {
                enabled:
                    access
                        ? Boolean(access.enabled)
                        : false,

                created_at:
                    access?.created_at || null,

                updated_at:
                    access?.updated_at || null
            }
        });


    } catch (error) {

        console.error(
            "ADMIN GET ACCESS ERROR:",
            error
        );

        return json({
            success: false,
            error:
                error?.message ||
                "Ошибка получения доступа"
        }, 500);
    }
}


/* =========================================================
   GRANT ADMIN ACCESS
========================================================= */

export async function adminGrantAccess(
    request,
    env
) {

    try {

        const auth =
            await requireAdmin(
                request,
                env
            );

        if (!auth.ok) {
            return auth.response;
        }


        if (!canManageAccess(auth.admin)) {
            return json({
                success: false,
                error: "Недостаточно прав"
            }, 403);
        }


        const body =
            await request.json();


        const result =
            await findAccount(
                env,
                body
            );


        if (result.error) {
            return json({
                success: false,
                error: result.error
            }, 400);
        }


        if (!result.account) {
            return json({
                success: false,
                error: "Пользователь не найден"
            }, 404);
        }


        const accessId =
            generateId();


        await env.DB
            .prepare(`
                INSERT INTO admin_access (
                    id,
                    account_id,
                    enabled,
                    created_at,
                    updated_at
                )
                VALUES (
                    ?,
                    ?,
                    1,
                    datetime('now'),
                    datetime('now')
                )
                ON CONFLICT(account_id)
                DO UPDATE SET
                    enabled = 1,
                    updated_at = datetime('now')
            `)
            .bind(
                accessId,
                result.account.id
            )
            .run();


        return json({
            success: true,

            message:
                "Доступ к админ-панели выдан",

            account: {
                id:
                    result.account.id,

                username:
                    result.account.username
            },

            access: {
                enabled: true
            }
        });


    } catch (error) {

        console.error(
            "ADMIN GRANT ACCESS ERROR:",
            error
        );

        return json({
            success: false,
            error:
                error?.message ||
                "Ошибка выдачи доступа"
        }, 500);
    }
}


/* =========================================================
   REVOKE ADMIN ACCESS
========================================================= */

export async function adminRevokeAccess(
    request,
    env
) {

    try {

        const auth =
            await requireAdmin(
                request,
                env
            );

        if (!auth.ok) {
            return auth.response;
        }


        if (!canManageAccess(auth.admin)) {
            return json({
                success: false,
                error: "Недостаточно прав"
            }, 403);
        }


        const body =
            await request.json();


        const result =
            await findAccount(
                env,
                body
            );


        if (result.error) {
            return json({
                success: false,
                error: result.error
            }, 400);
        }


        if (!result.account) {
            return json({
                success: false,
                error: "Пользователь не найден"
            }, 404);
        }


        await env.DB
            .prepare(`
                UPDATE admin_access
                SET
                    enabled = 0,
                    updated_at = datetime('now')
                WHERE account_id = ?
            `)
            .bind(
                result.account.id
            )
            .run();


        return json({
            success: true,

            message:
                "Доступ к админ-панели забран",

            account: {
                id:
                    result.account.id,

                username:
                    result.account.username
            },

            access: {
                enabled: false
            }
        });


    } catch (error) {

        console.error(
            "ADMIN REVOKE ACCESS ERROR:",
            error
        );

        return json({
            success: false,
            error:
                error?.message ||
                "Ошибка снятия доступа"
        }, 500);
    }
}


/* =========================================================
   CHECK ADMIN ACCESS FOR USER
   Это понадобится profile.html

   Передаём:
   {
       "accountId": "..."
   }

   или:
   {
       "username": "detox"
   }
========================================================= */

export async function checkAdminAccess(
    request,
    env
) {

    try {

        const body =
            await request.json();


        const result =
            await findAccount(
                env,
                body
            );


        if (!result.account) {
            return json({
                success: true,
                hasAccess: false
            });
        }


        const access =
            await env.DB
                .prepare(`
                    SELECT enabled
                    FROM admin_access
                    WHERE account_id = ?
                    LIMIT 1
                `)
                .bind(
                    result.account.id
                )
                .first();


        return json({
            success: true,

            hasAccess:
                Boolean(
                    access &&
                    Number(access.enabled) === 1
                ),

            account: {
                id:
                    result.account.id,

                username:
                    result.account.username
            }
        });


    } catch (error) {

        console.error(
            "CHECK ADMIN ACCESS ERROR:",
            error
        );

        return json({
            success: false,
            hasAccess: false,
            error:
                error?.message ||
                "Ошибка проверки доступа"
        }, 500);
    }
}
/* =========================================================
   ADMIN ACCESS MANAGEMENT
   Выдача / отзыв доступа пользователям

   Поиск пользователя:
   - по ID
   - по username

   Администратор может:
   - выдать доступ
   - забрать доступ
   - посмотреть текущий доступ
========================================================= */


/* =========================================================
   FIND ACCOUNT
========================================================= */

async function findAccount(env, identifier) {

    const value =
        String(identifier ?? "").trim();

    if (!value) {
        return null;
    }

    /*
       Сначала пробуем найти по ID.
    */

    let account =
        await env.DB
            .prepare(`
                SELECT
                    id,
                    username,
                    balance,
                    created_at
                FROM accounts
                WHERE id = ?
                LIMIT 1
            `)
            .bind(value)
            .first();

    if (account) {
        return account;
    }

    /*
       Если по ID не нашли —
       ищем по нику.
    */

    account =
        await env.DB
            .prepare(`
                SELECT
                    id,
                    username,
                    balance,
                    created_at
                FROM accounts
                WHERE LOWER(username) = LOWER(?)
                LIMIT 1
            `)
            .bind(value)
            .first();

    return account || null;
}


/* =========================================================
   CHECK ADMIN SESSION
========================================================= */

async function requireAdmin(request, env) {

    const sessionId =
        getCookie(
            request,
            "admin_session"
        );

    if (!sessionId) {
        return {
            ok: false,
            response: json(
                {
                    success: false,
                    authenticated: false,
                    error: "Необходима авторизация администратора"
                },
                401
            )
        };
    }

    const session =
        await env.DB
            .prepare(`
                SELECT
                    s.id,
                    s.admin_id,
                    s.expires_at,
                    a.username,
                    a.role
                FROM admin_sessions s
                INNER JOIN admin_accounts a
                    ON a.id = s.admin_id
                WHERE s.id = ?
                LIMIT 1
            `)
            .bind(sessionId)
            .first();

    if (!session) {
        return {
            ok: false,
            response: json(
                {
                    success: false,
                    authenticated: false,
                    error: "Сессия администратора недействительна"
                },
                401
            )
        };
    }

    const expiresAt =
        new Date(
            session.expires_at
        ).getTime();

    if (
        Number.isFinite(expiresAt) &&
        expiresAt <= Date.now()
    ) {

        await env.DB
            .prepare(`
                DELETE FROM admin_sessions
                WHERE id = ?
            `)
            .bind(sessionId)
            .run();

        return {
            ok: false,
            response: json(
                {
                    success: false,
                    authenticated: false,
                    error: "Сессия администратора истекла"
                },
                401
            )
        };
    }

    return {
        ok: true,
        session
    };
}


/* =========================================================
   GIVE ACCESS
========================================================= */

export async function adminGrantAccess(
    request,
    env
) {

    try {

        const auth =
            await requireAdmin(
                request,
                env
            );

        if (!auth.ok) {
            return auth.response;
        }

        const body =
            await request.json();

        /*
           Можно передать:

           {
               "identifier": "username"
           }

           или

           {
               "identifier": "account-id"
           }
        */

        const identifier =
            String(
                body.identifier ??
                body.username ??
                body.accountId ??
                ""
            ).trim();

        if (!identifier) {

            return json(
                {
                    success: false,
                    error:
                        "Введите ID или ник пользователя"
                },
                400
            );
        }


        /* -------------------------------------------------
           FIND ACCOUNT
        ------------------------------------------------- */

        const account =
            await findAccount(
                env,
                identifier
            );

        if (!account) {

            return json(
                {
                    success: false,
                    error:
                        "Пользователь не найден"
                },
                404
            );
        }


        /* -------------------------------------------------
           ACCESS DATA
        ------------------------------------------------- */

        const productId =
            String(
                body.productId ??
                "admin_granted"
            ).trim();

        const productName =
            String(
                body.productName ??
                "Административный доступ"
            ).trim();

        /*
           days:

           0 = навсегда
           7 = 7 дней
           30 = 30 дней
           90 = 90 дней
        */

        const days =
            Number(
                body.days ?? 0
            );

        if (
            !Number.isInteger(days) ||
            days < 0 ||
            days > 3650
        ) {

            return json(
                {
                    success: false,
                    error:
                        "Количество дней должно быть от 0 до 3650"
                },
                400
            );
        }


        /* -------------------------------------------------
           EXPIRATION
        ------------------------------------------------- */

        let expiresAt = null;

        if (days > 0) {

            const expiration =
                new Date(
                    Date.now() +
                    days *
                    24 *
                    60 *
                    60 *
                    1000
                );

            expiresAt =
                expiration.toISOString();
        }


        /* -------------------------------------------------
           REMOVE OLD ACTIVE ACCESS
        ------------------------------------------------- */

        await env.DB
            .prepare(`
                UPDATE entitlements
                SET status = 'revoked'
                WHERE account_id = ?
                  AND product_id = ?
                  AND status = 'active'
            `)
            .bind(
                account.id,
                productId
            )
            .run();


        /* -------------------------------------------------
           CREATE ACCESS
        ------------------------------------------------- */

        const result =
            await env.DB
                .prepare(`
                    INSERT INTO entitlements (
                        account_id,
                        product_id,
                        product_name,
                        expires_at,
                        status,
                        tebex_transaction_id,
                        created_at
                    )
                    VALUES (
                        ?,
                        ?,
                        ?,
                        ?,
                        'active',
                        NULL,
                        datetime('now')
                    )
                `)
                .bind(
                    account.id,
                    productId,
                    productName,
                    expiresAt
                )
                .run();


        /* -------------------------------------------------
           LOG
        ------------------------------------------------- */

        await env.DB
            .prepare(`
                INSERT INTO admin_logs (
                    admin_id,
                    action,
                    target_account_id,
                    details,
                    created_at
                )
                VALUES (
                    ?,
                    'grant_access',
                    ?,
                    ?,
                    datetime('now')
                )
            `)
            .bind(
                auth.session.admin_id,
                account.id,
                JSON.stringify({
                    productId,
                    productName,
                    days
                })
            )
            .run();


        return json(
            {
                success: true,

                message:
                    "Доступ успешно выдан",

                account: {
                    id:
                        account.id,

                    username:
                        account.username
                },

                access: {
                    productId,
                    productName,
                    days,
                    expiresAt,
                    status: "active"
                },

                result
            },
            201
        );


    } catch (error) {

        console.error(
            "ADMIN GRANT ACCESS ERROR:",
            error
        );

        return json(
            {
                success: false,
                error:
                    error?.message ||
                    "Ошибка выдачи доступа"
            },
            500
        );
    }
}


/* =========================================================
   REVOKE ACCESS
========================================================= */

export async function adminRevokeAccess(
    request,
    env
) {

    try {

        const auth =
            await requireAdmin(
                request,
                env
            );

        if (!auth.ok) {
            return auth.response;
        }

        const body =
            await request.json();

        const identifier =
            String(
                body.identifier ??
                body.username ??
                body.accountId ??
                ""
            ).trim();

        if (!identifier) {

            return json(
                {
                    success: false,
                    error:
                        "Введите ID или ник пользователя"
                },
                400
            );
        }


        /* -------------------------------------------------
           FIND ACCOUNT
        ------------------------------------------------- */

        const account =
            await findAccount(
                env,
                identifier
            );

        if (!account) {

            return json(
                {
                    success: false,
                    error:
                        "Пользователь не найден"
                },
                404
            );
        }


        /* -------------------------------------------------
           PRODUCT
        ------------------------------------------------- */

        const productId =
            body.productId
                ? String(
                    body.productId
                ).trim()
                : null;


        let result;


        if (productId) {

            result =
                await env.DB
                    .prepare(`
                        UPDATE entitlements
                        SET status = 'revoked'
                        WHERE account_id = ?
                          AND product_id = ?
                          AND status = 'active'
                    `)
                    .bind(
                        account.id,
                        productId
                    )
                    .run();

        } else {

            result =
                await env.DB
                    .prepare(`
                        UPDATE entitlements
                        SET status = 'revoked'
                        WHERE account_id = ?
                          AND status = 'active'
                    `)
                    .bind(
                        account.id
                    )
                    .run();
        }


        /* -------------------------------------------------
           LOG
        ------------------------------------------------- */

        await env.DB
            .prepare(`
                INSERT INTO admin_logs (
                    admin_id,
                    action,
                    target_account_id,
                    details,
                    created_at
                )
                VALUES (
                    ?,
                    'revoke_access',
                    ?,
                    ?,
                    datetime('now')
                )
            `)
            .bind(
                auth.session.admin_id,
                account.id,
                JSON.stringify({
                    productId
                })
            )
            .run();


        return json(
            {
                success: true,

                message:
                    "Доступ успешно забран",

                account: {
                    id:
                        account.id,

                    username:
                        account.username
                },

                productId:
                    productId || "all",

                result
            }
        );


    } catch (error) {

        console.error(
            "ADMIN REVOKE ACCESS ERROR:",
            error
        );

        return json(
            {
                success: false,

                error:
                    error?.message ||
                    "Ошибка отзыва доступа"
            },
            500
        );
    }
}


/* =========================================================
   GET USER ACCESS
========================================================= */

export async function adminUserAccess(
    request,
    env
) {

    try {

        const auth =
            await requireAdmin(
                request,
                env
            );

        if (!auth.ok) {
            return auth.response;
        }

        const url =
            new URL(
                request.url
            );

        const identifier =
            String(
                url.searchParams.get(
                    "identifier"
                ) ??
                url.searchParams.get(
                    "username"
                ) ??
                url.searchParams.get(
                    "accountId"
                ) ??
                ""
            ).trim();

        if (!identifier) {

            return json(
                {
                    success: false,
                    error:
                        "Укажите ID или ник"
                },
                400
            );
        }


        /* -------------------------------------------------
           FIND ACCOUNT
        ------------------------------------------------- */

        const account =
            await findAccount(
                env,
                identifier
            );

        if (!account) {

            return json(
                {
                    success: false,
                    error:
                        "Пользователь не найден"
                },
                404
            );
        }


        /* -------------------------------------------------
           GET ACCESS
        ------------------------------------------------- */

        const result =
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
                    ORDER BY created_at DESC
                `)
                .bind(
                    account.id
                )
                .all();


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
                        ),

                    created_at:
                        account.created_at
                },

                access:
                    result.results || []
            }
        );


    } catch (error) {

        console.error(
            "ADMIN USER ACCESS ERROR:",
            error
        );

        return json(
            {
                success: false,

                error:
                    error?.message ||
                    "Ошибка получения доступа"
            },
            500
        );
    }
}
