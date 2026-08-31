/* =========================================================
   ADMIN.JS — MEANT SHOP
   ОТДЕЛЬНАЯ СИСТЕМА АДМИНИСТРАТОРОВ

   НЕ ИСПОЛЬЗУЕТ auth.js
   НЕ ИСПОЛЬЗУЕТ обычные sessions
   ========================================================= */

const PBKDF2_ITERATIONS = 100000;
const HASH_BYTES = 32;
const ADMIN_SESSION_DAYS = 7;
const ADMIN_SESSION_SECONDS = 604800;


/* =========================================================
   RESPONSE
   ========================================================= */

function json(data, status = 200, extraHeaders = {}) {
    return new Response(
        JSON.stringify(data),
        {
            status,
            headers: {
                "Content-Type": "application/json; charset=utf-8",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
                ...extraHeaders
            }
        }
    );
}


/* =========================================================
   ID
   ========================================================= */

function generateId() {
    return crypto.randomUUID();
}


/* =========================================================
   USERNAME
   ========================================================= */

function normalizeUsername(username) {
    return String(username ?? "").trim();
}


function validUsername(username) {
    return /^[a-zA-Z0-9_-]{3,32}$/.test(username);
}


/* =========================================================
   PASSWORD HASH
   ========================================================= */

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


/* =========================================================
   PASSWORD VERIFY
   ========================================================= */

async function verifyPassword(
    password,
    storedHash,
    storedSalt
) {
    const encoder = new TextEncoder();

    const salt = hexToBytes(storedSalt);

    const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        {
            name: "PBKDF2"
        },
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

    const hash = bytesToHex(
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
    const bytes = new Uint8Array(
        hex.length / 2
    );

    for (
        let i = 0;
        i < hex.length;
        i += 2
    ) {
        bytes[i / 2] = parseInt(
            hex.substring(i, i + 2),
            16
        );
    }

    return bytes;
}


/* =========================================================
   COOKIE
   ========================================================= */

function getCookie(request, name) {
    const cookieHeader =
        request.headers.get("Cookie");

    if (!cookieHeader) {
        return null;
    }

    const cookies =
        cookieHeader.split(";");

    for (const cookie of cookies) {
        const [
            key,
            ...rest
        ] = cookie
            .trim()
            .split("=");

        if (key === name) {
            return rest.join("=");
        }
    }

    return null;
}


/* =========================================================
   ADMIN COOKIE
   ========================================================= */

function adminSessionCookie(sessionId) {
    return [
        `admin_session=${sessionId}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Secure",
        `Max-Age=${ADMIN_SESSION_SECONDS}`
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
}


/* =========================================================
   REQUIRE ADMIN
   ========================================================= */

async function requireAdmin(request, env) {
    const sessionId = getCookie(
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
                    error: "Администратор не авторизован"
                },
                401
            )
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
            response: json(
                {
                    success: false,
                    authenticated: false,
                    error: "Сессия недействительна"
                },
                401
            )
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
            response: json(
                {
                    success: false,
                    authenticated: false,
                    error: "Сессия истекла"
                },
                401
            )
        };
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
        return {
            ok: false,
            response: json(
                {
                    success: false,
                    authenticated: false,
                    error: "Администратор не найден"
                },
                404
            )
        };
    }

    return {
        ok: true,
        admin,
        session
    };
}
/* =========================================================
   ADMIN REGISTER
   ========================================================= */

export async function adminRegister(request, env) {
    try {
        const body = await request.json();

        const registerKey = String(
            body.registerKey ?? ""
        );

        if (!env.ADMIN_REGISTER_KEY) {
            return json(
                {
                    success: false,
                    error: "ADMIN_REGISTER_KEY не настроен на сервере"
                },
                500
            );
        }

        if (
            !registerKey ||
            registerKey !== env.ADMIN_REGISTER_KEY
        ) {
            return json(
                {
                    success: false,
                    error: "Неверный ключ регистрации администратора"
                },
                403
            );
        }

        const username = normalizeUsername(
            body.username
        );

        const password = String(
            body.password ?? ""
        );

        const role = String(
            body.role ?? "ADMIN"
        )
            .trim()
            .toUpperCase();

        if (!username) {
            return json(
                {
                    success: false,
                    error: "Введите логин администратора"
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
                    error: "Пароль должен быть не короче 8 символов"
                },
                400
            );
        }

        if (password.length > 128) {
            return json(
                {
                    success: false,
                    error: "Пароль слишком длинный"
                },
                400
            );
        }

        const allowedRoles = [
            "OWNER",
            "ADMIN"
        ];

        if (!allowedRoles.includes(role)) {
            return json(
                {
                    success: false,
                    error: "Недопустимая роль"
                },
                400
            );
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
            return json(
                {
                    success: false,
                    error: "Этот логин администратора уже занят"
                },
                409
            );
        }

        const passwordData =
            await hashPassword(password);

        const adminId =
            generateId();

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

        return json(
            {
                success: true,
                admin: {
                    id: adminId,
                    username,
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
   В админку может войти только:
   username = detox
   role     = OWNER
   ========================================================= */

export async function adminLogin(request, env) {
    try {

        /* -------------------------------------------------
           BODY
        ------------------------------------------------- */

        const body = await request.json();

        const username = normalizeUsername(
            body.username
        );

        const password = String(
            body.password ?? ""
        );


        /* -------------------------------------------------
           VALIDATION
        ------------------------------------------------- */

        if (!username) {
            return json(
                {
                    success: false,
                    authenticated: false,
                    error: "Введите логин"
                },
                400
            );
        }

        if (!password) {
            return json(
                {
                    success: false,
                    authenticated: false,
                    error: "Введите пароль"
                },
                400
            );
        }


        /* -------------------------------------------------
           ONLY DETOX / OWNER
        ------------------------------------------------- */

        if (username.toLowerCase() !== "detox") {
            return json(
                {
                    success: false,
                    authenticated: false,
                    error: "Доступ в админ-панель запрещён"
                },
                403
            );
        }


        /* -------------------------------------------------
           FIND ADMIN
        ------------------------------------------------- */

        const admin = await env.DB
            .prepare(`
                SELECT
                    id,
                    username,
                    password_hash,
                    password_salt,
                    role,
                    created_at,
                    updated_at
                FROM admin_accounts
                WHERE LOWER(username) = 'detox'
                  AND role = 'OWNER'
                LIMIT 1
            `)
            .first();


        /* -------------------------------------------------
           ADMIN NOT FOUND
        ------------------------------------------------- */

        if (!admin) {
            return json(
                {
                    success: false,
                    authenticated: false,
                    error: "Администратор detox не найден"
                },
                401
            );
        }


        /* -------------------------------------------------
           PASSWORD
        ------------------------------------------------- */

        const valid = await verifyPassword(
            password,
            admin.password_hash,
            admin.password_salt
        );


        if (!valid) {
            return json(
                {
                    success: false,
                    authenticated: false,
                    error: "Неверный логин или пароль"
                },
                401
            );
        }


        /* -------------------------------------------------
           CREATE SESSION
        ------------------------------------------------- */

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


        /* -------------------------------------------------
           SUCCESS
        ------------------------------------------------- */

        return json(
            {
                success: true,
                authenticated: true,

                admin: {
                    id: admin.id,
                    username: admin.username,
                    role: admin.role,
                    created_at: admin.created_at,
                    updated_at: admin.updated_at
                }
            },
            200,
            {
                "Set-Cookie":
                    adminSessionCookie(sessionId)
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
                authenticated: false,
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

export async function adminMe(request, env) {
    try {
        const auth =
            await requireAdmin(
                request,
                env
            );

        if (!auth.ok) {
            return auth.response;
        }

        return json(
            {
                success: true,
                authenticated: true,
                admin: {
                    id: auth.admin.id,
                    username: auth.admin.username,
                    role: auth.admin.role,
                    created_at:
                        auth.admin.created_at,
                    updated_at:
                        auth.admin.updated_at
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
                authenticated: false,
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

export async function adminLogout(request, env) {
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
                .bind(sessionId)
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


/* =========================================================
   ADMIN STATS
   ========================================================= */

export async function adminStats(request, env) {
    try {
        const auth =
            await requireAdmin(
                request,
                env
            );

        if (!auth.ok) {
            return auth.response;
        }

        const accounts = await env.DB
            .prepare(`
                SELECT COUNT(*) AS count
                FROM accounts
            `)
            .first();

        const administrators = await env.DB
            .prepare(`
                SELECT COUNT(*) AS count
                FROM admin_accounts
            `)
            .first();

        const transactions = await env.DB
            .prepare(`
                SELECT COUNT(*) AS count
                FROM transactions
            `)
            .first();

        const subscriptions = await env.DB
            .prepare(`
                SELECT COUNT(*) AS count
                FROM entitlements
                WHERE status = 'active'
            `)
            .first();

        return json({
            success: true,
            stats: {
                accounts:
                    Number(accounts?.count || 0),

                administrators:
                    Number(administrators?.count || 0),

                transactions:
                    Number(transactions?.count || 0),

                activeSubscriptions:
                    Number(subscriptions?.count || 0)
            }
        });

    } catch (error) {
        console.error(
            "ADMIN STATS ERROR:",
            error
        );

        return json(
            {
                success: false,
                error:
                    error?.message ||
                    "Не удалось получить статистику"
            },
            500
        );
    }
}
/* =========================================================
   ADMIN ACCOUNTS
   Просмотр обычных аккаунтов
   ========================================================= */

export async function adminAccounts(request, env) {
    try {
        const auth = await requireAdmin(request, env);

        if (!auth.ok) {
            return auth.response;
        }

        const result = await env.DB
            .prepare(`
                SELECT
                    id,
                    username,
                    balance,
                    created_at,
                    updated_at
                FROM accounts
                ORDER BY created_at DESC
            `)
            .all();

        return json({
            success: true,
            accounts: result.results || []
        });

    } catch (error) {
        console.error(
            "ADMIN ACCOUNTS ERROR:",
            error
        );

        return json(
            {
                success: false,
                error:
                    error?.message ||
                    "Не удалось получить аккаунты"
            },
            500
        );
    }
}


/* =========================================================
   ADMINISTRATORS
   ========================================================= */

export async function adminAdministrators(request, env) {
    try {
        const auth = await requireAdmin(request, env);

        if (!auth.ok) {
            return auth.response;
        }

        const result = await env.DB
            .prepare(`
                SELECT
                    id,
                    username,
                    role,
                    created_at,
                    updated_at
                FROM admin_accounts
                ORDER BY created_at DESC
            `)
            .all();

        return json({
            success: true,
            administrators:
                result.results || []
        });

    } catch (error) {
        console.error(
            "ADMIN ADMINISTRATORS ERROR:",
            error
        );

        return json(
            {
                success: false,
                error:
                    error?.message ||
                    "Не удалось получить администраторов"
            },
            500
        );
    }
}


/* =========================================================
   CREATE ADMINISTRATOR
   Только OWNER
   ========================================================= */

export async function createAdministrator(request, env) {
    try {
        const auth = await requireAdmin(request, env);

        if (!auth.ok) {
            return auth.response;
        }

        if (auth.admin.role !== "OWNER") {
            return json(
                {
                    success: false,
                    error:
                        "Только OWNER может создавать администраторов"
                },
                403
            );
        }

        const body = await request.json();

        const username = normalizeUsername(
            body.username
        );

        const password = String(
            body.password ?? ""
        );

        const role = String(
            body.role ?? "ADMIN"
        )
            .trim()
            .toUpperCase();

        if (!username) {
            return json(
                {
                    success: false,
                    error: "Введите логин"
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

        if (
            role !== "ADMIN" &&
            role !== "OWNER"
        ) {
            return json(
                {
                    success: false,
                    error: "Недопустимая роль"
                },
                400
            );
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
            return json(
                {
                    success: false,
                    error:
                        "Администратор с таким логином уже существует"
                },
                409
            );
        }

        const passwordData =
            await hashPassword(password);

        const adminId =
            generateId();

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

        return json(
            {
                success: true,
                administrator: {
                    id: adminId,
                    username,
                    role
                }
            },
            201
        );

    } catch (error) {
        console.error(
            "CREATE ADMINISTRATOR ERROR:",
            error
        );

        return json(
            {
                success: false,
                error:
                    error?.message ||
                    "Не удалось создать администратора"
            },
            500
        );
    }
}


/* =========================================================
   UPDATE ADMINISTRATOR
   Только OWNER
   ========================================================= */

export async function updateAdministrator(request, env) {
    try {
        const auth = await requireAdmin(request, env);

        if (!auth.ok) {
            return auth.response;
        }

        if (auth.admin.role !== "OWNER") {
            return json(
                {
                    success: false,
                    error:
                        "Только OWNER может изменять администраторов"
                },
                403
            );
        }

        const body = await request.json();

        const id = String(
            body.id ?? ""
        ).trim();

        if (!id) {
            return json(
                {
                    success: false,
                    error:
                        "Не указан ID администратора"
                },
                400
            );
        }

        const target = await env.DB
            .prepare(`
                SELECT
                    id,
                    username,
                    role
                FROM admin_accounts
                WHERE id = ?
                LIMIT 1
            `)
            .bind(id)
            .first();

        if (!target) {
            return json(
                {
                    success: false,
                    error:
                        "Администратор не найден"
                },
                404
            );
        }

        const username =
            body.username !== undefined
                ? normalizeUsername(body.username)
                : target.username;

        const role =
            body.role !== undefined
                ? String(body.role)
                    .trim()
                    .toUpperCase()
                : target.role;

        if (!validUsername(username)) {
            return json(
                {
                    success: false,
                    error:
                        "Недопустимый логин"
                },
                400
            );
        }

        if (
            role !== "ADMIN" &&
            role !== "OWNER"
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

        const duplicate = await env.DB
            .prepare(`
                SELECT id
                FROM admin_accounts
                WHERE LOWER(username) = LOWER(?)
                  AND id != ?
                LIMIT 1
            `)
            .bind(
                username,
                id
            )
            .first();

        if (duplicate) {
            return json(
                {
                    success: false,
                    error:
                        "Этот логин уже используется"
                },
                409
            );
        }

        await env.DB
            .prepare(`
                UPDATE admin_accounts
                SET
                    username = ?,
                    role = ?,
                    updated_at = datetime('now')
                WHERE id = ?
            `)
            .bind(
                username,
                role,
                id
            )
            .run();

        return json({
            success: true,
            administrator: {
                id,
                username,
                role
            }
        });

    } catch (error) {
        console.error(
            "UPDATE ADMINISTRATOR ERROR:",
            error
        );

        return json(
            {
                success: false,
                error:
                    error?.message ||
                    "Не удалось изменить администратора"
            },
            500
        );
    }
}


/* =========================================================
   DELETE ADMINISTRATOR
   Только OWNER
   ========================================================= */

export async function deleteAdministrator(request, env) {
    try {
        const auth = await requireAdmin(request, env);

        if (!auth.ok) {
            return auth.response;
        }

        if (auth.admin.role !== "OWNER") {
            return json(
                {
                    success: false,
                    error:
                        "Только OWNER может удалять администраторов"
                },
                403
            );
        }

        const body = await request.json();

        const id = String(
            body.id ?? ""
        ).trim();

        if (!id) {
            return json(
                {
                    success: false,
                    error:
                        "Не указан ID администратора"
                },
                400
            );
        }

        if (id === auth.admin.id) {
            return json(
                {
                    success: false,
                    error:
                        "Нельзя удалить самого себя"
                },
                400
            );
        }

        const target = await env.DB
            .prepare(`
                SELECT id
                FROM admin_accounts
                WHERE id = ?
                LIMIT 1
            `)
            .bind(id)
            .first();

        if (!target) {
            return json(
                {
                    success: false,
                    error:
                        "Администратор не найден"
                },
                404
            );
        }

        await env.DB
            .prepare(`
                DELETE FROM admin_sessions
                WHERE admin_id = ?
            `)
            .bind(id)
            .run();

        await env.DB
            .prepare(`
                DELETE FROM admin_accounts
                WHERE id = ?
            `)
            .bind(id)
            .run();

        return json({
            success: true,
            deleted: id
        });

    } catch (error) {
        console.error(
            "DELETE ADMINISTRATOR ERROR:",
            error
        );

        return json(
            {
                success: false,
                error:
                    error?.message ||
                    "Не удалось удалить администратора"
            },
            500
        );
    }
}


/* =========================================================
   PRODUCTS
   ========================================================= */

export async function adminProducts(request, env) {
    try {
        const auth = await requireAdmin(request, env);

        if (!auth.ok) {
            return auth.response;
        }

        return json({
            success: true,
            products: []
        });

    } catch (error) {
        console.error(
            "ADMIN PRODUCTS ERROR:",
            error
        );

        return json(
            {
                success: false,
                error:
                    error?.message ||
                    "Не удалось получить товары"
            },
            500
        );
    }
}


/* =========================================================
   TRANSACTIONS
   ========================================================= */

export async function adminTransactions(request, env) {
    try {
        const auth = await requireAdmin(request, env);

        if (!auth.ok) {
            return auth.response;
        }

        const result = await env.DB
            .prepare(`
                SELECT
                    id,
                    account_id,
                    type,
                    amount,
                    balance_after,
                    tebex_transaction_id,
                    webhook_id,
                    product_id,
                    created_at
                FROM transactions
                ORDER BY created_at DESC
                LIMIT 500
            `)
            .all();

        return json({
            success: true,
            transactions:
                result.results || []
        });

    } catch (error) {
        console.error(
            "ADMIN TRANSACTIONS ERROR:",
            error
        );

        return json(
            {
                success: false,
                error:
                    error?.message ||
                    "Не удалось получить транзакции"
            },
            500
        );
    }
}


/* =========================================================
   SUBSCRIPTIONS
   ========================================================= */

export async function adminSubscriptions(request, env) {
    try {
        const auth = await requireAdmin(request, env);

        if (!auth.ok) {
            return auth.response;
        }

        const result = await env.DB
            .prepare(`
                SELECT
                    id,
                    account_id,
                    product_id,
                    product_name,
                    expires_at,
                    status,
                    tebex_transaction_id,
                    created_at
                FROM entitlements
                ORDER BY created_at DESC
                LIMIT 500
            `)
            .all();

        return json({
            success: true,
            subscriptions:
                result.results || []
        });

    } catch (error) {
        console.error(
            "ADMIN SUBSCRIPTIONS ERROR:",
            error
        );

        return json(
            {
                success: false,
                error:
                    error?.message ||
                    "Не удалось получить подписки"
            },
            500
        );
    }
}
/* =========================================================
   PART 4/4
   ADMIN ACCESS CONTROL FOR NORMAL ACCOUNTS

   Выдача / снятие доступа обычному пользователю
   по ID или username.

   Использует:
   - accounts
   - entitlements
   - admin_sessions
   - admin_accounts

   НЕ использует:
   - credentials
   - обычные sessions
========================================================= */


/* =========================================================
   FIND NORMAL ACCOUNT
========================================================= */

async function findNormalAccount(env, identifier) {

    const value =
        String(identifier ?? "").trim();

    if (!value) {
        return null;
    }

    /*
       Сначала пытаемся найти по ID,
       затем по username.
    */

    let account =
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
            .bind(value)
            .first();

    if (account) {
        return account;
    }

    account =
        await env.DB
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
            .bind(value)
            .first();

    return account || null;
}


/* =========================================================
   CHECK ADMIN SESSION
========================================================= */

async function requireAdminForAccess(
    request,
    env
) {

    const sessionId =
        getCookie(
            request,
            "admin_session"
        );

    if (!sessionId) {
        return null;
    }

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
        return null;
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

        return null;
    }

    const admin =
        await env.DB
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
        return null;
    }

    return admin;
}


/* =========================================================
   GRANT ACCESS
=========================================================

POST /api/admin/access/grant

BODY:

{
    "identifier": "nickname",
    "productId": "visual",
    "productName": "Visual",
    "days": 30
}

identifier может быть:
- ID аккаунта
- username

days:
- 7
- 30
- 90
- null / 0 = навсегда
========================================================= */

export async function adminGrantAccess(
    request,
    env
) {

    try {

        /* -------------------------------------------------
           ADMIN AUTH
        ------------------------------------------------- */

        const admin =
            await requireAdminForAccess(
                request,
                env
            );

        if (!admin) {

            return json(
                {
                    success: false,
                    error:
                        "Требуется авторизация администратора"
                },
                401
            );

        }


        /* -------------------------------------------------
           BODY
        ------------------------------------------------- */

        const body =
            await request.json();


        const identifier =
            String(
                body.identifier ?? ""
            ).trim();


        const productId =
            String(
                body.productId ?? ""
            ).trim();


        const productName =
            String(
                body.productName ??
                productId
            ).trim();


        const daysValue =
            body.days;


        if (!identifier) {

            return json(
                {
                    success: false,
                    error:
                        "Укажите ID или ник пользователя"
                },
                400
            );

        }


        if (!productId) {

            return json(
                {
                    success: false,
                    error:
                        "Укажите productId"
                },
                400
            );

        }


        /* -------------------------------------------------
           FIND ACCOUNT
        ------------------------------------------------- */

        const account =
            await findNormalAccount(
                env,
                identifier
            );


        if (!account) {

            return json(
                {
                    success: false,
                    error:
                        "Обычный аккаунт не найден"
                },
                404
            );

        }


        /* -------------------------------------------------
           EXPIRATION
        -------------------------------------------------

           days = 7  -> 7 дней
           days = 30 -> 30 дней
           days = 90 -> 90 дней
           days = 0  -> навсегда
           days = null -> навсегда
        ------------------------------------------------- */

        let expiresAt = null;


        const days =
            Number(daysValue);


        if (
            Number.isFinite(days) &&
            days > 0
        ) {

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
           CREATE ENTITLEMENT
        ------------------------------------------------- */

        const entitlementId =
            crypto.randomUUID();


        await env.DB
            .prepare(`
                INSERT INTO entitlements (
                    id,
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
                    ?,
                    'active',
                    NULL,
                    datetime('now')
                )
            `)
            .bind(
                entitlementId,
                account.id,
                productId,
                productName,
                expiresAt
            )
            .run();


        /* -------------------------------------------------
           RESPONSE
        ------------------------------------------------- */

        return json(
            {
                success: true,

                message:
                    "Доступ выдан",

                account: {
                    id:
                        account.id,

                    username:
                        account.username
                },

                entitlement: {
                    id:
                        entitlementId,

                    productId:
                        productId,

                    productName:
                        productName,

                    expiresAt:
                        expiresAt,

                    status:
                        "active"
                },

                admin: {
                    id:
                        admin.id,

                    username:
                        admin.username,

                    role:
                        admin.role
                }
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
                    "Не удалось выдать доступ"
            },
            500
        );

    }

}


/* =========================================================
   REVOKE ACCESS
=========================================================

POST /api/admin/access/revoke

BODY:

{
    "identifier": "nickname",
    "productId": "visual"
}

identifier:
- ID
- username

productId:
- конкретный товар

Если productId не указан,
снимаются ВСЕ активные доступы
пользователя.
========================================================= */

export async function adminRevokeAccess(
    request,
    env
) {

    try {

        /* -------------------------------------------------
           ADMIN AUTH
        ------------------------------------------------- */

        const admin =
            await requireAdminForAccess(
                request,
                env
            );

        if (!admin) {

            return json(
                {
                    success: false,
                    error:
                        "Требуется авторизация администратора"
                },
                401
            );

        }


        /* -------------------------------------------------
           BODY
        ------------------------------------------------- */

        const body =
            await request.json();


        const identifier =
            String(
                body.identifier ?? ""
            ).trim();


        const productId =
            String(
                body.productId ?? ""
            ).trim();


        if (!identifier) {

            return json(
                {
                    success: false,
                    error:
                        "Укажите ID или ник пользователя"
                },
                400
            );

        }


        /* -------------------------------------------------
           FIND ACCOUNT
        ------------------------------------------------- */

        const account =
            await findNormalAccount(
                env,
                identifier
            );


        if (!account) {

            return json(
                {
                    success: false,
                    error:
                        "Обычный аккаунт не найден"
                },
                404
            );

        }


        /* -------------------------------------------------
           REVOKE ONE PRODUCT
        ------------------------------------------------- */

        if (productId) {

            const result =
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


            return json(
                {
                    success: true,

                    message:
                        result.meta?.changes
                            ? "Доступ снят"
                            : "Активный доступ не найден",

                    account: {
                        id:
                            account.id,

                        username:
                            account.username
                    },

                    productId:
                        productId,

                    changed:
                        result.meta?.changes || 0,

                    admin: {
                        id:
                            admin.id,

                        username:
                            admin.username,

                        role:
                            admin.role
                    }
                }
            );

        }


        /* -------------------------------------------------
           REVOKE ALL PRODUCTS
        ------------------------------------------------- */

        const result =
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


        return json(
            {
                success: true,

                message:
                    result.meta?.changes
                        ? "Все активные доступы сняты"
                        : "Активных доступов не найдено",

                account: {
                    id:
                        account.id,

                    username:
                        account.username
                },

                changed:
                    result.meta?.changes || 0,

                admin: {
                    id:
                        admin.id,

                    username:
                        admin.username,

                    role:
                        admin.role
                }
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
                    "Не удалось снять доступ"
            },
            500
        );

    }

}


/* =========================================================
   GET USER ACCESS
=========================================================

POST /api/admin/access/list

BODY:

{
    "identifier": "nickname"
}

Возвращает все entitlement пользователя.
========================================================= */

export async function adminUserAccess(
    request,
    env
) {

    try {

        /* -------------------------------------------------
           ADMIN AUTH
        ------------------------------------------------- */

        const admin =
            await requireAdminForAccess(
                request,
                env
            );

        if (!admin) {

            return json(
                {
                    success: false,
                    error:
                        "Требуется авторизация администратора"
                },
                401
            );

        }


        /* -------------------------------------------------
           BODY
        ------------------------------------------------- */

        const body =
            await request.json();


        const identifier =
            String(
                body.identifier ?? ""
            ).trim();


        if (!identifier) {

            return json(
                {
                    success: false,
                    error:
                        "Укажите ID или ник пользователя"
                },
                400
            );

        }


        /* -------------------------------------------------
           FIND ACCOUNT
        ------------------------------------------------- */

        const account =
            await findNormalAccount(
                env,
                identifier
            );


        if (!account) {

            return json(
                {
                    success: false,
                    error:
                        "Обычный аккаунт не найден"
                },
                404
            );

        }


        /* -------------------------------------------------
           ENTITLEMENTS
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


        /* -------------------------------------------------
           RESPONSE
        ------------------------------------------------- */

        return json(
            {
                success: true,

                account: {
                    id:
                        account.id,

                    username:
                        account.username,

                    balance:
                        account.balance,

                    created_at:
                        account.created_at
                },

                entitlements:
                    result.results || [],

                admin: {
                    id:
                        admin.id,

                    username:
                        admin.username,

                    role:
                        admin.role
                }
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
                    "Не удалось получить доступы пользователя"
            },
            500
        );

    }

}
