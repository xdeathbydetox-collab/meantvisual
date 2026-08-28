const PBKDF2_ITERATIONS = 100000; const HASH_BYTES = 32;
const SESSION_DAYS = 30;
/* ========================================================= RESPONSE ========================================================= */
function json(data, status = 200, extraHeaders = {}) { return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Credentials": "true",

  ...extraHeaders
}
}); }
function optionsResponse() { return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers":
    "Content-Type, Accept, Authorization",

  "Access-Control-Allow-Credentials": "true"
}
}); }
/* ========================================================= CRYPTO ========================================================= */
function randomBytes(length) { const bytes = new Uint8Array(length);
crypto.getRandomValues(bytes);
return bytes; }
function bytesToBase64(bytes) { let binary = "";
for (const byte of bytes) { binary += String.fromCharCode(byte); }
return btoa(binary); }
function base64ToBytes(value) { const binary = atob(value);
const bytes = new Uint8Array(binary.length);
for ( let i = 0; i < binary.length; i++ ) { bytes[i] = binary.charCodeAt(i); }
return bytes; }
async function sha256Base64(value) { const data = new TextEncoder().encode(value);
const hash = await crypto.subtle.digest( "SHA-256", data );
return bytesToBase64( new Uint8Array(hash) ); }
/* ========================================================= PASSWORD HASH ========================================================= */
async function hashPassword(password) { const salt = randomBytes(16);
const key = await crypto.subtle.importKey( "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"] );
const bits = await crypto.subtle.deriveBits( { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, key, HASH_BYTES * 8 );
return { hash: bytesToBase64( new Uint8Array(bits) ),
salt: bytesToBase64(
  salt
)
}; }
async function createPasswordHash(password) { const result = await hashPassword(password);
return ( result.salt + "$" + result.hash ); }
async function verifyPassword( password, stored ) { try { if (!stored) { return false; }
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
    actual[i] ^
    expected[i];
}

return difference === 0;
} catch { return false; } }
/* ========================================================= BASIC HELPERS ========================================================= */
function createToken() { return bytesToBase64( randomBytes(32) ) .replace(/+/g, "-") .replace(///g, "_") .replace(/=/g, ""); }
function getCookie(request, name) { const cookie = request.headers.get("Cookie");
if (!cookie) { return null; }
const parts = cookie.split(";");
for (const part of parts) { const item = part.trim();
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
return null; }
async function readJson(request) { try { return await request.json(); } catch { return null; } }
function normalizeEmail(value) { return String( value || "" ) .trim() .toLowerCase(); }
function normalizeUsername(value) { return String( value || "" ).trim(); }
function validEmail(email) { return /^[^\s@]+@[^\s@]+.[^\s@]+$/.test( email ); }
function validUsername(username) { return /^[a-zA-Z0-9_.-]{3,24}$/.test( username ); }
function cookieHeader(token) { return ( "meant_session=" + encodeURIComponent(token) + "; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax" ); }
function clearCookieHeader() { return ( "meant_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax" ); }
/* ========================================================= SESSION ========================================================= */
async function createSession( env, accountId ) { const token = createToken();
const tokenHash = await sha256Base64(token);
const sessionId = crypto.randomUUID();
const expires = new Date( Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000 ).toISOString();
await env.DB .prepare(INSERT INTO sessions ( id, account_id, token_hash, expires_at ) VALUES (?, ?, ?, ?)) .bind( sessionId, accountId, tokenHash, expires ) .run();
return { token, expires }; }
async function getSessionAccount( request, env ) { const token = getCookie( request, "meant_session" );
if (!token) { return null; }
const tokenHash = await sha256Base64(token);
const row = await env.DB .prepare(SELECT accounts.id, accounts.username, accounts.balance, accounts.email, sessions.id AS session_id, sessions.expires_at FROM sessions INNER JOIN accounts ON accounts.id = sessions.account_id WHERE sessions.token_hash = ? LIMIT 1) .bind(tokenHash) .first();
if (!row) { return null; }
if ( !row.expires_at || new Date( row.expires_at ).getTime() <= Date.now() ) { await env.DB .prepare(DELETE FROM sessions WHERE token_hash = ?) .bind(tokenHash) .run();
return null;
}
return row; }
/* ========================================================= PUBLIC ACCOUNT REGISTER ========================================================= */
async function register( request, env ) { const body = await readJson(request);
if (!body) { return json({ error: "Неверный JSON" }, 400); }
const username = normalizeUsername( body.username );
const email = normalizeEmail( body.email );
const password = String( body.password || "" );
if (!username) { return json({ error: "Введите никнейм" }, 400); }
if (!validUsername(username)) { return json({ error: "Никнейм должен содержать 3-24 символа: буквы, цифры, _, -, ." }, 400); }
if (!email) { return json({ error: "Введите email" }, 400); }
if (!validEmail(email)) { return json({ error: "Некорректный email" }, 400); }
if (!password) { return json({ error: "Введите пароль" }, 400); }
if (password.length < 8) { return json({ error: "Пароль должен содержать минимум 8 символов" }, 400); }
const existingUsername = await env.DB .prepare(SELECT id FROM accounts WHERE LOWER(username) = LOWER(?) LIMIT 1) .bind(username) .first();
if (existingUsername) { return json({ error: "Этот никнейм уже занят" }, 409); }
const existingEmail = await env.DB .prepare(SELECT id FROM accounts WHERE LOWER(email) = LOWER(?) LIMIT 1) .bind(email) .first();
if (existingEmail) { return json({ error: "Этот email уже используется" }, 409); }
const accountId = crypto.randomUUID();
const passwordHash = await createPasswordHash( password );
try { await env.DB .prepare(INSERT INTO accounts ( id, username, email, balance ) VALUES (?, ?, ?, 0)) .bind( accountId, username, email ) .run();
await env.DB
  .prepare(`
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
} catch (error) { try { await env.DB .prepare(DELETE FROM credentials WHERE account_id = ?) .bind(accountId) .run();
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
const session = await createSession( env, accountId );
return json( { success: true,
  account: {
    id: accountId,
    username,
    email,
    balance: 0
  }
},
200,
{
  "Set-Cookie":
    cookieHeader(
      session.token
    )
}
); }
/* ========================================================= PUBLIC LOGIN ========================================================= */
async function login( request, env ) { const body = await readJson(request);
if (!body) { return json({ error: "Неверный JSON" }, 400); }
const loginValue = String( body.login  body.username  body.email || "" ).trim();
const password = String( body.password || "" );
if ( !loginValue || !password ) { return json({ error: "Введите логин/email и пароль" }, 400); }
const account = await env.DB .prepare(SELECT accounts.id, accounts.username, accounts.email, accounts.balance, credentials.password_hash FROM accounts INNER JOIN credentials ON credentials.account_id = accounts.id WHERE LOWER(accounts.username) = LOWER(?) OR LOWER(accounts.email) = LOWER(?) LIMIT 1) .bind( loginValue, loginValue ) .first();
if (!account) { return json({ error: "Неверный логин/email или пароль" }, 401); }
const valid = await verifyPassword( password, account.password_hash );
if (!valid) { return json({ error: "Неверный логин/email или пароль" }, 401); }
const session = await createSession( env, account.id );
return json( { success: true,
  account: {
    id: account.id,
    username: account.username,
    email: account.email,
    balance:
      Number(
        account.balance || 0
      )
  }
},
200,
{
  "Set-Cookie":
    cookieHeader(
      session.token
    )
}
); }
/* ========================================================= PUBLIC ME ========================================================= */
async function me( request, env ) { const account = await getSessionAccount( request, env );
if (!account) { return json({ authenticated: false }, 401); }
return json({ authenticated: true,
account: {
  id: account.id,
  username: account.username,
  email: account.email,
  balance:
    Number(
      account.balance || 0
    )
}
}); }
/* ========================================================= PUBLIC LOGOUT ========================================================= */
async function logout( request, env ) { const token = getCookie( request, "meant_session" );
if (token) { const tokenHash = await sha256Base64( token );
await env.DB
  .prepare(`
    DELETE FROM sessions
    WHERE token_hash = ?
  `)
  .bind(tokenHash)
  .run();
}
return json( { success: true }, 200, { "Set-Cookie": clearCookieHeader() } ); }
/* ========================================================= ADMIN AUTH ========================================================= */
async function getCurrentAdmin( request, env ) { const account = await getSessionAccount( request, env );
if (!account) { return null; }
const admin = await env.DB .prepare(SELECT a.id, a.username, a.email, a.role, a.permissions, a.active, a.must_change_password, a.email_verified, a.created_at FROM administrators a WHERE a.account_id = ? LIMIT 1) .bind(account.id) .first();
if (!admin) { return null; }
if ( Number(admin.active) !== 1 ) { return null; }
return { ...admin, permissions: parsePermissions( admin.permissions ) }; }
function parsePermissions(value) { if (!value) { return []; }
try { const parsed = JSON.parse(value);
if (
  Array.isArray(parsed)
) {
  return parsed;
}

return [];
} catch { return []; } }
function hasPermission( admin, permission ) { if (!admin) { return false; }
if (admin.role === "OWNER") { return true; }
return ( Array.isArray( admin.permissions ) && admin.permissions.includes( permission ) ); }
async function requireAdmin( request, env ) { const admin = await getCurrentAdmin( request, env );
if (!admin) { return { error: json({ error: "Доступ запрещён" }, 403) }; }
return { admin }; }
/* ========================================================= ADMIN LOGIN ========================================================= */
async function adminLogin( request, env ) { const body = await readJson(request);
if (!body) { return json({ error: "Неверный JSON" }, 400); }
const loginValue = String( body.login  body.username  body.email || "" ).trim();
const password = String( body.password || "" );
if ( !loginValue || !password ) { return json({ error: "Введите логин/email и пароль" }, 400); }
const admin = await env.DB .prepare(` SELECT administrators.id AS admin_id, administrators.account_id, administrators.role, administrators.permissions, administrators.active, administrators.must_change_password, administrators.email_verified,
      accounts.username,
      accounts.email,

      credentials.password_hash

    FROM administrators

    INNER JOIN accounts
      ON accounts.id =
         administrators.account_id

    INNER JOIN credentials
      ON credentials.account_id =
         accounts.id

    WHERE
      (
        LOWER(accounts.username) =
          LOWER(?)
        OR
        LOWER(accounts.email) =
          LOWER(?)
      )

    LIMIT 1
  `)
  .bind(
    loginValue,
    loginValue
  )
  .first();
if (!admin) { return json({ error: "Неверный логин/email или пароль" }, 401); }
if ( Number(admin.active) !== 1 ) { return json({ error: "Администратор отключён" }, 403); }
const valid = await verifyPassword( password, admin.password_hash );
if (!valid) { return json({ error: "Неверный логин/email или пароль" }, 401); }
const session = await createSession( env, admin.account_id );
return json( { success: true,
  admin: {
    id: admin.admin_id,
    account_id:
      admin.account_id,
    username:
      admin.username,
    email:
      admin.email,
    role:
      admin.role,
    permissions:
      parsePermissions(
        admin.permissions
      ),
    must_change
   :
        Number(
          admin.must_change_password || 0
        ) === 1,

    email_verified:
      Number(
        admin.email_verified || 0
      ) === 1
  }
},
200,
{
  "Set-Cookie":
    cookieHeader(
      session.token
    )
}
); }
/* ========================================================= ADMIN ME ========================================================= */
async function adminMe( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
return json({ success: true,
admin: {
  id: admin.id,
  username: admin.username,
  email: admin.email,
  role: admin.role,
  permissions:
    admin.permissions,
  active:
    Number(admin.active) === 1,
  must_change_password:
    Number(
      admin.must_change_password || 0
    ) === 1,
  email_verified:
    Number(
      admin.email_verified || 0
    ) === 1,
  created_at:
    admin.created_at
}
}); }
/* ========================================================= ADMIN LOGOUT ========================================================= */
async function adminLogout( request, env ) { const token = getCookie( request, "meant_session" );
if (token) { const tokenHash = await sha256Base64( token );
await env.DB
  .prepare(`
    DELETE FROM sessions
    WHERE token_hash = ?
  `)
  .bind(tokenHash)
  .run();
}
return json( { success: true }, 200, { "Set-Cookie": clearCookieHeader() } ); }
/* ========================================================= ADMIN CHANGE PASSWORD ========================================================= */
async function adminChangePassword( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
const body = await readJson(request);
if (!body) { return json({ error: "Неверный JSON" }, 400); }
const newPassword = String( body.password  body.new_password  "" );
if (!newPassword) { return json({ error: "Введите новый пароль" }, 400); }
if (newPassword.length < 8) { return json({ error: "Пароль должен содержать минимум 8 символов" }, 400); }
const passwordHash = await createPasswordHash( newPassword );
await env.DB .prepare(UPDATE credentials SET password_hash = ? WHERE account_id = ?) .bind( passwordHash, admin.account_id ) .run();
await env.DB .prepare(UPDATE administrators SET must_change_password = 0 WHERE id = ?) .bind( admin.id ) .run();
return json({ success: true, message: "Пароль успешно изменён" }); }
/* ========================================================= ADMIN — STATISTICS ========================================================= */
async function adminStats( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "dashboard.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
const accounts = await env.DB .prepare(SELECT COUNT(*) AS count FROM accounts) .first();
const administrators = await env.DB .prepare(SELECT COUNT(*) AS count FROM administrators WHERE active = 1) .first();
const transactions = await env.DB .prepare(SELECT COUNT(*) AS count FROM transactions) .first();
const subscriptions = await env.DB .prepare(SELECT COUNT(*) AS count FROM entitlements WHERE status = 'active') .first();
const revenue = await env.DB .prepare(SELECT COALESCE( SUM( CASE WHEN amount > 0 THEN amount ELSE 0 END ), 0 ) AS total FROM transactions) .first();
return json({ success: true,
statistics: {
  accounts:
    Number(accounts?.count || 0),

  administrators:
    Number(
      administrators?.count || 0
    ),

  transactions:
    Number(
      transactions?.count || 0
    ),

  subscriptions:
    Number(
      subscriptions?.count || 0
    ),

  revenue:
    Number(
      revenue?.total || 0
    )
}
}); }
/* ========================================================= ADMIN — ACCOUNTS ========================================================= */
async function adminAccounts( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.
   error; }
const admin = result.admin;
if ( !hasPermission( admin, "accounts.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
const rows = await env.DB .prepare(SELECT id, username, email, balance, created_at, updated_at FROM accounts ORDER BY created_at DESC LIMIT 500) .all();
return json({ success: true, accounts: rows.results || [] }); }
/* ========================================================= ADMIN — ADMINISTRATORS ========================================================= */
async function adminAdministrators( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "admins.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
const rows = await env.DB .prepare(` SELECT administrators.id, administrators.account_id, administrators.role, administrators.permissions, administrators.active, administrators.must_change_password, administrators.email_verified, administrators.created_at,
      accounts.username,
      accounts.email

    FROM administrators

    INNER JOIN accounts
      ON accounts.id =
         administrators.account_id

    ORDER BY administrators.created_at DESC

    LIMIT 500
  `)
  .all();
const administrators = (rows.results || []).map( item => ({ ...item,
    permissions:
      parsePermissions(
        item.permissions
      ),

    active:
      Number(
        item.active || 0
      ) === 1,

    must_change_password:
      Number(
        item.must_change_password || 0
      ) === 1,

    email_verified:
      Number(
        item.email_verified || 0
      ) === 1
  })
);
return json({ success: true, administrators }); }
/* ========================================================= ADMIN — CREATE ADMINISTRATOR ========================================================= */
async function createAdministrator( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const creator = result.admin;
/* Только OWNER может создавать новых администраторов. */
if ( creator.role !== "OWNER" ) { return json({ error: "Только OWNER может создавать администраторов" }, 403); }
const body = await readJson(request);
if (!body) { return json({ error: "Неверный JSON" }, 400); }
const username = normalizeUsername( body.username );
const email = normalizeEmail( body.email );
const password = String( body.password || "" );
const role = String( body.role || "ADMIN" ).toUpperCase();
let permissions = body.permissions;
if (!Array.isArray(permissions)) { permissions = []; }
if (!username) { return json({ error: "Введите никнейм" }, 400); }
if (!validUsername(username)) { return json({ error: "Некорректный никнейм" }, 400); }
if (!email || !validEmail(email)) { return json({ error: "Некорректный email" }, 400); }
if (password.length < 8) { return json({ error: "Пароль должен содержать минимум 8 символов" }, 400); }
/* Запрещаем создавать второго OWNER через обычную форму. */
if ( role !== "ADMIN" && role !== "MODERATOR" && role !== "SUPPORT" ) { return json({ error: "Недопустимая роль" }, 400); }
const usernameExists = await env.DB .prepare(SELECT id FROM accounts WHERE LOWER(username) = LOWER(?) LIMIT 1) .bind(username) .first();
if (usernameExists) { return json({ error: "Этот никнейм уже занят" }, 409); }
const emailExists = await env.DB .prepare(SELECT id FROM accounts WHERE LOWER(email) = LOWER(?) LIMIT 1) .bind(email) .first();
if (emailExists) { return json({ error: "Этот email уже используется" }, 409); }
const accountId = crypto.randomUUID();
const adminId = crypto.randomUUID();
const passwordHash = await createPasswordHash( password );
try { await env.DB .prepare(INSERT INTO accounts ( id, username, email, balance ) VALUES (?, ?, ?, 0)) .bind( accountId, username, email ) .run();
await env.DB
  .prepare(`
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

await env.DB
  .prepare(`
    INSERT INTO administrators
    (
      id,
      account_id,
      role,
      permissions,
      active,
      must_change_password,
      email_verified
    )
    VALUES (?, ?, ?, ?, 1, 1, 0)
  `)
  .bind(
    adminId,
    accountId,
    role,
    JSON.stringify(
      permissions
    )
  )
  .run();
} catch (error) {
try {
  await env.DB
    .prepare(`
      DELETE FROM administrators
      WHERE id = ?
    `)
    .bind(adminId)
    .run();
} catch {}

try {
  await env.DB
    .prepare(`
      DELETE FROM credentials
      WHERE account_id = ?
    `)
    .bind(accountId)
    .run();
} catch {}

try {
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
    "Не удалось создать администратора: " +
    (
      error?.message ||
      String(error)
    )
}, 500);
}
return json({ success: true,
administrator: {
  id: adminId,
  account_id: accountId,
  username,
  email,
  role,
  permissions,
  must_change_password: true,
  email_verified: false
}
}, 201); }
/* ========================================================= ADMIN — UPDATE ADMINISTRATOR ========================================================= */
async function updateAdministrator( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const creator = result.admin;
if ( creator.role !== "OWNER" ) { return json({ error: "Только OWNER может изменять администраторов" }, 403); }
const body = await readJson(request);
if (!body) { return json({ error: "Неверный JSON" }, 400); }
const adminId = String( body.id || "" );
if (!adminId) { return json({ error: "Не указан ID администратора" }, 400); }
const target = await env.DB .prepare(SELECT id, account_id, role, active FROM administrators WHERE id = ? LIMIT 1) .bind(adminId) .first();
if (!target) { return json({ error: "Администратор не найден" }, 404); }
/* OWNER нельзя изменить через эту функцию. */
if ( target.role === "OWNER" ) { return json({ error: "Нельзя изменить OWNER" }, 403); }
if ( body.role !== undefined ) { const role = String( body.role ).toUpperCase();
if (
  ![
    "ADMIN",
    "MODERATOR",
    "SUPPORT"
  ].includes(role)
) {
  return json({
    error:
      "Недопустимая роль"
  }, 400);
}

await env.DB
  .prepare(`
    UPDATE administrators
    SET role = ?
    WHERE id = ?
  `)
  .bind(
    role,
    adminId
  )
  .run();
}
if ( body.permissions !== undefined ) { if ( !Array.isArray( body.permissions ) ) { return json({ error: "permissions должен быть массивом" }, 400); }
await env.DB
  .prepare(`
    UPDATE administrators
    SET permissions = ?
    WHERE id = ?
  `)
  .bind(
    JSON.stringify(
      body.permissions
    ),
    adminId
  )
  .run();
}
if ( body.active !== undefined ) { await env.DB .prepare(UPDATE administrators SET active = ? WHERE id = ?) .bind( body.active ? 1 : 0, adminId ) .run(); }
return json({ success: true }); }
/* ========================================================= ADMIN — DELETE ADMINISTRATOR ========================================================= */
async function deleteAdministrator( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const creator = result.admin;
if ( creator.role !== "OWNER" ) { return json({ error: "Только OWNER может удалять администраторов" }, 403); }
const body = await readJson(request);
if (!body) { return json({ error: "Неверный JSON" }, 400); }
const adminId = String( body.id || "" );
if (!adminId) { return json({ error: "Не указан ID администратора" }, 400); }
const target = await env.DB .prepare(SELECT id, account_id, role FROM administrators WHERE id = ? LIMIT 1) .bind(adminId) .first();
if (!target) { return json({ error: "Администратор не найден" }, 404); }
if ( target.role === "OWNER" ) { return json({ error: "OWNER нельзя удалить" }, 403); }
/* Удаляем сессии пользователя, затем администратора, credentials и аккаунт. */
await env.DB .prepare(DELETE FROM sessions WHERE account_id = ?) .bind( target.account_id ) .run();
await env.DB .
   prepare(DELETE FROM administrators WHERE id = ?) .bind(adminId) .run();
await env.DB .prepare(DELETE FROM credentials WHERE account_id = ?) .bind( target.account_id ) .run();
await env.DB .prepare(DELETE FROM accounts WHERE id = ?) .bind( target.account_id ) .run();
return json({ success: true, message: "Администратор удалён" }); }
/* ========================================================= ADMIN — PRODUCTS ========================================================= */
async function adminProducts( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "products.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
try { const rows = await env.DB .prepare(SELECT * FROM products ORDER BY created_at DESC LIMIT 500) .all();
return json({
  success: true,
  products:
    rows.results || []
});
} catch (error) {
return json({
  success: true,
  products: []
});
} }
/* ========================================================= ADMIN — TRANSACTIONS ========================================================= */
async function adminTransactions( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "transactions.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
const rows = await env.DB .prepare(SELECT transactions.*, accounts.username FROM transactions LEFT JOIN accounts ON accounts.id = transactions.account_id ORDER BY transactions.created_at DESC LIMIT 500) .all();
return json({ success: true,
transactions:
  rows.results || []
}); }
/* ========================================================= ADMIN — SUBSCRIPTIONS ========================================================= */
async function adminSubscriptions( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "subscriptions.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
const rows = await env.DB .prepare(SELECT entitlements.*, accounts.username, accounts.email FROM entitlements LEFT JOIN accounts ON accounts.id = entitlements.account_id ORDER BY entitlements.created_at DESC LIMIT 500) .all();
return json({ success: true,
subscriptions:
  rows.results || []
}); }
/* ========================================================= ADMIN — LOGS ========================================================= */
async function adminLogs( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "logs.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
try {
const rows =
  await env.DB
    .prepare(`
      SELECT *
      FROM admin_logs
      ORDER BY created_at DESC
      LIMIT 500
    `)
    .all();

return json({
  success: true,
  logs:
    rows.results || []
});
} catch {
return json({
  success: true,
  logs: []
});
} }
/* ========================================================= ADMIN — SETTINGS ========================================================= */
async function adminSettings( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "settings.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
return json({ success: true,
settings: {
  tebex:
    Boolean(
      env.TEBEX_PUBLIC_TOKEN
    ),

  tebex_packages: {
    "30-days":
      Boolean(
        env.TEBEX_PACKAGE_30_DAYS
      ),

    "90-days":
      Boolean(
        env.TEBEX_PACKAGE_90_DAYS
      ),

    forever:
      Boolean(
        env.TEBEX_PACKAGE_FOREVER
      )
  }
}
}); }
/* ========================================================= API ROUTER ========================================================= */
export default {
async fetch( request, env ) {
if (
  request.method ===
  "OPTIONS"
   prepare(DELETE FROM administrators WHERE id = ?) .bind(adminId) .run();
await env.DB .prepare(DELETE FROM credentials WHERE account_id = ?) .bind( target.account_id ) .run();
await env.DB .prepare(DELETE FROM accounts WHERE id = ?) .bind( target.account_id ) .run();
return json({ success: true, message: "Администратор удалён" }); }
/* ========================================================= ADMIN — PRODUCTS ========================================================= */
async function adminProducts( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "products.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
try { const rows = await env.DB .prepare(SELECT * FROM products ORDER BY created_at DESC LIMIT 500) .all();
return json({
  success: true,
  products:
    rows.results || []
});
} catch (error) {
return json({
  success: true,
  products: []
});
} }
/* ========================================================= ADMIN — TRANSACTIONS ========================================================= */
async function adminTransactions( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "transactions.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
const rows = await env.DB .prepare(SELECT transactions.*, accounts.username FROM transactions LEFT JOIN accounts ON accounts.id = transactions.account_id ORDER BY transactions.created_at DESC LIMIT 500) .all();
return json({ success: true,
transactions:
  rows.results || []
}); }
/* ========================================================= ADMIN — SUBSCRIPTIONS ========================================================= */
async function adminSubscriptions( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "subscriptions.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
const rows = await env.DB .prepare(SELECT entitlements.*, accounts.username, accounts.email FROM entitlements LEFT JOIN accounts ON accounts.id = entitlements.account_id ORDER BY entitlements.created_at DESC LIMIT 500) .all();
return json({ success: true,
subscriptions:
  rows.results || []
}); }
/* ========================================================= ADMIN — LOGS ========================================================= */
async function adminLogs( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "logs.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
try {
const rows =
  await env.DB
    .prepare(`
      SELECT *
      FROM admin_logs
      ORDER BY created_at DESC
      LIMIT 500
    `)
    .all();

return json({
  success: true,
  logs:
    rows.results || []
});
} catch {
return json({
  success: true,
  logs: []
});
} }
/* ========================================================= ADMIN — SETTINGS ========================================================= */
async function adminSettings( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "settings.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
return json({ success: true,
settings: {
  tebex:
    Boolean(
      env.TEBEX_PUBLIC_TOKEN
    ),

  tebex_packages: {
    "30-days":
      Boolean(
        env.TEBEX_PACKAGE_30_DAYS
      ),

    "90-days":
      Boolean(
        env.TEBEX_PACKAGE_90_DAYS
      ),

    forever:
      Boolean(
        env.TEBEX_PACKAGE_FOREVER
      )
  }
}
}); }
/* ========================================================= API ROUTER ========================================================= */
export default {
async fetch( request, env ) {
if (
  request.method ===
  "OPTIONS"
) {prepare(DELETE FROM administrators WHERE id = ?) .bind(adminId) .run();
await env.DB .prepare(DELETE FROM credentials WHERE account_id = ?) .bind( target.account_id ) .run();
await env.DB .prepare(DELETE FROM accounts WHERE id = ?) .bind( target.account_id ) .run();
return json({ success: true, message: "Администратор удалён" }); }
/* ========================================================= ADMIN — PRODUCTS ========================================================= */
async function adminProducts( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "products.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
try { const rows = await env.DB .prepare(SELECT * FROM products ORDER BY created_at DESC LIMIT 500) .all();
return json({
  success: true,
  products:
    rows.results || []
});
} catch (error) {
return json({
  success: true,
  products: []
});
} }
/* ========================================================= ADMIN — TRANSACTIONS ========================================================= */
async function adminTransactions( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "transactions.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
const rows = await env.DB .prepare(SELECT transactions.*, accounts.username FROM transactions LEFT JOIN accounts ON accounts.id = transactions.account_id ORDER BY transactions.created_at DESC LIMIT 500) .all();
return json({ success: true,
transactions:
  rows.results || []
}); }
/* ========================================================= ADMIN — SUBSCRIPTIONS ========================================================= */
async function adminSubscriptions( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "subscriptions.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
const rows = await env.DB .prepare(SELECT entitlements.*, accounts.username, accounts.email FROM entitlements LEFT JOIN accounts ON accounts.id = entitlements.account_id ORDER BY entitlements.created_at DESC LIMIT 500) .all();
return json({ success: true,
subscriptions:
  rows.results || []
}); }
/* ========================================================= ADMIN — LOGS ========================================================= */
async function adminLogs( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "logs.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
try {
const rows =
  await env.DB
    .prepare(`
      SELECT *
      FROM admin_logs
      ORDER BY created_at DESC
      LIMIT 500
    `)
    .all();

return json({
  success: true,
  logs:
    rows.results || []
});
} catch {
return json({
  success: true,
  logs: []
});
} }
/* ========================================================= ADMIN — SETTINGS ========================================================= */
async function adminSettings( request, env ) { const result = await requireAdmin( request, env );
if (result.error) { return result.error; }
const admin = result.admin;
if ( !hasPermission( admin, "settings.view" ) ) { return json({ error: "Недостаточно прав" }, 403); }
return json({ success: true,
settings: {
  tebex:
    Boolean(
      env.TEBEX_PUBLIC_TOKEN
    ),

  tebex_packages: {
    "30-days":
      Boolean(
        env.TEBEX_PACKAGE_30_DAYS
      ),

    "90-days":
      Boolean(
        env.TEBEX_PACKAGE_90_DAYS
      ),

    forever:
      Boolean(
        env.TEBEX_PACKAGE_FOREVER
      )
  }
}
}); }
/* ========================================================= API ROUTER ========================================================= */
export default {
async fetch( request, env ) {
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

  /* ===================================================
     PUBLIC AUTH
  =================================================== */

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

  /* ===================================================
     ADMIN AUTH
  =================================================== */

  if (
    path ===
    "/api/admin/login" &&
    request.method ===
    "POST"
  ) {
    return await adminLogin(
      request,
      env
    );
  }

  if (
    path ===
    "/api/admin/me" &&
    request.method ===
    "GET"
  ) {
    return await adminMe(
      request,
      env
    );
  }

  if (
    path ===
    "/api/admin/logout" &&
    request.method ===
    "POST"
  ) {
    return await adminLogout(
      request,
      env
    );
  }

  if (
    path ===
    "/api/admin/change-password" &&
    request.method ===
    "POST"
  ) {
    return await adminChangePassword(
      request,
      env
    );
  }

  /* ===================================================
     ADMIN DASHBOARD
  =================================================== */

  if (
    path ===
    "/api/admin/stats" &&
    request.method ===
    "GET"
  ) {
    return await adminStats(
      request,
      env
    );
  }

  /* ===================================================
     ADMIN ACCOUNTS
  =================================================== */

  if (
    path ===
    "/api/admin/accounts" &&
    request.method ===
    "GET"
  ) {
    return await adminAccounts(
      request,
      env
    );
  }

  /* ===================================================
     ADMINISTRATORS
  =================================================== */

  if (
    path ===
    "/api/admin/administrators" &&
    request.method ===
    "GET"
  ) {
    return await adminAdministrators(
      request,
      env
    );
  }

  if (
    path ===
    "/api/admin/administrators" &&
    request.method ===
    "POST"
  ) {
    return await createAdministrator(
      request,
      env
    );
  }

  if (
    path ===
    "/api/admin/administrators" &&
    request.method ===
    "PUT"
  ) {
    return await updateAdministrator(
      request,
      env
    );
  }

  if (
    path ===
    "/api/admin/administrators" &&
    request.method ===
    "DELETE"
  ) {
    return await deleteAdministrator(
      request,
      env
    );
  }

  /* ===================================================
     PRODUCTS
  =================================================== */

  if (
    path ===
    "/api/admin/products" &&
    request.method ===
    "GET"
  ) {
    return await adminProducts(
      request,
      env
    );
  }

  /* ===================================================
     TRANSACTIONS
  =================================================== */

  if (
    path ===
    "/api/admin/transactions" &&
    request.method ===
    "GET"
  ) {
    return await adminTransactions(
      request,
      env
    );
  }

  /* ===================================================
     SUBSCRIPTIONS
  =================================================== */

  if (
    path ===
    "/api/admin/subscriptions" &&
    request.method ===
    "GET"
  ) {
    return await adminSubscriptions(
      request,
      env
    );
  }

  /* ===================================================
     LOGS
  =================================================== */

  if (
    path ===
    "/api/admin/logs" &&
    request.method ===
    "GET"
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

  /* ===================================================
     PUBLIC AUTH
  =================================================== */

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

  /* ===================================================
     ADMIN AUTH
  =================================================== */

  if (
    path ===
    "/api/admin/login" &&
    request.method ===
    "POST"
  ) {
    return await adminLogin(
      request,
      env
    );
  }

  if (
    path ===
    "/api/admin/me" &&
    request.method ===
    "GET"
  ) {
    return await adminMe(
      request,
      env
    );
  }

  if (
    path ===
    "/api/admin/logout" &&
    request.method ===
    "POST"
  ) {
    return await adminLogout(
      request,
      env
    );
  }

  if (
    path ===
    "/api/admin/change-password" &&
    request.method ===
    "POST"
  ) {
    return await adminChangePassword(
      request,
      env
    );
  }

  /* ===================================================
     ADMIN DASHBOARD
  =================================================== */

  if (
    path ===
    "/api/admin/stats" &&
    request.method ===
    "GET"
  ) {
    return await adminStats(
      request,
      env
    );
  }

  /* ===================================================
     ADMIN ACCOUNTS
  =================================================== */

  if (
    path ===
    "/api/admin/accounts" &&
    request.method ===
    "GET"
  ) {
    return await adminAccounts(
      request,
      env
    );
  }

  /* ===================================================
     ADMINISTRATORS
  =================================================== */

  if (
    path ===
    "/api/admin/administrators" &&
    request.method ===
    "GET"
  ) {
 return await adminLogs(
      request,
      env
    );
  }

  /* ===================================================
     SETTINGS
  =================================================== */

  if (
    path ===
    "/api/admin/settings" &&
    request.method ===
    "GET"
  ) {
    return await adminSettings(
      request,
      env
    );
  }

  /* ===================================================
     CHECKOUT
  =================================================== */

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

  /* ===================================================
     HEALTH
  =================================================== */

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

  /* ===================================================
     STATIC FILES
  =================================================== */

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
    "WORKER ERROR:",
    error
  );

  return json({
    success: false,

    error:
      error?.message ||
      String(error)
  }, 500);
}
} };
