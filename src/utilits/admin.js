import {
  createPasswordHash,
  verifyPassword
} from "./crypto.js";

import {
  createSession,
  getSessionAccount,
  deleteSession
} from "./session.js";

import {
  json
} from "./response.js";


/* =========================================================
   PERMISSIONS
========================================================= */

export const ADMIN_PERMISSIONS = [
  "configs",
  "new_admins",
  "titles",
  "promocodes",
  "keys",
  "current_admins"
];


/* =========================================================
   HELPERS
========================================================= */

function normalizeUsername(value) {
  return String(value || "").trim();
}

function validUsername(username) {
  return /^[a-zA-Z0-9_.-]{3,24}$/.test(username);
}

function parsePermissions(value) {
  if (!value) return [];

  try {
    const parsed =
      typeof value === "string"
        ? JSON.parse(value)
        : value;

    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed.filter(
      permission =>
        ADMIN_PERMISSIONS.includes(permission)
    );

  } catch {
    return [];
  }
}

function isOwner(admin) {
  return admin?.role === "OWNER";
}

function hasPermission(admin, permission) {

  if (!admin) {
    return false;
  }

  if (admin.role === "OWNER") {
    return true;
  }

  return (
    Array.isArray(admin.permissions) &&
    admin.permissions.includes(permission)
  );
}


/* =========================================================
   CURRENT ADMIN
========================================================= */

export async function getCurrentAdmin(
  request,
  env
) {

  const account =
    await getSessionAccount(
      request,
      env
    );

  if (!account) {
    return null;
  }

  const admin =
    await env.DB
      .prepare(`
        SELECT
          administrators.id,
          administrators.account_id,
          administrators.role,
          administrators.permissions,
          administrators.active,
          administrators.approved,
          administrators.must_change_password,
          administrators.created_at,
          accounts.username
        FROM administrators
        INNER JOIN accounts
          ON accounts.id =
             administrators.account_id
        WHERE administrators.account_id = ?
        LIMIT 1
      `)
      .bind(account.id)
      .first();

  if (!admin) {
    return null;
  }

  return {
    ...admin,

    permissions:
      parsePermissions(
        admin.permissions
      ),

    active:
      Number(admin.active || 0) === 1,

    approved:
      Number(admin.approved || 0) === 1,

    must_change_password:
      Number(
        admin.must_change_password || 0
      ) === 1
  };
}


/* =========================================================
   REQUIRE ADMIN
========================================================= */

export async function requireAdmin(
  request,
  env
) {

  const admin =
    await getCurrentAdmin(
      request,
      env
    );

  if (!admin) {
    return {
      error: json(
        {
          success: false,
          error: "Доступ запрещён"
        },
        403
      )
    };
  }

  if (!admin.active) {
    return {
      error: json(
        {
          success: false,
          error: "Администратор отключён"
        },
        403
      )
    };
  }

  if (!admin.approved) {
    return {
      error: json(
        {
          success: false,
          error: "Аккаунт администратора ещё не одобрен OWNER"
        },
        403
      )
    };
  }

  return {
    admin
  };
}


/* =========================================================
   ADMIN LOGIN
========================================================= */

export async function adminLogin(
  request,
  env
) {

  let body;

  try {
    body =
      await request.json();
  } catch {
    return json(
      {
        success: false,
        error: "Неверный JSON"
      },
      400
    );
  }

  const username =
    normalizeUsername(
      body.username ??
      body.login
    );

  const password =
    String(
      body.password || ""
    );

  if (!username || !password) {
    return json(
      {
        success: false,
        error: "Введите ник и пароль"
      },
      400
    );
  }

  const admin =
    await env.DB
      .prepare(`
        SELECT
          administrators.id AS admin_id,
          administrators.account_id,
          administrators.role,
          administrators.permissions,
          administrators.active,
          administrators.approved,
          administrators.must_change_password,
          accounts.username,
          credentials.password_hash
        FROM administrators
        INNER JOIN accounts
          ON accounts.id =
             administrators.account_id
        INNER JOIN credentials
          ON credentials.account_id =
             accounts.id
        WHERE LOWER(accounts.username) =
              LOWER(?)
        LIMIT 1
      `)
      .bind(username)
      .first();

  if (!admin) {
    return json(
      {
        success: false,
        error: "Неверный ник или пароль"
      },
      401
    );
  }

  if (
    Number(admin.active || 0) !== 1
  ) {
    return json(
      {
        success: false,
        error: "Администратор отключён"
      },
      403
    );
  }

  if (
    Number(admin.approved || 0) !== 1
  ) {
    return json(
      {
        success: false,
        error: "Ваш аккаунт ещё не одобрен OWNER"
      },
      403
    );
  }

  const valid =
    await verifyPassword(
      password,
      admin.password_hash
    );

  if (!valid) {
    return json(
      {
        success: false,
        error: "Неверный ник или пароль"
      },
      401
    );
  }

  const session =
    await createSession(
      env,
      admin.account_id
    );

  return json(
    {
      success: true,

      admin: {
        id: admin.admin_id,

        account_id:
          admin.account_id,

        username:
          admin.username,

        role:
          admin.role,

        permissions:
          parsePermissions(
            admin.permissions
          ),

        must_change_password:
          Number(
            admin.must_change_password || 0
          ) === 1
      }
    },

    200,

    {
      "Set-Cookie":
        session.cookie
    }
  );
}


/* =========================================================
   ADMIN ME
========================================================= */

export async function adminMe(
  request,
  env
) {

  const result =
    await requireAdmin(
      request,
      env
    );

  if (result.error) {
    return result.error;
  }

  const admin =
    result.admin;

  return json({
    success: true,

    admin: {
      id: admin.id,

      account_id:
        admin.account_id,

      username:
        admin.username,

      role:
        admin.role,

      permissions:
        admin.permissions,

      active:
        admin.active,

      approved:
        admin.approved,

      must_change_password:
        admin.must_change_password,

      created_at:
        admin.created_at
    }
  });
}


/* =========================================================
   ADMIN LOGOUT
========================================================= */

export async function adminLogout(
  request,
  env
) {

  await deleteSession(
    request,
    env
  );

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
   CREATE ADMIN
========================================================= */

export async function createAdministrator(
  request,
  env
) {

  const result =
    await requireAdmin(
      request,
      env
    );

  if (result.error) {
    return result.error;
  }

  const creator =
    result.admin;

  if (!isOwner(creator)) {
    return json(
      {
        success: false,
        error:
          "Только OWNER может создавать администраторов"
      },
      403
    );
  }

  const body =
    await request.json();

  const username =
    normalizeUsername(
      body.username
    );

  const password =
    String(
      body.password || ""
    );

  const role =
    String(
      body.role || "ADMIN"
    ).toUpperCase();

  let permissions =
    Array.isArray(
      body.permissions
    )
      ? body.permissions
      : [];

  permissions =
    permissions.filter(
      permission =>
        ADMIN_PERMISSIONS.includes(
          permission
        )
    );

  if (!validUsername(username)) {
    return json(
      {
        success: false,
        error:
          "Ник должен содержать 3-24 символа"
      },
      400
    );
  }

  if (password.length < 8) {
    return json(
      {
        success: false,
        error:
          "Пароль должен содержать минимум 8 символов"
      },
      400
    );
  }

  if (
    ![
      "ADMIN",
      "MODERATOR",
      "SUPPORT"
    ].includes(role)
  ) {
    return json(
      {
        success: false,
        error: "Недопустимая роль"
      },
      400
    );
  }

  const exists =
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

  if (exists) {
    return json(
      {
        success: false,
        error:
          "Этот ник уже занят"
      },
      409
    );
  }

  const accountId =
    crypto.randomUUID();

  const adminId =
    crypto.randomUUID();

  const passwordHash =
    await createPasswordHash(
      password
    );

  try {

    await env.DB
      .prepare(`
        INSERT INTO accounts
        (
          id,
          username,
          balance
        )
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
          approved,
          must_change_password
        )
        VALUES (?, ?, ?, ?, 1, 0, 1)
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

    return json(
      {
        success: false,
        error:
          "Ошибка создания администратора: " +
          (
            error?.message ||
            String(error)
          )
      },
      500
    );
  }

  return json(
    {
      success: true,

      administrator: {
        id: adminId,
        account_id: accountId,
        username,
        role,
        permissions,
        active: true,
        approved: false,
        must_change_password: true
      }
    },
    201
  );
}


/* =========================================================
   APPROVE ADMIN
========================================================= */

export async function approveAdministrator(
  request,
  env
) {

  const result =
    await requireAdmin(
      request,
      env
    );

  if (result.error) {
    return result.error;
  }

  if (!isOwner(result.admin)) {
    return json(
      {
        success: false,
        error:
          "Только OWNER может одобрять администраторов"
      },
      403
    );
  }

  const body =
    await request.json();

  const id =
    String(
      body.id || ""
    );

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

  const target =
    await env.DB
      .prepare(`
        SELECT id, role
        FROM administrators
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
      UPDATE administrators
      SET approved = 1,
          active = 1
      WHERE id = ?
    `)
    .bind(id)
    .run();

  return json({
    success: true,
    message:
      "Администратор одобрен"
  });
}


/* =========================================================
   UPDATE PERMISSIONS
========================================================= */

export async function updateAdministratorPermissions(
  request,
  env
) {

  const result =
    await requireAdmin(
      request,
      env
    );

  if (result.error) {
    return result.error;
  }

  if (!isOwner(result.admin)) {
    return json(
      {
        success: false,
        error:
          "Только OWNER может изменять права"
      },
      403
    );
  }

  const body =
    await request.json();

  const id =
    String(
      body.id || ""
    );

  let permissions =
    Array.isArray(
      body.permissions
    )
      ? body.permissions
      : [];

  permissions =
    permissions.filter(
      permission =>
        ADMIN_PERMISSIONS.includes(
          permission
        )
    );

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

  const target =
    await env.DB
      .prepare(`
        SELECT role
        FROM administrators
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

  if (target.role === "OWNER") {
    return json(
      {
        success: false,
        error:
          "Права OWNER нельзя изменить"
      },
      403
    );
  }

  await env.DB
    .prepare(`
      UPDATE administrators
      SET permissions = ?
      WHERE id = ?
    `)
    .bind(
      JSON.stringify(
        permissions
      ),
      id
    )
    .run();

  return json({
    success: true,
    permissions
  });
}


/* =========================================================
   LIST ADMINISTRATORS
========================================================= */

export async function listAdministrators(
  request,
  env
) {

  const result =
    await requireAdmin(
      request,
      env
    );

  if (result.error) {
    return result.error;
  }

  if (
    !hasPermission(
      result.admin,
      "current_admins"
    )
  ) {
    return json(
      {
        success: false,
        error:
          "Недостаточно прав"
      },
      403
    );
  }

  const rows =
    await env.DB
      .prepare(`
        SELECT
          administrators.id,
          administrators.account_id,
          administrators.role,
          administrators.permissions,
          administrators.active,
          administrators.approved,
          administrators.must_change_password,
          administrators.created_at,
          accounts.username
        FROM administrators
        INNER JOIN accounts
          ON accounts.id =
             administrators.account_id
        ORDER BY administrators.created_at DESC
      `)
      .all();

  return json({
    success: true,

    administrators:
      (rows.results || []).map(
        admin => ({
          ...admin,

          permissions:
            parsePermissions(
              admin.permissions
            ),

          active:
            Number(
              admin.active || 0
            ) === 1,

          approved:
            Number(
              admin.approved || 0
            ) === 1,

          must_change_password:
            Number(
              admin.must_change_password || 0
            ) === 1
        })
      )
  });
}


/* =========================================================
   CHECK PERMISSION
========================================================= */

export {
  hasPermission
};
/* =========================================================
   CHANGE ADMIN PASSWORD
========================================================= */

export async function adminChangePassword(request, env) {
  const result = await requireAdmin(request, env);

  if (result.error) {
    return result.error;
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        error: "Неверный JSON"
      },
      400
    );
  }

  const currentPassword = String(
    body.currentPassword || ""
  );

  const newPassword = String(
    body.newPassword || ""
  );

  if (!currentPassword || !newPassword) {
    return json(
      {
        success: false,
        error: "Введите текущий и новый пароль"
      },
      400
    );
  }

  if (newPassword.length < 8) {
    return json(
      {
        success: false,
        error: "Новый пароль должен содержать минимум 8 символов"
      },
      400
    );
  }

  const accountId = result.admin.account_id;

  const credential = await env.DB
    .prepare(`
      SELECT password_hash
      FROM credentials
      WHERE account_id = ?
      LIMIT 1
    `)
    .bind(accountId)
    .first();

  if (!credential) {
    return json(
      {
        success: false,
        error: "Учетные данные не найдены"
      },
      404
    );
  }

  const valid = await verifyPassword(
    currentPassword,
    credential.password_hash
  );

  if (!valid) {
    return json(
      {
        success: false,
        error: "Неверный текущий пароль"
      },
      401
    );
  }

  const passwordHash =
    await createPasswordHash(newPassword);

  await env.DB
    .prepare(`
      UPDATE credentials
      SET password_hash = ?,
          updated_at = CURRENT_TIMESTAMP
      WHERE account_id = ?
    `)
    .bind(
      passwordHash,
      accountId
    )
    .run();

  await env.DB
    .prepare(`
      UPDATE administrators
      SET must_change_password = 0
      WHERE account_id = ?
    `)
    .bind(accountId)
    .run();

  return json({
    success: true,
    message: "Пароль успешно изменён"
  });
}


/* =========================================================
   ADMIN STATISTICS
========================================================= */

export async function adminStats(request, env) {
  const result = await requireAdmin(request, env);

  if (result.error) {
    return result.error;
  }

  if (!hasPermission(result.admin, "current_admins")) {
    return json(
      {
        success: false,
        error: "Недостаточно прав"
      },
      403
    );
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
      FROM administrators
    `)
    .first();

  return json({
    success: true,
    stats: {
      accounts: Number(accounts?.count || 0),
      administrators: Number(
        administrators?.count || 0
      )
    }
  });
}


/* =========================================================
   ADMIN ACCOUNTS
========================================================= */

export async function adminAccounts(request, env) {
  const result = await requireAdmin(request, env);

  if (result.error) {
    return result.error;
  }

  const rows = await env.DB
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
    accounts: rows.results || []
  });
}


/* =========================================================
   ADMINISTRATORS
========================================================= */

export async function adminAdministrators(request, env) {
  return listAdministrators(request, env);
}


/* =========================================================
   UPDATE ADMINISTRATOR
========================================================= */

export async function updateAdministrator(request, env) {
  const result = await requireAdmin(request, env);

  if (result.error) {
    return result.error;
  }

  if (!isOwner(result.admin)) {
    return json(
      {
        success: false,
        error: "Только OWNER может изменять администраторов"
      },
      403
    );
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        error: "Неверный JSON"
      },
      400
    );
  }

  const id = String(body.id || "");

  if (!id) {
    return json(
      {
        success: false,
        error: "Не указан ID администратора"
      },
      400
    );
  }

  const target = await env.DB
    .prepare(`
      SELECT id, role
      FROM administrators
      WHERE id = ?
      LIMIT 1
    `)
    .bind(id)
    .first();

  if (!target) {
    return json(
      {
        success: false,
        error: "Администратор не найден"
      },
      404
    );
  }

  if (target.role === "OWNER") {
    return json(
      {
        success: false,
        error: "OWNER нельзя изменить"
      },
      403
    );
  }

  if (body.role !== undefined) {
    const role = String(body.role).toUpperCase();

    if (
      !["ADMIN", "MODERATOR", "SUPPORT"].includes(role)
    ) {
      return json(
        {
          success: false,
          error: "Недопустимая роль"
        },
        400
      );
    }

    await env.DB
      .prepare(`
        UPDATE administrators
        SET role = ?
        WHERE id = ?
      `)
      .bind(role, id)
      .run();
  }

  if (Array.isArray(body.permissions)) {
    const permissions = body.permissions.filter(
      permission =>
        ADMIN_PERMISSIONS.includes(permission)
    );

    await env.DB
      .prepare(`
        UPDATE administrators
        SET permissions = ?
        WHERE id = ?
      `)
      .bind(
        JSON.stringify(permissions),
        id
      )
      .run();
  }

  if (body.active !== undefined) {
    await env.DB
      .prepare(`
        UPDATE administrators
        SET active = ?
        WHERE id = ?
      `)
      .bind(
        body.active ? 1 : 0,
        id
      )
      .run();
  }

  if (body.approved !== undefined) {
    await env.DB
      .prepare(`
        UPDATE administrators
        SET approved = ?
        WHERE id = ?
      `)
      .bind(
        body.approved ? 1 : 0,
        id
      )
      .run();
  }

  return json({
    success: true,
    message: "Администратор обновлён"
  });
}


/* =========================================================
   DELETE ADMINISTRATOR
========================================================= */

export async function deleteAdministrator(request, env) {
  const result = await requireAdmin(request, env);

  if (result.error) {
    return result.error;
  }

  if (!isOwner(result.admin)) {
    return json(
      {
        success: false,
        error: "Только OWNER может удалять администраторов"
      },
      403
    );
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        error: "Неверный JSON"
      },
      400
    );
  }

  const id = String(body.id || "");

  if (!id) {
    return json(
      {
        success: false,
        error: "Не указан ID администратора"
      },
      400
    );
  }

  const target = await env.DB
    .prepare(`
      SELECT account_id, role
      FROM administrators
      WHERE id = ?
      LIMIT 1
    `)
    .bind(id)
    .first();

  if (!target) {
    return json(
      {
        success: false,
        error: "Администратор не найден"
      },
      404
    );
  }

  if (target.role === "OWNER") {
    return json(
      {
        success: false,
        error: "OWNER нельзя удалить"
      },
      403
    );
  }

  await env.DB
    .prepare(`
      DELETE FROM administrators
      WHERE id = ?
    `)
    .bind(id)
    .run();

  await env.DB
    .prepare(`
      DELETE FROM credentials
      WHERE account_id = ?
    `)
    .bind(target.account_id)
    .run();

  await env.DB
    .prepare(`
      DELETE FROM accounts
      WHERE id = ?
    `)
    .bind(target.account_id)
    .run();

  return json({
    success: true,
    message: "Администратор удалён"
  });
}


/* =========================================================
   PRODUCTS
========================================================= */

export async function adminProducts(request, env) {
  const result = await requireAdmin(request, env);

  if (result.error) {
    return result.error;
  }

  return json({
    success: true,
    products: []
  });
}


/* =========================================================
   TRANSACTIONS
========================================================= */

export async function adminTransactions(request, env) {
  const result = await requireAdmin(request, env);

  if (result.error) {
    return result.error;
  }

  const rows = await env.DB
    .prepare(`
      SELECT *
      FROM transactions
      ORDER BY created_at DESC
      LIMIT 500
    `)
    .all();

  return json({
    success: true,
    transactions: rows.results || []
  });
}


/* =========================================================
   SUBSCRIPTIONS
========================================================= */

export async function adminSubscriptions(request, env) {
  const result = await requireAdmin(request, env);

  if (result.error) {
    return result.error;
  }

  const rows = await env.DB
    .prepare(`
      SELECT *
      FROM entitlements
      ORDER BY created_at DESC
      LIMIT 500
    `)
    .all();

  return json({
    success: true,
    subscriptions: rows.results || []
  });
}


/* =========================================================
   LOGS
========================================================= */

export async function adminLogs(request, env) {
  const result = await requireAdmin(request, env);

  if (result.error) {
    return result.error;
  }

  return json({
    success: true,
    logs: []
  });
}


/* =========================================================
   SETTINGS
========================================================= */

export async function adminSettings(request, env) {
  const result = await requireAdmin(request, env);

  if (result.error) {
    return result.error;
  }

  return json({
    success: true,
    settings: {}
  });
}
