import { getSessionAccount } from "./session.js";
import { json } from "./response.js";

/* =========================================================
   PERMISSIONS
========================================================= */

export function parsePermissions(value) {
  if (!value) {
    return [];
  }

  try {
    const parsed = JSON.parse(value);

    return Array.isArray(parsed)
      ? parsed
      : [];
  } catch {
    return [];
  }
}

export function hasPermission(admin, permission) {
  if (!admin) {
    return false;
  }

  // OWNER имеет все права
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

export async function getCurrentAdmin(request, env) {
  const account = await getSessionAccount(
    request,
    env
  );

  if (!account) {
    return null;
  }

  const admin = await env.DB
    .prepare(`
      SELECT
        a.id,
        a.account_id,
        a.role,
        a.permissions,
        a.active,
        a.must_change_password,
        a.email_verified,
        a.created_at,

        accounts.username,
        accounts.email

      FROM administrators a

      INNER JOIN accounts
        ON accounts.id = a.account_id

      WHERE a.account_id = ?

      LIMIT 1
    `)
    .bind(account.id)
    .first();

  if (!admin) {
    return null;
  }

  if (Number(admin.active) !== 1) {
    return null;
  }

  return {
    ...admin,

    permissions:
      parsePermissions(
        admin.permissions
      ),

    active:
      Number(admin.active) === 1,

    must_change_password:
      Number(
        admin.must_change_password || 0
      ) === 1,

    email_verified:
      Number(
        admin.email_verified || 0
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

  return {
    admin
  };
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

  const admin = result.admin;

  return json({
    success: true,

    admin: {
      id: admin.id,

      account_id:
        admin.account_id,

      username:
        admin.username,

      email:
        admin.email,

      role:
        admin.role,

      permissions:
        admin.permissions,

      active:
        admin.active,

      must_change_password:
        admin.must_change_password,

      email_verified:
        admin.email_verified,

      created_at:
        admin.created_at
    }
  });
}

/* =========================================================
   ADMIN STATISTICS
========================================================= */

export async function adminStats(
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

  const admin = result.admin;

  if (
    !hasPermission(
      admin,
      "dashboard.view"
    )
  ) {
    return json(
      {
        success: false,
        error: "Недостаточно прав"
      },
      403
    );
  }

  const accounts =
    await env.DB
      .prepare(`
        SELECT COUNT(*) AS count
        FROM accounts
      `)
      .first();

  const administrators =
    await env.DB
      .prepare(`
        SELECT COUNT(*) AS count
        FROM administrators
        WHERE active = 1
      `)
      .first();

  const transactions =
    await env.DB
      .prepare(`
        SELECT COUNT(*) AS count
        FROM transactions
      `)
      .first();

  const subscriptions =
    await env.DB
      .prepare(`
        SELECT COUNT(*) AS count
        FROM entitlements
        WHERE status = 'active'
      `)
      .first();

  const revenue =
    await env.DB
      .prepare(`
        SELECT
          COALESCE(
            SUM(
              CASE
                WHEN amount > 0
                THEN amount
                ELSE 0
              END
            ),
            0
          ) AS total
        FROM transactions
      `)
      .first();

  return json({
    success: true,

    statistics: {
      accounts:
        Number(
          accounts?.count || 0
        ),

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
  });
}

/* =========================================================
   ADMIN ACCOUNTS
========================================================= */

export async function adminAccounts(
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

  const admin = result.admin;

  if (
    !hasPermission(
      admin,
      "accounts.view"
    )
  ) {
    return json(
      {
        success: false,
        error: "Недостаточно прав"
      },
      403
    );
  }

  const rows =
    await env.DB
      .prepare(`
        SELECT
          id,
          username,
          email,
          balance,
          created_at,
          updated_at
        FROM accounts
        ORDER BY created_at DESC
        LIMIT 500
      `)
      .all();

  return json({
    success: true,

    accounts:
      rows.results || []
  });
}

/* =========================================================
   ADMINISTRATORS LIST
========================================================= */

export async function adminAdministrators(
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

  const admin = result.admin;

  if (
    !hasPermission(
      admin,
      "admins.view"
    )
  ) {
    return json(
      {
        success: false,
        error: "Недостаточно прав"
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
          administrators.must_change_password,
          administrators.email_verified,
          administrators.created_at,

          accounts.username,
          accounts.email

        FROM administrators

        INNER JOIN accounts
          ON accounts.id =
             administrators.account_id

        ORDER BY
          administrators.created_at DESC

        LIMIT 500
      `)
      .all();

  const administrators =
    (rows.results || []).map(
      item => ({
        id: item.id,

        account_id:
          item.account_id,

        username:
          item.username,

        email:
          item.email,

        role:
          item.role,

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
            item.must_change_password ||
            0
          ) === 1,

        email_verified:
          Number(
            item.email_verified ||
            0
          ) === 1,

        created_at:
          item.created_at
      })
    );

  return json({
    success: true,
    administrators
  });
}

/* =========================================================
   CREATE ADMINISTRATOR
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

  const creator = result.admin;

  // Только OWNER
  if (creator.role !== "OWNER") {
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
    await request.json().catch(
      () => null
    );

  if (!body) {
    return json(
      {
        success: false,
        error: "Неверный JSON"
      },
      400
    );
  }

  const username =
    String(
      body.username || ""
    ).trim();

  const email =
    String(
      body.email || ""
    )
      .trim()
      .toLowerCase();

  const password =
    String(
      body.password || ""
    );

  const role =
    String(
      body.role || "ADMIN"
    ).toUpperCase();

  let permissions =
    body.permissions;

  if (
    !Array.isArray(
      permissions
    )
  ) {
    permissions = [];
  }

  if (
    !/^[a-zA-Z0-9_.-]{3,24}$/.test(
      username
    )
  ) {
    return json(
      {
        success: false,
        error:
          "Некорректный никнейм"
      },
      400
    );
  }

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
      email
    )
  ) {
    return json(
      {
        success: false,
        error:
          "Некорректный email"
      },
      400
    );
  }

  if (
    password.length < 8
  ) {
    return json(
      {
        success: false,
        error:
          "Пароль должен содержать минимум 8 символов"
      },
      400
    );
  }

  const allowedRoles = [
    "ADMIN",
    "MODERATOR",
    "SUPPORT"
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

  const usernameExists =
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

  if (usernameExists) {
    return json(
      {
        success: false,
        error:
          "Этот никнейм уже занят"
      },
      409
    );
  }

  const emailExists =
    await env.DB
      .prepare(`
        SELECT id
        FROM accounts
        WHERE LOWER(email) = ?
        LIMIT 1
      `)
      .bind(email)
      .first();

  if (emailExists) {
    return json(
      {
        success: false,
        error:
          "Этот email уже используется"
      },
      409
    );
  }

  const accountId =
    crypto.randomUUID();

  const adminId =
    crypto.randomUUID();

  // Импортируем функцию только здесь,
  // чтобы admin.js не дублировал crypto
  const {
    createPasswordHash
  } = await import(
    "./session.js"
  );

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
          email,
          balance
        )
        VALUES (?, ?, ?, 0)
      `)
      .bind(
        accountId,
        username,
        email
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

    return json(
      {
        success: false,
        error:
          "Не удалось создать администратора: " +
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

        account_id:
          accountId,

        username,

        email,

        role,

        permissions,

        must_change_password:
          true,

        email_verified:
          false
      }
    },
    201
  );
}

/* =========================================================
   UPDATE ADMINISTRATOR
========================================================= */

export async function updateAdministrator(
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

  const creator = result.admin;

  if (creator.role !== "OWNER") {
    return json(
      {
        success: false,
        error:
          "Только OWNER может изменять администраторов"
      },
      403
    );
  }

  const body =
    await request.json().catch(
      () => null
    );

  if (!body) {
    return json(
      {
        success: false,
        error: "Неверный JSON"
      },
      400
    );
  }

  const adminId =
    String(
      body.id || ""
    );

  if (!adminId) {
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
        SELECT
          id,
          account_id,
          role,
          active
        FROM administrators
        WHERE id = ?
        LIMIT 1
      `)
      .bind(adminId)
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

  if (
    target.role === "OWNER"
  ) {
    return json(
      {
        success: false,
        error:
          "Нельзя изменить OWNER"
      },
      403
    );
  }

  if (
    body.role !== undefined
  ) {
    const role =
      String(
        body.role
      ).toUpperCase();

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
          error:
            "Недопустимая роль"
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
      .bind(
        role,
        adminId
      )
      .run();
  }

  if (
    body.permissions !==
    undefined
  ) {
    if (
      !Array.isArray(
        body.permissions
      )
    ) {
      return json(
        {
          success: false,
          error:
            "permissions должен быть массивом"
        },
        400
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
          body.permissions
        ),
        adminId
      )
      .run();
  }

  if (
    body.active !==
    undefined
  ) {
    await env.DB
      .prepare(`
        UPDATE administrators
        SET active = ?
        WHERE id = ?
      `)
      .bind(
        body.active ? 1 : 0,
        adminId
      )
      .run();
  }

  return json({
    success: true
  });
}

/* =========================================================
   DELETE ADMINISTRATOR
========================================================= */

export async function deleteAdministrator(
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

  const creator = result.admin;

  if (creator.role !== "OWNER") {
    return json(
      {
        success: false,
        error:
          "Только OWNER может удалять администраторов"
      },
      403
    );
  }

  const body =
    await request.json().catch(
      () => null
    );

  if (!body) {
    return json(
      {
        success: false,
        error: "Неверный JSON"
      },
      400
    );
  }

  const adminId =
    String(
      body.id || ""
    );

  if (!adminId) {
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
        SELECT
          id,
          account_id,
          role
        FROM administrators
        WHERE id = ?
        LIMIT 1
      `)
      .bind(adminId)
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

  if (
    target.role === "OWNER"
  ) {
    return json(
      {
        success: false,
        error:
          "OWNER нельзя удалить"
      },
      403
    );
  }

  await env.DB
    .prepare(`
      DELETE FROM sessions
      WHERE account_id = ?
    `)
    .bind(
      target.account_id
    )
    .run();

  await env.DB
    .prepare(`
      DELETE FROM administrators
      WHERE id = ?
    `)
    .bind(adminId)
    .run();

  await env.DB
    .prepare(`
      DELETE FROM credentials
      WHERE account_id = ?
    `)
    .bind(
      target.account_id
    )
    .run();

  await env.DB
    .prepare(`
      DELETE FROM accounts
      WHERE id = ?
    `)
    .bind(
      target.account_id
    )
    .run();

  return json({
    success: true,

    message:
      "Администратор удалён"
  });
}

/* =========================================================
   CHANGE ADMIN PASSWORD
========================================================= */

export async function adminChangePassword(
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

  const admin = result.admin;

  const body =
    await request.json().catch(
      () => null
    );

  if (!body) {
    return json(
      {
        success: false,
        error: "Неверный JSON"
      },
      400
    );
  }

  const newPassword =
    String(
      body.password ||
      body.new_password ||
      ""
    );

  if (!newPassword) {
    return json(
      {
        success: false,
        error:
          "Введите новый пароль"
      },
      400
    );
  }

  if (
    newPassword.length < 8
  ) {
    return json(
      {
        success: false,
        error:
          "Пароль должен содержать минимум 8 символов"
      },
      400
    );
  }

  const {
    createPasswordHash
  } = await import(
    "./session.js"
  );

  const passwordHash =
    await createPasswordHash(
      newPassword
    );

  await env.DB
    .prepare(`
      UPDATE credentials
      SET
        password_hash = ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE account_id = ?
    `)
    .bind(
      passwordHash,
      admin.account_id
    )
    .run();

  await env.DB
    .prepare(`
      UPDATE administrators
      SET must_change_password = 0
      WHERE id = ?
    `)
    .bind(admin.id)
    .run();

  return json({
    success: true,

    message:
      "Пароль успешно изменён"
  });
}

/* =========================================================
   PRODUCTS
========================================================= */

export async function adminProducts(
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

  const admin = result.admin;

  if (
    !hasPermission(
      admin,
      "products.view"
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

  try {
    const rows =
      await env.DB
        .prepare(`
          SELECT *
          FROM products
          ORDER BY created_at DESC
          LIMIT 500
        `)
        .all();

    return json({
      success: true,

      products:
        rows.results || []
    });

  } catch {
    return json({
      success: true,
      products: []
    });
  }
}

/* =========================================================
   TRANSACTIONS
========================================================= */

export async function adminTransactions(
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

  const admin = result.admin;

  if (
    !hasPermission(
      admin,
      "transactions.view"
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
          transactions.*,
          accounts.username

        FROM transactions

        LEFT JOIN accounts
          ON accounts.id =
             transactions.account_id

        ORDER BY
          transactions.created_at DESC

        LIMIT 500
      `)
      .all();

  return json({
    success: true,

    transactions:
      rows.results || []
  });
}

/* =========================================================
   SUBSCRIPTIONS
========================================================= */

export async function adminSubscriptions(
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

  const admin = result.admin;

  if (
    !hasPermission(
      admin,
      "subscriptions.view"
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
          entitlements.*,
          accounts.username,
          accounts.email

        FROM entitlements

        LEFT JOIN accounts
          ON accounts.id =
             entitlements.account_id

        ORDER BY
          entitlements.created_at DESC

        LIMIT 500
      `)
      .all();

  return json({
    success: true,

    subscriptions:
      rows.results || []
  });
}

/* =========================================================
   LOGS
========================================================= */

export async function adminLogs(
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

  const admin = result.admin;

  if (
    !hasPermission(
      admin,
      "logs.view"
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
  }
}

/* =========================================================
   SETTINGS
========================================================= */

export async function adminSettings(
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

  const admin = result.admin;

  if (
    !hasPermission(
      admin,
      "settings.view"
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

  return json({
    success: true,

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
  });
}
