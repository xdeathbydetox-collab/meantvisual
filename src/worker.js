import {
  register,
  login,
  me,
  logout
} from "./utilits/auth.js";

import {
  adminLogin,
  adminMe,
  adminLogout,
  adminChangePassword,
  adminStats,
  adminAccounts,
  adminAdministrators,
  createAdministrator,
  updateAdministrator,
  deleteAdministrator,
  adminProducts,
  adminTransactions,
  adminSubscriptions,
  adminLogs,
  adminSettings
} from "./utilits/admin.js";

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
   OPTIONS / CORS
========================================================= */

function optionsResponse() {
  return new Response(
    null,
    {
      status: 204,

      headers: {
        "Access-Control-Allow-Origin":
          "*",

        "Access-Control-Allow-Methods":
          "GET, POST, PUT, PATCH, DELETE, OPTIONS",

        "Access-Control-Allow-Headers":
          "Content-Type, Accept, Authorization",

        "Access-Control-Allow-Credentials":
          "true"
      }
    }
  );
}

/* =========================================================
   HEALTH
========================================================= */

async function health(env) {
  try {
    await env.DB
      .prepare("SELECT 1")
      .first();

    return json({
      success: true,
      status: "ok",
      database: true
    });

  } catch (error) {

    return json(
      {
        success: false,
        status: "error",
        database: false,
        error:
          error?.message ||
          String(error)
      },
      500
    );
  }
}

/* =========================================================
   ROUTER
========================================================= */

export default {

  async fetch(request, env) {

    /* -------------------------------------------------------
       CORS PREFLIGHT
    ------------------------------------------------------- */

    if (request.method === "OPTIONS") {
      return optionsResponse();
    }

    const url =
      new URL(request.url);

    const path =
      url.pathname;

    try {

      /* =====================================================
         PUBLIC AUTH
      ===================================================== */

      if (
        path === "/api/auth/register" &&
        request.method === "POST"
      ) {

        return await register(
          request,
          env
        );
      }


      if (
        path === "/api/auth/login" &&
        request.method === "POST"
      ) {

        return await login(
          request,
          env
        );
      }


      if (
        path === "/api/auth/me" &&
        request.method === "GET"
      ) {

        return await me(
          request,
          env
        );
      }


      if (
        path === "/api/auth/logout" &&
        request.method === "POST"
      ) {

        return await logout(
          request,
          env
        );
      }


      /* =====================================================
         ADMIN AUTH
      ===================================================== */

      if (
        path === "/api/admin/login" &&
        request.method === "POST"
      ) {

        return await adminLogin(
          request,
          env
        );
      }


      if (
        path === "/api/admin/me" &&
        request.method === "GET"
      ) {

        return await adminMe(
          request,
          env
        );
      }


      if (
        path === "/api/admin/logout" &&
        request.method === "POST"
      ) {

        return await adminLogout(
          request,
          env
        );
      }


      if (
        path === "/api/admin/change-password" &&
        request.method === "POST"
      ) {

        return await adminChangePassword(
          request,
          env
        );
      }


      /* =====================================================
         ADMIN DASHBOARD
      ===================================================== */

      if (
        path === "/api/admin/stats" &&
        request.method === "GET"
      ) {

        return await adminStats(
          request,
          env
        );
      }


      /* =====================================================
         ACCOUNTS
      ===================================================== */

      if (
        path === "/api/admin/accounts" &&
        request.method === "GET"
      ) {

        return await adminAccounts(
          request,
          env
        );
      }


      /* =====================================================
         ADMINISTRATORS
      ===================================================== */

      if (
        path === "/api/admin/administrators" &&
        request.method === "GET"
      ) {

        return await adminAdministrators(
          request,
          env
        );
      }


      if (
        path === "/api/admin/administrators" &&
        request.method === "POST"
      ) {

        return await createAdministrator(
          request,
          env
        );
      }


      if (
        path === "/api/admin/administrators" &&
        request.method === "PUT"
      ) {

        return await updateAdministrator(
          request,
          env
        );
      }


      if (
        path === "/api/admin/administrators" &&
        request.method === "DELETE"
      ) {

        return await deleteAdministrator(
          request,
          env
        );
      }


      /* =====================================================
         PRODUCTS
      ===================================================== */

      if (
        path === "/api/admin/products" &&
        request.method === "GET"
      ) {

        return await adminProducts(
          request,
          env
        );
      }


      /* =====================================================
         TRANSACTIONS
      ===================================================== */

      if (
        path === "/api/admin/transactions" &&
        request.method === "GET"
      ) {

        return await adminTransactions(
          request,
          env
        );
      }


      /* =====================================================
         SUBSCRIPTIONS
      ===================================================== */

      if (
        path === "/api/admin/subscriptions" &&
        request.method === "GET"
      ) {

        return await adminSubscriptions(
          request,
          env
        );
      }


      /* =====================================================
         LOGS
      ===================================================== */

      if (
        path === "/api/admin/logs" &&
        request.method === "GET"
      ) {

        return await adminLogs(
          request,
          env
        );
      }


      /* =====================================================
         SETTINGS
      ===================================================== */

      if (
        path === "/api/admin/settings" &&
        request.method === "GET"
      ) {

        return await adminSettings(
          request,
          env
        );
      }


      /* =====================================================
         HEALTH
      ===================================================== */

      if (
        path === "/api/health" &&
        request.method === "GET"
      ) {

        return await health(
          env
        );
      }


      /* =====================================================
         STATIC ASSETS
      ===================================================== */

      if (env.ASSETS) {

        return env.ASSETS.fetch(
          request
        );
      }


      /* =====================================================
         NOT FOUND
      ===================================================== */

      return json(
        {
          success: false,
          error: "Not Found"
        },
        404
      );

    } catch (error) {

      console.error(
        "WORKER ERROR:",
        error
      );

      return json(
        {
          success: false,

          error:
            error?.message ||
            String(error)
        },
        500
      );
    }
  }
};
