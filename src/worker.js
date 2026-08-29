import {
  register,
  login,
  me,
  logout
} from "./utilits/auth.js";

import {
  json,
  optionsResponse
} from "./utilits/response.js";


/* =========================================================
   WORKER
========================================================= */

export default {

  async fetch(request, env, ctx) {

    /* =====================================================
       CORS
    ===================================================== */

    if (request.method === "OPTIONS") {
      return optionsResponse();
    }


    /* =====================================================
       URL
    ===================================================== */

    const url = new URL(request.url);
    const path = url.pathname;


    try {

      /* ===================================================
         PUBLIC AUTH — REGISTER
      =================================================== */

      if (
        path === "/api/auth/register" &&
        request.method === "POST"
      ) {
        return await register(
          request,
          env
        );
      }


      /* ===================================================
         PUBLIC AUTH — LOGIN
      =================================================== */

      if (
        path === "/api/auth/login" &&
        request.method === "POST"
      ) {
        return await login(
          request,
          env
        );
      }


      /* ===================================================
         PUBLIC AUTH — ME
      =================================================== */

      if (
        path === "/api/auth/me" &&
        request.method === "GET"
      ) {
        return await me(
          request,
          env
        );
      }


      /* ===================================================
         PUBLIC AUTH — LOGOUT
      =================================================== */

      if (
        path === "/api/auth/logout" &&
        request.method === "POST"
      ) {
        return await logout(
          request,
          env
        );
      }


      /* ===================================================
         HEALTH
      =================================================== */

      if (
        path === "/api/health" &&
        request.method === "GET"
      ) {
        return json({
          success: true,
          status: "ok"
        });
      }


      /* ===================================================
         STATIC FILES
      =================================================== */

      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }


      /* ===================================================
         NOT FOUND
      =================================================== */

      return json({
        success: false,
        error: "Not Found"
      }, 404);


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
  }
};
