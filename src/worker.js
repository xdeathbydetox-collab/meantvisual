import {
    register,
    login,
    me,
    logout
} from "./utilits/auth.js";

import {
    adminRegister,
    adminLogin,
    adminMe,
    adminLogout,
    adminGrantAccess,
    adminRevokeAccess,
    adminUserAccess
} from "./utilits/admin.js";


export default {

    async fetch(request, env) {

        const url = new URL(request.url);

        const path = url.pathname;
        const method = request.method;


        /* =====================================================
           CORS
        ===================================================== */

        if (method === "OPTIONS") {

            return new Response(null, {
                status: 204,

                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods":
                        "GET,POST,PUT,DELETE,OPTIONS",
                    "Access-Control-Allow-Headers":
                        "Content-Type",
                    "Access-Control-Allow-Credentials":
                        "true"
                }
            });
        }


        /* =====================================================
           ОБЫЧНАЯ АВТОРИЗАЦИЯ
           auth.js

           Эти маршруты НЕ связаны с admin.js
        ===================================================== */

        if (
            path === "/api/auth/register" &&
            method === "POST"
        ) {

            return register(
                request,
                env
            );
        }


        if (
            path === "/api/auth/login" &&
            method === "POST"
        ) {

            return login(
                request,
                env
            );
        }


        if (
            path === "/api/auth/me" &&
            method === "GET"
        ) {

            return me(
                request,
                env
            );
        }


        if (
            path === "/api/auth/logout" &&
            method === "POST"
        ) {

            return logout(
                request,
                env
            );
        }


        /* =====================================================
           АДМИНСКАЯ АВТОРИЗАЦИЯ
           admin.js
        ===================================================== */

        if (
            path === "/api/admin/register" &&
            method === "POST"
        ) {

            return adminRegister(
                request,
                env
            );
        }


        if (
            path === "/api/admin/login" &&
            method === "POST"
        ) {

            return adminLogin(
                request,
                env
            );
        }


        if (
            path === "/api/admin/me" &&
            method === "GET"
        ) {

            return adminMe(
                request,
                env
            );
        }


        if (
            path === "/api/admin/logout" &&
            method === "POST"
        ) {

            return adminLogout(
                request,
                env
            );
        }


        /* =====================================================
           ВЫДАЧА ДОСТУПА ОБЫЧНОМУ АККАУНТУ

           POST /api/admin/access/grant

           BODY:

           {
               "identifier": "nickname или ID",
               "productId": "visual",
               "productName": "Visual",
               "days": 30
           }

           days:
           7  = 7 дней
           30 = 30 дней
           90 = 90 дней
           0  = навсегда
        ===================================================== */

        if (
            path === "/api/admin/access/grant" &&
            method === "POST"
        ) {

            return adminGrantAccess(
                request,
                env
            );
        }


        /* =====================================================
           СНЯТИЕ ДОСТУПА

           POST /api/admin/access/revoke

           BODY:

           {
               "identifier": "nickname или ID",
               "productId": "visual"
           }

           Если productId не указан,
           будут сняты все активные доступы.
        ===================================================== */

        if (
            path === "/api/admin/access/revoke" &&
            method === "POST"
        ) {

            return adminRevokeAccess(
                request,
                env
            );
        }


        /* =====================================================
           ПРОСМОТР ДОСТУПОВ ПОЛЬЗОВАТЕЛЯ

           POST /api/admin/access/list

           BODY:

           {
               "identifier": "nickname или ID"
           }
        ===================================================== */

        if (
            path === "/api/admin/access/list" &&
            method === "POST"
        ) {

            return adminUserAccess(
                request,
                env
            );
        }


        /* =====================================================
           404
        ===================================================== */

        return new Response(
            JSON.stringify({
                success: false,
                error: "API endpoint not found"
            }),
            {
                status: 404,

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
};
