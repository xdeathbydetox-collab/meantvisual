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

    adminStats,
    adminAccounts,
    adminAdministrators,

    createAdministrator,
    updateAdministrator,
    deleteAdministrator,

    adminProducts,
    adminTransactions,
    adminSubscriptions,

    adminGrantAccess,
    adminRevokeAccess,
    adminUserAccess
} from "./utilits/admin.js";


/* =========================================================
   MEANT SHOP — WORKER
   ========================================================= */

export default {

    async fetch(request, env) {

        const url = new URL(request.url);

        const path = url.pathname;
        const method = request.method;


        /* =====================================================
           CORS
        ===================================================== */

        const corsHeaders = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods":
                "GET,POST,PUT,DELETE,OPTIONS",
            "Access-Control-Allow-Headers":
                "Content-Type",
            "Access-Control-Allow-Credentials":
                "true"
        };


        /* =====================================================
           OPTIONS
        ===================================================== */

        if (method === "OPTIONS") {

            return new Response(null, {
                status: 204,
                headers: corsHeaders
            });

        }


        /* =====================================================
           ОКНОШНЫЙ HELPER ДЛЯ ДОБАВЛЕНИЯ CORS
        ===================================================== */

        const addCors = (response) => {

            const headers =
                new Headers(response.headers);

            for (
                const [key, value]
                of Object.entries(corsHeaders)
            ) {

                headers.set(key, value);

            }

            return new Response(
                response.body,
                {
                    status: response.status,
                    statusText: response.statusText,
                    headers
                }
            );
        };


        /* =====================================================
           ОБЫЧНЫЙ АККАУНТ
           auth.js
        ===================================================== */


        /* -----------------------------------------------------
           REGISTER
           POST /api/auth/register
        ----------------------------------------------------- */

        if (
            path === "/api/auth/register" &&
            method === "POST"
        ) {

            return addCors(
                await register(
                    request,
                    env
                )
            );

        }


        /* -----------------------------------------------------
           LOGIN
           POST /api/auth/login
        ----------------------------------------------------- */

        if (
            path === "/api/auth/login" &&
            method === "POST"
        ) {

            return addCors(
                await login(
                    request,
                    env
                )
            );

        }


        /* -----------------------------------------------------
           ME
           GET /api/auth/me
        ----------------------------------------------------- */

        if (
            path === "/api/auth/me" &&
            method === "GET"
        ) {

            return addCors(
                await me(
                    request,
                    env
                )
            );

        }


        /* -----------------------------------------------------
           LOGOUT
           POST /api/auth/logout
        ----------------------------------------------------- */

        if (
            path === "/api/auth/logout" &&
            method === "POST"
        ) {

            return addCors(
                await logout(
                    request,
                    env
                )
            );

        }


        /* =====================================================
           ADMIN AUTH
           admin.js
        ===================================================== */


        /* -----------------------------------------------------
           ADMIN REGISTER
           POST /api/admin/register
        ----------------------------------------------------- */

        if (
            path === "/api/admin/register" &&
            method === "POST"
        ) {

            return addCors(
                await adminRegister(
                    request,
                    env
                )
            );

        }


        /* -----------------------------------------------------
           ADMIN LOGIN
           POST /api/admin/login
        ----------------------------------------------------- */

        if (
            path === "/api/admin/login" &&
            method === "POST"
        ) {

            return addCors(
                await adminLogin(
                    request,
                    env
                )
            );

        }


        /* -----------------------------------------------------
           ADMIN ME
           GET /api/admin/me
        ----------------------------------------------------- */

        if (
            path === "/api/admin/me" &&
            method === "GET"
        ) {

            return addCors(
                await adminMe(
                    request,
                    env
                )
            );

        }


        /* -----------------------------------------------------
           ADMIN LOGOUT
           POST /api/admin/logout
        ----------------------------------------------------- */

        if (
            path === "/api/admin/logout" &&
            method === "POST"
        ) {

            return addCors(
                await adminLogout(
                    request,
                    env
                )
            );

        }


        /* =====================================================
           ADMIN STATISTICS
        ===================================================== */


        /* -----------------------------------------------------
           GET /api/admin/stats
        ----------------------------------------------------- */

        if (
            path === "/api/admin/stats" &&
            method === "GET"
        ) {

            return addCors(
                await adminStats(
                    request,
                    env
                )
            );

        }


        /* =====================================================
           NORMAL ACCOUNTS
        ===================================================== */


        /* -----------------------------------------------------
           GET /api/admin/accounts
        ----------------------------------------------------- */

        if (
            path === "/api/admin/accounts" &&
            method === "GET"
        ) {

            return addCors(
                await adminAccounts(
                    request,
                    env
                )
            );

        }


        /* =====================================================
           ADMINISTRATORS
        ===================================================== */


        /* -----------------------------------------------------
           GET /api/admin/administrators
        ----------------------------------------------------- */

        if (
            path === "/api/admin/administrators" &&
            method === "GET"
        ) {

            return addCors(
                await adminAdministrators(
                    request,
                    env
                )
            );

        }


        /* -----------------------------------------------------
           CREATE ADMINISTRATOR
           POST /api/admin/administrators/create
        ----------------------------------------------------- */

        if (
            path === "/api/admin/administrators/create" &&
            method === "POST"
        ) {

            return addCors(
                await createAdministrator(
                    request,
                    env
                )
            );

        }


        /* -----------------------------------------------------
           UPDATE ADMINISTRATOR
           POST /api/admin/administrators/update
        ----------------------------------------------------- */

        if (
            path === "/api/admin/administrators/update" &&
            method === "POST"
        ) {

            return addCors(
                await updateAdministrator(
                    request,
                    env
                )
            );

        }


        /* -----------------------------------------------------
           DELETE ADMINISTRATOR
           POST /api/admin/administrators/delete
        ----------------------------------------------------- */

        if (
            path === "/api/admin/administrators/delete" &&
            method === "POST"
        ) {

            return addCors(
                await deleteAdministrator(
                    request,
                    env
                )
            );

        }


        /* =====================================================
           PRODUCTS
        ===================================================== */


        /* -----------------------------------------------------
           GET /api/admin/products
        ----------------------------------------------------- */

        if (
            path === "/api/admin/products" &&
            method === "GET"
        ) {

            return addCors(
                await adminProducts(
                    request,
                    env
                )
            );

        }


        /* =====================================================
           TRANSACTIONS
        ===================================================== */


        /* -----------------------------------------------------
           GET /api/admin/transactions
        ----------------------------------------------------- */

        if (
            path === "/api/admin/transactions" &&
            method === "GET"
        ) {

            return addCors(
                await adminTransactions(
                    request,
                    env
                )
            );

        }


        /* =====================================================
           SUBSCRIPTIONS
        ===================================================== */


        /* -----------------------------------------------------
           GET /api/admin/subscriptions
        ----------------------------------------------------- */

        if (
            path === "/api/admin/subscriptions" &&
            method === "GET"
        ) {

            return addCors(
                await adminSubscriptions(
                    request,
                    env
                )
            );

        }


        /* =====================================================
           ACCESS CONTROL
           ВЫДАЧА / СНЯТИЕ ДОСТУПА
        ===================================================== */


        /* -----------------------------------------------------
           GRANT ACCESS

           POST /api/admin/access/grant

           BODY:

           {
               "identifier": "detox",
               "productId": "visual",
               "productName": "Visual",
               "days": 30
           }

           identifier:
           - ID аккаунта
           - username

           days:
           7  = 7 дней
           30 = 30 дней
           90 = 90 дней
           0  = навсегда
        ----------------------------------------------------- */

        if (
            path === "/api/admin/access/grant" &&
            method === "POST"
        ) {

            return addCors(
                await adminGrantAccess(
                    request,
                    env
                )
            );

        }


        /* -----------------------------------------------------
           REVOKE ACCESS

           POST /api/admin/access/revoke

           BODY:

           {
               "identifier": "detox",
               "productId": "visual"
           }

           Если productId не указан,
           снимаются все активные доступы.
        ----------------------------------------------------- */

        if (
            path === "/api/admin/access/revoke" &&
            method === "POST"
        ) {

            return addCors(
                await adminRevokeAccess(
                    request,
                    env
                )
            );

        }


        /* -----------------------------------------------------
           USER ACCESS

           POST /api/admin/access/list

           BODY:

           {
               "identifier": "detox"
           }
        ----------------------------------------------------- */

        if (
            path === "/api/admin/access/list" &&
            method === "POST"
        ) {

            return addCors(
                await adminUserAccess(
                    request,
                    env
                )
            );

        }


        /* =====================================================
           API 404
        ===================================================== */

        return new Response(
            JSON.stringify({
                success: false,
                error: "API endpoint not found",
                path,
                method
            }),
            {
                status: 404,

                headers: {
                    "Content-Type":
                        "application/json; charset=utf-8",

                    ...corsHeaders
                }
            }
        );

    }
};
