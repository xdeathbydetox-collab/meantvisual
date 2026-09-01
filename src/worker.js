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
   MEANT SHOP WORKER
========================================================= */

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
           Обычная авторизация пользователей
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
           ADMIN AUTH
        ===================================================== */


        /*
           Создание администратора
           
           POST /api/admin/register
        */

        if (
            path === "/api/admin/register" &&
            method === "POST"
        ) {

            return adminRegister(
                request,
                env
            );
        }


        /*
           Вход администратора

           POST /api/admin/login
        */

        if (
            path === "/api/admin/login" &&
            method === "POST"
        ) {

            return adminLogin(
                request,
                env
            );
        }


        /*
           Проверка текущего администратора

           GET /api/admin/me
        */

        if (
            path === "/api/admin/me" &&
            method === "GET"
        ) {

            return adminMe(
                request,
                env
            );
        }


        /*
           Выход администратора

           POST /api/admin/logout
        */

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
           ADMIN PANEL — STATISTICS
        ===================================================== */


        /*
           GET /api/admin/stats
        */

        if (
            path === "/api/admin/stats" &&
            method === "GET"
        ) {

            return adminStats(
                request,
                env
            );
        }


        /* =====================================================
           ADMIN PANEL — USERS
        ===================================================== */


        /*
           GET /api/admin/accounts
        */

        if (
            path === "/api/admin/accounts" &&
            method === "GET"
        ) {

            return adminAccounts(
                request,
                env
            );
        }


        /* =====================================================
           ADMIN PANEL — ADMINISTRATORS
        ===================================================== */


        /*
           GET /api/admin/administrators
        */

        if (
            path === "/api/admin/administrators" &&
            method === "GET"
        ) {

            return adminAdministrators(
                request,
                env
            );
        }


        /*
           POST /api/admin/administrators

           Создание администратора.
           Только OWNER.
        */

        if (
            path === "/api/admin/administrators" &&
            method === "POST"
        ) {

            return createAdministrator(
                request,
                env
            );
        }


        /*
           PUT /api/admin/administrators

           Изменение администратора.
           Только OWNER.
        */

        if (
            path === "/api/admin/administrators" &&
            method === "PUT"
        ) {

            return updateAdministrator(
                request,
                env
            );
        }


        /*
           DELETE /api/admin/administrators

           Удаление администратора.
           Только OWNER.
        */

        if (
            path === "/api/admin/administrators" &&
            method === "DELETE"
        ) {

            return deleteAdministrator(
                request,
                env
            );
        }


        /* =====================================================
           ADMIN PANEL — PRODUCTS
        ===================================================== */


        /*
           GET /api/admin/products
        */

        if (
            path === "/api/admin/products" &&
            method === "GET"
        ) {

            return adminProducts(
                request,
                env
            );
        }


        /* =====================================================
           ADMIN PANEL — TRANSACTIONS
        ===================================================== */


        /*
           GET /api/admin/transactions
        */

        if (
            path === "/api/admin/transactions" &&
            method === "GET"
        ) {

            return adminTransactions(
                request,
                env
            );
        }


        /* =====================================================
           ADMIN PANEL — SUBSCRIPTIONS
        ===================================================== */


        /*
           GET /api/admin/subscriptions
        */

        if (
            path === "/api/admin/subscriptions" &&
            method === "GET"
        ) {

            return adminSubscriptions(
                request,
                env
            );
        }


        /* =====================================================
           ADMIN ACCESS — GRANT
        ===================================================== */


        /*
           POST /api/admin/access/grant

           BODY:

           {
               "identifier": "detox",
               "productId": "visual",
               "productName": "Visual",
               "days": 30
           }

           days:

           7  = 7 дней
           30 = 30 дней
           90 = 90 дней
           0  = навсегда
        */

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
           ADMIN ACCESS — REVOKE
        ===================================================== */


        /*
           POST /api/admin/access/revoke

           BODY:

           {
               "identifier": "detox",
               "productId": "visual"
           }

           Если productId отсутствует —
           снимаются все активные доступы.
        */

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
           ADMIN ACCESS — LIST
        ===================================================== */


        /*
           POST /api/admin/access/list

           BODY:

           {
               "identifier": "detox"
           }
        */

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
