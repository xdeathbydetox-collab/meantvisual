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

    adminTransactions,
    adminSubscriptions,

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
           ADMIN STATS

           GET /api/admin/stats
        ===================================================== */

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
           ОБЫЧНЫЕ АККАУНТЫ

           GET /api/admin/accounts
        ===================================================== */

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
           СПИСОК АДМИНИСТРАТОРОВ

           GET /api/admin/administrators
        ===================================================== */

        if (
            path === "/api/admin/administrators" &&
            method === "GET"
        ) {

            return adminAdministrators(
                request,
                env
            );
        }


        /* =====================================================
           СОЗДАНИЕ АДМИНИСТРАТОРА

           POST /api/admin/administrators/create

           Только OWNER
        ===================================================== */

        if (
            path === "/api/admin/administrators/create" &&
            method === "POST"
        ) {

            return createAdministrator(
                request,
                env
            );
        }


        /* =====================================================
           ИЗМЕНЕНИЕ АДМИНИСТРАТОРА

           POST /api/admin/administrators/update

           Только OWNER
        ===================================================== */

        if (
            path === "/api/admin/administrators/update" &&
            method === "POST"
        ) {

            return updateAdministrator(
                request,
                env
            );
        }


        /* =====================================================
           УДАЛЕНИЕ АДМИНИСТРАТОРА

           POST /api/admin/administrators/delete

           Только OWNER
        ===================================================== */

        if (
            path === "/api/admin/administrators/delete" &&
            method === "POST"
        ) {

            return deleteAdministrator(
                request,
                env
            );
        }


        /* =====================================================
           ТРАНЗАКЦИИ

           GET /api/admin/transactions
        ===================================================== */

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
           ПОДПИСКИ

           GET /api/admin/subscriptions
        ===================================================== */

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
           ВЫДАЧА ДОСТУПА

           POST /api/admin/access/grant
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
