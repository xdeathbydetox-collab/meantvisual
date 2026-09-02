/* =========================================================
   MEANT SHOP — CLOUDFLARE WORKER
   ========================================================= */

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
    adminUserAccess,

    adminAddBalance,
    adminRemoveBalance
} from "./utilits/admin.js";


/* =========================================================
   CORS / RESPONSE
   ========================================================= */

function json(data, status = 200, extraHeaders = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type": "application/json; charset=utf-8",

            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",

            ...extraHeaders
        }
    });
}


/* =========================================================
   OPTIONS
   ========================================================= */

function options() {
    return new Response(null, {
        status: 204,
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        }
    });
}


/* =========================================================
   MAIN FETCH
   ========================================================= */

export default {
    async fetch(request, env, ctx) {

        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method.toUpperCase();


        /* =====================================================
           CORS PREFLIGHT
           ===================================================== */

        if (method === "OPTIONS") {
            return options();
        }


        /* =====================================================
           NORMAL USER AUTH
           ===================================================== */

        // POST /api/auth/register
        if (
            path === "/api/auth/register" &&
            method === "POST"
        ) {
            try {
                return await register(request, env);
            } catch (error) {
                console.error("AUTH REGISTER ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка регистрации"
                }, 500);
            }
        }


        // POST /api/auth/login
        if (
            path === "/api/auth/login" &&
            method === "POST"
        ) {
            try {
                return await login(request, env);
            } catch (error) {
                console.error("AUTH LOGIN ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка входа"
                }, 500);
            }
        }


        // GET /api/auth/me
        if (
            path === "/api/auth/me" &&
            method === "GET"
        ) {
            try {
                return await me(request, env);
            } catch (error) {
                console.error("AUTH ME ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка получения профиля"
                }, 500);
            }
        }


        // POST /api/auth/logout
        if (
            path === "/api/auth/logout" &&
            method === "POST"
        ) {
            try {
                return await logout(request, env);
            } catch (error) {
                console.error("AUTH LOGOUT ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка выхода"
                }, 500);
            }
        }


        /* =====================================================
           ADMIN AUTH
           ===================================================== */

        // POST /api/admin/register
        if (
            path === "/api/admin/register" &&
            method === "POST"
        ) {
            try {
                return await adminRegister(request, env);
            } catch (error) {
                console.error("ADMIN REGISTER ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка регистрации администратора"
                }, 500);
            }
        }


        // POST /api/admin/login
        if (
            path === "/api/admin/login" &&
            method === "POST"
        ) {
            try {
                return await adminLogin(request, env);
            } catch (error) {
                console.error("ADMIN LOGIN ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка входа администратора"
                }, 500);
            }
        }


        // GET /api/admin/me
        if (
            path === "/api/admin/me" &&
            method === "GET"
        ) {
            try {
                return await adminMe(request, env);
            } catch (error) {
                console.error("ADMIN ME ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка получения администратора"
                }, 500);
            }
        }


        // POST /api/admin/logout
        if (
            path === "/api/admin/logout" &&
            method === "POST"
        ) {
            try {
                return await adminLogout(request, env);
            } catch (error) {
                console.error("ADMIN LOGOUT ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка выхода администратора"
                }, 500);
            }
        }


        /* =====================================================
           ADMIN — DASHBOARD
           ===================================================== */

        // GET /api/admin/stats
        if (
            path === "/api/admin/stats" &&
            method === "GET"
        ) {
            try {
                return await adminStats(request, env);
            } catch (error) {
                console.error("ADMIN STATS ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка получения статистики"
                }, 500);
            }
        }


        /* =====================================================
           ADMIN — ACCOUNTS
           ===================================================== */

        // GET /api/admin/accounts
        if (
            path === "/api/admin/accounts" &&
            method === "GET"
        ) {
            try {
                return await adminAccounts(request, env);
            } catch (error) {
                console.error("ADMIN ACCOUNTS ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка получения пользователей"
                }, 500);
            }
        }


        /* =====================================================
           ADMIN — ADMINISTRATORS
           ===================================================== */

        // GET /api/admin/administrators
        if (
            path === "/api/admin/administrators" &&
            method === "GET"
        ) {
            try {
                return await adminAdministrators(request, env);
            } catch (error) {
                console.error("ADMIN ADMINISTRATORS ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка получения администраторов"
                }, 500);
            }
        }


        // POST /api/admin/administrators
        if (
            path === "/api/admin/administrators" &&
            method === "POST"
        ) {
            try {
                return await createAdministrator(request, env);
            } catch (error) {
                console.error("CREATE ADMIN ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка создания администратора"
                }, 500);
            }
        }


        // PATCH /api/admin/administrators
        if (
            path === "/api/admin/administrators" &&
            method === "PATCH"
        ) {
            try {
                return await updateAdministrator(request, env);
            } catch (error) {
                console.error("UPDATE ADMIN ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка изменения администратора"
                }, 500);
            }
        }


        // DELETE /api/admin/administrators
        if (
            path === "/api/admin/administrators" &&
            method === "DELETE"
        ) {
            try {
                return await deleteAdministrator(request, env);
            } catch (error) {
                console.error("DELETE ADMIN ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка удаления администратора"
                }, 500);
            }
        }


        /* =====================================================
           ADMIN — PRODUCTS
           ===================================================== */

        // GET /api/admin/products
        if (
            path === "/api/admin/products" &&
            method === "GET"
        ) {
            try {
                return await adminProducts(request, env);
            } catch (error) {
                console.error("ADMIN PRODUCTS ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка получения товаров"
                }, 500);
            }
        }


        /* =====================================================
           ADMIN — TRANSACTIONS
           ===================================================== */

        // GET /api/admin/transactions
        if (
            path === "/api/admin/transactions" &&
            method === "GET"
        ) {
            try {
                return await adminTransactions(request, env);
            } catch (error) {
                console.error("ADMIN TRANSACTIONS ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка получения транзакций"
                }, 500);
            }
        }


        /* =====================================================
           ADMIN — SUBSCRIPTIONS
           ===================================================== */

        // GET /api/admin/subscriptions
        if (
            path === "/api/admin/subscriptions" &&
            method === "GET"
        ) {
            try {
                return await adminSubscriptions(request, env);
            } catch (error) {
                console.error("ADMIN SUBSCRIPTIONS ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка получения подписок"
                }, 500);
            }
        }


        /* =====================================================
           ADMIN — ACCESS
           ===================================================== */

        // POST /api/admin/access/grant
        //
        // Пример:
        // {
        //     "identifier": "detox",
        //     "productId": "30-days",
        //     "productName": "30 дней",
        //     "expiresAt": "2026-10-01T12:00:00.000Z"
        // }
        //
        if (
            path === "/api/admin/access/grant" &&
            method === "POST"
        ) {
            try {
                return await adminGrantAccess(request, env);
            } catch (error) {
                console.error("GRANT ACCESS ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка выдачи доступа"
                }, 500);
            }
        }


        // POST /api/admin/access/revoke
        //
        // {
        //     "identifier": "detox",
        //     "productId": "30-days"
        // }
        //
        if (
            path === "/api/admin/access/revoke" &&
            method === "POST"
        ) {
            try {
                return await adminRevokeAccess(request, env);
            } catch (error) {
                console.error("REVOKE ACCESS ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка отзыва доступа"
                }, 500);
            }
        }


        // POST /api/admin/access/list
        //
        // {
        //     "identifier": "detox"
        // }
        //
        if (
            path === "/api/admin/access/list" &&
            method === "POST"
        ) {
            try {
                return await adminUserAccess(request, env);
            } catch (error) {
                console.error("LIST ACCESS ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка получения доступов"
                }, 500);
            }
        }


        /* =====================================================
           ADMIN — BALANCE
           ===================================================== */

        // POST /api/admin/balance/add
        //
        // {
        //     "identifier": "detox",
        //     "amount": 500
        // }
        //
        if (
            path === "/api/admin/balance/add" &&
            method === "POST"
        ) {
            try {
                return await adminAddBalance(request, env);
            } catch (error) {
                console.error("ADD BALANCE ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка пополнения баланса"
                }, 500);
            }
        }


        // POST /api/admin/balance/remove
        //
        // {
        //     "identifier": "detox",
        //     "amount": 500
        // }
        //
        if (
            path === "/api/admin/balance/remove" &&
            method === "POST"
        ) {
            try {
                return await adminRemoveBalance(request, env);
            } catch (error) {
                console.error("REMOVE BALANCE ERROR:", error);

                return json({
                    success: false,
                    error: "Ошибка снятия баланса"
                }, 500);
            }
        }


        /* =====================================================
           404
           ===================================================== */

        return json({
            success: false,
            error: "API endpoint not found",
            path,
            method
        }, 404);
    }
};
