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
    adminLogout
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
                        "Content-Type"
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
                        "application/json; charset=utf-8"
                }
            }
        );
    }
};
