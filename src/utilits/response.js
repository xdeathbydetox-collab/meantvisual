export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Credentials": "true",
      ...extraHeaders
    }
  });
}

export function optionsResponse() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods":
        "GET, POST, PUT, PATCH, DELETE, OPTIONS",
      "Access-Control-Allow-Headers":
        "Content-Type, Accept, Authorization",
      "Access-Control-Allow-Credentials": "true"
    }
  });
}

export function notFound() {
  return json({
    success: false,
    error: "Маршрут не найден"
  }, 404);
}
