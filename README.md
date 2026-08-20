# MEANT SHOP — merged + Tebex server

Собрано из трёх загруженных частей: главное меню, магазин и профиль/финансы.

## Сервер
- Cloudflare Workers + D1.
- Tebex Checkout API: Project ID `1881893` и Private Key хранятся только в secrets.
- Tebex webhook: `/api/tebex/webhook`.
- Проверка `X-Signature` по схеме Tebex (SHA-256 body → HMAC-SHA256).
- Idempotency по `webhook.id`.
- Баланс меняется только сервером после `payment.completed`.
- Refund/dispute отзывает entitlement и возвращает списанное пополнение.

## Важно
Checkout API Tebex требует предварительного одобрения. После развёртывания укажи webhook endpoint в Creator → Developers → Webhooks → Endpoints и секрет webhook.

### Secrets
`wrangler secret put TEBEX_PRIVATE_KEY`
`wrangler secret put TEBEX_WEBHOOK_SECRET`

`TEBEX_PROJECT_ID=1881893` можно оставить в wrangler environment или задать как переменную.

### D1
Создай D1 `meant-shop`, подставь `database_id` в `wrangler.toml`, затем:
`wrangler d1 execute meant-shop --remote --file=schema.sql`

### Deploy
`npm install`
`npx wrangler login`
`npx wrangler deploy`

Webhook URL после deploy:
`https://YOUR-DOMAIN/api/tebex/webhook`

Private Key и webhook secret в этот ZIP не включены.
