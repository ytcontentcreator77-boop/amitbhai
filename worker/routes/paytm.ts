import { Hono } from "hono";
import type { AppEnv } from "./app";
import { getPaytmConfig, initiatePaytmTransaction, verifyAndCreditPaytm } from "../paytm";

export const paytm = new Hono<AppEnv>();

paytm.post("/create", async (c) => {
  const user = c.get("user");
  const config = await getPaytmConfig(c.env);
  if (!config.enabled) return c.json({ error: "PAYTM_DISABLED" }, 403);
  if (!config.merchant_id || !config.merchant_key) return c.json({ error: "PAYTM_NOT_CONFIGURED" }, 503);

  const body = await c.req.json().catch(() => null) as { amount?: unknown } | null;
  const amount = Number(body?.amount);
  const cents = Math.round(amount * 100);
  if (!Number.isFinite(amount) || !Number.isSafeInteger(cents) ||
      cents / 100 !== amount || amount < config.min_amount || amount > config.max_amount) {
    return c.json({ error: "INVALID_AMOUNT", min: config.min_amount, max: config.max_amount }, 400);
  }

  const random = new Uint32Array(1);
  crypto.getRandomValues(random);
  const orderId = `AMIT-${Date.now()}-${random[0].toString(36).toUpperCase()}`;
  const now = Math.floor(Date.now() / 1000);
  await c.env.DB.prepare(
    `INSERT INTO paytm_payments(order_id,user_id,amount_inr,status,created_at)
     VALUES(?1,?2,?3,'pending',?4)`,
  ).bind(orderId, user.id, cents / 100, now).run();

  try {
    const callbackUrl = c.env.PAYTM_CALLBACK_URL || `${new URL(c.req.url).origin}/hooks/paytm`;
    const payment = await initiatePaytmTransaction(config, orderId, cents / 100, callbackUrl, user.id);
    return c.json({ ok: true, ...payment, environment: config.environment });
  } catch (error) {
    console.error("Paytm initiation failed", orderId, error);
    await c.env.DB.prepare(
      `UPDATE paytm_payments SET status='failed' WHERE order_id=?1 AND status='pending'`,
    ).bind(orderId).run();
    return c.json({ error: "PAYTM_INITIATION_FAILED" }, 502);
  }
});

paytm.get("/status/:orderId", async (c) => {
  const orderId = c.req.param("orderId");
  if (!/^AMIT-[A-Z0-9-]{8,45}$/.test(orderId)) return c.json({ ok: false, error: "INVALID_ORDER_ID" }, 400);
  try {
    const result = await verifyAndCreditPaytm(c.env, orderId, c.get("user").id);
    const status = !result.ok && result.error === "FORBIDDEN" ? 403 : 200;
    return c.json(result, status);
  } catch (error) {
    console.error("Paytm status verification failed", orderId, error);
    return c.json({ ok: false, error: "VERIFICATION_FAILED" }, 502);
  }
});
