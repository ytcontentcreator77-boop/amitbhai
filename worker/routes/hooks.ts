import { Hono } from "hono";
import { notpanelSignature, timingSafeEqual } from "../auth";
import type { Env } from "../env";
import type { NpStatus } from "../notpanel";
import { applyStatus, type OrderRow } from "../orders";
import { getSettings } from "../settings";
import { verifyAndCreditPaytm } from "../paytm";

export const hooks = new Hono<{ Bindings: Env }>();

/** Deletes webhook de-duplication rows older than 7 days. Called hourly from the cron job (not per request). */
export async function cleanupWebhookEvents(env: Env): Promise<void> {
  const cutoff = Math.floor(Date.now() / 1000) - 7 * 86400;
  await env.DB.prepare("DELETE FROM webhook_events WHERE received_at < ?1").bind(cutoff).run();
}



/** Paytm callback is only a notification. Never trust its posted status; reconcile with Paytm's status API. */
hooks.post("/paytm", async (c) => {
  let fields: Record<string, unknown> = {};
  try {
    const contentType = c.req.header("content-type") || "";
    if (contentType.includes("application/json")) {
      fields = await c.req.json() as Record<string, unknown>;
    } else {
      fields = await c.req.parseBody();
    }
  } catch {
    return c.text("invalid callback", 400);
  }
  const orderId = String(fields.ORDERID || fields.orderId || "");
  if (!/^AMIT-[A-Z0-9-]{8,45}$/.test(orderId)) return c.text("ignored", 200);
  try {
    const result = await verifyAndCreditPaytm(c.env, orderId);
    if (!result.ok && result.error !== "PAYMENT_NOT_CONFIRMED" && result.error !== "PAYMENT_NOT_PENDING") {
      console.warn("Paytm callback could not be reconciled", orderId, result.error);
    }
    return c.text("OK", 200);
  } catch (error) {
    console.error("Paytm callback verification failed", orderId, error);
    // A transient error should be retried by status polling; don't accept the callback as proof of payment.
    return c.text("verification pending", 200);
  }
});

/** NotPanel order events. Signed with the secret we got from webhook.add; delivered at least once. */
hooks.post("/notpanel", async (c) => {
  const body = await c.req.text();
  const ts = c.req.header("x-webhook-timestamp") ?? "";
  const sig = (c.req.header("x-webhook-signature") ?? "").replace(/^sha256=/, "");
  const s = await getSettings(c.env);
  if (!s.np_webhook_secret || !ts || !sig) return c.text("forbidden", 403);
  const expected = await notpanelSignature(s.np_webhook_secret, ts, body);
  if (!timingSafeEqual(expected, sig)) return c.text("forbidden", 403);
  if (!(Math.abs(Date.now() / 1000 - Number(ts)) <= 3600)) return c.text("stale", 400);

  let evt: { id: string; type: string; data?: { order?: NpStatus & { order: number }; refill?: { refill: number; order: number; status_key: string } } };
  try {
    evt = JSON.parse(body);
  } catch {
    return c.text("bad request", 400);
  }
  if (!evt || typeof evt !== "object" || typeof evt.id !== "string" || !evt.id) return c.text("bad request", 400);
  const now = Math.floor(Date.now() / 1000);
  const fresh = await c.env.DB.prepare("INSERT INTO webhook_events (id, received_at) VALUES (?1, ?2) ON CONFLICT DO NOTHING")
    .bind(evt.id, now)
    .run();
  if (!fresh.meta.changes) return c.text("duplicate");

  const work = async () => {
    if (evt.data?.order?.order) {
      const o = await c.env.DB.prepare("SELECT * FROM orders WHERE np_order_id = ?1 AND provider_id = 0").bind(evt.data.order.order).first<OrderRow>();
      if (o) await applyStatus(c.env, o, evt.data.order);
    }
    if (evt.data?.refill?.refill) {
      const st = evt.data.refill.status_key === "completed" || evt.data.refill.status_key === "rejected" ? evt.data.refill.status_key : "pending";
      await c.env.DB.prepare("UPDATE orders SET refill_status = ?2 WHERE refill_id = ?1").bind(evt.data.refill.refill, st).run();
    }
  };
  c.executionCtx.waitUntil(work().catch((e) => console.error("webhook failed", e)));
  return c.text("ok");
});
