import type { Env } from "./env";
import { tg } from "./telegram";

export interface PaytmConfig {
  enabled: boolean;
  merchant_id: string;
  merchant_key: string;
  environment: "staging" | "production";
  min_amount: number;
  max_amount: number;
  website_name: string;
}

export interface PaytmTransaction {
  ORDERID: string;
  MID: string;
  TXNAMOUNT: string;
  STATUS: string;
  TXNID?: string;
  RESPMSG?: string;
  CURRENCY?: string;
}

/** Paytm's current JS Checkout hosts (not the legacy securegw.* endpoints). */
export function paytmBase(environment: string): string {
  return environment === "production"
    ? "https://secure.paytmpayments.com"
    : "https://securestage.paytmpayments.com";
}

const encoder = new TextEncoder();
const IV = encoder.encode("@@@@&&&&####$$$$");

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, Math.min(i + 0x8000, bytes.length)));
  }
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

async function encryptChecksum(plainText: string, merchantKey: string): Promise<string> {
  const keyBytes = encoder.encode(merchantKey);
  if (keyBytes.length !== 16) throw new Error("PAYTM_MERCHANT_KEY_MUST_BE_16_BYTES");
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv: IV },
    key,
    encoder.encode(plainText),
  );
  return toBase64(new Uint8Array(encrypted));
}

async function checksumHash(body: string, salt: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(`${body}|${salt}`));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("") + salt;
}

/** Matches Paytm's official Node checksum utility: AES-128-CBC over SHA256(payload|salt)+salt. */
export async function createPaytmSignature(payload: string | Record<string, unknown>, merchantKey: string): Promise<string> {
  const body = typeof payload === "string" ? payload : JSON.stringify(payload);
  const random = new Uint8Array(3);
  crypto.getRandomValues(random);
  const salt = toBase64(random); // Paytm's 4-character base64 salt
  return encryptChecksum(await checksumHash(body, salt), merchantKey);
}

export async function verifyPaytmSignature(
  payload: string | Record<string, unknown>,
  merchantKey: string,
  checksum: string,
): Promise<boolean> {
  try {
    const keyBytes = encoder.encode(merchantKey);
    if (keyBytes.length !== 16) return false;
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-CBC" }, false, ["decrypt"]);
    const plain = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: IV },
      key,
      fromBase64(checksum),
    );
    const decoded = new TextDecoder().decode(plain);
    if (decoded.length < 68) return false;
    const salt = decoded.slice(-4);
    const body = typeof payload === "string" ? payload : JSON.stringify(payload);
    return decoded === await checksumHash(body, salt);
  } catch {
    return false;
  }
}

export async function getPaytmConfig(env: Env): Promise<PaytmConfig> {
  const rows = await env.DB.prepare(
    `SELECT key,value FROM settings WHERE key IN (
      'paytm_enabled','paytm_mid','paytm_key','paytm_environment',
      'paytm_min_amount','paytm_max_amount','paytm_website_name'
    )`,
  ).all<{ key: string; value: string }>();
  const values = Object.fromEntries(rows.results.map((r) => [r.key, r.value]));
  return {
    enabled: values.paytm_enabled === "1",
    merchant_id: env.PAYTM_MID || values.paytm_mid || "",
    merchant_key: env.PAYTM_MERCHANT_KEY || values.paytm_key || "",
    environment: (env.PAYTM_ENV || values.paytm_environment) === "production" ? "production" : "staging",
    min_amount: Number(values.paytm_min_amount || 10),
    max_amount: Number(values.paytm_max_amount || 10000),
    website_name: values.paytm_website_name || "DEFAULT",
  };
}

export async function initiatePaytmTransaction(
  config: PaytmConfig,
  orderId: string,
  amount: number,
  callbackUrl: string,
  customerId: number,
) {
  if (!config.enabled) throw new Error("PAYTM_DISABLED");
  if (!config.merchant_id || !config.merchant_key) throw new Error("PAYTM_NOT_CONFIGURED");
  const body = {
    requestType: "Payment",
    mid: config.merchant_id,
    websiteName: config.website_name || "DEFAULT",
    orderId,
    callbackUrl,
    txnAmount: { value: amount.toFixed(2), currency: "INR" },
    userInfo: { custId: String(customerId) },
  };
  const bodyJson = JSON.stringify(body);
  const signature = await createPaytmSignature(bodyJson, config.merchant_key);
  const base = paytmBase(config.environment);
  const response = await fetch(
    `${base}/theia/api/v1/initiateTransaction?mid=${encodeURIComponent(config.merchant_id)}&orderId=${encodeURIComponent(orderId)}`,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ body, head: { signature } }) },
  );
  const result = await response.json() as {
    head?: { signature?: string };
    body?: { resultInfo?: { resultStatus?: string; resultMsg?: string }; txnToken?: string };
  };
  if (!response.ok || !result.body) throw new Error("PAYTM_INITIATION_FAILED");
  if (!result.head?.signature || !(await verifyPaytmSignature(result.body, config.merchant_key, result.head.signature))) {
    throw new Error("PAYTM_INITIATION_SIGNATURE_INVALID");
  }
  if (result.body.resultInfo?.resultStatus !== "S" || !result.body.txnToken) {
    throw new Error(result.body.resultInfo?.resultMsg || "PAYTM_TOKEN_FAILED");
  }
  return {
    txnToken: result.body.txnToken,
    mid: config.merchant_id,
    orderId,
    amount: amount.toFixed(2),
    checkoutScript: `${base}/merchantpgpui/checkoutjs/merchants/${encodeURIComponent(config.merchant_id)}.js`,
  };
}

export async function getPaytmTransaction(config: PaytmConfig, orderId: string): Promise<PaytmTransaction> {
  if (!config.merchant_id || !config.merchant_key) throw new Error("PAYTM_NOT_CONFIGURED");
  const body = { mid: config.merchant_id, orderId };
  const signature = await createPaytmSignature(JSON.stringify(body), config.merchant_key);
  const response = await fetch(`${paytmBase(config.environment)}/v3/order/status`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ body, head: { signature } }),
  });
  const result = await response.json() as {
    head?: { signature?: string };
    body?: PaytmTransaction & { txnInfo?: PaytmTransaction; resultInfo?: { resultStatus?: string } };
  };
  if (!response.ok || !result.body || !result.head?.signature) throw new Error("PAYTM_STATUS_FAILED");
  if (!(await verifyPaytmSignature(result.body, config.merchant_key, result.head.signature))) {
    throw new Error("PAYTM_STATUS_SIGNATURE_INVALID");
  }
  return (result.body.txnInfo || result.body) as PaytmTransaction;
}

export function isSuccessfulPaytmPayment(
  transaction: PaytmTransaction,
  config: PaytmConfig,
  orderId: string,
  expectedAmount: number,
): boolean {
  const actualCents = Math.round(Number(transaction.TXNAMOUNT) * 100);
  return transaction.STATUS === "TXN_SUCCESS" &&
    transaction.MID === config.merchant_id &&
    transaction.ORDERID === orderId &&
    transaction.CURRENCY === "INR" &&
    Number.isFinite(actualCents) &&
    actualCents === Math.round(expectedAmount * 100) &&
    !!transaction.TXNID;
}

/** Server-to-server status check followed by a single atomic, idempotent D1 wallet credit. */
export async function verifyAndCreditPaytm(env: Env, orderId: string, expectedUserId?: number) {
  const config = await getPaytmConfig(env);
  const payment = await env.DB.prepare(
    "SELECT id,order_id,user_id,amount_inr,status,txn_id FROM paytm_payments WHERE order_id=?1",
  ).bind(orderId).first<{
    id: number; order_id: string; user_id: number; amount_inr: number; status: string; txn_id: string | null;
  }>();
  if (!payment) return { ok: false as const, error: "PAYMENT_NOT_FOUND" };
  if (expectedUserId !== undefined && payment.user_id !== expectedUserId) return { ok: false as const, error: "FORBIDDEN" };
  if (payment.status === "paid") return { ok: true as const, alreadyPaid: true };
  if (payment.status !== "pending") return { ok: false as const, error: "PAYMENT_NOT_PENDING" };

  const transaction = await getPaytmTransaction(config, orderId);
  if (transaction.STATUS === "TXN_FAILURE") {
    await env.DB.prepare(
      "UPDATE paytm_payments SET status='failed' WHERE order_id=?1 AND status='pending'",
    ).bind(orderId).run();
    return { ok: false as const, error: "PAYMENT_FAILED" };
  }
  if (!isSuccessfulPaytmPayment(transaction, config, orderId, Number(payment.amount_inr))) {
    return { ok: false as const, error: "PAYMENT_NOT_CONFIRMED" };
  }

  const now = Math.floor(Date.now() / 1000);
  const result = await env.DB.batch([
    env.DB.prepare(
      `UPDATE paytm_payments SET status='paid',txn_id=?2,paid_at=?3
       WHERE order_id=?1 AND status='pending' AND EXISTS(SELECT 1 FROM users WHERE id=?4)`,
    ).bind(orderId, transaction.TXNID!, now, payment.user_id),
    env.DB.prepare(
      `UPDATE users SET balance_inr=balance_inr+?2 WHERE id=?1 AND changes()=1`,
    ).bind(payment.user_id, Number(payment.amount_inr)),
    env.DB.prepare(
      `INSERT INTO inr_ledger(user_id,delta_inr,kind,ref,note,created_at)
       SELECT ?1,?2,'paytm_topup',?3,'Paytm automatic top-up',?4 WHERE changes()=1`,
    ).bind(payment.user_id, Number(payment.amount_inr), payment.id, now),
  ]);
  if (!result[0].meta.changes) {
    const current = await env.DB.prepare("SELECT status FROM paytm_payments WHERE order_id=?1")
      .bind(orderId).first<{ status: string }>();
    return current?.status === "paid"
      ? { ok: true as const, alreadyPaid: true }
      : { ok: false as const, error: "PAYMENT_ALREADY_PROCESSED" };
  }

  const userBalance = await env.DB.prepare("SELECT balance_inr FROM users WHERE id=?1")
    .bind(payment.user_id).first<{ balance_inr: number }>();
  await tg(env.BOT_TOKEN, "sendMessage", {
    chat_id: payment.user_id,
    text: `✅ Paytm payment successful!\n\nAmount: ₹${Number(payment.amount_inr).toFixed(2)}\nOrder: ${orderId}\nWallet balance: ₹${Number(userBalance?.balance_inr || 0).toFixed(2)}`,
  }).catch((e) => console.error("Paytm notification failed", e));
  return { ok: true as const, alreadyPaid: false };
}
