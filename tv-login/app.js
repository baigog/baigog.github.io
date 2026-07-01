"use strict";

const supabaseUrl = "https://vdswakmrxsgfjyivnkbb.supabase.co";
const anonKey = "sb_publishable_ij3hgWd11_dY03bQQS0rjA_KDXjMmRT";
const pairingEndpoint = `${supabaseUrl}/functions/v1/tv-passkey-pairing`;
const encoder = new TextEncoder();
const message = document.querySelector("#message");
const approveButton = document.querySelector("#approve");

const pairingId = new URLSearchParams(location.search).get("id") ?? "";
const secretText = new URLSearchParams(location.hash.slice(1)).get("secret") ?? "";
const validRequest = /^[0-9a-f-]{36}$/.test(pairingId) && /^[A-Za-z0-9_-]{43}$/.test(secretText);

if (!validRequest) {
  show("El QR no contiene una solicitud válida o ya perdió su secreto.", "error");
  approveButton.disabled = true;
}

approveButton.addEventListener("click", async () => {
  approveButton.disabled = true;
  try {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      throw new Error("Este navegador no admite passkeys.");
    }
    show("Buscando tu passkey…");
    const challenge = await postJson(`${supabaseUrl}/auth/v1/passkeys/authentication/options`, {
      gotrue_meta_security: {},
    });
    const publicKey = normalizeRequestOptions(challenge.options);
    const credential = await navigator.credentials.get({ publicKey });
    if (!credential) throw new Error("No se recibió una credencial.");

    show("Verificando la passkey…");
    const session = await postJson(`${supabaseUrl}/auth/v1/passkeys/authentication/verify`, {
      challenge_id: challenge.challenge_id,
      credential: serializeCredential(credential),
    });
    if (!session.access_token || !session.refresh_token) {
      throw new Error("Supabase no devolvió una sesión válida.");
    }

    show("Cifrando la sesión para la TV…");
    const secret = fromBase64Url(secretText);
    const secretHash = toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", secret)));
    const encrypted = await encryptSession(secret, session);
    await postJson(pairingEndpoint, {
      action: "approve",
      pairing_id: pairingId,
      secret_hash: secretHash,
      encrypted_session: encrypted.ciphertext,
      iv: encrypted.iv,
    }, session.access_token);

    history.replaceState(null, "", `${location.pathname}?id=${encodeURIComponent(pairingId)}`);
    show("Listo. La TV inició sesión; ya podés cerrar esta página.", "success");
  } catch (error) {
    const cancelled = error?.name === "NotAllowedError" || error?.name === "AbortError";
    show(cancelled ? "Se canceló la confirmación. Podés intentarlo nuevamente." : safeError(error), "error");
    approveButton.disabled = false;
  }
});

async function postJson(url, body, accessToken = null) {
  const headers = {
    "Content-Type": "application/json",
    "apikey": anonKey,
  };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    cache: "no-store",
    credentials: "omit",
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.msg || payload.message || payload.error_description || payload.error || `HTTP ${response.status}`);
  }
  return payload;
}

function normalizeRequestOptions(options) {
  return {
    ...options,
    challenge: fromBase64Url(options.challenge),
    allowCredentials: (options.allowCredentials ?? []).map((entry) => ({
      ...entry,
      id: fromBase64Url(entry.id),
    })),
  };
}

function serializeCredential(credential) {
  if (typeof credential.toJSON === "function") return credential.toJSON();
  return {
    id: credential.id,
    rawId: toBase64Url(new Uint8Array(credential.rawId)),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      authenticatorData: toBase64Url(new Uint8Array(credential.response.authenticatorData)),
      clientDataJSON: toBase64Url(new Uint8Array(credential.response.clientDataJSON)),
      signature: toBase64Url(new Uint8Array(credential.response.signature)),
      userHandle: credential.response.userHandle
        ? toBase64Url(new Uint8Array(credential.response.userHandle))
        : null,
    },
  };
}

async function encryptSession(secret, session) {
  const keyMaterial = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({
    name: "HKDF",
    hash: "SHA-256",
    salt: encoder.encode(pairingId),
    info: encoder.encode("aniranking-tv-pairing-v1"),
  }, keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify({
    access_token: session.access_token,
    refresh_token: session.refresh_token,
    token_type: session.token_type ?? "bearer",
    expires_at: session.expires_at ?? null,
  }));
  const ciphertext = await crypto.subtle.encrypt({
    name: "AES-GCM",
    iv,
    additionalData: encoder.encode(pairingId),
    tagLength: 128,
  }, key, plaintext);
  return {
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(new Uint8Array(ciphertext)),
  };
}

function fromBase64Url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function toBase64Url(value) {
  let binary = "";
  value.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function show(text, className = "") {
  message.textContent = text;
  message.className = className;
}

function safeError(error) {
  const detail = String(error?.message ?? "");
  if (detail.includes("pairing_not_found")) return "La solicitud venció. Generá un QR nuevo en la TV.";
  if (detail.includes("pairing_already_used")) return "Esta solicitud ya fue utilizada.";
  return "No se pudo completar el acceso. Volvé a intentarlo desde la TV.";
}
