"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

test("encrypts the minted TV session and confirms the pairing", async () => {
  let click;
  let encryptedPlaintext;
  const requests = [];
  const approveButton = {
    disabled: false,
    addEventListener: (_event, handler) => { click = handler; },
  };
  const message = { textContent: "", className: "" };
  const responses = [
    { options: { challenge: "AA", allowCredentials: [] }, challenge_id: "challenge" },
    { access_token: "phone-access", refresh_token: "phone-refresh" },
    { status: "minted", access_token: "tv-access", refresh_token: "tv-refresh" },
    { status: "approved" },
  ];
  const context = {
    URLSearchParams,
    TextEncoder,
    Uint8Array,
    console,
    location: {
      search: "?id=123e4567-e89b-42d3-a456-426614174000",
      hash: `#secret=${"A".repeat(43)}`,
      pathname: "/tv-login/",
    },
    history: { replaceState() {} },
    document: { querySelector: (selector) => selector === "#message" ? message : approveButton },
    window: { PublicKeyCredential: function PublicKeyCredential() {} },
    navigator: {
      credentials: {
        get: async () => ({
          id: "credential",
          rawId: new Uint8Array([1]).buffer,
          type: "public-key",
          authenticatorAttachment: null,
          getClientExtensionResults: () => ({}),
          response: {
            authenticatorData: new Uint8Array([1]).buffer,
            clientDataJSON: new Uint8Array([2]).buffer,
            signature: new Uint8Array([3]).buffer,
            userHandle: null,
          },
        }),
      },
    },
    crypto: {
      getRandomValues: (value) => value.fill(7),
      subtle: {
        digest: async () => new Uint8Array(32).buffer,
        importKey: async () => ({}),
        deriveKey: async () => ({}),
        encrypt: async (_options, _key, plaintext) => {
          encryptedPlaintext = new TextDecoder().decode(plaintext);
          return new Uint8Array(80).fill(1).buffer;
        },
      },
    },
    fetch: async (url, options) => {
      requests.push({ url, options, body: JSON.parse(options.body) });
      const payload = responses.shift();
      return { ok: true, status: 200, json: async () => payload };
    },
    atob: (value) => Buffer.from(value, "base64").toString("binary"),
    btoa: (value) => Buffer.from(value, "binary").toString("base64"),
  };

  vm.runInNewContext(fs.readFileSync(`${__dirname}/app.js`, "utf8"), context);
  await click();

  assert.equal(requests[2].body.action, "approve");
  assert.equal(requests[3].body.action, "confirm");
  assert.deepEqual(JSON.parse(encryptedPlaintext), {
    access_token: "tv-access",
    refresh_token: "tv-refresh",
    token_type: "bearer",
    expires_at: null,
  });
  assert.equal(message.className, "success");
});
