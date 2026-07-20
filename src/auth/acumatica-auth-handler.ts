// Copyright 2026 Hall Boys, Inc.
// SPDX-License-Identifier: Apache-2.0

import { Hono } from "hono";
import type { Env } from "../types/acumatica";
import { docsApp } from "../docs/docs-handler";
import { logAuthEvent } from "../lib/logger";
import { encryptString, parseCookies } from "../lib/crypto";
import { interpretTokenError } from "../lib/preflight";
import { resolveTenantConfig, TenantConfigError, type TenantConfig } from "../lib/tenant-config";
import { CloudflareKVStore } from "../platform/cloudflare-kv-store";
import installScript from "../../install.sh";

// OAuth state cookie — binds the `state` parameter to the browser that
// started the flow, preventing login-CSRF / session-fixation on /callback.
// SameSite=Lax is required because Acumatica's redirect is a cross-origin
// top-level navigation; Strict would block the cookie.
const OAUTH_STATE_COOKIE = "acu_oauth_state";
const OAUTH_STATE_TTL_SECONDS = 600;

// Redirect URI bidon du client OAuth permanent "Orbit Web (internal token
// mint)" — jamais réellement visitée, requise uniquement pour la validation
// de l'AuthRequest synthétique (session 2.6, voir /internal/mint-mcp-token).
const MINT_REDIRECT_URI = "https://orbit-web.adilbekkaye.workers.dev/internal/oauth-noop-callback";

// KV TTL for per-user Acumatica tokens. Long enough that normal users
// don't have to re-auth mid-day, short enough to bound the blast radius
// of a stolen refresh token.
const USER_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days

type AuthEnv = Env & {
  COOKIE_ENCRYPTION_KEY: string;
  OAUTH_PROVIDER: {
    parseAuthRequest(request: Request): Promise<OAuthReqInfo>;
    completeAuthorization(opts: {
      request: OAuthReqInfo;
      userId: string;
      metadata: { label: string };
      scope: string[];
      props: Record<string, unknown>;
    }): Promise<{ redirectTo: string }>;
  };
};

interface OAuthReqInfo {
  clientId: string;
  redirectUri: string;
  scope: string[];
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  [key: string]: unknown;
}

/** Data stored in KV while waiting for consent acknowledgment */
interface PendingConsent {
  oauthReqInfo: OAuthReqInfo;
  tenantSlug: string;
  acumaticaUsername: string;
  acumaticaDisplayName: string;
  acumaticaTokens: {
    access_token: string;
    refresh_token: string;
    expires_in: number;
  };
}

/**
 * Session 2.4 (multi-tenant) — determine which tenant this OAuth flow is
 * for. Two sources, in order of preference:
 *
 *   1. The RFC 8707 `resource` parameter on the auth request, which MCP
 *      clients set to the exact resource URL they're connecting to
 *      (`https://.../mcp/{slug}`) — this is the "real" mechanism and
 *      matches the /mcp/{tenant_slug} routing decision (MCP.md §Multi-tenant).
 *      ⚠️ UNVERIFIED: whether @cloudflare/workers-oauth-provider's
 *      parseAuthRequest() reliably populates `resource`, and whether
 *      Claude.ai/Claude Desktop actually send it, has not been tested live
 *      (wrangler is broken on the dev machine that wrote this — see
 *      apps/mcp/CLAUDE.md session notes). Verify before relying on this
 *      path in production; the query-param fallback below exists so the
 *      flow still works if it doesn't.
 *   2. A `?tenant=` query param on /authorize, for direct testing or as a
 *      client-side fallback.
 */
function extractTenantSlug(
  oauthReqInfo: { resource?: unknown },
  requestUrl: string
): string | null {
  const resource = oauthReqInfo.resource;
  if (typeof resource === "string") {
    try {
      const match = new URL(resource).pathname.match(/\/mcp\/([^/]+)/);
      if (match) return decodeURIComponent(match[1]);
    } catch {
      // resource wasn't a valid absolute URL — fall through
    }
  }
  const queryTenant = new URL(requestUrl).searchParams.get("tenant");
  return queryTenant || null;
}

/**
 * Persist a user's Acumatica token: encrypt the refresh token, write the
 * KV backup, and seed the authoritative TokenManager DO. Shared by /consent
 * (fresh browser login, session 2.4/2.5) and /internal/store-token
 * (session-driven OAuth initiated from apps/web — session 2.6).
 */
async function storeUserToken(
  env: AuthEnv,
  tenantSlug: string,
  acumaticaUsername: string,
  token: { access_token: string; refresh_token: string; expires_at: number }
): Promise<void> {
  const tokenIdentity = `${tenantSlug}:${acumaticaUsername}`;
  const userTokenKey = `user_token:${tokenIdentity}`;
  const encryptedRefresh = await encryptString(token.refresh_token, env.COOKIE_ENCRYPTION_KEY);
  const storedToken = {
    access_token: token.access_token,
    refresh_token: encryptedRefresh,
    expires_at: token.expires_at,
  };

  await env.TOKEN_STORE.put(userTokenKey, JSON.stringify(storedToken), {
    expirationTtl: USER_TOKEN_TTL_SECONDS,
  });

  try {
    const tmId = env.TOKEN_MANAGER.idFromName(tokenIdentity);
    await env.TOKEN_MANAGER.get(tmId).setToken(storedToken);
  } catch (e) {
    // Non-fatal: the DO will adopt the token from KV on its first read.
    console.warn("TokenManager seed failed (will adopt from KV):", e instanceof Error ? e.message : e);
  }
}

const app = new Hono<{ Bindings: AuthEnv }>();

// ──────────────────────────────────────────────────────────────
// Step 1: /authorize — Claude initiates the MCP OAuth flow.
// Stash the MCP request, redirect straight to Acumatica login.
// ──────────────────────────────────────────────────────────────
app.get("/authorize", async (c) => {
  // parseAuthRequest() fetches the CIMD client-metadata document server-side
  // when the client_id is a URL (Claude.ai/Claude Code use CIMD). If that
  // fetch fails — the client's metadata endpoint is down (503) or the
  // client_id is malformed/unfetchable — parseAuthRequest throws. Without
  // this guard the throw surfaces as an opaque HTTP 500; catch it and return
  // a diagnosable error instead. A fetch/network failure is an upstream
  // problem (502); anything else is a bad request (400).
  let oauthReqInfo;
  try {
    oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const clientId = c.req.query("client_id") ?? "(none)";
    console.log(
      `authorize_parse_failed client_id=${clientId} error=${msg}`
    );
    const looksLikeFetch = /fetch|network|timeout|502|503|504|upstream|unhealthy/i.test(
      msg
    );
    return c.text(
      looksLikeFetch
        ? `Could not fetch the OAuth client's metadata document (client_id=${clientId}). ` +
            `This is usually a temporary outage of the client's metadata endpoint, not this server. ` +
            `Details: ${msg}`
        : `Invalid OAuth request: ${msg}`,
      looksLikeFetch ? 502 : 400
    );
  }
  if (!oauthReqInfo) {
    return c.text("Invalid OAuth request", 400);
  }

  // Session 2.4 (multi-tenant): resolve which tenant's XRP Flex config to
  // use for this login. See extractTenantSlug() for the resolution order.
  const tenantSlug = extractTenantSlug(oauthReqInfo, c.req.url);
  if (!tenantSlug) {
    return c.text(
      "Missing tenant. This server requires a tenant to be specified — connect via " +
        "the /mcp/{tenant_slug} URL for your organization, or add ?tenant=<slug> for testing.",
      400
    );
  }

  let tenantConfig: TenantConfig;
  try {
    tenantConfig = await resolveTenantConfig(
      tenantSlug,
      new CloudflareKVStore(c.env.TOKEN_STORE),
      c.env.INTERNAL_API_URL,
      c.env.INTERNAL_SERVICE_TOKEN
    );
  } catch (err) {
    const msg = err instanceof TenantConfigError ? err.message : String(err);
    console.error(`Tenant config resolution failed for '${tenantSlug}': ${msg}`);
    return c.text(`Configuration error for tenant '${tenantSlug}': ${msg}`, 502);
  }

  const state = crypto.randomUUID();

  // Store the resolved tenant config alongside the OAuth request so
  // /callback (token exchange, user lookup, access check) uses the exact
  // same config without a second resolution call — the KV cache in
  // resolveTenantConfig() would likely return the same thing anyway, but
  // this avoids any window where the tenant's config could change between
  // /authorize and /callback (which happen seconds apart in the same flow).
  await c.env.TOKEN_STORE.put(
    `acumatica_state:${state}`,
    JSON.stringify({ oauthReqInfo, tenantSlug, tenantConfig }),
    { expirationTtl: OAUTH_STATE_TTL_SECONDS }
  );

  const origin = new URL(c.req.url).origin;
  const acumaticaAuthorizeUrl = new URL(
    `${tenantConfig.url}/identity/connect/authorize`
  );
  acumaticaAuthorizeUrl.searchParams.set("response_type", "code");
  acumaticaAuthorizeUrl.searchParams.set("client_id", tenantConfig.clientId);
  acumaticaAuthorizeUrl.searchParams.set(
    "redirect_uri",
    `${origin}/callback`
  );
  // `offline_access` is REQUIRED for Acumatica/IdentityServer to issue a
  // refresh token. Without it the token response has no refresh_token, the
  // stored token can never be refreshed, and every session dies the moment
  // its ~1h access token expires. Scopes are requested here, not configured
  // on the Connected App in SM303010 (which has no scope field).
  acumaticaAuthorizeUrl.searchParams.set("scope", "api openid profile email offline_access");
  acumaticaAuthorizeUrl.searchParams.set("state", state);

  // Bind the state to this browser via an HttpOnly cookie. /callback
  // will require cookie.state === query.state before exchanging the code.
  c.header(
    "Set-Cookie",
    `${OAUTH_STATE_COOKIE}=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${OAUTH_STATE_TTL_SECONDS}`
  );

  return c.redirect(acumaticaAuthorizeUrl.toString());
});

// ──────────────────────────────────────────────────────────────
// Step 2: /callback — Acumatica redirects here after login.
// Exchange code for tokens, look up the user, check access,
// then redirect to consent page.
// ──────────────────────────────────────────────────────────────
app.get("/callback", async (c) => {
  const code = c.req.query("code");
  const state = c.req.query("state");
  const error = c.req.query("error");

  if (error) {
    return c.text(
      `Acumatica error: ${error} — ${c.req.query("error_description") || ""}`,
      400
    );
  }

  if (!code || !state) {
    return c.text("Missing code or state in callback", 400);
  }

  // Verify the state cookie set at /authorize — this is what protects
  // /callback from login-CSRF. Without the cookie, an attacker who
  // captures a valid (code, state) pair cannot complete the flow in a
  // victim's browser because the cookie was never set there.
  const cookies = parseCookies(c.req.header("cookie"));
  const cookieState = cookies[OAUTH_STATE_COOKIE];
  if (!cookieState || cookieState !== state) {
    logAuthEvent("callback_state_mismatch", "unknown", {
      hasCookie: Boolean(cookieState),
    });
    // Burn the KV state record so a subsequent replay with the same
    // `state` query parameter cannot succeed even if the attacker later
    // manages to plant the matching cookie. State records are
    // single-use by design; mismatch is abandonment.
    await c.env.TOKEN_STORE.delete(`acumatica_state:${state}`).catch(() => {});
    return c.text(
      "OAuth state mismatch. Please close this tab and try connecting again.",
      400
    );
  }

  // Retrieve the original MCP OAuth request + the tenant config resolved
  // at /authorize time (session 2.4 — see the comment there for why the
  // config travels with the state record instead of being re-resolved here).
  const stored = await c.env.TOKEN_STORE.get(`acumatica_state:${state}`);
  if (!stored) {
    return c.text("Invalid or expired state. Please try connecting again.", 400);
  }
  const { oauthReqInfo, tenantSlug, tenantConfig } = JSON.parse(stored) as {
    oauthReqInfo: OAuthReqInfo;
    tenantSlug: string;
    tenantConfig: TenantConfig;
  };
  await c.env.TOKEN_STORE.delete(`acumatica_state:${state}`);

  // Clear the state cookie — it has served its purpose.
  c.header(
    "Set-Cookie",
    `${OAUTH_STATE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
  );

  // Exchange Acumatica code for tokens
  const origin = new URL(c.req.url).origin;
  const tokenResponse = await fetch(
    `${tenantConfig.url}/identity/connect/token`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: tenantConfig.clientId,
        client_secret: tenantConfig.clientSecret,
        redirect_uri: `${origin}/callback`,
      }),
    }
  );

  if (!tokenResponse.ok) {
    // Do NOT log or echo the full response body — some IdentityServer
    // error responses contain the submitted form (client_secret, code).
    // Safe to extract only the OAuth `error` code from the JSON body
    // and render a targeted page keyed on it; interpretTokenError maps
    // the known codes to admin-facing remediation text.
    let errorCode: string | undefined;
    try {
      const body = (await tokenResponse.json()) as { error?: string };
      errorCode = body.error;
    } catch {
      // Body wasn't JSON — leave errorCode undefined
    }
    console.error(
      `Acumatica token exchange failed: HTTP ${tokenResponse.status}${errorCode ? ` (${errorCode})` : ""}`
    );
    logAuthEvent("login_denied", "unknown", {
      reason: "token_exchange_failed",
      status: tokenResponse.status,
      errorCode,
    });
    const info = interpretTokenError(tokenResponse.status, errorCode);
    return c.html(renderTokenExchangeErrorPage(info), 502);
  }

  const acumaticaTokens = (await tokenResponse.json()) as {
    access_token: string;
    refresh_token: string;
    expires_in: number;
  };

  // Fetch current Acumatica user identity
  let acumaticaUsername = "unknown";
  let acumaticaDisplayName = "Unknown User";

  // Try multiple endpoints to identify the user:
  // 1. OIDC userinfo (standard, most reliable)
  // 2. auth contract UserSecurityInfo (may not exist on all instances)
  // 3. Fall back to UUID-based key
  try {
    // Attempt 1: OIDC userinfo endpoint
    const oidcUrl = `${tenantConfig.url}/identity/connect/userinfo`;
    console.log(`User info: trying OIDC ${oidcUrl}`);
    const oidcResp = await fetch(oidcUrl, {
      headers: {
        Authorization: `Bearer ${acumaticaTokens.access_token}`,
        Accept: "application/json",
      },
    });
    if (oidcResp.ok) {
      const oidcInfo = (await oidcResp.json()) as {
        sub?: string;
        name?: string;
        preferred_username?: string;
        email?: string;
      };
      // Don't echo `sub`, `name`, or `email` to logs — these are IdP
      // identity attributes that don't need long-term retention and end
      // up in Logpush / R2. The chosen username already appears in the
      // downstream `auth_event` log for the successful login.
      acumaticaUsername = oidcInfo.preferred_username || oidcInfo.sub || "unknown";
      acumaticaDisplayName = oidcInfo.name || acumaticaUsername;
      console.log(`User info (OIDC): resolved username`);
    } else {
      console.log(`User info (OIDC): HTTP ${oidcResp.status}, trying auth contract...`);
      // Attempt 2: auth contract
      const authUrl = `${tenantConfig.url}/entity/auth/${tenantConfig.endpointVersion}/UserSecurityInfo`;
      const authResp = await fetch(authUrl, {
        headers: {
          Authorization: `Bearer ${acumaticaTokens.access_token}`,
          Accept: "application/json",
        },
      });
      if (authResp.ok) {
        const userInfo = (await authResp.json()) as {
          Username?: { value: string };
          DisplayName?: { value: string };
        };
        acumaticaUsername = userInfo.Username?.value || "unknown";
        acumaticaDisplayName =
          userInfo.DisplayName?.value || acumaticaUsername;
        console.log(`User info (auth): resolved username`);
      } else {
        // Body omitted — may contain auth error payloads from Acumatica.
        console.error(`User info (auth): HTTP ${authResp.status}`);
      }
    }
  } catch (e) {
    console.error("Failed to fetch Acumatica user info:", e);
    // Use the full state UUID rather than an 8-char slice. 8 hex chars is
    // only 32 bits of entropy — on a busy instance, two simultaneous failed
    // lookups could collide and cause users to share a token key.
    acumaticaUsername = `user_${state}`;
  }

  // ── Access gate: verify the user may use MCP ────────────────
  // We never query role membership — SaaS blocks the User/Role tables over
  // the API. Instead we check whether the user's token can read a canary
  // Generic Inquiry over OData. Restrict who can read that GI in Acumatica
  // however you like; a marker role is the recommended way.
  // Canary GI name stays a global default across tenants for now (every
  // tenant is instructed in MCP.md to name theirs "MCPAccess") — not part
  // of tenant_connectors.config_json. Revisit if a tenant ever needs a
  // different name.
  const canaryGi = c.env.ACUMATICA_CANARY_GI || "MCPAccess";
  const accessResult = await checkAccess(
    tenantConfig.url,
    tenantConfig.tenant,
    acumaticaTokens.access_token,
    acumaticaUsername,
    canaryGi
  );

  if (accessResult.kind === "denied") {
    logAuthEvent("login_denied", acumaticaUsername, {
      reason: "access_denied",
    });
    return c.html(renderAccessDeniedPage(acumaticaDisplayName), 403);
  }

  if (accessResult.kind === "misconfigured") {
    logAuthEvent("login_denied", acumaticaUsername, {
      reason: "access_check_misconfigured",
      status: accessResult.status,
      detail: accessResult.reason,
    });
    return c.html(renderAccessCheckErrorPage(accessResult.reason), 503);
  }

  // ── Store pending consent in KV and redirect ────────────────
  const consentId = crypto.randomUUID();
  const pendingConsent: PendingConsent = {
    oauthReqInfo,
    tenantSlug,
    acumaticaUsername,
    acumaticaDisplayName,
    acumaticaTokens,
  };

  await c.env.TOKEN_STORE.put(
    `consent:${consentId}`,
    JSON.stringify(pendingConsent),
    { expirationTtl: 300 } // 5 minutes
  );

  return c.redirect(`/consent?id=${consentId}`);
});

// ──────────────────────────────────────────────────────────────
// Step 3: /consent — Show consent interstitial before completing
// the MCP OAuth flow.
// ──────────────────────────────────────────────────────────────
app.get("/consent", async (c) => {
  const consentId = c.req.query("id");
  if (!consentId) {
    return c.text("Missing consent ID", 400);
  }

  const stored = await c.env.TOKEN_STORE.get(`consent:${consentId}`);
  if (!stored) {
    return c.text("Consent request expired. Please try connecting again.", 400);
  }

  const pending: PendingConsent = JSON.parse(stored);
  return c.html(renderConsentPage(consentId, pending.acumaticaDisplayName));
});

app.post("/consent", async (c) => {
  const body = await c.req.parseBody();
  const consentId = body["consent_id"] as string;

  if (!consentId) {
    return c.text("Missing consent ID", 400);
  }

  const stored = await c.env.TOKEN_STORE.get(`consent:${consentId}`);
  if (!stored) {
    return c.text("Consent request expired. Please try connecting again.", 400);
  }

  const pending: PendingConsent = JSON.parse(stored);
  await c.env.TOKEN_STORE.delete(`consent:${consentId}`);

  // Store the per-user token in KV, keyed by tenant + username (session
  // 2.4 — a bare username key would let two tenants' users collide if they
  // happened to share an Acumatica username on different instances). The
  // refresh_token is encrypted at rest with COOKIE_ENCRYPTION_KEY
  // (AES-256-GCM) — access_token lives in plaintext because it's
  // short-lived and worthless after expiry. The record also carries a TTL
  // so a leaked refresh token can't be used forever after the user stops
  // logging in.
  // Seed the per-(tenant,user) TokenManager DO directly so its authoritative
  // copy is fresh immediately — otherwise the DO might read a stale
  // (expired) KV record in the eventual-consistency window right after
  // re-auth and try to refresh a dead token. (The DO also adopts from KV on
  // cold read, but seeding removes the race entirely.)
  await storeUserToken(c.env, pending.tenantSlug, pending.acumaticaUsername, {
    access_token: pending.acumaticaTokens.access_token,
    refresh_token: pending.acumaticaTokens.refresh_token,
    expires_at: Date.now() + pending.acumaticaTokens.expires_in * 1000,
  });

  logAuthEvent("consent_accepted", pending.acumaticaUsername);

  // Complete the MCP OAuth flow
  const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
    request: pending.oauthReqInfo,
    userId: pending.acumaticaUsername,
    metadata: { label: pending.acumaticaDisplayName },
    scope: pending.oauthReqInfo.scope,
    props: {
      acumaticaUsername: pending.acumaticaUsername,
      acumaticaDisplayName: pending.acumaticaDisplayName,
      tenantSlug: pending.tenantSlug,
    },
  });

  logAuthEvent("login_success", pending.acumaticaUsername);

  return c.redirect(redirectTo);
});

// ──────────────────────────────────────────────────────────────
// POST /internal/store-token — service-to-service token write, appelé par
// apps/web après avoir mené lui-même l'échange OAuth Authorization Code
// avec Acumatica (session 2.6 — flow OAuth utilisateur dans le chat).
// Sens inverse de resolveTenantConfig() qui appelle apps/web depuis ici ;
// même mécanisme d'auth (INTERNAL_SERVICE_TOKEN), dans l'autre sens.
// Réutilise exactement la persistance de /consent via storeUserToken().
// ──────────────────────────────────────────────────────────────
app.post("/internal/store-token", async (c) => {
  const authHeader = c.req.header("authorization");
  const expected = `Bearer ${c.env.INTERNAL_SERVICE_TOKEN}`;
  if (!c.env.INTERNAL_SERVICE_TOKEN || authHeader !== expected) {
    return c.json({ error: "Non autorisé" }, 401);
  }

  let body: {
    tenantSlug?: string;
    acumaticaUsername?: string;
    storedToken?: { access_token?: string; refresh_token?: string; expires_at?: number };
  };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Corps de requête JSON invalide" }, 400);
  }

  const { tenantSlug, acumaticaUsername, storedToken } = body;
  if (
    !tenantSlug ||
    !acumaticaUsername ||
    !storedToken ||
    typeof storedToken.access_token !== "string" ||
    typeof storedToken.refresh_token !== "string" ||
    typeof storedToken.expires_at !== "number"
  ) {
    return c.json(
      {
        error:
          "Champs requis : tenantSlug, acumaticaUsername, storedToken.{access_token,refresh_token,expires_at}",
      },
      400
    );
  }

  await storeUserToken(c.env, tenantSlug, acumaticaUsername, {
    access_token: storedToken.access_token,
    refresh_token: storedToken.refresh_token,
    expires_at: storedToken.expires_at,
  });

  logAuthEvent("token_stored_via_internal_api", acumaticaUsername, { tenantSlug });

  return c.json({ ok: true });
});

// ──────────────────────────────────────────────────────────────
// POST /internal/mint-mcp-token — mint synthétique d'un token MCP pour un
// utilisateur déjà authentifié via l'OAuth Acumatica mené par apps/web
// (session 2.6). Reproduit exactement ce que /consent ferait pour un vrai
// client MCP (Claude.ai), sauf qu'ici c'est le client OAuth permanent
// "Orbit Web" (INTERNAL_MCP_CLIENT_ID/SECRET) qui joue ce rôle, et que
// l'échange authorization_code → access_token se fait en mémoire (voir
// plus bas) plutôt que via un vrai aller-retour réseau — évite l'erreur
// Cloudflare 1042 rencontrée avec un fetch() public vers *.workers.dev.
// ──────────────────────────────────────────────────────────────
app.post("/internal/mint-mcp-token", async (c) => {
  const authHeader = c.req.header("authorization");
  const expected = `Bearer ${c.env.INTERNAL_SERVICE_TOKEN}`;
  if (!c.env.INTERNAL_SERVICE_TOKEN || authHeader !== expected) {
    return c.json({ error: "Non autorisé" }, 401);
  }

  let body: {
    tenantSlug?: string;
    acumaticaUsername?: string;
    acumaticaDisplayName?: string;
  };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Corps de requête JSON invalide" }, 400);
  }

  const { tenantSlug, acumaticaUsername, acumaticaDisplayName } = body;
  if (!tenantSlug || !acumaticaUsername) {
    return c.json({ error: "Champs requis : tenantSlug, acumaticaUsername" }, 400);
  }

  if (!c.env.INTERNAL_MCP_CLIENT_ID || !c.env.INTERNAL_MCP_CLIENT_SECRET) {
    return c.json(
      { error: "Client OAuth interne non configuré (INTERNAL_MCP_CLIENT_ID/SECRET)" },
      500
    );
  }

  // 1. AuthRequest synthétique — même scope que oauthProviderOptions.scopesSupported.
  const authRequest = {
    responseType: "code",
    clientId: c.env.INTERNAL_MCP_CLIENT_ID,
    redirectUri: MINT_REDIRECT_URI,
    scope: ["api"],
    state: crypto.randomUUID(), // requis par le type, jamais relu ensuite
  };

  // 2. Crée le grant + code d'autorisation — mêmes props que /consent poserait
  // sur une vraie session MCP (this.props côté AcumaticaMcpServer).
  let redirectTo: string;
  try {
    const result = await c.env.OAUTH_PROVIDER.completeAuthorization({
      request: authRequest,
      userId: acumaticaUsername,
      metadata: { label: acumaticaDisplayName ?? acumaticaUsername },
      scope: ["api"],
      props: { acumaticaUsername, acumaticaDisplayName, tenantSlug },
    });
    redirectTo = result.redirectTo;
  } catch (err) {
    console.error(
      "mint-mcp-token: completeAuthorization failed:",
      err instanceof Error ? err.message : err
    );
    return c.json({ error: "Échec de la création du grant MCP" }, 502);
  }

  // 3. Extrait le code — l'URL n'est jamais réellement suivie.
  const code = new URL(redirectTo).searchParams.get("code");
  if (!code) {
    return c.json({ error: "Code d'autorisation manquant dans la réponse" }, 502);
  }

  // 4. Échange le code contre le vrai access_token — appel EN MÉMOIRE (pas
  // réseau) sur ce même Worker. Import différé pour casser le cycle
  // d'import avec index.ts (qui importe AcumaticaAuthHandler depuis ce
  // fichier) : une résolution au niveau module échouerait / renverrait
  // undefined tant qu'index.ts n'a pas fini de s'évaluer.
  const { default: mcpWorker } = await import("../index");

  const tokenRequest = new Request("https://internal/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: c.env.INTERNAL_MCP_CLIENT_ID,
      client_secret: c.env.INTERNAL_MCP_CLIENT_SECRET,
      redirect_uri: MINT_REDIRECT_URI,
    }),
  });

  // Cast : Hono type c.executionCtx contre une définition ExecutionContext
  // légèrement différente de celle attendue par @cloudflare/workers-oauth-provider
  // (désaccord de version entre les deux packages sur ce type ambiant) — le
  // même objet réel est fourni par le runtime Cloudflare dans les deux cas.
  const tokenResponse = await mcpWorker.fetch(
    tokenRequest,
    c.env,
    c.executionCtx as unknown as Parameters<typeof mcpWorker.fetch>[2]
  );
  const tokenData = await tokenResponse.json();

  if (!tokenResponse.ok) {
    console.error(
      "mint-mcp-token: /token exchange failed:",
      tokenResponse.status,
      JSON.stringify(tokenData)
    );
    return c.json(
      { error: "Échec de l'échange du code contre un token MCP", detail: tokenData },
      502
    );
  }

  logAuthEvent("token_minted_via_internal_api", acumaticaUsername, { tenantSlug });

  // 5. Réponse /token retournée telle quelle (access_token, token_type,
  // expires_in, scope, refresh_token le cas échéant).
  return c.json(tokenData, 200);
});

// OpenID Connect discovery — some MCP clients (e.g. ChatGPT) also check this
// endpoint. 302 to the OAuth authorization server metadata so CIMD support
// is advertised consistently without re-entering the worker over HTTP
// (the previous implementation did a same-origin fetch back to
// /.well-known/oauth-authorization-server, which burned an extra round trip
// and a subrequest on every discovery probe).
app.get("/.well-known/openid-configuration", (c) => {
  return c.redirect("/.well-known/oauth-authorization-server", 302);
});

// Health check. Open CORS so external uptime monitors / dashboards can
// poll cross-origin. OAuthProvider already adds CORS headers to the
// OAuth/MCP endpoints it handles (`/mcp`, `/token`, `/register`,
// `/.well-known/oauth-authorization-server`); the documentation site is
// HTML served same-origin and doesn't need them.
app.get("/health", (c) => {
  c.header("Access-Control-Allow-Origin", "*");
  c.header("Access-Control-Allow-Methods", "GET, OPTIONS");
  return c.json({ status: "ok", service: "mcp4acumatica" });
});
app.options("/health", (c) => {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Max-Age": "86400",
    },
  });
});

// One-line installer served at /install.sh. Meant to be piped into bash:
//   curl -fsSL https://<this-worker>/install.sh | bash
// The script clones the repo, installs deps, and runs setup.sh. Keeping
// the script at the same origin as the worker means users don't need to
// trust a separate hosting domain.
app.get("/install.sh", (c) => {
  c.header("Content-Type", "text/x-shellscript; charset=utf-8");
  c.header("Cache-Control", "public, max-age=300");
  return c.body(installScript);
});

// Documentation site
app.route("/docs", docsApp);
app.get("/", (c) => c.redirect("/docs"));

export { app as AcumaticaAuthHandler };

// ──────────────────────────────────────────────────────────────
// Access check — canary GI reachability over OData
// ──────────────────────────────────────────────────────────────

type AccessCheckResult =
  | { kind: "granted" }
  | { kind: "denied" }
  | { kind: "misconfigured"; reason: string; status?: number };

/**
 * Check whether the authenticated user may use MCP by querying a canary
 * Generic Inquiry via OData. The server never inspects role membership —
 * it only asks "can this user's token read the canary GI?". Restrict who
 * can read that GI in Acumatica however you like (a marker role is the
 * recommended way). Returns a discriminated result so the caller can
 * render a meaningful error:
 *
 *   - 200 → `granted` (user can read the canary GI)
 *   - 403 → `denied` (user cannot read it — no access)
 *   - 404 → `misconfigured` (canary GI is missing or not exposed via OData)
 *   - 5xx / network errors → `misconfigured` (Acumatica or tenant misconfig)
 *
 * Previously every non-200 was collapsed into "denied", which meant a
 * tenant typo or a missing GI looked identical to "no access" and admins
 * only found out via support tickets.
 */
async function checkAccess(
  acumaticaUrl: string,
  tenant: string,
  accessToken: string,
  username: string,
  giName: string
): Promise<AccessCheckResult> {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    Accept: "application/json",
  };

  const giUrl = `${acumaticaUrl}/t/${tenant}/api/odata/gi/${giName}?$top=1`;
  console.log(`Access check (canary GI): querying ${giUrl} for user ${username}`);

  let resp: Response;
  try {
    resp = await fetch(giUrl, { headers });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`Access check (canary GI): network failure: ${msg}`);
    return { kind: "misconfigured", reason: `Unable to reach Acumatica: ${msg}` };
  }

  console.log(`Access check (canary GI): HTTP ${resp.status}`);

  if (resp.ok) return { kind: "granted" };
  if (resp.status === 403) return { kind: "denied" };
  if (resp.status === 404) {
    return {
      kind: "misconfigured",
      status: 404,
      reason: `Canary Generic Inquiry '${giName}' is missing or not exposed via OData on tenant '${tenant}'. Create it (SM208000), expose it via OData, and restrict who can read it.`,
    };
  }
  // 401 here would mean the just-minted access token is already rejected —
  // treat as misconfig so the user gets a useful message rather than "denied".
  return {
    kind: "misconfigured",
    status: resp.status,
    reason: `Acumatica returned HTTP ${resp.status} during the access check. Verify ACUMATICA_TENANT, that the '${giName}' GI is exposed via OData, and that the instance is reachable.`,
  };
}

// ──────────────────────────────────────────────────────────────
// HTML templates
// ──────────────────────────────────────────────────────────────

function renderTokenExchangeErrorPage(info: {
  title: string;
  detail: string;
  remediation: string;
}): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Configuration Error — Acumatica MCP</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 640px; margin: 80px auto; padding: 0 20px; color: #333; }
    .card { background: #fff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 32px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    h1 { color: #b45309; font-size: 1.5rem; margin-top: 0; }
    .detail { margin-top: 16px; padding: 12px 16px; background: #fffbeb; border: 1px solid #fde68a; border-radius: 6px; font-size: 0.9rem; }
    .action { margin-top: 20px; padding: 16px; background: #f8f9fa; border-radius: 6px; }
    .action h3 { margin-top: 0; font-size: 0.9rem; text-transform: uppercase; color: #666; }
    .hint { margin-top: 16px; font-size: 0.85rem; color: #666; }
    code { background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }
  </style>
</head>
<body>
  <div class="card">
    <h1>${escapeHtml(info.title)}</h1>
    <p>The Acumatica MCP server could not complete the login because the Acumatica identity server rejected our request.</p>
    <div class="detail">${escapeHtml(info.detail)}</div>
    <div class="action">
      <h3>What to fix</h3>
      <p>${escapeHtml(info.remediation)}</p>
    </div>
    <p class="hint">Your Acumatica administrator can run the preflight check at <code>/docs/admin/preflight</code> to confirm every configured value before reconnecting.</p>
  </div>
</body>
</html>`;
}

function renderAccessCheckErrorPage(detail: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Configuration Error — Acumatica MCP</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 600px; margin: 80px auto; padding: 0 20px; color: #333; }
    .card { background: #fff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 32px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    h1 { color: #b45309; font-size: 1.5rem; margin-top: 0; }
    .detail { margin-top: 20px; padding: 16px; background: #fffbeb; border: 1px solid #fde68a; border-radius: 6px; font-family: "SF Mono", Menlo, monospace; font-size: 0.85rem; white-space: pre-wrap; }
    .action { margin-top: 24px; padding: 16px; background: #f8f9fa; border-radius: 6px; }
    .action h3 { margin-top: 0; font-size: 0.9rem; text-transform: uppercase; color: #666; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Configuration Error</h1>
    <p>The AI assistant cannot verify your access because Acumatica did not respond as expected.</p>
    <div class="detail">${escapeHtml(detail)}</div>
    <div class="action">
      <h3>What to do</h3>
      <p>This is a server-side configuration problem, not a permissions issue with your account. Ask your Acumatica administrator to check the MCP instance configuration — specifically the tenant name, the canary Generic Inquiry, and OData exposure.</p>
    </div>
  </div>
</body>
</html>`;
}

function renderAccessDeniedPage(displayName: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Access Denied — Acumatica MCP</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 600px; margin: 80px auto; padding: 0 20px; color: #333; }
    .card { background: #fff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 32px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    h1 { color: #c0392b; font-size: 1.5rem; margin-top: 0; }
    .action { margin-top: 24px; padding: 16px; background: #f8f9fa; border-radius: 6px; }
    .action h3 { margin-top: 0; font-size: 0.9rem; text-transform: uppercase; color: #666; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Access Denied</h1>
    <p>Hello, <strong>${escapeHtml(displayName)}</strong>. Your Acumatica account does not have access to this AI assistant.</p>
    <div class="action">
      <h3>What to do</h3>
      <p>Ask your Acumatica administrator to grant your user account access to the AI assistant, then try connecting again.</p>
    </div>
  </div>
</body>
</html>`;
}

function renderConsentPage(consentId: string, displayName: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Connect to AI Assistant — Acumatica MCP</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 600px; margin: 80px auto; padding: 0 20px; color: #333; background: #f5f5f5; }
    .card { background: #fff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 32px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    h1 { font-size: 1.5rem; margin-top: 0; }
    ul { padding-left: 20px; }
    li { margin-bottom: 8px; line-height: 1.5; }
    .warning-banner { background: #dc3545; color: #fff; border-radius: 8px; padding: 20px 24px; margin-bottom: 24px; display: flex; align-items: flex-start; gap: 16px; }
    .warning-icon { font-size: 2.5rem; line-height: 1; flex-shrink: 0; }
    .warning-banner h2 { margin: 0 0 4px 0; font-size: 1.1rem; }
    .warning-banner p { margin: 0; font-size: 0.95rem; opacity: 0.95; }
    .info-box { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px; padding: 16px 20px; margin: 20px 0; font-size: 0.9rem; }
    .info-box strong { display: block; margin-bottom: 4px; }
    button { background: #2563eb; color: #fff; border: none; padding: 12px 32px; border-radius: 6px; font-size: 1rem; cursor: pointer; margin-top: 16px; }
    button:hover { background: #1d4ed8; }
  </style>
</head>
<body>
  <div class="warning-banner">
    <span class="warning-icon">&#9888;</span>
    <div>
      <h2>AI Data Access Warning</h2>
      <p>You are connecting your Acumatica account to an AI assistant. ERP data will be shared with an external AI model. Do not proceed unless you understand the implications.</p>
    </div>
  </div>
  <div class="card">
    <h1>Hello, ${escapeHtml(displayName)}</h1>
    <p>By continuing, you acknowledge that:</p>
    <ul>
      <li>Acumatica data you access through the AI assistant will be <strong>sent to an external AI model</strong> for processing</li>
      <li>All data access is <strong>logged for audit purposes</strong></li>
      <li>Sensitive fields (SSN, bank accounts, salary, etc.) are <strong>automatically redacted</strong> before leaving the server</li>
      <li>AI responses may contain errors or misinterpretations — always <strong>verify critical information directly in Acumatica</strong></li>
    </ul>
    <div class="info-box">
      <strong>Do not rely on AI output for:</strong>
      Financial decisions, compliance reporting, audit evidence, or any action where accuracy is critical. The AI assistant is a convenience tool, not a source of truth.
    </div>
    <form method="POST" action="/consent">
      <input type="hidden" name="consent_id" value="${escapeHtml(consentId)}">
      <button type="submit">I Understand — Continue</button>
    </form>
  </div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
