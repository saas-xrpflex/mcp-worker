// Copyright 2026 Hall Boys, Inc.
// SPDX-License-Identifier: Apache-2.0

import type { IKeyValueStore } from "./kv-store";

/**
 * Multi-tenant config resolution (session 2.4, see MCP.md §Multi-tenant).
 *
 * The worker does NOT talk to Supabase directly — it calls a Next.js
 * internal API route (`/api/internal/connector/{slug}`) protected by a
 * shared service token. Decryption of the stored client_secret happens
 * server-side in Next.js only; this module never sees the encrypted form.
 *
 * Cached in KV for up to 5 minutes (product decision) to avoid a Next.js
 * round-trip on every tool call.
 */

export interface TenantConfig {
  url: string;
  tenant: string;
  endpointVersion: string;
  clientId: string;
  clientSecret: string;
}

const CACHE_TTL_SECONDS = 300; // 5 minutes max

export class TenantConfigError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = "TenantConfigError";
  }
}

export async function resolveTenantConfig(
  tenantSlug: string,
  store: IKeyValueStore,
  internalApiUrl: string,
  internalServiceToken: string,
): Promise<TenantConfig> {
  const cacheKey = `tenant_config:${tenantSlug}`;
  const cached = await store.get(cacheKey);
  if (cached) {
    return JSON.parse(cached) as TenantConfig;
  }

  let res: Response;
  try {
    res = await fetch(
      `${internalApiUrl.replace(/\/+$/, "")}/api/internal/connector/${encodeURIComponent(tenantSlug)}`,
      { headers: { Authorization: `Bearer ${internalServiceToken}` } },
    );
  } catch (e) {
    throw new TenantConfigError(
      `Impossible de joindre l'API interne pour résoudre le tenant '${tenantSlug}': ${
        e instanceof Error ? e.message : String(e)
      }`,
    );
  }

  if (!res.ok) {
    throw new TenantConfigError(
      `Config introuvable pour le tenant '${tenantSlug}' (HTTP ${res.status}). ` +
        `Vérifiez que le connecteur XRP Flex est configuré dans /settings pour ce tenant.`,
      res.status,
    );
  }

  const config = (await res.json()) as TenantConfig;
  await store.put(cacheKey, JSON.stringify(config), { expirationTtl: CACHE_TTL_SECONDS });
  return config;
}
