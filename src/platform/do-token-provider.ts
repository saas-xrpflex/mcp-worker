// Copyright 2026 Hall Boys, Inc.
// SPDX-License-Identifier: Apache-2.0

import type { ITokenProvider, TokenResult } from "../lib/token-provider";
import type { AcumaticaTokenConfig } from "../auth/acumatica-oauth";
import type { TokenManager } from "../token-manager";

/**
 * Cloudflare ITokenProvider — forwards token resolution to the per-(tenant,
 * user) TokenManager Durable Object. Keying the DO by `{tenantSlug}:{username}`
 * (session 2.4, multi-tenant) means all of a user's concurrent sessions
 * WITHIN THE SAME TENANT share one token owner, so refreshes serialize
 * globally — and two different tenants can never collide even if they
 * happen to share a username on their respective Acumatica instances.
 */
export class DOTokenProvider implements ITokenProvider {
  constructor(
    private readonly namespace: DurableObjectNamespace<TokenManager>,
    private readonly tenantSlug: string,
  ) {}

  getAccessToken(username: string, config: AcumaticaTokenConfig): Promise<TokenResult> {
    const identity = `${this.tenantSlug}:${username}`;
    const id = this.namespace.idFromName(identity);
    const stub = this.namespace.get(id);
    return stub.getAccessToken(identity, config);
  }
}
