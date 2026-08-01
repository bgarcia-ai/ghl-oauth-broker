# ghl-oauth-broker

A tiny Cloudflare Worker that solves the annoying part of building on GoHighLevel: **keeping a Marketplace agency OAuth token alive forever, and handing out scoped, revocable, expiring access to it.**

It holds the agency-level OAuth token, refreshes it on a 12h cron (persisting each rotated refresh token), auto-discovers every sub-account the app is installed on, and mints sub-account ("location") access tokens on demand.

It does **not** proxy GHL API calls. It only does OAuth: the one-time agency authorization, the agency-token refresh loop, and location-token minting. Your scripts, agents, and CLIs ask the broker for a token and talk to GHL themselves.

## Why you'd want this

If you build automations across many GHL sub-accounts, you normally end up with a pile of Private Integration Tokens — one per location, pasted into scripts, impossible to rotate, all-or-nothing when you hand one to a teammate.

This replaces that with one authorization and a key registry:

- **One OAuth install.** Authorize once at the agency level; the broker keeps the token alive indefinitely (GHL refresh tokens rotate on every use — the broker persists them so the chain never breaks).
- **Tokens on demand.** `POST /location-token` with a `locationId` → a fresh, cached, ~24h location token.
- **Scoped keys per person or agent.** Issue a key limited to specific sub-accounts, with an expiry date and instant revocation — instead of sharing the master credential.
- **No secrets at rest in plaintext.** Issued keys are stored SHA-256 hashed; the plaintext is shown exactly once.

Pairs with [`ghl-cli`](https://github.com/Bleupreneur/ghl-cli) (`kind:'broker'` profiles), but the HTTP API is plain JSON — use it from anything.

## Endpoints

| Method · path | Auth | Purpose |
|---|---|---|
| `GET /` , `GET /health` | any valid key | status: agency token expiry, last refresh, `needsReauth`, cached-location count, `knownLocations` count |
| `GET /oauth/start` | — | 302 → GHL consent screen (`/v2/oauth/chooselocation`) — do this once, pick the agency |
| `GET /oauth/callback?code&state` | — (validates `state`) | exchanges the code, stores the agency token in KV; auto-discovers sub-accounts in the background |
| `POST /location-token` | any valid key | body `{ locationId }` → `{ access_token, token_type, expires_in, locationId, companyId, scope, policy }` |
| `GET /locations` | owner tier | list all known sub-accounts with `hasToken` + `tokenExpiresAt` for each |
| `POST /admin/warm-all` | owner tier | re-enumerate all installed sub-accounts and mint/cache a token for each → `{ enumerated, warmed, failed[] }` |
| `POST /admin/clear-location-cache` | owner tier | body `{ locationId? }` → drop one / all cached location tokens |
| `POST /admin/keys` | owner tier | issue a key: `{ id, label?, tier, locations, denied?, expiresAt? }` → `{ key, policy }` — plaintext `key` returned **once**, never stored |
| `GET /admin/keys` | owner tier | list all key policies (metadata only — never plaintext or hash) |
| `POST /admin/keys/revoke` | owner tier | body `{ id }` → `{ ok, revoked }` — instant |
| `POST /admin/keys/update` | owner tier | body `{ id, tier?, locations?, denied?, expiresAt?, label? }` → `{ ok, policy }` |

Error shapes on `/location-token`: `403 {error:"location_forbidden"}` when the key's allowlist excludes the location, `409 {error:"needs_reauth", reauthUrl}` when the agency token is dead, `502 {error:"ghl_error", status, detail, hint}` when GHL rejects the mint.

Cron `0 */12 * * *` refreshes the agency access token, then re-enumerates and re-warms all sub-account tokens.

## Access control

Two kinds of credential are accepted as `Authorization: Bearer …`:

- **`BROKER_KEY` secret** — the bootstrap **owner** credential. Compared timing-safe against the Worker secret, never stored in KV. Full power.
- **Issued keys** (`glk_<40 hex>`) — per-user / per-agent keys created via `POST /admin/keys`. Stored in KV SHA-256-hashed (`key:<hash>` → policy, plus a `keyid:<id>` → hash index so admin ops can address a key by id). Plaintext is shown exactly once at issue time.

Each issued key carries a `KeyPolicy`:

```ts
{
  id: string;                 // stable human id, e.g. "teammate"
  label: string;
  tier: 'owner' | 'team';     // team keys are refused on all owner-gated endpoints
  locations: '*' | string[];  // sub-account allowlist; '*' = all installed
  denied: DeniedClass[];      // capability classes the client refuses (owner => [])
  expiresAt: number | null;   // epoch seconds; null = never
  revoked: boolean;
  createdAt: number; updatedAt: number;
}
```

`DeniedClass` values: `'sub-accounts' | 'users' | 'saas-billing' | 'bulk-destructive'`. Issuing a `team` key with no explicit `denied` defaults to **all four** classes.

Revoked/expired keys get `401 {error:"key_revoked"}` / `401 {error:"key_expired"}`; a team key on an owner endpoint gets `403 {error:"owner_required"}`.

### What is enforced where — read this before trusting it

| Control | Enforced | Strength |
|---|---|---|
| Location allowlist | Broker, on `/location-token` | **Hard** — the token is never minted |
| Expiry (`expiresAt`) | Broker, on every request | **Hard** |
| Revocation | Broker, on every request | **Hard**, instant |
| Owner-only endpoints | Broker | **Hard** |
| `denied` capability classes | **Client side** | **Soft** — advisory |

The `denied` list is returned in the `policy` field of every token response, and the client (e.g. `ghl-cli`) refuses matching commands before making a request. A holder who bypasses the client and calls GHL directly with the minted token is **not** blocked by it. Treat `denied` as guardrails for trusted teammates, not as a security boundary against an adversary. The hard boundary is which locations a key can mint for, and for how long.

### Example: give a contractor 2 weeks on one sub-account

```bash
curl -sX POST "$BROKER_URL/admin/keys" \
  -H "Authorization: Bearer $BROKER_KEY" \
  -H 'content-type: application/json' \
  -d '{"id":"contractor","label":"Contractor — Clinic A","tier":"team",
       "locations":["<locationId>"],"expiresAt":1786000000}'
# => { "key": "glk_…", "policy": { … } }   <- the key is shown ONCE
```

Kill it early:

```bash
curl -sX POST "$BROKER_URL/admin/keys/revoke" \
  -H "Authorization: Bearer $BROKER_KEY" \
  -H 'content-type: application/json' -d '{"id":"contractor"}'
```

With [`ghl-cli`](https://github.com/Bleupreneur/ghl-cli) the same thing is:

```bash
ghl auth admin issue --name contractor --tier team \
  --locations <locationId> --expires 2026-08-15
ghl auth admin list
ghl auth admin revoke --id contractor
```

## Setup

Prerequisites: a **GoHighLevel agency account** with Marketplace developer access, a **Cloudflare account** (the free plan is enough), and Node 18+.

The order below matters — the GHL app needs a redirect URI you don't know until the Worker is deployed, so you create the app first, deploy second, then wire them together.

### Part A — create the GoHighLevel Marketplace app

1. Go to the developer portal at **https://marketplace.gohighlevel.com/** and sign in with your agency account → **My Apps** → create a new app.

2. **Distribution type: Agency.** This is what lets one authorization cover every sub-account. (A Sub-Account-only app can't mint location tokens and this broker won't work with it.)

3. **Scopes — get these right now, changing them later means re-authorizing.** Two are mandatory:

   | Scope | Why |
   |---|---|
   | `oauth.readonly` | enumerate installed sub-accounts (`/oauth/installedLocations`) |
   | `oauth.write` | mint location tokens (`/oauth/locationToken`) |

   Then add **every scope you want the minted location tokens to carry** — a location token inherits the app's scopes, so if you plan to read contacts you need `contacts.readonly` on the app itself. A typical automation set:

   ```
   oauth.readonly oauth.write contacts.readonly contacts.write
   conversations.readonly conversations.write conversations/message.readonly
   conversations/message.write opportunities.readonly opportunities.write
   calendars.readonly calendars.write calendars/events.readonly
   calendars/events.write locations.readonly workflows.readonly users.readonly
   ```

   Keep this exact space-separated string — it becomes the `GHL_OAUTH_SCOPES` secret in Part C, and it must match what the app is configured for.

4. Copy the **Client ID** and **Client Secret**. The Client ID looks like `65f1c2d4e8a9b0c3d1e2f3a4-x7k2m9p1` — **paste it whole**, including the suffix. The broker derives the app's `version_id` from the part before the dash (`src/worker.ts:169`), so trimming it breaks the consent URL.

5. Leave the Redirect URI for now — you'll add it in Part C.

### Part B — deploy the Worker

```bash
git clone https://github.com/Bleupreneur/ghl-oauth-broker.git
cd ghl-oauth-broker
npm install
npx wrangler login
```

Create the KV namespace and paste the returned id into `wrangler.toml` (replacing `<your-kv-namespace-id>`):

```bash
npx wrangler kv namespace create OAUTH
```

Also set `account_id` in `wrangler.toml`, or export it instead:

```bash
export CLOUDFLARE_ACCOUNT_ID=<your-cloudflare-account-id>   # Cloudflare dashboard → Workers & Pages → Account ID
```

Deploy. This prints your Worker URL — **note it, everything below uses it**:

```bash
npm run deploy
# → https://ghl-oauth-broker.<your-subdomain>.workers.dev
export BROKER_URL=https://ghl-oauth-broker.<your-subdomain>.workers.dev
```

Rename the worker by changing `name` in `wrangler.toml` before this step if you want a different hostname.

### Part C — wire them together

1. **Register the redirect URI.** Back in the Marketplace app, add exactly:

   ```
   https://ghl-oauth-broker.<your-subdomain>.workers.dev/oauth/callback
   ```

   It must match the `GHL_REDIRECT_URI` secret character for character — a trailing slash will break the token exchange.

2. **Set the secrets.** These apply immediately; no redeploy needed.

   ```bash
   npx wrangler secret put GHL_CLIENT_ID       # whole id, including the -suffix
   npx wrangler secret put GHL_CLIENT_SECRET
   npx wrangler secret put GHL_REDIRECT_URI    # $BROKER_URL/oauth/callback
   npx wrangler secret put GHL_OAUTH_SCOPES    # the space-separated string from Part A step 3
   npx wrangler secret put BROKER_KEY          # openssl rand -hex 32 — save this, it's your master key
   npx wrangler secret put ALERT_WEBHOOK_URL   # optional — Slack/Discord webhook for re-auth alerts
   ```

   For local dev with `npm run dev`, copy `.dev.vars.example` → `.dev.vars` and fill it in instead.

3. **Authorize once.** Open `$BROKER_URL/oauth/start` in a browser. On the GHL consent screen pick the **agency** (not an individual sub-account) so the app bulk-installs across sub-accounts, and tick "install on future sub-accounts" if offered so new clients are covered automatically. You should land on "✅ Broker authorized".

4. **Verify.**

   ```bash
   export BROKER_KEY=<the key from step 2>
   curl -s -H "Authorization: Bearer $BROKER_KEY" "$BROKER_URL/health"
   ```

   Expect `needsReauth:false`, `agencyTokenExpiresAt` in the future, and `knownLocations` matching your sub-account count (discovery runs in the background — give it a few seconds).

5. **Mint your first token.**

   ```bash
   curl -s -X POST "$BROKER_URL/location-token" \
     -H "Authorization: Bearer $BROKER_KEY" \
     -H 'content-type: application/json' \
     -d '{"locationId":"<a-locationId-from-/locations>"}'
   ```

   Use `curl -s -H "Authorization: Bearer $BROKER_KEY" "$BROKER_URL/locations"` to list them.

### Troubleshooting

| Symptom | Cause |
|---|---|
| Consent screen errors or won't load | `GHL_CLIENT_ID` was trimmed at the dash, or the app isn't Agency distribution |
| `invalid_grant` / callback fails | `GHL_REDIRECT_URI` doesn't exactly match the URI registered on the app |
| `502 ghl_error` on `/location-token` | app not approved/installed on that sub-account — re-install with future-locations, or approve it there |
| `409 needs_reauth` | agency refresh token is dead — re-open `/oauth/start` |
| Minted token 401s on a GHL endpoint | that scope wasn't on the app at authorize time — add it and re-authorize |
| `knownLocations: 0` | discovery needs `oauth.readonly`; check the app's scopes, then `POST /admin/warm-all` |

### `/health` response shape

```json
{
  "ok": true,
  "service": "ghl-oauth-broker",
  "agencyTokenExpiresAt": 1234567890,
  "lastRefreshAt": 1234567800,
  "needsReauth": false,
  "cachedLocations": 5,
  "knownLocations": 7
}
```

`knownLocations` is the count of sub-accounts in the stored location list. `cachedLocations` is the count of currently cached location tokens (KV `loc:` keys).

### Auto-discovery

After the one-time agency authorization the broker automatically:

1. Enumerates every sub-account where the app is installed (`GET /oauth/installedLocations`, paginated).
2. Stores the list under `locations:list` in KV (durable, no TTL).
3. Mints and caches a location token for each sub-account, in chunks of 6.

The 12h cron repeats this after each agency-token refresh. Use `GET /locations` to inspect state, or `POST /admin/warm-all` to trigger it manually.

## When the refresh token finally dies

GHL refresh tokens last roughly a year, and die immediately if the app is uninstalled or the token is revoked. When that happens `/health` reports `needsReauth:true`, `/location-token` returns `409`, and an alert fires if `ALERT_WEBHOOK_URL` is set. Re-open `/oauth/start` and authorize again — nothing else to do.

## Security notes

- Never commit `.dev.vars`. It is git-ignored; `.dev.vars.example` is the template.
- `BROKER_KEY` is the master credential — it can mint a token for **every** sub-account and issue new keys. Keep it out of shared scripts; hand out issued `glk_` keys instead.
- Location tokens are cached in KV with a ~23h TTL (just under GHL's ~24h lifetime). Anyone with read access to that KV namespace effectively has those tokens — treat the namespace as a secret store.
- The `denied` capability classes are client-enforced. See the enforcement table above.

## Dev

```bash
npm install
npm test         # vitest
npm run typecheck
npm run dev      # local worker
npm run deploy
```

## License

MIT
