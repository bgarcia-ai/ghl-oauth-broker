/** GHL Marketplace OAuth calls — pure functions; pass `fetchFn` for testability. */

const TOKEN_URL = 'https://services.leadconnectorhq.com/oauth/token';
const LOCATION_TOKEN_URL = 'https://services.leadconnectorhq.com/oauth/locationToken';
const INSTALLED_LOCATIONS_URL = 'https://services.leadconnectorhq.com/oauth/installedLocations';
const GHL_VERSION = '2021-07-28';

export interface GhlTokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
  scope?: string;
  userType?: string;
  companyId?: string;
  locationId?: string;
  [k: string]: unknown;
}

export class GhlHttpError extends Error {
  constructor(public status: number, public body: unknown) {
    super(`GHL HTTP ${status}: ${typeof body === 'string' ? body : JSON.stringify(body)}`);
    this.name = 'GhlHttpError';
  }
}

async function postForm(
  fetchFn: typeof fetch,
  url: string,
  form: Record<string, string>,
  extraHeaders: Record<string, string> = {},
): Promise<GhlTokenResponse> {
  const res = await fetchFn(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
      ...extraHeaders,
    },
    body: new URLSearchParams(form).toString(),
  });
  const text = await res.text();
  let parsed: unknown;
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = text;
  }
  if (!res.ok) throw new GhlHttpError(res.status, parsed);
  const tok = parsed as GhlTokenResponse;
  if (!tok || typeof tok.access_token !== 'string') {
    throw new GhlHttpError(res.status, { error: 'missing access_token', body: parsed });
  }
  return tok;
}

export function exchangeAuthCode(
  fetchFn: typeof fetch,
  p: { clientId: string; clientSecret: string; code: string; redirectUri: string },
): Promise<GhlTokenResponse> {
  return postForm(fetchFn, TOKEN_URL, {
    client_id: p.clientId,
    client_secret: p.clientSecret,
    grant_type: 'authorization_code',
    code: p.code,
    redirect_uri: p.redirectUri,
  });
}

export function refreshAccessToken(
  fetchFn: typeof fetch,
  p: { clientId: string; clientSecret: string; refreshToken: string },
): Promise<GhlTokenResponse> {
  return postForm(fetchFn, TOKEN_URL, {
    client_id: p.clientId,
    client_secret: p.clientSecret,
    grant_type: 'refresh_token',
    refresh_token: p.refreshToken,
  });
}

export function mintLocationToken(
  fetchFn: typeof fetch,
  p: { agencyAccessToken: string; companyId: string; locationId: string },
): Promise<GhlTokenResponse> {
  return postForm(
    fetchFn,
    LOCATION_TOKEN_URL,
    { companyId: p.companyId, locationId: p.locationId },
    { Authorization: `Bearer ${p.agencyAccessToken}`, Version: GHL_VERSION },
  );
}

export interface InstalledLocation {
  id: string;
  name: string;
  isInstalled: boolean;
}

interface InstalledLocationsPage {
  locations: { _id: string; name: string; address?: string; isInstalled: boolean }[];
  count: number;
  installToFutureLocations?: boolean;
}

export async function getInstalledLocations(
  fetchFn: typeof fetch,
  p: {
    agencyAccessToken: string;
    companyId: string;
    appId: string;
    limit?: number;
    cap?: number;
  },
): Promise<InstalledLocation[]> {
  const limit = p.limit ?? 200;
  const cap = p.cap ?? 1000;
  const collected: InstalledLocation[] = [];
  let skip = 0;

  while (collected.length < cap) {
    const url = new URL(INSTALLED_LOCATIONS_URL);
    url.searchParams.set('companyId', p.companyId);
    url.searchParams.set('appId', p.appId);
    url.searchParams.set('limit', String(limit));
    url.searchParams.set('skip', String(skip));
    url.searchParams.set('isInstalled', 'true');

    const res = await fetchFn(url.toString(), {
      headers: {
        Authorization: `Bearer ${p.agencyAccessToken}`,
        Version: GHL_VERSION,
        Accept: 'application/json',
      },
    });

    const text = await res.text();
    let parsed: unknown;
    try { parsed = text ? JSON.parse(text) : {}; } catch { parsed = text; }
    if (!res.ok) throw new GhlHttpError(res.status, parsed);

    const page = parsed as InstalledLocationsPage;
    const locs = page.locations ?? [];
    for (const loc of locs) {
      collected.push({ id: loc._id, name: loc.name, isInstalled: loc.isInstalled });
    }

    // Stop when we have fetched all items or a page returns 0
    if (locs.length === 0 || collected.length >= page.count) break;
    skip += locs.length;
  }

  return collected;
}
