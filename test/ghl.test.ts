import { describe, it, expect, vi } from 'vitest';
import { exchangeAuthCode, refreshAccessToken, mintLocationToken, getInstalledLocations, GhlHttpError } from '../src/ghl';

function mockFetch(status: number, body: unknown) {
  return vi.fn(async () =>
    new Response(typeof body === 'string' ? body : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    }),
  ) as unknown as typeof fetch;
}

describe('exchangeAuthCode', () => {
  it('POSTs form body to /oauth/token and returns parsed token', async () => {
    const f = mockFetch(200, { access_token: 'a', refresh_token: 'r', expires_in: 86399, token_type: 'Bearer', userType: 'Company', companyId: 'C1' });
    const tok = await exchangeAuthCode(f, { clientId: 'cid', clientSecret: 'sec', code: 'CODE', redirectUri: 'https://x/cb' });
    expect(tok.access_token).toBe('a');
    expect(tok.companyId).toBe('C1');
    const [url, init] = (f as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('https://services.leadconnectorhq.com/oauth/token');
    expect(init.method).toBe('POST');
    expect(init.headers['Content-Type']).toBe('application/x-www-form-urlencoded');
    const params = new URLSearchParams(init.body as string);
    expect(params.get('grant_type')).toBe('authorization_code');
    expect(params.get('client_id')).toBe('cid');
    expect(params.get('code')).toBe('CODE');
    expect(params.get('redirect_uri')).toBe('https://x/cb');
  });

  it('throws GhlHttpError on non-2xx', async () => {
    const f = mockFetch(401, { error: 'invalid_grant' });
    await expect(exchangeAuthCode(f, { clientId: 'c', clientSecret: 's', code: 'x', redirectUri: 'y' }))
      .rejects.toBeInstanceOf(GhlHttpError);
  });
});

describe('refreshAccessToken', () => {
  it('POSTs grant_type=refresh_token and returns the rotated token', async () => {
    const f = mockFetch(200, { access_token: 'a2', refresh_token: 'r2', expires_in: 86399, token_type: 'Bearer' });
    const tok = await refreshAccessToken(f, { clientId: 'c', clientSecret: 's', refreshToken: 'r1' });
    expect(tok.refresh_token).toBe('r2');
    const [, init] = (f as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    const params = new URLSearchParams(init.body as string);
    expect(params.get('grant_type')).toBe('refresh_token');
    expect(params.get('refresh_token')).toBe('r1');
  });
});

describe('mintLocationToken', () => {
  it('POSTs to /oauth/locationToken with Bearer + Version header + form body', async () => {
    const f = mockFetch(200, { access_token: 'loc', expires_in: 86400, token_type: 'Bearer', locationId: 'L1', companyId: 'C1' });
    const tok = await mintLocationToken(f, { agencyAccessToken: 'AG', companyId: 'C1', locationId: 'L1' });
    expect(tok.access_token).toBe('loc');
    const [url, init] = (f as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('https://services.leadconnectorhq.com/oauth/locationToken');
    expect(init.headers['Authorization']).toBe('Bearer AG');
    expect(init.headers['Version']).toBe('2021-07-28');
    const params = new URLSearchParams(init.body as string);
    expect(params.get('companyId')).toBe('C1');
    expect(params.get('locationId')).toBe('L1');
  });

  it('throws GhlHttpError carrying status + body on 4xx', async () => {
    const f = mockFetch(403, { message: 'not authorized for this location' });
    try {
      await mintLocationToken(f, { agencyAccessToken: 'AG', companyId: 'C1', locationId: 'Lx' });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(GhlHttpError);
      expect((e as GhlHttpError).status).toBe(403);
      expect(JSON.stringify((e as GhlHttpError).body)).toContain('not authorized');
    }
  });
});

describe('getInstalledLocations', () => {
  it('returns all locations from a single page (count <= limit)', async () => {
    const page = {
      locations: [
        { _id: 'L1', name: 'Clinic A', address: '1 Main St', isInstalled: true },
        { _id: 'L2', name: 'Clinic B', address: '2 Main St', isInstalled: true },
      ],
      count: 2,
      installToFutureLocations: false,
    };
    const f = vi.fn(async (_url: string) =>
      new Response(JSON.stringify(page), { status: 200, headers: { 'content-type': 'application/json' } }),
    ) as unknown as typeof fetch;
    const locs = await getInstalledLocations(f, { agencyAccessToken: 'AG', companyId: 'C1', appId: 'myapp' });
    expect(locs).toHaveLength(2);
    expect(locs[0]).toEqual({ id: 'L1', name: 'Clinic A', isInstalled: true });
    expect(locs[1]).toEqual({ id: 'L2', name: 'Clinic B', isInstalled: true });
    // Verify request shape: correct URL, headers, query params
    expect(f).toHaveBeenCalledTimes(1);
    const [url, init] = (f as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit];
    const parsed = new URL(url);
    expect(parsed.origin + parsed.pathname).toBe('https://services.leadconnectorhq.com/oauth/installedLocations');
    expect(parsed.searchParams.get('companyId')).toBe('C1');
    expect(parsed.searchParams.get('appId')).toBe('myapp');
    expect(parsed.searchParams.get('isInstalled')).toBe('true');
    expect(parsed.searchParams.get('skip')).toBe('0');
    const headers = init?.headers as Record<string, string>;
    expect(headers['Authorization']).toBe('Bearer AG');
    expect(headers['Version']).toBe('2021-07-28');
  });

  it('paginates via skip when count > limit', async () => {
    const page1 = {
      locations: [{ _id: 'L1', name: 'Clinic A', address: '', isInstalled: true }],
      count: 2,
      installToFutureLocations: false,
    };
    const page2 = {
      locations: [{ _id: 'L2', name: 'Clinic B', address: '', isInstalled: true }],
      count: 2,
      installToFutureLocations: false,
    };
    let call = 0;
    const f = vi.fn(async (_url: string) => {
      const body = call++ === 0 ? page1 : page2;
      return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;
    const locs = await getInstalledLocations(f, { agencyAccessToken: 'AG', companyId: 'C1', appId: 'myapp', limit: 1 });
    expect(locs).toHaveLength(2);
    expect(locs.map((l) => l.id)).toEqual(['L1', 'L2']);
    expect(f).toHaveBeenCalledTimes(2);
    // Second call should have skip=1
    const [url2] = (f as unknown as ReturnType<typeof vi.fn>).mock.calls[1] as [string, RequestInit];
    expect(new URL(url2).searchParams.get('skip')).toBe('1');
  });

  it('throws GhlHttpError on a non-2xx page', async () => {
    const f = vi.fn(async () =>
      new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401, headers: { 'content-type': 'application/json' } }),
    ) as unknown as typeof fetch;
    await expect(
      getInstalledLocations(f, { agencyAccessToken: 'BAD', companyId: 'C1', appId: 'myapp' }),
    ).rejects.toBeInstanceOf(GhlHttpError);
  });
});
