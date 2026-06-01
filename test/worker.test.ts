import { describe, it, expect, vi } from 'vitest';
import worker from '../src/index';

function makeEnv() {
    const stub = { fetch: vi.fn(async () => new Response('do-response')) };
    const get = vi.fn(() => stub);
    const idFromName = vi.fn(() => 'object-id');
    const ASSETS = { fetch: vi.fn(async () => new Response('asset-response')) };
    const env = { ANALYSIS_OBJECT: { idFromName, get }, ASSETS, AI: {} };
    return { env, stub, get, idFromName, ASSETS };
}

describe('worker fetch routing', () => {
    it('routes /api/analyze to the Durable Object, pinned to weur', async () => {
        const { env, stub, get } = makeEnv();
        const res = await worker.fetch(new Request('https://app/api/analyze', { method: 'POST' }), env as any);

        expect(await res.text()).toBe('do-response');
        expect(get).toHaveBeenCalledWith('object-id', { locationHint: 'weur' });
        expect(stub.fetch).toHaveBeenCalledOnce();
    });

    it('derives the Durable Object id from the X-Session-ID header', async () => {
        const { env, idFromName } = makeEnv();
        await worker.fetch(
            new Request('https://app/api/analyze/status', { headers: { 'X-Session-ID': 'abc-123' } }),
            env as any
        );
        expect(idFromName).toHaveBeenCalledWith('abc-123');
    });

    it('falls back to "default" id when no session header is present', async () => {
        const { env, idFromName } = makeEnv();
        await worker.fetch(new Request('https://app/api/debug'), env as any);
        expect(idFromName).toHaveBeenCalledWith('default');
    });

    it('serves everything else from static assets', async () => {
        const { env, ASSETS, stub } = makeEnv();
        const res = await worker.fetch(new Request('https://app/index.html'), env as any);

        expect(await res.text()).toBe('asset-response');
        expect(ASSETS.fetch).toHaveBeenCalledOnce();
        expect(stub.fetch).not.toHaveBeenCalled();
    });
});
