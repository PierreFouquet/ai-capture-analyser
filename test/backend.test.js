import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Backend } from '../public/backend.js';

describe('Backend.generateSessionId', () => {
    it('produces a unique, well-formed id', () => {
        const backend = new Backend();
        expect(backend.sessionId).toMatch(/^session-\d+-[a-z0-9]+$/);
    });
});

describe('Backend payload construction', () => {
    it('analyzePcap forwards a well-formed analysis payload', async () => {
        const backend = new Backend();
        const spy = vi.spyOn(backend, 'submitAndPoll').mockResolvedValue('result');
        const summary = { packetCount: 5 };

        await backend.analyzePcap(summary, 'a.pcap', '@cf/google/gemma-4-26b-a4b-it');

        expect(spy).toHaveBeenCalledWith(
            {
                type: 'analysis',
                pcap_summary: summary,
                file_name: 'a.pcap',
                llm_model_key: '@cf/google/gemma-4-26b-a4b-it',
            },
            'Analysis failed'
        );
    });

    it('comparePcaps forwards both summaries', async () => {
        const backend = new Backend();
        const spy = vi.spyOn(backend, 'submitAndPoll').mockResolvedValue('result');

        await backend.comparePcaps({ a: 1 }, 'one.pcap', { b: 2 }, 'two.pcap', 'm');

        expect(spy).toHaveBeenCalledWith(
            expect.objectContaining({
                type: 'comparison',
                pcap_summary1: { a: 1 },
                pcap_summary2: { b: 2 },
                file_name1: 'one.pcap',
                file_name2: 'two.pcap',
            }),
            'Comparison failed'
        );
    });
});

describe('Backend.pollStatus', () => {
    beforeEach(() => vi.useFakeTimers());
    afterEach(() => {
        vi.useRealTimers();
        vi.unstubAllGlobals();
    });

    it('resolves with the result once status is complete', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => ({
            ok: true,
            json: async () => ({ status: 'complete', result: { summary: 'done' } }),
        })));

        const backend = new Backend();
        const promise = backend.pollStatus('/api/analyze/status');
        await vi.advanceTimersByTimeAsync(1000);

        await expect(promise).resolves.toEqual({ summary: 'done' });
    });

    it('rejects when the status fetch itself fails', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network down'); }));
        const backend = new Backend();
        const promise = backend.pollStatus('/api/analyze/status');
        const assertion = expect(promise).rejects.toThrow('network down');
        await vi.advanceTimersByTimeAsync(1000);
        await assertion;
    });

    it('rejects with the server error when status is error', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => ({
            ok: true,
            json: async () => ({ status: 'error', error: 'boom' }),
        })));

        const backend = new Backend();
        const promise = backend.pollStatus('/api/analyze/status');
        const assertion = expect(promise).rejects.toThrow('boom');
        await vi.advanceTimersByTimeAsync(1000);
        await assertion;
    });

    it('rejects when a status response is not ok', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 503, json: async () => ({}) })));
        const backend = new Backend();
        const promise = backend.pollStatus('/api/analyze/status');
        const assertion = expect(promise).rejects.toThrow(/Status check failed: 503/);
        await vi.advanceTimersByTimeAsync(1000);
        await assertion;
    });

    it('gives up with a timeout when the job never finishes (abuse / stuck job)', async () => {
        // Always 'processing': without a cap this would poll forever.
        vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ status: 'processing' }) })));
        const backend = new Backend();
        const promise = backend.pollStatus('/api/analyze/status');
        const assertion = expect(promise).rejects.toThrow(/timed out/i);
        await vi.advanceTimersByTimeAsync(5 * 60 * 1000 + 1000);
        await assertion;
    });

    it('does not overlap requests when a status fetch is slower than the interval', async () => {
        let inFlight = 0;
        let maxConcurrent = 0;
        const fetchMock = vi.fn(() => new Promise((resolve) => {
            inFlight++;
            maxConcurrent = Math.max(maxConcurrent, inFlight);
            // Resolve after 3 poll intervals to simulate a slow status check.
            setTimeout(() => {
                inFlight--;
                resolve({ ok: true, json: async () => ({ status: 'processing' }) });
            }, 3000);
        }));
        vi.stubGlobal('fetch', fetchMock);

        const backend = new Backend();
        backend.pollStatus('/api/analyze/status').catch(() => {});
        await vi.advanceTimersByTimeAsync(10000); // 10 ticks, but each request takes 3s

        expect(maxConcurrent).toBe(1); // the in-flight guard prevents pile-ups
    });
});

describe('Backend.submitAndPoll (end to end)', () => {
    beforeEach(() => vi.useFakeTimers());
    afterEach(() => {
        vi.useRealTimers();
        vi.unstubAllGlobals();
    });

    it('submits then polls to a completed result', async () => {
        const fetchMock = vi.fn()
            .mockResolvedValueOnce({ ok: true, status: 202, json: async () => ({ status: 'processing' }) })
            .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'complete', result: { ok: 1 } }) });
        vi.stubGlobal('fetch', fetchMock);

        const backend = new Backend();
        const promise = backend.submitAndPoll({ type: 'analysis' }, 'Analysis failed');
        await vi.advanceTimersByTimeAsync(1000);

        await expect(promise).resolves.toEqual({ ok: 1 });
        // First call is the POST submit; its body carries the payload.
        expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ type: 'analysis' });
    });

    it('throws with the failure prefix when the submit is rejected by the server', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => ({
            ok: false,
            status: 500,
            json: async () => ({ error: 'server boom' }),
        })));

        const backend = new Backend();
        await expect(backend.submitAndPoll({}, 'Analysis failed')).rejects.toThrow(/Analysis failed: server boom/);
    });

    it('wraps a network failure during submit with the failure prefix', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network down'); }));
        const backend = new Backend();
        await expect(backend.submitAndPoll({}, 'Comparison failed')).rejects.toThrow(/Comparison failed: network down/);
    });
});

describe('Backend.debug', () => {
    afterEach(() => vi.unstubAllGlobals());

    it('returns the parsed debug payload on success', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ environment: { AI_AVAILABLE: true } }) })));
        const backend = new Backend();
        await expect(backend.debug()).resolves.toEqual({ environment: { AI_AVAILABLE: true } });
    });

    it('throws when the debug endpoint fails', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 500 })));
        const backend = new Backend();
        await expect(backend.debug()).rejects.toThrow(/Debug check failed: 500/);
    });
});
