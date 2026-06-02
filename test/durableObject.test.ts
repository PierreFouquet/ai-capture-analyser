import { describe, it, expect, vi } from 'vitest';
import { AnalysisObject } from '../src/index';
import { createFakeState, createFakeEnv, jsonRequest, tick } from './helpers/durableObject.js';

const VALID_REPORT = JSON.stringify({
    summary: 'All good',
    protocol_distribution: { TCP: 100 },
    anomalies_and_errors: [],
    sip_rtp_info: 'N/A',
    important_timestamps_packets: 'N/A',
});

const sampleSummary = {
    format: 'pcap',
    packetCount: 3,
    totalBytes: 100,
    durationSeconds: 1,
    protocolDistribution: { TCP: 100 },
    sipRtp: { sipPackets: 0, rtpPackets: 0, rtpStreams: 0 },
    truncated: false,
};

function statusOf(obj) {
    return obj.fetch(new Request('https://do/api/analyze/status')).then((r) => r.json());
}

describe('AnalysisObject lifecycle', () => {
    it('starts idle and reports debug info', async () => {
        const state = createFakeState();
        const env = createFakeEnv(vi.fn());
        const obj = new AnalysisObject(state, env);
        await tick();

        const status = await statusOf(obj);
        expect(status.status).toBe('idle');

        const debug = await obj.fetch(new Request('https://do/api/analyze/debug')).then((r) => r.json());
        expect(debug.environment.AI_AVAILABLE).toBe(true);
        expect(debug.environment.ASSETS_AVAILABLE).toBe(true);
    });

    it('restores persisted state in the constructor', async () => {
        const state = createFakeState({
            analysisState: { status: 'complete', result: { summary: 'restored' }, error: undefined },
        });
        const obj = new AnalysisObject(state, createFakeEnv(vi.fn()));
        await tick();

        const status = await statusOf(obj);
        expect(status.status).toBe('complete');
        expect(status.result.summary).toBe('restored');
    });

    it('runs an analysis to completion and persists the result', async () => {
        const aiRun = vi.fn().mockResolvedValue({ response: VALID_REPORT });
        const state = createFakeState();
        const obj = new AnalysisObject(state, createFakeEnv(aiRun));
        await tick();

        const res = await obj.fetch(
            jsonRequest('https://do/api/analyze', {
                type: 'analysis',
                file_name: 'a.pcap',
                pcap_summary: sampleSummary,
                llm_model_key: '@cf/google/gemma-4-26b-a4b-it',
            })
        );
        expect(res.status).toBe(202);
        expect((await res.json()).status).toBe('processing');

        await state._settleBackground();

        const status = await statusOf(obj);
        expect(status.status).toBe('complete');
        expect(status.result.summary).toBe('All good');
        // The model was given the chosen key and a messages payload.
        expect(aiRun).toHaveBeenCalledWith(
            '@cf/google/gemma-4-26b-a4b-it',
            expect.objectContaining({ messages: expect.any(Array) })
        );
        // State was persisted under the single STATE_KEY.
        expect(state._store.get('analysisState').status).toBe('complete');
    });

    it('runs a comparison to completion', async () => {
        const aiRun = vi.fn().mockResolvedValue({ response: VALID_REPORT });
        const state = createFakeState();
        const obj = new AnalysisObject(state, createFakeEnv(aiRun));
        await tick();

        await obj.fetch(
            jsonRequest('https://do/api/analyze', {
                type: 'comparison',
                file_name1: 'a.pcap',
                file_name2: 'b.pcap',
                pcap_summary1: sampleSummary,
                pcap_summary2: sampleSummary,
                llm_model_key: '@cf/openai/gpt-oss-120b',
            })
        );
        await state._settleBackground();

        expect((await statusOf(obj)).status).toBe('complete');
    });

    it('records an error when the model fails on every input format', async () => {
        const aiRun = vi.fn().mockRejectedValue(new Error('model exploded'));
        const state = createFakeState();
        const obj = new AnalysisObject(state, createFakeEnv(aiRun));
        await tick();

        await obj.fetch(
            jsonRequest('https://do/api/analyze', {
                type: 'analysis',
                file_name: 'a.pcap',
                pcap_summary: sampleSummary,
                llm_model_key: '@cf/x',
            })
        );
        await state._settleBackground();

        const status = await statusOf(obj);
        expect(status.status).toBe('error');
        expect(status.error).toMatch(/Analysis failed/);
        expect(aiRun).toHaveBeenCalledTimes(3); // messages -> prompt -> input fallbacks
    });

    it('errors on missing capture statistics', async () => {
        const state = createFakeState();
        const obj = new AnalysisObject(state, createFakeEnv(vi.fn()));
        await tick();

        await obj.fetch(
            jsonRequest('https://do/api/analyze', { type: 'analysis', file_name: 'a.pcap', llm_model_key: 'm' })
        );
        await state._settleBackground();

        expect((await statusOf(obj)).status).toBe('error');
    });

    it('errors on an invalid analysis type', async () => {
        const state = createFakeState();
        const obj = new AnalysisObject(state, createFakeEnv(vi.fn()));
        await tick();

        await obj.fetch(jsonRequest('https://do/api/analyze', { type: 'nonsense' }));
        await state._settleBackground();

        expect((await statusOf(obj)).status).toBe('error');
    });

    it('returns 404 for unknown paths', async () => {
        const state = createFakeState();
        const obj = new AnalysisObject(state, createFakeEnv(vi.fn()));
        const res = await obj.fetch(new Request('https://do/api/analyze/unknown'));
        expect(res.status).toBe(404);
    });

    it('returns 500 when the request body is not valid JSON', async () => {
        const state = createFakeState();
        const obj = new AnalysisObject(state, createFakeEnv(vi.fn()));
        await tick();

        const res = await obj.fetch(new Request('https://do/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: 'not json',
        }));
        expect(res.status).toBe(500);
        expect((await res.json()).status).toBe('error');
        // Regression: the error state must be persisted under the single STATE_KEY
        // so it survives a constructor rehydration (not scattered across keys).
        expect(state._store.get('analysisState')).toMatchObject({ status: 'error', result: null });
        expect(state._store.has('status')).toBe(false);
    });

    it('falls back from messages to the prompt format and still completes', async () => {
        const aiRun = vi
            .fn()
            .mockRejectedValueOnce(new Error('messages unsupported')) // messages format fails
            .mockResolvedValueOnce({ response: VALID_REPORT }); // prompt format succeeds
        const state = createFakeState();
        const obj = new AnalysisObject(state, createFakeEnv(aiRun));
        await tick();

        await obj.fetch(
            jsonRequest('https://do/api/analyze', {
                type: 'analysis',
                file_name: 'a.pcap',
                pcap_summary: sampleSummary,
                llm_model_key: '@cf/x',
            })
        );
        await state._settleBackground();

        expect((await statusOf(obj)).status).toBe('complete');
        expect(aiRun).toHaveBeenCalledTimes(2); // messages -> prompt
        // Second call used the prompt shape, not messages.
        expect(aiRun.mock.calls[1][1]).toHaveProperty('prompt');
    });

    it('errors when the AI resolves an empty response', async () => {
        const aiRun = vi.fn().mockResolvedValue(undefined);
        const state = createFakeState();
        const obj = new AnalysisObject(state, createFakeEnv(aiRun));
        await tick();

        await obj.fetch(
            jsonRequest('https://do/api/analyze', {
                type: 'analysis',
                file_name: 'a.pcap',
                pcap_summary: sampleSummary,
                llm_model_key: '@cf/x',
            })
        );
        await state._settleBackground();

        const status = await statusOf(obj);
        expect(status.status).toBe('error');
        expect(status.error).toMatch(/empty response/i);
    });

    it('reports AI as unavailable in debug when the binding is missing', async () => {
        const state = createFakeState();
        const env = createFakeEnv(vi.fn());
        delete (env as any).AI;
        const obj = new AnalysisObject(state, env);
        await tick();

        const debug = await obj.fetch(new Request('https://do/api/analyze/debug')).then((r) => r.json());
        expect(debug.environment.AI_AVAILABLE).toBe(false);
    });

    it('settles to a terminal state when two analyses are fired back-to-back', async () => {
        const aiRun = vi.fn().mockResolvedValue({ response: VALID_REPORT });
        const state = createFakeState();
        const obj = new AnalysisObject(state, createFakeEnv(aiRun));
        await tick();

        const body = {
            type: 'analysis',
            file_name: 'a.pcap',
            pcap_summary: sampleSummary,
            llm_model_key: '@cf/google/gemma-4-26b-a4b-it',
        };
        await Promise.all([
            obj.fetch(jsonRequest('https://do/api/analyze', body)),
            obj.fetch(jsonRequest('https://do/api/analyze', body)),
        ]);
        await state._settleBackground();

        // No stuck 'processing': the object reaches a consistent terminal state.
        expect((await statusOf(obj)).status).toBe('complete');
    });

    it('resets the 6-hour cleanup alarm on every request', async () => {
        const state = createFakeState();
        const obj = new AnalysisObject(state, createFakeEnv(vi.fn()));
        await obj.fetch(new Request('https://do/api/analyze/status'));
        expect(state._alarm).toBeGreaterThan(Date.now());
    });

    it('clears storage when the cleanup alarm fires', async () => {
        const state = createFakeState({ analysisState: { status: 'complete', result: {} } });
        const obj = new AnalysisObject(state, createFakeEnv(vi.fn()));
        await tick();

        await obj.alarm();
        expect(state._store.size).toBe(0);
        expect((await statusOf(obj)).status).toBe('idle');
    });
});
