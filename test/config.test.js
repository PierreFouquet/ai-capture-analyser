// @vitest-environment jsdom
import { describe, it, expect, beforeAll } from 'vitest';

let config;

beforeAll(async () => {
    // config.js publishes itself onto window as a side effect.
    await import('../public/config.js');
    config = window.pcapAnalyzerConfig;
});

describe('frontend model config', () => {
    it('exposes models and settings (but not the server-only prompts)', () => {
        expect(config).toBeTruthy();
        expect(config.llm_models).toBeTruthy();
        expect(config.llm_settings).toBeTruthy();
        expect(config.llm_prompts).toBeUndefined();
    });

    it('only lists Cloudflare-hosted (@cf/) models', () => {
        for (const key of Object.keys(config.llm_models)) {
            expect(key.startsWith('@cf/')).toBe(true);
        }
    });

    it('records the true provider and Cloudflare as the host', () => {
        for (const model of Object.values(config.llm_models)) {
            expect(model.provider).toBeTruthy();
            expect(model.provider).not.toBe('Cloudflare');
            expect(model.host).toContain('Cloudflare');
        }
    });

    it('defaults to a model that exists in the list', () => {
        const { default_llm_model_analysis, default_llm_model_comparison } = config.llm_settings;
        expect(config.llm_models[default_llm_model_analysis]).toBeTruthy();
        expect(config.llm_models[default_llm_model_comparison]).toBeTruthy();
    });
});
