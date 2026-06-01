// This file contains the configuration for the frontend application.

// llm_models: A list of available LLM models (latest generation on Cloudflare Workers AI).
// Keep this in sync with src/config.ts.
export const llm_models = {
    // --- FRONTIER (highest quality, slower & pricier) ---
    // `provider` is the model's true creator; Cloudflare Workers AI is only the host.
    "@cf/moonshotai/kimi-k2.6": {
        name: "Moonshot Kimi K2.6 (1T) - Frontier Reasoning",
        provider: "Moonshot AI",
        host: "Cloudflare Workers AI"
    },
    "@cf/nvidia/nemotron-3-120b-a12b": {
        name: "NVIDIA Nemotron 3 Super (120B) - Agentic",
        provider: "NVIDIA",
        host: "Cloudflare Workers AI"
    },
    "@cf/openai/gpt-oss-120b": {
        name: "OpenAI gpt-oss (120B) - High Reasoning",
        provider: "OpenAI",
        host: "Cloudflare Workers AI"
    },
    "@cf/google/gemma-4-26b-a4b-it": {
        name: "Google Gemma 4 (26B MoE) - Vision + Reasoning",
        provider: "Google",
        host: "Cloudflare Workers AI"
    },

    // --- FAST & EFFICIENT ---
    "@cf/meta/llama-4-scout-17b-16e-instruct": {
        name: "Meta Llama 4 Scout (17B MoE) - Multimodal",
        provider: "Meta",
        host: "Cloudflare Workers AI"
    },
    "@cf/openai/gpt-oss-20b": {
        name: "OpenAI gpt-oss (20B) - Fast Reasoning",
        provider: "OpenAI",
        host: "Cloudflare Workers AI"
    },
    "@cf/zai-org/glm-4.7-flash": {
        name: "Zhipu GLM-4.7 Flash - Fast Multilingual",
        provider: "Zhipu AI (Z.ai)",
        host: "Cloudflare Workers AI"
    },
    "@cf/qwen/qwen3-30b-a3b-fp8": {
        name: "Qwen3 (30B MoE) - Reasoning",
        provider: "Alibaba (Qwen)",
        host: "Cloudflare Workers AI"
    }
};

// llm_settings: which model is pre-selected in each dropdown.
const llm_settings = {
    default_llm_model_analysis: "@cf/google/gemma-4-26b-a4b-it",
    default_llm_model_comparison: "@cf/google/gemma-4-26b-a4b-it",
};

// The prompt templates and JSON schemas are used only on the server and live in
// src/config.ts — they are intentionally not duplicated here.

// Make the configuration available globally for the frontend
if (typeof window !== 'undefined') {
    window.pcapAnalyzerConfig = { llm_models, llm_settings };
}