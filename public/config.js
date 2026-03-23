// This file contains the configuration for the frontend application.

// llm_models: A list of available LLM models.
export const llm_models = {
    // --- TOP TIER REASONING & LOGIC ---
    "@cf/qwen/qwq-32b": {
        name: "Qwen QwQ (32B) - High Reasoning",
        provider: "Cloudflare"
    },
    "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b": {
        name: "DeepSeek R1 (32B) - High Reasoning",
        provider: "Cloudflare"
    },
    "@cf/meta/llama-3.3-70b-instruct-fp8-fast": {
        name: "Meta Llama 3.3 (70B) - Deep Analysis",
        provider: "Cloudflare"
    },

    // --- FAST & HIGHLY CAPABLE ---
    "@cf/mistralai/mistral-small-3.1-24b-instruct": {
        name: "Mistral Small 3.1 (24B) - Fast",
        provider: "Cloudflare"
    },
    "@cf/meta/llama-3.1-8b-instruct-fast": {
        name: "Meta Llama 3.1 (8B) - Fast",
        provider: "Cloudflare"
    }
};

// llm_settings: Global LLM settings
const llm_settings = {
    default_llm_model_analysis: "@cf/meta/llama-3.1-8b-instruct-fast",
    default_llm_model_comparison: "@cf/meta/llama-3.1-8b-instruct-fast",
};

// llm_prompts: Prompt templates and JSON schemas for LLM interactions.
const llm_prompts = {
    analysis_pcap_explanation_template: `
    You are an expert SIP and RTP packet analyst. Your task is to analyze a raw PCAP file snippet and provide a detailed report.
    The user will provide a snippet of raw PCAP data.
    Your response must be a JSON object that adheres to the provided schema.
    ---
    PCAP Snippet ({file_name}):
    {pcap_data_snippet}
    `,
    analysis_pcap_explanation_schema: {
        type: "object",
        properties: {
            summary: { type: "string" },
            protocol_distribution: { type: "object", patternProperties: { ".*": { "type": "number" } } },
            anomalies_and_errors: { type: "array", items: { type: "string" } },
            sip_rtp_info: { type: "string" },
            important_timestamps_packets: { type: "string" }
        },
        required: ["summary", "protocol_distribution", "anomalies_and_errors", "sip_rtp_info", "important_timestamps_packets"]
    },

    comparison_pcap_explanation_template: `
    You are an expert SIP and RTP packet analyst. Your task is to compare two raw PCAP file snippets.
    The user will provide two snippets of raw PCAP data, labeled {label1} and {label2}.
    Your response must be a JSON object that adheres to the provided schema.
    ---
    PCAP 1 Snippet ({label1}):
    {pcap_data_snippet1}
    ---
    PCAP 2 Snippet ({label2}):
    {pcap_data_snippet2}
    `,
    comparison_pcap_explanation_schema: {
        type: "object",
        properties: {
            overall_comparison_summary: { type: "string" },
            key_differences: { type: "array", items: { type: "string" } },
            key_similarities: { type: "array", items: { type: "string" } },
            security_implications: { type: "array", items: { type: "string" } },
            important_timestamps_packets: { type: "string" }
        },
        required: ["overall_comparison_summary", "key_differences", "key_similarities", "security_implications", "important_timestamps_packets"]
    },
};

// Make the configuration available globally for the frontend
if (typeof window !== 'undefined') {
    window.pcapAnalyzerConfig = { llm_models, llm_settings, llm_prompts };
}