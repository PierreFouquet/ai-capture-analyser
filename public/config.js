// This file contains the configuration for the application.

// llm_models: A list of available LLM models.
export const llm_models = {
    // Cloudflare Workers AI Models
    "@cf/openai/gpt-oss-120b": {
        name: "GPT OSS 120b",
        provider: "Cloudflare"
    },
    "@cf/openai/gpt-oss-20b": {
        name: "GPT OSS 20b",
        provider: "Cloudflare"
    },
    "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b": {
        name: "DeepSeek R1 Distill Qwen 32B",
        provider: "Cloudflare"
    },
    "@cf/deepseek-ai/deepseek-math-7b-instruct": {
        name: "DeepSeek Math Instruct 7B",
        provider: "Cloudflare"
    },
    "@cf/microsoft/phi-2": {
        name: "Microsoft Phi-2",
        provider: "Cloudflare"
    },
    "@hf/google/gemma-7b-it": {
        name: "Google Gemma 7b",
        provider: "Cloudflare"
    },
    "@cf/google/gemma-3-12b-it": {
        name: "Google Gemma 3 12b",
        provider: "Cloudflare"
    },
    "@cf/meta/llama-4-scout-17b-16e-instruct": {
        name: "Meta Llama 4 Scout",
        provider: "Cloudflare"
    },
    "@cf/mistral/mistral-7b-instruct-v0.2": {
        name: "Mistral 7b Instruct",
        provider: "Cloudflare"
    },
    "@cf/qwen/qwen-1.8b-chat": {
        name: "Qwen 1.8b Chat",
        provider: "Cloudflare"
    },
    "@cf/openchat/openchat-3.5-0106": {
        name: "OpenChat 3.5",
        provider: "Cloudflare"
    },
    "@cf/tiiuae/falcon-7b-instruct": {
        name: "Falcon 7b Instruct",
        provider: "Cloudflare"
    },
    "@cf/google/gemma-2-9b-it": {
        name: "Google Gemma 2 9b",
        provider: "Cloudflare"
    },
    "@cf/llama-4-scout-17b-16e-instruct": {
        name: "Llama 4 Scout",
        provider: "Cloudflare"
    },
};

// llm_settings: Global LLM settings
export const llm_settings = {
    default_llm_model_analysis: "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b",
    default_llm_model_comparison: "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b",
    // Note: async_mode_enabled is for the Python backend, not relevant for this JS/TS app
};

// llm_prompts: LLM prompts for analysis and comparison
export const llm_prompts = {
    // Prompt for single PCAP analysis
    analysis_pcap_explanation: `You are a network security analyst. Analyze the following packet capture data.
    Provide a detailed explanation covering:
    - Overall traffic summary and key protocols.
    - Identification of any anomalies, errors, or suspicious activities.
    - If SIP or RTP traffic is present, describe the call flow and identify potential issues.
    - Important timestamps or packet numbers if relevant.
    
    Respond strictly in JSON format according to the schema provided.
    
    ---
    PCAP Data Snippet:
    {pcap_data_snippet}
    `,
    analysis_pcap_explanation_schema: {
        type: "object",
        properties: {
            summary: {
                type: "string",
                description: "Overall traffic summary and key protocols identified."
            },
            anomalies_and_errors: {
                type: "array",
                items: {
                    type: "string"
                },
                description: "List of anomalies or errors detected."
            },
            sip_rtp_info: {
                type: "string",
                description: "Detailed information on SIP/RTP traffic if present, otherwise 'N/A'."
            },
            important_timestamps_packets: {
                type: "string",
                description: "Key timestamps or packet numbers relevant to the analysis, otherwise 'N/A'."
            }
        },
        required: ["summary", "anomalies_and_errors", "sip_rtp_info", "important_timestamps_packets"]
    },

    // Prompt for PCAP comparison
    comparison_pcap_explanation: `You are a network security analyst. Compare the following two packet capture data snippets.
    Provide a detailed comparison covering:
    - Overall summary of the comparison.
    - Key differences between the two captures.
    - Key similarities between the two captures.
    - Analysis of any security implications or risks identified.

    Respond strictly in JSON format according to the schema provided.

    ---
    PCAP 1 Snippet ({label1}):
    {pcap_data_snippet1}
    ---
    PCAP 2 Snippet ({label2}):
    {pcap_data_snippet2}`,
    comparison_pcap_explanation_schema: {
        type: "object",
        properties: {
            overall_comparison_summary: {
                type: "string",
                description: "Overall summary of the comparison."
            },
            key_differences: {
                type: "array",
                items: {
                    type: "string"
                },
                description: "List of key differences between the two captures."
            },
            key_similarities: {
                type: "array",
                items: {
                    type: "string"
                },
                description: "List of key similarities between the two captures."
            },
            security_implications: {
                type: "array",
                items: {
                    type: "string"
                },
                description: "Analysis of any security implications or risks identified."
            },
            important_timestamps_packets: {
                type: "string",
                description: "Key timestamps or packet numbers relevant to the comparison, otherwise 'N/A'."
            }
        },
        required: ["overall_comparison_summary", "key_differences", "key_similarities", "security_implications", "important_timestamps_packets"]
    },
};
