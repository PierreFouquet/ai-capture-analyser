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
    "@cf/meta/llama-3.3-70b-instruct-fp8-fast": {
        name: "Meta Llama 3.3 70B",
        provider: "Cloudflare"
    },
    "@cf/mistralai/mistral-small-3.1-24b-instruct": {
        name: "Mistral Small 3.1",
        provider: "Cloudflare"
    }
};

// llm_settings: Default model to use.
export const llm_settings = {
    default_llm_model_analysis: "DeepSeek R1 Distill Qwen 32B",
    default_llm_model_comparison: "DeepSeek R1 Distill Qwen 32B",
    async_mode_enabled: true
};

// VoIP port configuration
export const voip_ports = {
    sip_udp: [9997, 9998],
    sip_tcp: [9997, 9998],
    sip_tls: [9997, 9998],
    rtp_udp: [10000, 60000]
};

// llm_prompts: Prompts for the LLM models.
export const llm_prompts = {
    analysis_pcap_explanation: `You are a SIP and RTP packet analyst. Analyze the following packet capture data.
    Provide a detailed explanation covering:
    - Overall traffic summary and key protocols.
    - Identification of any anomalies, errors, or suspicious activities.
    - If SIP or RTP traffic is present, describe the call flow and identify potential issues.
    - Important timestamps or packet numbers if relevant.
    
    Respond strictly in JSON format according to the schema provided.
    ---
    PCAP Data Snippet:
    {pcap_data_snippet}`,
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
                description: "List of identified anomalies, errors, or suspicious activities."
            },
            sip_rtp_info: {
                type: "string",
                description: "Detailed information about SIP/RTP traffic if present, otherwise 'N/A'."
            },
            important_timestamps_packets: {
                type: "string",
                description: "Key timestamps or packet numbers relevant to the analysis, otherwise 'N/A'."
            }
        },
        required: ["summary", "anomalies_and_errors", "sip_rtp_info", "important_timestamps_packets"]
    },
    comparison_pcap_explanation: `You are a SIP and RTP packet analyst. Compare the following two packet capture data snippets.
    Provide a detailed explanation covering:
    - An overall summary of the comparison.
    - A list of key differences between the two captures.
    - A list of key similarities between the two captures.
    - An analysis of any security implications or risks identified.
    - Important timestamps or packet numbers if relevant to the comparison.

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