// Pure, framework-free helpers for PCAP analysis.
//
// These are deliberately kept out of the Durable Object class so they can be
// unit-tested without spinning up the Workers runtime. Everything here is a
// pure function of its inputs.
import { llm_prompts } from './config';

export type AnalysisType = 'analysis' | 'comparison';

/** Aggregated statistics produced by the browser-side PCAP parser. */
export interface PcapSummary {
    format: string;
    packetCount: number;
    totalBytes: number;
    durationSeconds: number | null;
    protocolDistribution: Record<string, number>;
    sipRtp: { sipPackets: number; rtpPackets: number; rtpStreams: number };
    truncated: boolean;
}

/**
 * Normalise the many shapes a Workers AI response can take into a plain string.
 *
 * Handles: raw strings, `{ response }`, `{ result }`, `{ result.response }`,
 * OpenAI chat completions (`{ choices[].message.content }`), the gpt-oss
 * "harmony"/Responses format (`{ output: [{ content: [{ text }] }] }`), and
 * `{ output_text }`. Falls back to JSON-stringifying the whole object.
 */
export function extractResponseText(response: unknown): string {
    if (response == null) return '';
    if (typeof response === 'string') return response;

    const r = response as Record<string, any>;

    if (typeof r.response === 'string') return r.response;
    if (typeof r.result === 'string') return r.result;
    if (r.result && typeof r.result.response === 'string') return r.result.response;

    // OpenAI chat-completions shape.
    const choice = r.choices?.[0];
    if (choice?.message?.content != null) {
        const content = choice.message.content;
        return typeof content === 'string' ? content : String(content);
    }

    // gpt-oss / Responses API "harmony" shape: output[] of items, each with a
    // content[] array. Skip the separate "reasoning" channel.
    if (Array.isArray(r.output)) {
        const text = r.output
            .filter((item: any) => item?.type !== 'reasoning')
            .flatMap((item: any) => (Array.isArray(item?.content) ? item.content : []))
            .map((part: any) => (typeof part === 'string' ? part : part?.text ?? ''))
            .join('');
        if (text) return text;
    }

    if (typeof r.output_text === 'string') return r.output_text;

    return JSON.stringify(response);
}

/**
 * Strip a reasoning model's `<think>…</think>` block, returning only the final
 * answer. Throws if a `<think>` block was opened but never closed (the model
 * exhausted its token budget before producing the answer).
 */
export function stripThinkBlock(text: string): string {
    if (text.includes('</think>')) {
        return (text.split('</think>').pop() ?? '').trim();
    }
    if (text.includes('<think>')) {
        throw new Error(
            "The model ran out of token budget while 'thinking' and never produced a report. " +
            'Try a faster model such as Llama 4 Scout or GLM-4.7 Flash.'
        );
    }
    return text;
}

/**
 * Extract and parse the first top-level JSON object found in a string. Throws a
 * descriptive error if none is found or if the parsed object is empty.
 */
export function extractJsonObject(text: string): Record<string, unknown> {
    const match = text.match(/\{[\s\S]*\}/);
    if (!match) {
        throw new Error(
            'No JSON object could be extracted. The AI returned: ' + text.slice(0, 100) + '...'
        );
    }
    const result = JSON.parse(match[0]);
    if (!result || typeof result !== 'object' || Object.keys(result).length === 0) {
        throw new Error(
            'The AI model returned an empty report. Please try analyzing the file again or use a different model.'
        );
    }
    return result as Record<string, unknown>;
}

/** Turn a raw Workers AI response into the parsed report object, end to end. */
export function parseModelResponse(response: unknown): Record<string, unknown> {
    const raw = extractResponseText(response);
    if (!raw) throw new Error('AI returned an empty response');
    return extractJsonObject(stripThinkBlock(raw));
}

/** Render a PcapSummary as a compact, human-readable block for the prompt. */
export function summarizeStats(summary: PcapSummary): string {
    const lines: string[] = [];
    lines.push(`Capture format: ${summary.format}`);
    lines.push(
        `Packets analysed: ${summary.packetCount.toLocaleString('en-GB')}` +
        (summary.truncated ? ' (capture was large; analysis capped)' : '')
    );
    if (summary.durationSeconds != null) {
        lines.push(`Capture duration: ${summary.durationSeconds} s`);
    }
    lines.push(`Total captured bytes: ${summary.totalBytes.toLocaleString('en-GB')}`);

    const protocols = Object.entries(summary.protocolDistribution)
        .sort((a, b) => b[1] - a[1])
        .map(([name, pct]) => `${name} ${pct}%`)
        .join(', ');
    lines.push(`Protocol distribution (by packet count): ${protocols || 'none detected'}`);

    const { sipPackets, rtpPackets, rtpStreams } = summary.sipRtp;
    if (sipPackets > 0 || rtpPackets > 0) {
        lines.push(
            `VoIP signals: ${sipPackets} SIP message(s); ${rtpPackets} RTP packet(s) ` +
            `across ${rtpStreams} stream(s)`
        );
    } else {
        lines.push('VoIP signals: no SIP or RTP traffic detected');
    }
    return lines.join('\n');
}

export interface AnalysisPromptData {
    fileName: string;
    summary: PcapSummary;
}

export interface ComparisonPromptData {
    label1: string;
    label2: string;
    summary1: PcapSummary;
    summary2: PcapSummary;
}

const SCHEMA_INSTRUCTION =
    '\n\nIMPORTANT: You must fully populate the JSON schema below with your ' +
    'analysis. DO NOT return an empty object. Return ONLY the raw JSON object ' +
    'and no other text:\n';

export function formatPrompt(type: 'analysis', data: AnalysisPromptData): string;
export function formatPrompt(type: 'comparison', data: ComparisonPromptData): string;
export function formatPrompt(
    type: AnalysisType,
    data: AnalysisPromptData | ComparisonPromptData
): string {
    if (type === 'analysis') {
        const d = data as AnalysisPromptData;
        const schema = JSON.stringify(llm_prompts.analysis_pcap_explanation_schema, null, 2);
        const body = llm_prompts.analysis_pcap_explanation_template
            .replaceAll('{file_name}', d.fileName)
            .replaceAll('{stats}', summarizeStats(d.summary));
        return body + SCHEMA_INSTRUCTION + schema;
    }

    const d = data as ComparisonPromptData;
    const schema = JSON.stringify(llm_prompts.comparison_pcap_explanation_schema, null, 2);
    const body = llm_prompts.comparison_pcap_explanation_template
        .replaceAll('{label1}', d.label1)
        .replaceAll('{label2}', d.label2)
        .replaceAll('{stats1}', summarizeStats(d.summary1))
        .replaceAll('{stats2}', summarizeStats(d.summary2));
    return body + SCHEMA_INSTRUCTION + schema;
}
