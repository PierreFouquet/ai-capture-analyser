import { describe, it, expect } from 'vitest';
import {
    extractResponseText,
    stripThinkBlock,
    extractJsonObject,
    parseModelResponse,
    summarizeStats,
    formatPrompt,
    type PcapSummary,
} from '../src/analysis';

const sampleSummary: PcapSummary = {
    format: 'pcap',
    packetCount: 1234,
    totalBytes: 567890,
    durationSeconds: 12.5,
    protocolDistribution: { TCP: 40, UDP: 35, SIP: 15, RTP: 10 },
    sipRtp: { sipPackets: 12, rtpPackets: 340, rtpStreams: 2 },
    truncated: false,
};

describe('extractResponseText', () => {
    it('returns a raw string unchanged', () => {
        expect(extractResponseText('hello')).toBe('hello');
    });

    it('reads the common { response } shape', () => {
        expect(extractResponseText({ response: 'hi' })).toBe('hi');
    });

    it('reads { result } and { result.response }', () => {
        expect(extractResponseText({ result: 'a' })).toBe('a');
        expect(extractResponseText({ result: { response: 'b' } })).toBe('b');
    });

    it('reads OpenAI chat completions', () => {
        const res = { choices: [{ message: { content: 'chat-text' } }] };
        expect(extractResponseText(res)).toBe('chat-text');
    });

    it('reads an already-parsed object under response (Llama 4 Scout shape)', () => {
        const res = { response: { summary: 'ok' }, tool_calls: [], usage: { total_tokens: 1 } };
        expect(extractResponseText(res)).toBe('{"summary":"ok"}');
    });

    it('reads an already-parsed object under result', () => {
        expect(extractResponseText({ result: { summary: 'ok' } })).toBe('{"summary":"ok"}');
    });

    it('reads the gpt-oss harmony output array and skips reasoning', () => {
        const res = {
            output: [
                { type: 'reasoning', content: [{ text: 'secret thoughts' }] },
                { type: 'message', content: [{ type: 'output_text', text: '{"a":1}' }] },
            ],
        };
        expect(extractResponseText(res)).toBe('{"a":1}');
    });

    it('falls back to JSON.stringify for unknown shapes', () => {
        expect(extractResponseText({ weird: true })).toBe('{"weird":true}');
    });

    it('treats null/undefined as empty', () => {
        expect(extractResponseText(null)).toBe('');
        expect(extractResponseText(undefined)).toBe('');
    });
});

describe('stripThinkBlock', () => {
    it('keeps only the text after a closed think block', () => {
        expect(stripThinkBlock('<think>reasoning</think> {"x":1}')).toBe('{"x":1}');
    });

    it('passes through text with no think block', () => {
        expect(stripThinkBlock('plain')).toBe('plain');
    });

    it('throws on an unterminated think block', () => {
        expect(() => stripThinkBlock('<think>still going')).toThrow(/token budget/i);
    });
});

describe('extractJsonObject', () => {
    it('extracts JSON embedded in surrounding prose', () => {
        expect(extractJsonObject('Here you go: {"summary":"ok"} thanks')).toEqual({ summary: 'ok' });
    });

    it('throws when there is no JSON object', () => {
        expect(() => extractJsonObject('no json here')).toThrow(/No JSON object/);
    });

    it('throws on an empty object', () => {
        expect(() => extractJsonObject('{}')).toThrow(/empty report/i);
    });
});

describe('parseModelResponse', () => {
    it('handles a harmony response with reasoning and JSON end-to-end', () => {
        const res = {
            output: [
                { type: 'reasoning', content: [{ text: 'thinking' }] },
                { type: 'message', content: [{ text: '<think>x</think>\n{"summary":"done"}' }] },
            ],
        };
        expect(parseModelResponse(res)).toEqual({ summary: 'done' });
    });

    it('throws on an empty response', () => {
        expect(() => parseModelResponse(null)).toThrow(/empty response/i);
    });

    it('parses the Llama 4 Scout wrapper (object response + tool_calls)', () => {
        const res = {
            response: { summary: 'done', protocol_distribution: { TCP: 100 } },
            tool_calls: [],
            usage: { total_tokens: 42 },
        };
        expect(parseModelResponse(res)).toEqual({ summary: 'done', protocol_distribution: { TCP: 100 } });
    });
});

describe('summarizeStats', () => {
    it('includes packet count, sorted protocols and VoIP signals', () => {
        const text = summarizeStats(sampleSummary);
        expect(text).toContain('1,234');
        expect(text).toContain('Capture duration: 12.5 s');
        // Highest-share protocol should be listed first.
        expect(text.indexOf('TCP 40%')).toBeLessThan(text.indexOf('RTP 10%'));
        expect(text).toContain('12 SIP message(s)');
    });

    it('notes when no VoIP traffic is present', () => {
        const text = summarizeStats({
            ...sampleSummary,
            sipRtp: { sipPackets: 0, rtpPackets: 0, rtpStreams: 0 },
        });
        expect(text).toContain('no SIP or RTP traffic detected');
    });

    it('flags truncated captures', () => {
        expect(summarizeStats({ ...sampleSummary, truncated: true })).toContain('capped');
    });
});

describe('formatPrompt', () => {
    it('builds an analysis prompt with the file name, stats and schema', () => {
        const prompt = formatPrompt('analysis', { fileName: 'capture.pcap', summary: sampleSummary });
        expect(prompt).toContain('capture.pcap');
        expect(prompt).toContain('Protocol distribution');
        expect(prompt).toContain('"summary"'); // schema field
        expect(prompt).not.toContain('{file_name}');
        expect(prompt).not.toContain('{stats}');
    });

    it('replaces every label placeholder in a comparison prompt', () => {
        const prompt = formatPrompt('comparison', {
            label1: 'before.pcap',
            label2: 'after.pcap',
            summary1: sampleSummary,
            summary2: sampleSummary,
        });
        expect(prompt).toContain('before.pcap');
        expect(prompt).toContain('after.pcap');
        // Regression: the old code used .replace() and left the 2nd {label1}.
        expect(prompt).not.toContain('{label1}');
        expect(prompt).not.toContain('{label2}');
        expect(prompt).not.toContain('{stats1}');
        expect(prompt).not.toContain('{stats2}');
    });
});
