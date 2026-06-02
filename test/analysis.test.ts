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

    it('reads the { output_text } shape', () => {
        expect(extractResponseText({ output_text: 'plain answer' })).toBe('plain answer');
    });

    it('coerces non-string OpenAI message content', () => {
        const res = { choices: [{ message: { content: 42 } }] };
        expect(extractResponseText(res)).toBe('42');
    });

    it('joins harmony content parts given as plain strings', () => {
        const res = { output: [{ type: 'message', content: ['{"a":', '1}'] }] };
        expect(extractResponseText(res)).toBe('{"a":1}');
    });

    it('falls back past an empty harmony output to output_text', () => {
        const res = { output: [{ type: 'reasoning', content: [{ text: 'just thinking' }] }], output_text: 'final' };
        expect(extractResponseText(res)).toBe('final');
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

    it('returns empty when nothing follows the closed think block', () => {
        expect(stripThinkBlock('<think>done</think>')).toBe('');
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

    it('omits the duration line when duration is null', () => {
        expect(summarizeStats({ ...sampleSummary, durationSeconds: null })).not.toContain('Capture duration');
    });

    it('notes when no protocols were detected', () => {
        expect(summarizeStats({ ...sampleSummary, protocolDistribution: {} })).toContain('none detected');
    });

    it('renders the expanded fields when present', () => {
        const rich = {
            ...sampleSummary,
            packetSizeBytes: { min: 60, max: 1500, average: 540 },
            throughput: { packetsPerSecond: 120, bitsPerSecond: 980000 },
            ipVersions: { ipv4: 1200, ipv6: 34 },
            endpoints: { unique: 12, top: [{ name: '10.0.0.1', count: 800 }] },
            conversations: { unique: 9, top: [{ name: '10.0.0.1 <-> 10.0.0.2', count: 500 }] },
            topPorts: [{ name: '443', count: 600 }],
            tcpFlags: { syn: 30, synAck: 25, fin: 20, rst: 5 },
        };
        const text = summarizeStats(rich);
        expect(text).toContain('Packet size (bytes): min 60, average 540, max 1500');
        expect(text).toContain('Throughput');
        expect(text).toContain('IP version split');
        expect(text).toContain('top talkers');
        expect(text).toContain('10.0.0.1 <-> 10.0.0.2');
        expect(text).toContain('443');
        expect(text).toContain('TCP health');
        expect(text).toContain('5 reset(s)');
    });

    it('stays backward compatible when the expanded fields are absent', () => {
        // sampleSummary has none of the new fields — must not throw or emit them.
        const text = summarizeStats(sampleSummary);
        expect(text).not.toContain('TCP health');
        expect(text).not.toContain('top talkers');
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

    it('includes the expanded analysis schema fields', () => {
        const prompt = formatPrompt('analysis', { fileName: 'c.pcap', summary: sampleSummary });
        expect(prompt).toContain('"traffic_health"');
        expect(prompt).toContain('"security_assessment"');
        expect(prompt).toContain('"issues_and_recommendations"');
        expect(prompt).toContain('"suggested_resolution"');
    });

    it('includes the issues_and_recommendations field in the comparison schema', () => {
        const prompt = formatPrompt('comparison', {
            label1: 'a.pcap', label2: 'b.pcap', summary1: sampleSummary, summary2: sampleSummary,
        });
        expect(prompt).toContain('"issues_and_recommendations"');
        expect(prompt).toContain('"likely_cause"');
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
