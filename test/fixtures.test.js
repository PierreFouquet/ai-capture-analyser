import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PcapParser } from '../public/pcapParser.js';
import { formatPrompt } from '../src/analysis';

// Load a committed fixture as an ArrayBuffer.
function loadFixture(name) {
    const path = fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
    const buf = readFileSync(path);
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

// Wrap an ArrayBuffer as a File-like object so parse() exercises validateFile too.
function asFile(name, arrayBuffer) {
    return { name, size: arrayBuffer.byteLength, arrayBuffer: async () => arrayBuffer };
}

describe('parsing committed PCAP fixtures', () => {
    const parser = new PcapParser();

    it('parses the VoIP fixture into SIP + RTP traffic', async () => {
        const summary = await parser.parse(asFile('voip-call.pcap', loadFixture('voip-call.pcap')));

        expect(summary.format).toBe('pcap');
        expect(summary.packetCount).toBe(10); // 2 SIP + 8 RTP
        expect(summary.protocolDistribution).toHaveProperty('SIP');
        expect(summary.protocolDistribution).toHaveProperty('RTP');
        expect(summary.sipRtp.sipPackets).toBe(2);
        expect(summary.sipRtp.rtpPackets).toBe(8);
        expect(summary.sipRtp.rtpStreams).toBe(1); // single SSRC
        // RTP should dominate by packet share.
        expect(summary.protocolDistribution.RTP).toBeGreaterThan(summary.protocolDistribution.SIP);
    });

    it('parses the web fixture into DNS + HTTP(S) traffic', async () => {
        const summary = await parser.parse(asFile('web-browsing.pcap', loadFixture('web-browsing.pcap')));

        expect(summary.packetCount).toBe(5);
        expect(Object.keys(summary.protocolDistribution).sort()).toEqual(['DNS', 'HTTP', 'TLS/HTTPS']);
        expect(summary.sipRtp.sipPackets).toBe(0);
        expect(summary.sipRtp.rtpPackets).toBe(0);
        expect(summary.durationSeconds).toBeCloseTo(1.5, 3);
    });
});

describe('comparing two different VoIP captures', () => {
    const parser = new PcapParser();

    it('produces materially different summaries', () => {
        const a = parser.parseBuffer(loadFixture('voip-call.pcap'));
        const b = parser.parseBuffer(loadFixture('voip-call-2.pcap'));

        expect(a.sipRtp.rtpStreams).toBe(1);
        expect(b.sipRtp.rtpStreams).toBe(2); // bidirectional
        expect(a.packetCount).not.toBe(b.packetCount);
        expect(a.durationSeconds).not.toBe(b.durationSeconds);
    });

    it('builds a comparison prompt that reflects both captures', () => {
        const a = parser.parseBuffer(loadFixture('voip-call.pcap'));
        const b = parser.parseBuffer(loadFixture('voip-call-2.pcap'));

        const prompt = formatPrompt('comparison', {
            label1: 'voip-call.pcap',
            label2: 'voip-call-2.pcap',
            summary1: a,
            summary2: b,
        });

        expect(prompt).toContain('voip-call.pcap');
        expect(prompt).toContain('voip-call-2.pcap');
        // Both captures' distinct stream counts should appear in the prompt.
        expect(prompt).toContain('across 1 stream(s)');
        expect(prompt).toContain('across 2 stream(s)');
        expect(prompt).not.toContain('{label1}');
        expect(prompt).not.toContain('{stats1}');
    });
});
