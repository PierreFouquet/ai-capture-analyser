import { describe, it, expect } from 'vitest';
import { PcapParser } from '../public/pcapParser.js';
import { buildClassicPcap, frame, ascii, sipFrame, rtpFrame, httpsFrame } from './helpers/buildPcap.js';

describe('PcapParser.validateFile', () => {
    const parser = new PcapParser();

    it('rejects unsupported extensions', () => {
        expect(() => parser.validateFile({ name: 'notes.txt', size: 10 })).toThrow(/Unsupported/);
    });

    it('rejects files over the size limit', () => {
        expect(() => parser.validateFile({ name: 'big.pcap', size: 26 * 1024 * 1024 })).toThrow(/maximum/);
    });

    it('accepts a valid small pcap', () => {
        expect(parser.validateFile({ name: 'good.pcapng', size: 1000 })).toBe(true);
    });
});

describe('PcapParser.parseBuffer (classic pcap)', () => {
    const parser = new PcapParser();
    const buf = buildClassicPcap([
        { tsSec: 1000, tsUsec: 0, bytes: sipFrame() },
        { tsSec: 1001, tsUsec: 0, bytes: rtpFrame() },
        { tsSec: 1002, tsUsec: 500000, bytes: httpsFrame() },
    ]);
    const summary = parser.parseBuffer(buf);

    it('detects the format and counts packets', () => {
        expect(summary.format).toBe('pcap');
        expect(summary.packetCount).toBe(3);
    });

    it('computes capture duration from timestamps', () => {
        expect(summary.durationSeconds).toBe(2.5);
    });

    it('classifies SIP, RTP and TLS/HTTPS protocols', () => {
        expect(Object.keys(summary.protocolDistribution).sort()).toEqual(['RTP', 'SIP', 'TLS/HTTPS']);
        // Three packets, one each => ~33.3% apiece.
        expect(summary.protocolDistribution.SIP).toBeCloseTo(33.3, 1);
    });

    it('reports SIP/RTP signal counts', () => {
        expect(summary.sipRtp.sipPackets).toBe(1);
        expect(summary.sipRtp.rtpPackets).toBe(1);
        expect(summary.sipRtp.rtpStreams).toBe(1);
    });

    it('rejects a buffer too small to be a capture', () => {
        expect(() => parser.parseBuffer(new ArrayBuffer(8))).toThrow(/too small/);
    });
});

describe('PcapParser protocol dissection', () => {
    const parser = new PcapParser();

    // Build a one-packet classic pcap from raw frame bytes.
    const single = (bytes) => parser.parseBuffer(buildClassicPcap([{ tsSec: 1, tsUsec: 0, bytes }]));

    function ethFrame(etherType, l3 = []) {
        return new Uint8Array([0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, (etherType >> 8) & 0xff, etherType & 0xff, ...l3]);
    }

    it('classifies ARP', () => {
        expect(single(ethFrame(0x0806)).protocolDistribution).toHaveProperty('ARP');
    });

    it('classifies ICMP over IPv4', () => {
        const ip = [0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]; // protocol 1 = ICMP
        expect(single(ethFrame(0x0800, ip)).protocolDistribution).toHaveProperty('ICMP');
    });

    it('classifies ICMPv6 over IPv6', () => {
        // IPv6 header (40 bytes); next-header 58 = ICMPv6.
        const ip6 = [0x60, 0, 0, 0, 0, 0, 58, 64, ...new Array(32).fill(0)];
        expect(single(ethFrame(0x86dd, ip6)).protocolDistribution).toHaveProperty('ICMPv6');
    });

    it('classifies plain UDP and DNS by port', () => {
        const dist = single(frame({ proto: 'udp', srcPort: 50000, dstPort: 53 })).protocolDistribution;
        expect(dist).toHaveProperty('DNS');
    });

    it('classifies plain TCP that is not a known service', () => {
        const dist = single(frame({ proto: 'tcp', srcPort: 40000, dstPort: 40001 })).protocolDistribution;
        expect(dist).toHaveProperty('TCP');
    });

    it('handles raw-IP link type (no Ethernet header)', () => {
        // Build a classic pcap but with network=101 (raw IP). Re-create header manually.
        const ip = [0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
            0, 53, 0, 53, 0, 0, 0, 0]; // UDP to port 53
        const buf = buildClassicPcap([{ tsSec: 1, tsUsec: 0, bytes: new Uint8Array(ip) }]);
        new DataView(buf).setUint32(20, 101, true); // override link type to raw IP
        const dist = parser.parseBuffer(buf).protocolDistribution;
        expect(dist).toHaveProperty('DNS');
    });

    it('flags truncation past the packet cap is false for small captures', () => {
        expect(single(frame({ proto: 'udp', srcPort: 1, dstPort: 2 })).truncated).toBe(false);
    });

    it('detects SIP by payload on a non-standard port', () => {
        const f = frame({ proto: 'udp', srcPort: 30000, dstPort: 30001, payload: ascii('REGISTER sip:x') });
        const dist = single(f).protocolDistribution;
        expect(dist).toHaveProperty('SIP');
    });

    it('walks 802.1Q VLAN tags to reach the IP header', () => {
        const vlan = new Uint8Array([
            0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0x81, 0x00, // eth + VLAN ethertype
            0x00, 0x64, 0x08, 0x00, // VLAN tag (vid 100) + inner ethertype IPv4
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, // IPv4/UDP
            0, 53, 0, 53, 0, 0, 0, 0,
        ]);
        expect(single(vlan).protocolDistribution).toHaveProperty('DNS');
    });

    it('handles Linux SLL link type', () => {
        const sll = new Uint8Array([
            ...new Array(14).fill(0), 0x08, 0x00, // 16-byte SLL header, ethertype IPv4 at 14
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
            0, 53, 0, 53, 0, 0, 0, 0,
        ]);
        const buf = buildClassicPcap([{ tsSec: 1, tsUsec: 0, bytes: sll }]);
        new DataView(buf).setUint32(20, 113, true); // LINKTYPE_LINUX_SLL
        expect(parser.parseBuffer(buf).protocolDistribution).toHaveProperty('DNS');
    });

    it('handles BSD loopback (NULL) link type', () => {
        const loop = new Uint8Array([
            2, 0, 0, 0, // AF_INET, little-endian
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
            0, 53, 0, 53, 0, 0, 0, 0,
        ]);
        const buf = buildClassicPcap([{ tsSec: 1, tsUsec: 0, bytes: loop }]);
        new DataView(buf).setUint32(20, 0, true); // LINKTYPE_NULL
        expect(parser.parseBuffer(buf).protocolDistribution).toHaveProperty('DNS');
    });

    it('classifies UDP over IPv6 by port', () => {
        const ip6 = [0x60, 0, 0, 0, 0, 8, 17, 64, ...new Array(32).fill(0), 0, 53, 0, 53, 0, 0, 0, 0];
        expect(single(ethFrame(0x86dd, ip6)).protocolDistribution).toHaveProperty('DNS');
    });
});

describe('PcapParser.parseBuffer (pcapng)', () => {
    // Minimal PCAPNG: SHB + IDB(Ethernet) + EPB(one SIP frame).
    function buildPcapng(frameBytes) {
        const padded = (frameBytes.length + 3) & ~3;
        const epbLen = 32 + padded;
        const total = 28 + 20 + epbLen;
        const buf = new ArrayBuffer(total);
        const dv = new DataView(buf);
        let o = 0;
        // SHB
        dv.setUint32(o, 0x0a0d0d0a, true);
        dv.setUint32(o + 4, 28, true);
        dv.setUint32(o + 8, 0x1a2b3c4d, true); // byte-order magic
        dv.setUint16(o + 12, 1, true);
        dv.setUint32(o + 24, 28, true);
        o += 28;
        // IDB
        dv.setUint32(o, 0x00000001, true);
        dv.setUint32(o + 4, 20, true);
        dv.setUint16(o + 8, 1, true); // linktype Ethernet
        dv.setUint32(o + 12, 65535, true);
        dv.setUint32(o + 16, 20, true);
        o += 20;
        // EPB
        dv.setUint32(o, 0x00000006, true);
        dv.setUint32(o + 4, epbLen, true);
        dv.setUint32(o + 8, 0, true); // interface id
        dv.setUint32(o + 20, frameBytes.length, true); // captured len
        dv.setUint32(o + 24, frameBytes.length, true); // original len
        new Uint8Array(buf, o + 28, frameBytes.length).set(frameBytes);
        dv.setUint32(o + epbLen - 4, epbLen, true);
        return buf;
    }

    it('parses an enhanced packet block', () => {
        const summary = new PcapParser().parseBuffer(buildPcapng(sipFrame()));
        expect(summary.format).toBe('pcapng');
        expect(summary.packetCount).toBe(1);
        expect(summary.sipRtp.sipPackets).toBe(1);
    });
});
