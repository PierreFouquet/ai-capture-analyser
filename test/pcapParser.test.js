import { describe, it, expect } from 'vitest';
import { PcapParser } from '../public/pcapParser.js';
import {
    buildClassicPcap, buildSimplePacketPcapng, frame, ipv6Frame, ascii,
    sipFrame, rtpFrame, httpsFrame, httpFrame, dnsFrame,
    TCP_SYN, TCP_ACK, TCP_FIN, TCP_RST,
} from './helpers/buildPcap.js';

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

    it('parses a Simple Packet Block (no per-packet timestamp)', () => {
        const summary = new PcapParser().parseBuffer(buildSimplePacketPcapng(sipFrame()));
        expect(summary.format).toBe('pcapng');
        expect(summary.packetCount).toBe(1);
        expect(summary.sipRtp.sipPackets).toBe(1);
        // No timestamps in an SPB, so no duration can be computed.
        expect(summary.durationSeconds).toBeNull();
    });
});

describe('PcapParser expanded statistics', () => {
    const parser = new PcapParser();

    it('reports min/average/max packet size', () => {
        const buf = buildClassicPcap([
            { tsSec: 1, tsUsec: 0, bytes: frame({ proto: 'udp', srcPort: 1, dstPort: 2 }) }, // 42 bytes
            { tsSec: 1, tsUsec: 0, bytes: frame({ proto: 'udp', srcPort: 1, dstPort: 2, payload: ascii('hello world!') }) }, // 54 bytes
        ]);
        const { packetSizeBytes } = parser.parseBuffer(buf);
        expect(packetSizeBytes.min).toBe(42);
        expect(packetSizeBytes.max).toBe(54);
        expect(packetSizeBytes.average).toBe(48);
    });

    it('identifies top talkers and counts unique hosts & conversations', () => {
        const buf = buildClassicPcap([
            { tsSec: 1, tsUsec: 0, bytes: frame({ proto: 'udp', srcPort: 1, dstPort: 2, srcIp: '10.0.0.1', dstIp: '10.0.0.2' }) },
            { tsSec: 1, tsUsec: 0, bytes: frame({ proto: 'udp', srcPort: 1, dstPort: 2, srcIp: '10.0.0.1', dstIp: '10.0.0.3' }) },
            { tsSec: 1, tsUsec: 0, bytes: frame({ proto: 'udp', srcPort: 1, dstPort: 2, srcIp: '10.0.0.1', dstIp: '10.0.0.2' }) },
        ]);
        const { endpoints, conversations } = parser.parseBuffer(buf);
        expect(endpoints.unique).toBe(3); // .1, .2, .3
        expect(endpoints.top[0]).toEqual({ name: '10.0.0.1', count: 3 }); // in every packet
        expect(conversations.unique).toBe(2); // 1<->2 and 1<->3
        expect(conversations.top[0]).toEqual({ name: '10.0.0.1 <-> 10.0.0.2', count: 2 });
    });

    it('counts TCP flags (SYN / SYN-ACK / FIN / RST)', () => {
        const buf = buildClassicPcap([
            { tsSec: 1, tsUsec: 0, bytes: frame({ proto: 'tcp', srcPort: 1, dstPort: 80, flags: TCP_SYN }) },
            { tsSec: 1, tsUsec: 0, bytes: frame({ proto: 'tcp', srcPort: 80, dstPort: 1, flags: TCP_SYN | TCP_ACK }) },
            { tsSec: 1, tsUsec: 0, bytes: frame({ proto: 'tcp', srcPort: 1, dstPort: 80, flags: TCP_FIN }) },
            { tsSec: 1, tsUsec: 0, bytes: frame({ proto: 'tcp', srcPort: 80, dstPort: 1, flags: TCP_RST }) },
        ]);
        const { tcpFlags } = parser.parseBuffer(buf);
        expect(tcpFlags.syn).toBe(2); // SYN and SYN-ACK both carry the SYN bit
        expect(tcpFlags.synAck).toBe(1);
        expect(tcpFlags.fin).toBe(1);
        expect(tcpFlags.rst).toBe(1);
    });

    it('computes throughput from packet count and duration', () => {
        const buf = buildClassicPcap([
            { tsSec: 1000, tsUsec: 0, bytes: frame({ proto: 'udp', srcPort: 1, dstPort: 2 }) },
            { tsSec: 1002, tsUsec: 0, bytes: frame({ proto: 'udp', srcPort: 1, dstPort: 2 }) },
        ]);
        const summary = parser.parseBuffer(buf);
        expect(summary.durationSeconds).toBe(2);
        expect(summary.throughput.packetsPerSecond).toBe(1); // 2 packets / 2 s
        expect(summary.throughput.bitsPerSecond).toBe((summary.totalBytes * 8) / 2);
    });

    it('returns null throughput when there is no duration', () => {
        const summary = parser.parseBuffer(buildSimplePacketPcapng(sipFrame()));
        expect(summary.throughput.packetsPerSecond).toBeNull();
        expect(summary.throughput.bitsPerSecond).toBeNull();
    });

    it('records the top destination ports', () => {
        const buf = buildClassicPcap([
            { tsSec: 1, tsUsec: 0, bytes: dnsFrame() },     // dst 53
            { tsSec: 1, tsUsec: 0, bytes: dnsFrame() },     // dst 53
            { tsSec: 1, tsUsec: 0, bytes: httpsFrame() },   // dst 443
        ]);
        const { topPorts } = parser.parseBuffer(buf);
        expect(topPorts[0]).toEqual({ name: '53', count: 2 });
        expect(topPorts.map((p) => p.name)).toContain('443');
    });

    it('counts IPv4 vs IPv6 and compresses IPv6 addresses', () => {
        const buf = buildClassicPcap([
            { tsSec: 1, tsUsec: 0, bytes: frame({ proto: 'udp', srcPort: 1, dstPort: 2 }) },
            { tsSec: 1, tsUsec: 0, bytes: ipv6Frame() },
        ]);
        const summary = parser.parseBuffer(buf);
        expect(summary.ipVersions).toEqual({ ipv4: 1, ipv6: 1 });
        // ipv6Frame defaults to 2001:db8::1 -> 2001:db8::2.
        const names = summary.endpoints.top.map((e) => e.name);
        expect(names).toContain('2001:db8::1');
        expect(names).toContain('2001:db8::2');
    });
});

describe('PcapParser additional protocol/branch coverage', () => {
    const parser = new PcapParser();
    const single = (bytes) => parser.parseBuffer(buildClassicPcap([{ tsSec: 1, tsUsec: 0, bytes }]));

    it('classifies HTTP on port 8080', () => {
        const dist = single(frame({ proto: 'tcp', srcPort: 12345, dstPort: 8080 })).protocolDistribution;
        expect(dist).toHaveProperty('HTTP');
    });

    it('classifies HTTP via the legacy httpFrame helper (port 80)', () => {
        expect(single(httpFrame()).protocolDistribution).toHaveProperty('HTTP');
    });

    it('detects SIP on the secure port 5061', () => {
        const dist = single(frame({ proto: 'udp', srcPort: 5061, dstPort: 40000 })).protocolDistribution;
        expect(dist).toHaveProperty('SIP');
    });

    it('detects SIP by other request methods (BYE, OPTIONS)', () => {
        const bye = single(frame({ proto: 'udp', srcPort: 30000, dstPort: 30001, payload: ascii('BYE sip:x') }));
        const opt = single(frame({ proto: 'udp', srcPort: 30000, dstPort: 30001, payload: ascii('OPTIONS sip') }));
        expect(bye.protocolDistribution).toHaveProperty('SIP');
        expect(opt.protocolDistribution).toHaveProperty('SIP');
    });

    it('does not treat RTCP (payload types 72-76) as RTP', () => {
        // RTP v2 header but payload type 200 & 0x7f = 72 (RTCP sender report).
        const rtcp = frame({
            proto: 'udp', srcPort: 16384, dstPort: 16385,
            payload: [0x80, 0xc8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        });
        const summary = single(rtcp);
        expect(summary.sipRtp.rtpPackets).toBe(0);
        expect(summary.protocolDistribution).not.toHaveProperty('RTP');
    });

    it('rejects RTP whose version field is not 2', () => {
        const notRtp = frame({
            proto: 'udp', srcPort: 16384, dstPort: 16385,
            payload: [0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // version 0
        });
        expect(single(notRtp).sipRtp.rtpPackets).toBe(0);
    });

    it('classifies TCP over IPv6 by port', () => {
        const ip6 = [0x60, 0, 0, 0, 0, 20, 6, 64, ...new Array(32).fill(0)]; // next-header 6 = TCP
        const tcp = [0x01, 0xbb, 0x30, 0x39, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0, 0, 0, 0, 0, 0, 0]; // dst 443
        const eth = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0x86, 0xdd];
        const bytes = new Uint8Array([...eth, ...ip6, ...tcp]);
        expect(single(bytes).protocolDistribution).toHaveProperty('TLS/HTTPS');
    });

    it('walks double 802.1Q VLAN tags to the IP header', () => {
        const dbl = new Uint8Array([
            0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0x81, 0x00, // eth + outer VLAN ethertype
            0x00, 0x64, 0x81, 0x00, // outer tag, inner ethertype 0x8100
            0x00, 0xc8, 0x08, 0x00, // inner tag, ethertype IPv4
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
            0, 53, 0, 53, 0, 0, 0, 0,
        ]);
        expect(single(dbl).protocolDistribution).toHaveProperty('DNS');
    });
});

describe('PcapParser endianness & timestamp resolution', () => {
    const parser = new PcapParser();

    it('parses a big-endian classic pcap', () => {
        const buf = buildClassicPcap([{ tsSec: 1, tsUsec: 0, bytes: dnsFrame() }], { littleEndian: false });
        const summary = parser.parseBuffer(buf);
        expect(summary.format).toBe('pcap');
        expect(summary.protocolDistribution).toHaveProperty('DNS');
    });

    it('scales nanosecond timestamps correctly', () => {
        const buf = buildClassicPcap([
            { tsSec: 1000, tsUsec: 0, bytes: dnsFrame() },
            { tsSec: 1000, tsUsec: 500_000_000, bytes: dnsFrame() }, // +0.5 s in ns
        ], { nanos: true });
        expect(parser.parseBuffer(buf).durationSeconds).toBeCloseTo(0.5, 3);
    });

    it('throws on an unrecognised magic number', () => {
        const buf = new ArrayBuffer(32);
        new DataView(buf).setUint32(0, 0x12345678, false);
        expect(() => parser.parseBuffer(buf)).toThrow(/magic/i);
    });

    it('honours the PCAPNG if_tsresol option (decimal and power-of-two)', () => {
        // Build SHB + IDB(with if_tsresol) + two EPBs differing by `ticks`.
        function buildWithResol(rawResol, ticks) {
            const total = 28 + 32 + 32 + 32;
            const buf = new ArrayBuffer(total);
            const dv = new DataView(buf);
            let o = 0;
            // SHB
            dv.setUint32(o, 0x0a0d0d0a, true);
            dv.setUint32(o + 4, 28, true);
            dv.setUint32(o + 8, 0x1a2b3c4d, true);
            dv.setUint16(o + 12, 1, true);
            dv.setUint32(o + 24, 28, true);
            o += 28;
            // IDB (32 bytes) with if_tsresol option (code 9, len 1)
            dv.setUint32(o, 0x00000001, true);
            dv.setUint32(o + 4, 32, true);
            dv.setUint16(o + 8, 1, true); // linktype Ethernet
            dv.setUint32(o + 12, 65535, true); // snaplen
            dv.setUint16(o + 16, 9, true); // opt code if_tsresol
            dv.setUint16(o + 18, 1, true); // opt len
            dv.setUint8(o + 20, rawResol); // resolution byte
            dv.setUint16(o + 24, 0, true); // opt_endofopt code
            dv.setUint16(o + 26, 0, true); // opt_endofopt len
            dv.setUint32(o + 28, 32, true); // trailing block len
            o += 32;
            // Two zero-data EPBs at t=0 and t=ticks
            for (const t of [0, ticks]) {
                dv.setUint32(o, 0x00000006, true);
                dv.setUint32(o + 4, 32, true);
                dv.setUint32(o + 8, 0, true); // interface id
                dv.setUint32(o + 12, 0, true); // ts high
                dv.setUint32(o + 16, t, true); // ts low
                dv.setUint32(o + 20, 0, true); // captured len
                dv.setUint32(o + 24, 0, true); // original len
                dv.setUint32(o + 28, 32, true); // trailing len
                o += 32;
            }
            return buf;
        }

        // Decimal: rawResol 3 => 10^-3 s/tick; 1000 ticks => 1.0 s.
        expect(parser.parseBuffer(buildWithResol(3, 1000)).durationSeconds).toBeCloseTo(1.0, 3);
        // Power-of-two: rawResol 0x80|10 => 1/2^10 s/tick; 1024 ticks => 1.0 s.
        expect(parser.parseBuffer(buildWithResol(0x80 | 10, 1024)).durationSeconds).toBeCloseTo(1.0, 3);
    });
});

describe('PcapParser adversarial / malformed input', () => {
    const parser = new PcapParser();

    it('throws on garbage bytes with a bad magic number', () => {
        const buf = new ArrayBuffer(64);
        new Uint8Array(buf).fill(0xab);
        expect(() => parser.parseBuffer(buf)).toThrow();
    });

    it('stops cleanly at a zero-length packet record', () => {
        const buf = buildClassicPcap([{ tsSec: 1, tsUsec: 0, bytes: dnsFrame() }]);
        // Append a 16-byte record header claiming inclLen 0.
        const grown = new ArrayBuffer(buf.byteLength + 16);
        new Uint8Array(grown).set(new Uint8Array(buf));
        // (inclLen field defaults to 0) — parser should break, not loop or throw.
        const summary = parser.parseBuffer(grown);
        expect(summary.packetCount).toBe(1);
    });

    it('handles an empty-but-valid capture without dividing by zero', () => {
        const buf = buildClassicPcap([]); // header only, no packets
        const summary = parser.parseBuffer(buf);
        expect(summary.packetCount).toBe(0);
        expect(summary.protocolDistribution).toEqual({});
        expect(summary.durationSeconds).toBeNull();
        expect(summary.truncated).toBe(false);
        expect(summary.packetSizeBytes).toEqual({ min: 0, max: 0, average: 0 });
    });

    it('counts a frame too short for its link layer as Other, never throwing', () => {
        const summary = parser.parseBuffer(buildClassicPcap([{ tsSec: 1, tsUsec: 0, bytes: new Uint8Array([1, 2, 3]) }]));
        expect(summary.packetCount).toBe(1);
        expect(summary.protocolDistribution).toHaveProperty('Other');
    });
});
