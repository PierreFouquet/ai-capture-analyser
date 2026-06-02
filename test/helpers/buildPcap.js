// Shared helpers for constructing synthetic PCAP captures in tests/fixtures.

/** ASCII string -> array of byte values. */
export const ascii = (s) => [...s].map((c) => c.charCodeAt(0));

/** "10.0.0.1" -> [10, 0, 0, 1]. */
const ipBytes = (ip) => ip.split('.').map((n) => parseInt(n, 10) & 0xff);

/**
 * Build an Ethernet + IPv4 + TCP/UDP frame with an optional payload.
 * Optional: `srcIp`/`dstIp` (dotted-quad) and TCP `flags` byte.
 */
export function frame({ proto, srcPort, dstPort, payload = [], srcIp = '10.0.0.1', dstIp = '10.0.0.2', flags = 0 }) {
    const eth = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0x08, 0x00];
    const ipProto = proto === 'tcp' ? 6 : 17;
    const ip = [0x45, 0, 0, 0, 0, 0, 0, 0, 64, ipProto, 0, 0, ...ipBytes(srcIp), ...ipBytes(dstIp)];
    const ports = [(srcPort >> 8) & 0xff, srcPort & 0xff, (dstPort >> 8) & 0xff, dstPort & 0xff];
    const l4 = proto === 'tcp'
        ? [...ports, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, flags & 0xff, 0, 0, 0, 0, 0, 0] // 20-byte TCP; flags at offset 13
        : [...ports, 0, 0, 0, 0]; // 8-byte UDP
    return new Uint8Array([...eth, ...ip, ...l4, ...payload]);
}

/** Build an Ethernet + IPv6 + UDP frame between two IPv6 addresses (16-byte arrays). */
export function ipv6Frame({ srcPort = 50000, dstPort = 53, src, dst } = {}) {
    const eth = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0x86, 0xdd];
    const srcAddr = src || [0x20, 0x01, 0x0d, 0xb8, ...new Array(11).fill(0), 1];
    const dstAddr = dst || [0x20, 0x01, 0x0d, 0xb8, ...new Array(11).fill(0), 2];
    // version 6, payload length 8, next-header 17 (UDP), hop limit 64.
    const ip6 = [0x60, 0, 0, 0, 0, 8, 17, 64, ...srcAddr, ...dstAddr];
    const ports = [(srcPort >> 8) & 0xff, srcPort & 0xff, (dstPort >> 8) & 0xff, dstPort & 0xff];
    return new Uint8Array([...eth, ...ip6, ...ports, 0, 0, 0, 0]);
}

// TCP flag bit constants for tests.
export const TCP_SYN = 0x02;
export const TCP_ACK = 0x10;
export const TCP_FIN = 0x01;
export const TCP_RST = 0x04;

/** A SIP request frame (UDP/5060). */
export const sipFrame = () =>
    frame({ proto: 'udp', srcPort: 5060, dstPort: 5060, payload: ascii('INVITE sip:bob@example') });

/** An RTP frame (UDP, RTP version 2) for the given SSRC. */
export const rtpFrame = (ssrc = 0xdeadbeef) =>
    frame({
        proto: 'udp', srcPort: 16384, dstPort: 16385,
        payload: [0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0, (ssrc >>> 24) & 0xff, (ssrc >>> 16) & 0xff, (ssrc >>> 8) & 0xff, ssrc & 0xff],
    });

export const httpsFrame = () => frame({ proto: 'tcp', srcPort: 12345, dstPort: 443 });
export const httpFrame = () => frame({ proto: 'tcp', srcPort: 23456, dstPort: 80 });
export const dnsFrame = () => frame({ proto: 'udp', srcPort: 50000, dstPort: 53 });

/**
 * Build a classic PCAP (link type Ethernet) from a list of
 * `{ tsSec, tsUsec, bytes }` records. Returns an ArrayBuffer.
 *
 * Defaults to little-endian, microsecond. Options:
 *   `littleEndian` — byte order of all header/record fields (default true).
 *   `nanos` — use the nanosecond magic variant (the timestamp fraction field is
 *   then interpreted as nanoseconds by the parser).
 */
export function buildClassicPcap(packets, { littleEndian = true, nanos = false } = {}) {
    const le = littleEndian;
    // Magic encodes both byte order and us/ns; the parser reads it big-endian.
    const magic = nanos
        ? (le ? 0x4d3cb2a1 : 0xa1b23c4d)
        : (le ? 0xd4c3b2a1 : 0xa1b2c3d4);
    const bodyLen = packets.reduce((n, p) => n + 16 + p.bytes.length, 0);
    const buf = new ArrayBuffer(24 + bodyLen);
    const dv = new DataView(buf);
    dv.setUint32(0, magic, false); // magic is always stored as a raw big-endian token
    dv.setUint16(4, 2, le);
    dv.setUint16(6, 4, le);
    dv.setUint32(16, 65535, le); // snaplen
    dv.setUint32(20, 1, le); // network = Ethernet
    let off = 24;
    for (const p of packets) {
        dv.setUint32(off, p.tsSec, le);
        dv.setUint32(off + 4, p.tsUsec, le);
        dv.setUint32(off + 8, p.bytes.length, le);
        dv.setUint32(off + 12, p.bytes.length, le);
        off += 16;
        new Uint8Array(buf, off, p.bytes.length).set(p.bytes);
        off += p.bytes.length;
    }
    return buf;
}

/** A small VoIP capture: 2 SIP messages + a single 8-packet RTP stream, ~2s. */
export function voipCapture() {
    const packets = [];
    packets.push({ tsSec: 1000, tsUsec: 0, bytes: sipFrame() });
    for (let i = 0; i < 8; i++) {
        packets.push({ tsSec: 1000, tsUsec: 20000 * (i + 1), bytes: rtpFrame(0x11223344) });
    }
    packets.push({ tsSec: 1002, tsUsec: 0, bytes: sipFrame() });
    return buildClassicPcap(packets);
}

/**
 * A different VoIP capture for comparison: 5 SIP messages and a *bidirectional*
 * call (two RTP streams / SSRCs, 12 RTP packets; 17 packets total), spanning ~5s.
 */
export function voipCapture2() {
    const packets = [];
    // SIP signalling: INVITE / Trying / Ringing / OK (all UDP/5060).
    for (let i = 0; i < 4; i++) {
        packets.push({ tsSec: 5000, tsUsec: 100000 * i, bytes: sipFrame() });
    }
    // Two RTP streams interleaved (caller + callee), 6 packets each.
    for (let i = 0; i < 6; i++) {
        packets.push({ tsSec: 5001, tsUsec: 20000 * i, bytes: rtpFrame(0xaaaa0001) });
        packets.push({ tsSec: 5001, tsUsec: 20000 * i + 10000, bytes: rtpFrame(0xbbbb0002) });
    }
    packets.push({ tsSec: 5005, tsUsec: 0, bytes: sipFrame() }); // BYE
    return buildClassicPcap(packets);
}

/**
 * Build a minimal PCAPNG (SHB + IDB + Simple Packet Block) from frame bytes.
 * The SPB carries no per-packet timestamp, exercising that code path.
 */
export function buildSimplePacketPcapng(frameBytes, linkType = 1) {
    const padded = (frameBytes.length + 3) & ~3;
    const spbLen = 16 + padded; // type, len, origlen, data(+pad), trailing len
    const total = 28 + 20 + spbLen;
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
    // IDB
    dv.setUint32(o, 0x00000001, true);
    dv.setUint32(o + 4, 20, true);
    dv.setUint16(o + 8, linkType, true);
    dv.setUint32(o + 12, 65535, true);
    dv.setUint32(o + 16, 20, true);
    o += 20;
    // SPB
    dv.setUint32(o, 0x00000003, true);
    dv.setUint32(o + 4, spbLen, true);
    dv.setUint32(o + 8, frameBytes.length, true); // original length
    new Uint8Array(buf, o + 12, frameBytes.length).set(frameBytes);
    dv.setUint32(o + spbLen - 4, spbLen, true);
    return buf;
}

/** A small web-browsing capture: DNS lookups then HTTP/HTTPS traffic. */
export function webCapture() {
    const packets = [
        { tsSec: 2000, tsUsec: 0, bytes: dnsFrame() },
        { tsSec: 2000, tsUsec: 100000, bytes: dnsFrame() },
        { tsSec: 2000, tsUsec: 250000, bytes: httpsFrame() },
        { tsSec: 2001, tsUsec: 0, bytes: httpsFrame() },
        { tsSec: 2001, tsUsec: 500000, bytes: httpFrame() },
    ];
    return buildClassicPcap(packets);
}
