// Shared helpers for constructing synthetic PCAP captures in tests/fixtures.

/** ASCII string -> array of byte values. */
export const ascii = (s) => [...s].map((c) => c.charCodeAt(0));

/** Build an Ethernet + IPv4 + TCP/UDP frame with an optional payload. */
export function frame({ proto, srcPort, dstPort, payload = [] }) {
    const eth = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0x08, 0x00];
    const ipProto = proto === 'tcp' ? 6 : 17;
    const ip = [0x45, 0, 0, 0, 0, 0, 0, 0, 64, ipProto, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
    const ports = [(srcPort >> 8) & 0xff, srcPort & 0xff, (dstPort >> 8) & 0xff, dstPort & 0xff];
    const l4 = proto === 'tcp'
        ? [...ports, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0, 0, 0, 0, 0, 0, 0] // 20-byte TCP, data offset 5
        : [...ports, 0, 0, 0, 0]; // 8-byte UDP
    return new Uint8Array([...eth, ...ip, ...l4, ...payload]);
}

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
 * Build a classic little-endian, microsecond PCAP (link type Ethernet) from a
 * list of `{ tsSec, tsUsec, bytes }` records. Returns an ArrayBuffer.
 */
export function buildClassicPcap(packets) {
    const bodyLen = packets.reduce((n, p) => n + 16 + p.bytes.length, 0);
    const buf = new ArrayBuffer(24 + bodyLen);
    const dv = new DataView(buf);
    dv.setUint32(0, 0xa1b2c3d4, true); // magic (stored LE)
    dv.setUint16(4, 2, true);
    dv.setUint16(6, 4, true);
    dv.setUint32(16, 65535, true); // snaplen
    dv.setUint32(20, 1, true); // network = Ethernet
    let off = 24;
    for (const p of packets) {
        dv.setUint32(off, p.tsSec, true);
        dv.setUint32(off + 4, p.tsUsec, true);
        dv.setUint32(off + 8, p.bytes.length, true);
        dv.setUint32(off + 12, p.bytes.length, true);
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
