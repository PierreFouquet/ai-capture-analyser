// Real PCAP / PCAPNG parser.
//
// Parsing happens entirely in the browser: the raw packets never leave the
// user's machine. Only the aggregated statistics produced here are sent to the
// AI for narrative analysis. The parser is intentionally lightweight — it
// dissects enough of each frame (link layer -> IP -> transport) to produce a
// useful protocol distribution and a SIP/RTP heuristic, then stops.

const SUPPORTED_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];
const MAX_FILE_SIZE = 25 * 1024 * 1024; // 25 MB
const MAX_PACKETS = 200000; // Safety cap so a huge capture can't hang the tab.

// Link-layer types we know how to walk into the IP header.
const LINKTYPE_ETHERNET = 1;
const LINKTYPE_RAW = 101; // raw IPv4/IPv6
const LINKTYPE_LINUX_SLL = 113;
const LINKTYPE_NULL = 0; // BSD loopback

export class PcapParser {
    constructor() {
        this.supportedFormats = SUPPORTED_EXTENSIONS;
        this.maxFileSize = MAX_FILE_SIZE;
    }

    /** Throw a descriptive error if the file is the wrong type or too large. */
    validateFile(file) {
        const name = (file?.name || '').toLowerCase();
        const isValidFormat = this.supportedFormats.some((ext) => name.endsWith(ext));
        if (!isValidFormat) {
            throw new Error(
                `Unsupported file format. Please use a ${this.supportedFormats.join(', ')} file.`
            );
        }
        if (file.size > this.maxFileSize) {
            throw new Error(
                `File is ${(file.size / 1024 / 1024).toFixed(1)} MB; the maximum is ${this.maxFileSize / 1024 / 1024} MB.`
            );
        }
        return true;
    }

    /** Validate, read and parse a File (or File-like object), returning stats. */
    async parse(file) {
        this.validateFile(file);
        const buffer = await file.arrayBuffer();
        return this.parseBuffer(buffer);
    }

    /** Parse an ArrayBuffer, auto-detecting classic PCAP vs PCAPNG. */
    parseBuffer(buffer) {
        if (buffer.byteLength < 24) {
            throw new Error('File is too small to be a valid capture.');
        }
        const magic = new DataView(buffer).getUint32(0, true);
        // PCAPNG Section Header Block starts with 0x0A0D0D0A.
        if (magic === 0x0a0d0d0a) {
            return this.parsePcapng(buffer);
        }
        return this.parseClassicPcap(buffer);
    }

    // --- Classic PCAP --------------------------------------------------------

    parseClassicPcap(buffer) {
        const view = new DataView(buffer);
        const magic = view.getUint32(0, false); // read big-endian, then decide
        let littleEndian;
        let nanos = false;

        if (magic === 0xa1b2c3d4) { littleEndian = false; }
        else if (magic === 0xd4c3b2a1) { littleEndian = true; }
        else if (magic === 0xa1b23c4d) { littleEndian = false; nanos = true; }
        else if (magic === 0x4d3cb2a1) { littleEndian = true; nanos = true; }
        else throw new Error('Unrecognised PCAP magic number; the file may be corrupt.');

        const linkType = view.getUint32(20, littleEndian);
        const tsScale = nanos ? 1e9 : 1e6;

        const acc = new StatsAccumulator(linkType);
        let offset = 24;
        while (offset + 16 <= buffer.byteLength && acc.packetCount < MAX_PACKETS) {
            const tsSec = view.getUint32(offset, littleEndian);
            const tsFrac = view.getUint32(offset + 4, littleEndian);
            const inclLen = view.getUint32(offset + 8, littleEndian);
            offset += 16;
            if (inclLen === 0 || offset + inclLen > buffer.byteLength) break;
            const timestamp = tsSec + tsFrac / tsScale;
            acc.addPacket(new DataView(buffer, offset, inclLen), timestamp, linkType);
            offset += inclLen;
        }
        return acc.finalize('pcap');
    }

    // --- PCAPNG --------------------------------------------------------------

    parsePcapng(buffer) {
        const view = new DataView(buffer);
        // Determine endianness from the Section Header Block's byte-order magic.
        const byteOrderMagic = view.getUint32(8, true);
        const littleEndian = byteOrderMagic === 0x1a2b3c4d;

        const interfaces = []; // { linkType, tsresol }
        const acc = new StatsAccumulator(null);
        let offset = 0;

        while (offset + 8 <= buffer.byteLength && acc.packetCount < MAX_PACKETS) {
            const blockType = view.getUint32(offset, littleEndian);
            const blockLen = view.getUint32(offset + 4, littleEndian);
            if (blockLen < 12 || offset + blockLen > buffer.byteLength) break;

            if (blockType === 0x00000001) {
                // Interface Description Block: linktype(u16), reserved(u16), snaplen(u32)
                const linkType = view.getUint16(offset + 8, littleEndian);
                const tsresol = this.readTsResol(view, offset, blockLen, littleEndian);
                interfaces.push({ linkType, tsresol });
            } else if (blockType === 0x00000006) {
                // Enhanced Packet Block
                const interfaceId = view.getUint32(offset + 8, littleEndian);
                const tsHigh = view.getUint32(offset + 12, littleEndian);
                const tsLow = view.getUint32(offset + 16, littleEndian);
                const capturedLen = view.getUint32(offset + 20, littleEndian);
                const iface = interfaces[interfaceId] || interfaces[0];
                const linkType = iface ? iface.linkType : LINKTYPE_ETHERNET;
                const tsresol = iface ? iface.tsresol : 1e-6;
                const dataStart = offset + 28;
                if (dataStart + capturedLen <= offset + blockLen) {
                    const ts = (tsHigh * 2 ** 32 + tsLow) * tsresol;
                    acc.addPacket(new DataView(buffer, dataStart, capturedLen), ts, linkType);
                }
            } else if (blockType === 0x00000003) {
                // Simple Packet Block: original length(u32), then data
                const iface = interfaces[0];
                const linkType = iface ? iface.linkType : LINKTYPE_ETHERNET;
                const dataStart = offset + 12;
                const dataLen = blockLen - 16; // minus type, len, origlen, trailing len
                if (dataLen > 0 && dataStart + dataLen <= offset + blockLen) {
                    acc.addPacket(new DataView(buffer, dataStart, dataLen), null, linkType);
                }
            }

            offset += blockLen; // blocks are padded to 32-bit; blockLen already includes padding
        }
        return acc.finalize('pcapng');
    }

    // Read the if_tsresol option (code 9) from an IDB; default 1e-6 seconds.
    readTsResol(view, blockOffset, blockLen, le) {
        let p = blockOffset + 16; // after type,len,linktype,reserved,snaplen
        const end = blockOffset + blockLen - 4;
        while (p + 4 <= end) {
            const optCode = view.getUint16(p, le);
            const optLen = view.getUint16(p + 2, le);
            if (optCode === 0) break; // opt_endofopt
            if (optCode === 9 && optLen >= 1) {
                const raw = view.getUint8(p + 4);
                return raw & 0x80 ? 1 / 2 ** (raw & 0x7f) : 1 / 10 ** raw;
            }
            p += 4 + optLen + ((4 - (optLen % 4)) % 4); // pad to 32-bit
        }
        return 1e-6;
    }
}

// Accumulates protocol counts and SIP/RTP signals across packets.
class StatsAccumulator {
    constructor() {
        this.packetCount = 0;
        this.totalBytes = 0;
        this.protocols = new Map();
        this.firstTs = null;
        this.lastTs = null;
        this.sipPackets = 0;
        this.rtpPackets = 0;
        this.rtpStreams = new Set(); // ssrc values
        this.truncated = false;

        // Expanded signal (all derived from headers already being walked).
        this.minPacketSize = null;
        this.maxPacketSize = 0;
        this.ipv4Packets = 0;
        this.ipv6Packets = 0;
        this.endpoints = new Map(); // ip address -> packet count
        this.conversations = new Map(); // "a <-> b" -> packet count
        this.ports = new Map(); // destination port -> packet count
        this.tcpFlags = { syn: 0, synAck: 0, fin: 0, rst: 0 };
    }

    bump(proto) {
        this.protocols.set(proto, (this.protocols.get(proto) || 0) + 1);
    }

    bumpMap(map, key) {
        map.set(key, (map.get(key) || 0) + 1);
    }

    addPacket(view, timestamp, linkType) {
        this.packetCount++;
        const len = view.byteLength;
        this.totalBytes += len;
        if (this.minPacketSize == null || len < this.minPacketSize) this.minPacketSize = len;
        if (len > this.maxPacketSize) this.maxPacketSize = len;
        if (timestamp != null && Number.isFinite(timestamp)) {
            if (this.firstTs == null || timestamp < this.firstTs) this.firstTs = timestamp;
            if (this.lastTs == null || timestamp > this.lastTs) this.lastTs = timestamp;
        }
        try {
            this.dissect(view, linkType);
        } catch {
            this.bump('Other');
        }
    }

    // Walk the link layer to find the EtherType / IP version.
    dissect(view, linkType) {
        let offset = 0;
        let etherType;

        if (linkType === LINKTYPE_ETHERNET) {
            if (view.byteLength < 14) { this.bump('Other'); return; }
            etherType = view.getUint16(12, false);
            offset = 14;
            // Skip 802.1Q VLAN tags.
            while (etherType === 0x8100 && offset + 4 <= view.byteLength) {
                etherType = view.getUint16(offset + 2, false);
                offset += 4;
            }
        } else if (linkType === LINKTYPE_RAW) {
            etherType = (view.getUint8(0) >> 4) === 6 ? 0x86dd : 0x0800;
        } else if (linkType === LINKTYPE_LINUX_SLL) {
            if (view.byteLength < 16) { this.bump('Other'); return; }
            etherType = view.getUint16(14, false);
            offset = 16;
        } else if (linkType === LINKTYPE_NULL) {
            if (view.byteLength < 4) { this.bump('Other'); return; }
            const family = view.getUint32(0, true);
            etherType = family === 2 ? 0x0800 : 0x86dd;
            offset = 4;
        } else {
            // Unknown link type: guess from first nibble (IP version).
            etherType = (view.getUint8(0) >> 4) === 6 ? 0x86dd : 0x0800;
        }

        if (etherType === 0x0806) { this.bump('ARP'); return; }
        if (etherType === 0x0800) { this.dissectIPv4(view, offset); return; }
        if (etherType === 0x86dd) { this.dissectIPv6(view, offset); return; }
        this.bump('Other');
    }

    dissectIPv4(view, offset) {
        if (offset + 20 > view.byteLength) { this.bump('IPv4'); return; }
        this.ipv4Packets++;
        this.recordEndpoints(readIPv4(view, offset + 12), readIPv4(view, offset + 16));
        const ihl = (view.getUint8(offset) & 0x0f) * 4;
        const protocol = view.getUint8(offset + 9);
        this.dissectTransport(view, offset + ihl, protocol);
    }

    dissectIPv6(view, offset) {
        if (offset + 40 > view.byteLength) { this.bump('IPv6'); return; }
        this.ipv6Packets++;
        this.recordEndpoints(readIPv6(view, offset + 8), readIPv6(view, offset + 24));
        const nextHeader = view.getUint8(offset + 6);
        this.dissectTransport(view, offset + 40, nextHeader);
    }

    // Record the source/destination addresses and the conversation between them.
    recordEndpoints(src, dst) {
        this.bumpMap(this.endpoints, src);
        this.bumpMap(this.endpoints, dst);
        const key = src <= dst ? `${src} <-> ${dst}` : `${dst} <-> ${src}`;
        this.bumpMap(this.conversations, key);
    }

    dissectTransport(view, offset, protocol) {
        if (protocol === 6) {
            // TCP
            if (offset + 20 > view.byteLength) { this.bump('TCP'); return; }
            const srcPort = view.getUint16(offset, false);
            const dstPort = view.getUint16(offset + 2, false);
            this.bumpMap(this.ports, dstPort);
            // Flags live in the low 6 bits of the byte at TCP offset 13.
            const flags = view.getUint8(offset + 13);
            if (flags & 0x02) { this.tcpFlags.syn++; if (flags & 0x10) this.tcpFlags.synAck++; }
            if (flags & 0x01) this.tcpFlags.fin++;
            if (flags & 0x04) this.tcpFlags.rst++;
            const dataOffset = (view.getUint8(offset + 12) >> 4) * 4;
            const payloadOffset = offset + dataOffset;
            this.classifyAppLayer(view, payloadOffset, srcPort, dstPort, 'TCP');
        } else if (protocol === 17) {
            // UDP
            if (offset + 8 > view.byteLength) { this.bump('UDP'); return; }
            const srcPort = view.getUint16(offset, false);
            const dstPort = view.getUint16(offset + 2, false);
            this.bumpMap(this.ports, dstPort);
            this.classifyAppLayer(view, offset + 8, srcPort, dstPort, 'UDP');
        } else if (protocol === 1) {
            this.bump('ICMP');
        } else if (protocol === 58) {
            this.bump('ICMPv6');
        } else {
            this.bump('Other');
        }
    }

    classifyAppLayer(view, payloadOffset, srcPort, dstPort, transport) {
        const isSip = srcPort === 5060 || dstPort === 5060 || srcPort === 5061 || dstPort === 5061;
        const isDns = srcPort === 53 || dstPort === 53;
        const isHttps = srcPort === 443 || dstPort === 443;
        const isHttp = srcPort === 80 || dstPort === 80 || srcPort === 8080 || dstPort === 8080;

        if (isSip || this.looksLikeSip(view, payloadOffset)) {
            this.sipPackets++;
            this.bump('SIP');
            return;
        }
        if (transport === 'UDP' && this.looksLikeRtp(view, payloadOffset)) {
            this.rtpPackets++;
            this.bump('RTP');
            return;
        }
        if (isDns) { this.bump('DNS'); return; }
        if (isHttps) { this.bump('TLS/HTTPS'); return; }
        if (isHttp) { this.bump('HTTP'); return; }
        this.bump(transport);
    }

    // SIP messages are ASCII and begin with a method or the SIP version token.
    looksLikeSip(view, offset) {
        if (offset + 7 > view.byteLength) return false;
        let s = '';
        for (let i = 0; i < 7 && offset + i < view.byteLength; i++) {
            s += String.fromCharCode(view.getUint8(offset + i));
        }
        return /^(INVITE|REGISTE|SIP\/2|ACK |BYE |CANCEL|OPTIONS|SUBSCRI|NOTIFY|PUBLIS|REFER |MESSAG|INFO |UPDATE)/.test(s);
    }

    // RTP heuristic: version field == 2 and a sane, non-SIP payload type.
    looksLikeRtp(view, offset) {
        if (offset + 12 > view.byteLength) return false;
        const b0 = view.getUint8(offset);
        if (b0 >> 6 !== 2) return false; // version must be 2
        const payloadType = view.getUint8(offset + 1) & 0x7f;
        // Exclude RTCP payload types (72-76) which share the port range.
        if (payloadType >= 72 && payloadType <= 76) return false;
        const ssrc = view.getUint32(offset + 8, false);
        this.rtpStreams.add(ssrc);
        return true;
    }

    finalize(format) {
        if (this.packetCount >= MAX_PACKETS) this.truncated = true;

        // Convert raw counts into a percentage distribution (rounded, summing ~100).
        const distribution = {};
        const total = this.packetCount || 1;
        for (const [proto, count] of this.protocols.entries()) {
            distribution[proto] = Math.round((count / total) * 1000) / 10; // one decimal
        }

        const durationSeconds =
            this.firstTs != null && this.lastTs != null
                ? Math.max(0, Number((this.lastTs - this.firstTs).toFixed(3)))
                : null;

        // Top-N entries of a count Map, highest first, as { name, count }.
        const topN = (map, n) =>
            [...map.entries()]
                .sort((a, b) => b[1] - a[1])
                .slice(0, n)
                .map(([name, count]) => ({ name: String(name), count }));

        const hasDuration = durationSeconds != null && durationSeconds > 0;

        return {
            format,
            packetCount: this.packetCount,
            totalBytes: this.totalBytes,
            durationSeconds,
            protocolDistribution: distribution,
            sipRtp: {
                sipPackets: this.sipPackets,
                rtpPackets: this.rtpPackets,
                rtpStreams: this.rtpStreams.size,
            },
            truncated: this.truncated,
            packetSizeBytes: {
                min: this.minPacketSize ?? 0,
                max: this.maxPacketSize,
                average: this.packetCount ? Math.round(this.totalBytes / this.packetCount) : 0,
            },
            throughput: {
                packetsPerSecond: hasDuration
                    ? Math.round((this.packetCount / durationSeconds) * 10) / 10
                    : null,
                bitsPerSecond: hasDuration
                    ? Math.round((this.totalBytes * 8) / durationSeconds)
                    : null,
            },
            ipVersions: { ipv4: this.ipv4Packets, ipv6: this.ipv6Packets },
            endpoints: { unique: this.endpoints.size, top: topN(this.endpoints, 5) },
            conversations: { unique: this.conversations.size, top: topN(this.conversations, 5) },
            topPorts: topN(this.ports, 5),
            tcpFlags: { ...this.tcpFlags },
        };
    }
}

// --- Address formatting helpers ---------------------------------------------

/** Read a 4-byte IPv4 address as a dotted-quad string. */
function readIPv4(view, p) {
    return `${view.getUint8(p)}.${view.getUint8(p + 1)}.${view.getUint8(p + 2)}.${view.getUint8(p + 3)}`;
}

/** Read a 16-byte IPv6 address and format it with `::` zero-run compression. */
function readIPv6(view, p) {
    const groups = [];
    for (let i = 0; i < 8; i++) groups.push(view.getUint16(p + i * 2, false));
    return compressIPv6(groups);
}

/** Format eight 16-bit groups as a canonical, `::`-compressed IPv6 string. */
function compressIPv6(groups) {
    // Find the longest run of consecutive zero groups (must be length >= 2).
    let bestStart = -1, bestLen = 0;
    let curStart = -1, curLen = 0;
    for (let i = 0; i < 8; i++) {
        if (groups[i] === 0) {
            if (curStart === -1) curStart = i;
            curLen++;
            if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
        } else {
            curStart = -1;
            curLen = 0;
        }
    }
    const hex = groups.map((g) => g.toString(16));
    if (bestLen < 2) return hex.join(':');
    const head = hex.slice(0, bestStart).join(':');
    const tail = hex.slice(bestStart + bestLen).join(':');
    return `${head}::${tail}`;
}
