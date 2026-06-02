// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest';
import { ReportRenderer } from '../public/reportRenderer.js';

const renderer = new ReportRenderer();

describe('renderAnalysisReport', () => {
    it('escapes AI-supplied text to prevent XSS', () => {
        const { html } = renderer.renderAnalysisReport(
            {
                summary: '<script>alert(1)</script>',
                anomalies_and_errors: ['<img src=x onerror=alert(2)>'],
                protocol_distribution: {},
            },
            'normal.pcap'
        );
        expect(html).not.toContain('<script>alert(1)</script>');
        expect(html).toContain('&lt;script&gt;');
        expect(html).not.toContain('onerror=alert(2)>');
    });

    it('escapes a malicious file name', () => {
        const { html } = renderer.renderAnalysisReport({ protocol_distribution: {} }, '<b>x</b>.pcap');
        expect(html).toContain('&lt;b&gt;x&lt;/b&gt;.pcap');
    });

    it('renders the real packet count when provided', () => {
        const { html } = renderer.renderAnalysisReport(
            { protocol_distribution: {}, packetCount: 1234, duration: 5 },
            'c.pcap'
        );
        expect(html).toContain('1,234');
        expect(html).toContain('5s');
    });

    it('renders a zero packet count / duration as 0, not N/A (regression)', () => {
        const { html } = renderer.renderAnalysisReport(
            { protocol_distribution: {}, packetCount: 0, duration: 0 },
            'c.pcap'
        );
        expect(html).toContain('Packet Count: 0');
        expect(html).toContain('Duration: 0s');
        expect(html).not.toContain('Packet Count: N/A');
    });

    it('renders the new sections and real capture stats', () => {
        const { html } = renderer.renderAnalysisReport(
            {
                summary: 's',
                protocol_distribution: { TCP: 100 },
                traffic_health: 'Connections look healthy.',
                security_assessment: 'No notable concerns.',
                issues_and_recommendations: [
                    { issue: 'Many RSTs', likely_cause: 'Refused connections', suggested_resolution: 'Check the firewall' },
                ],
                capture_stats: {
                    protocolDistribution: { TCP: 100 },
                    packetSizeBytes: { min: 60, max: 1500, average: 500 },
                    throughput: { packetsPerSecond: 42, bitsPerSecond: 1000 },
                    endpoints: { unique: 3, top: [{ name: '10.0.0.1', count: 9 }] },
                    conversations: { unique: 2, top: [] },
                    tcpFlags: { syn: 4, synAck: 3, fin: 2, rst: 1 },
                },
            },
            'c.pcap'
        );
        expect(html).toContain('Traffic Health');
        expect(html).toContain('Connections look healthy.');
        expect(html).toContain('Security Assessment');
        expect(html).toContain('Top Talkers');
        expect(html).toContain('10.0.0.1');
        expect(html).toContain('Avg Packet Size: 500 bytes');
        expect(html).toContain('Issues & Recommendations');
        expect(html).toContain('Many RSTs');
        expect(html).toContain('Refused connections');
        expect(html).toContain('Check the firewall');
    });

    it('escapes hostile issues_and_recommendations payloads', () => {
        const { html } = renderer.renderAnalysisReport(
            {
                protocol_distribution: {},
                issues_and_recommendations: [
                    { issue: '<script>alert(1)</script>', likely_cause: '<img src=x onerror=alert(2)>', suggested_resolution: 'ok' },
                    '<b>plain string issue</b>',
                ],
            },
            'c.pcap'
        );
        expect(html).not.toContain('<script>alert(1)</script>');
        expect(html).toContain('&lt;script&gt;');
        expect(html).not.toContain('onerror=alert(2)>');
        expect(html).toContain('&lt;b&gt;plain string issue');
    });

    it('shows a fallback when there are no issues', () => {
        const { html } = renderer.renderAnalysisReport({ protocol_distribution: {} }, 'c.pcap');
        expect(html).toContain('No issues identified.');
    });

    it('does not throw on a very large issues array (abuse)', () => {
        const issues = Array.from({ length: 500 }, (_, i) => ({
            issue: `issue ${i}`, likely_cause: 'cause', suggested_resolution: 'fix',
        }));
        expect(() =>
            renderer.renderAnalysisReport({ protocol_distribution: {}, issues_and_recommendations: issues }, 'c.pcap')
        ).not.toThrow();
    });

    it('returns a postRender function', () => {
        const result = renderer.renderAnalysisReport({ protocol_distribution: {} }, 'c.pcap');
        expect(typeof result.postRender).toBe('function');
    });
});

describe('renderComparisonReport', () => {
    afterEach(() => vi.unstubAllGlobals());

    it('escapes file names and list items', () => {
        const { html } = renderer.renderComparisonReport(
            {
                overall_comparison_summary: 'ok',
                key_differences: ['<script>bad</script>'],
            },
            '<a>1</a>.pcap',
            'two.pcap'
        );
        expect(html).toContain('&lt;a&gt;1&lt;/a&gt;.pcap');
        expect(html).not.toContain('<script>bad</script>');
        expect(html).toContain('&lt;script&gt;bad&lt;/script&gt;');
    });

    it('shows fallback text when lists are empty', () => {
        const { html } = renderer.renderComparisonReport({}, 'a.pcap', 'b.pcap');
        expect(html).toContain('No significant differences found.');
        expect(html).toContain('No significant similarities found.');
        expect(html).toContain('No security implications identified.');
        expect(html).toContain('No issues identified.');
    });

    it('renders the Issues & Recommendations section for comparisons', () => {
        const { html } = renderer.renderComparisonReport(
            {
                overall_comparison_summary: 'ok',
                issues_and_recommendations: [
                    { issue: 'New RSTs in capture 2', likely_cause: 'A new firewall rule', suggested_resolution: 'Audit the rule' },
                ],
            },
            'a.pcap', 'b.pcap'
        );
        expect(html).toContain('New RSTs in capture 2');
        expect(html).toContain('Audit the rule');
    });

    it('omits the comparison chart canvas when no capture stats are given', () => {
        const { html } = renderer.renderComparisonReport({}, 'a.pcap', 'b.pcap');
        expect(html).not.toContain('comparison-chart');
    });

    it('wires up a comparison chart from the two real protocol distributions', () => {
        const created = [];
        vi.stubGlobal('Chart', class {
            constructor(ctx, config) { created.push(config); }
        });
        const canvas = document.createElement('canvas');
        canvas.id = 'comparison-chart';
        canvas.getContext = () => ({});
        document.body.appendChild(canvas);

        const { html, postRender } = renderer.renderComparisonReport(
            { overall_comparison_summary: 'x' },
            'a.pcap', 'b.pcap',
            { protocolDistribution: { TCP: 80, UDP: 20 } },
            { protocolDistribution: { TCP: 50, DNS: 50 } }
        );
        expect(html).toContain('comparison-chart');
        postRender();

        expect(created).toHaveLength(1);
        expect(created[0].type).toBe('bar');
        expect(created[0].data.datasets.map((d) => d.label)).toEqual(['a.pcap', 'b.pcap']);
        document.body.innerHTML = '';
    });
});

describe('renderAnalysisReport postRender', () => {
    afterEach(() => vi.unstubAllGlobals());

    it('creates a protocol chart when distribution data is present', () => {
        const created = [];
        vi.stubGlobal('Chart', class {
            constructor(ctx, config) { created.push(config); }
        });
        const canvas = document.createElement('canvas');
        canvas.id = 'protocol-chart';
        canvas.getContext = () => ({});
        document.body.appendChild(canvas);

        const { postRender } = renderer.renderAnalysisReport(
            { summary: 's', protocol_distribution: { TCP: 100 } },
            'c.pcap'
        );
        postRender();

        expect(created).toHaveLength(1);
        expect(created[0].type).toBe('doughnut');
        document.body.innerHTML = '';
    });
});
