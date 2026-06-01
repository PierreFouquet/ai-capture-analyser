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

    it('returns a postRender function', () => {
        const result = renderer.renderAnalysisReport({ protocol_distribution: {} }, 'c.pcap');
        expect(typeof result.postRender).toBe('function');
    });
});

describe('renderComparisonReport', () => {
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
