import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { PDFExporter } from '../public/pdfExporter.js';

// A minimal stand-in for jsPDF that records the text it is asked to render and
// the filename it saves to, so we can assert the exporter's behaviour without
// pulling in the real (heavy) library.
class FakeJsPDF {
    constructor() {
        this.texts = [];
        this.savedAs = null;
        this.pages = 1;
    }
    setDrawColor() {}
    setFillColor() {}
    setTextColor() {}
    setFontSize() {}
    setFont() {}
    text(content) {
        this.texts.push(Array.isArray(content) ? content.join(' ') : content);
    }
    splitTextToSize(text) {
        // Simulate wrapping: long strings produce many lines, pushing the cursor
        // down the page so the exporter's page-break logic kicks in.
        return text.length > 100 ? new Array(60).fill('wrapped line') : [text];
    }
    addPage() {
        this.pages++;
    }
    save(name) {
        this.savedAs = name;
    }
}

let lastDoc;

beforeEach(() => {
    vi.stubGlobal('jspdf', {
        jsPDF: function () {
            lastDoc = new FakeJsPDF();
            return lastDoc;
        },
    });
});

afterEach(() => vi.unstubAllGlobals());

describe('PDFExporter.exportAnalysisReport', () => {
    it('saves a file named after the capture and includes the summary text', () => {
        new PDFExporter().exportAnalysisReport(
            {
                summary: 'A concise summary',
                anomalies_and_errors: ['weird packet'],
                sip_rtp_info: 'N/A',
                important_timestamps_packets: 'N/A',
            },
            'capture.pcap'
        );

        expect(lastDoc.savedAs).toBe('analysis-report-capture.pcap.pdf');
        expect(lastDoc.texts.join('\n')).toContain('A concise summary');
        expect(lastDoc.texts.join('\n')).toContain('weird packet');
    });
});

describe('PDFExporter.exportComparisonReport', () => {
    it('saves a comparison file named after both captures', () => {
        new PDFExporter().exportComparisonReport(
            {
                overall_comparison_summary: 'They differ',
                key_differences: ['a'],
                key_similarities: ['b'],
                security_implications: [],
                important_timestamps_packets: 'N/A',
            },
            'one.pcap',
            'two.pcap'
        );

        expect(lastDoc.savedAs).toBe('comparison-report-one.pcap-vs-two.pcap.pdf');
        expect(lastDoc.texts.join('\n')).toContain('They differ');
    });
});

describe('PDFExporter page breaks', () => {
    const longText = 'x'.repeat(200);

    it('adds pages when an analysis report overflows', () => {
        new PDFExporter().exportAnalysisReport(
            { summary: longText, anomalies_and_errors: [longText], sip_rtp_info: longText, important_timestamps_packets: longText },
            'big.pcap'
        );
        expect(lastDoc.pages).toBeGreaterThan(1);
    });

    it('adds pages when a comparison report overflows', () => {
        new PDFExporter().exportComparisonReport(
            {
                overall_comparison_summary: longText,
                key_differences: [longText],
                key_similarities: [longText],
                security_implications: [longText],
                important_timestamps_packets: longText,
            },
            'one.pcap',
            'two.pcap'
        );
        expect(lastDoc.pages).toBeGreaterThan(1);
    });
});
