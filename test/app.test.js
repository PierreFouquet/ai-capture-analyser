// @vitest-environment jsdom
import { describe, it, expect, beforeEach, beforeAll, vi } from 'vitest';
import { PCAPAnalyzerApp } from '../public/app.js';

const DOM = `
  <input id="pcap-file-1"><input id="pcap-file-2"><input id="pcap-file-3">
  <select id="model-select-1"></select><select id="model-select-2"></select>
  <button id="start-analysis-btn"></button><button id="start-comparison-btn"></button>
  <div id="report-container"></div>
  <div id="loading-indicator" class="hidden"><p></p></div>
  <div id="message-box"><span id="message-text"></span><button id="message-close"></button></div>
  <div id="export-buttons" class="hidden"><button id="export-pdf"></button><button id="export-json"></button></div>
`;

function setFiles(input, files) {
    Object.defineProperty(input, 'files', { value: files, configurable: true });
}

const stubRenderer = () => ({
    renderAnalysisReport: vi.fn(() => ({ html: '<p>report</p>', postRender: vi.fn() })),
    renderComparisonReport: vi.fn(() => ({ html: '<p>report</p>', postRender: vi.fn() })),
});

let app;

beforeAll(async () => {
    await import('../public/config.js'); // publishes window.pcapAnalyzerConfig
});

beforeEach(() => {
    document.body.innerHTML = DOM;
    app = new PCAPAnalyzerApp();
    app.reportRenderer = stubRenderer();
});

describe('populateLlmModels', () => {
    it('fills both selects and pre-selects the configured default', () => {
        const modelCount = Object.keys(window.pcapAnalyzerConfig.llm_models).length;
        expect(app.llmModelSelect1.options.length).toBe(modelCount);
        expect(app.llmModelSelect1.value).toBe('@cf/google/gemma-4-26b-a4b-it');
        expect(app.llmModelSelect2.value).toBe('@cf/google/gemma-4-26b-a4b-it');
    });
});

describe('mergeRealStats', () => {
    it('overlays parsed figures onto the AI result', () => {
        const merged = app.mergeRealStats(
            { summary: 'ai' },
            { protocolDistribution: { TCP: 100 }, packetCount: 9, durationSeconds: 3 }
        );
        expect(merged).toMatchObject({
            summary: 'ai',
            protocol_distribution: { TCP: 100 },
            packetCount: 9,
            duration: 3,
        });
    });
});

describe('startAnalysis', () => {
    it('parses, calls the backend, and renders with real stats merged in', async () => {
        const summary = { protocolDistribution: { TCP: 100 }, packetCount: 5, durationSeconds: 2 };
        setFiles(app.pcapFile1, [{ name: 'a.pcap', size: 100 }]);
        app.pcapParser = { parse: vi.fn().mockResolvedValue(summary) };
        app.backend = { analyzePcap: vi.fn().mockResolvedValue({ summary: 'ok' }) };

        await app.startAnalysis();

        expect(app.pcapParser.parse).toHaveBeenCalledOnce();
        expect(app.backend.analyzePcap).toHaveBeenCalledWith(summary, 'a.pcap', '@cf/google/gemma-4-26b-a4b-it');
        expect(app.reportRenderer.renderAnalysisReport).toHaveBeenCalledWith(
            expect.objectContaining({ protocol_distribution: { TCP: 100 }, packetCount: 5 }),
            'a.pcap'
        );
        expect(app.exportButtons.classList.contains('hidden')).toBe(false);
    });

    it('warns and does nothing when no file is selected', async () => {
        setFiles(app.pcapFile1, []);
        app.backend = { analyzePcap: vi.fn() };
        const warn = vi.spyOn(app, 'showMessage');

        await app.startAnalysis();

        expect(warn).toHaveBeenCalled();
        expect(app.backend.analyzePcap).not.toHaveBeenCalled();
    });

    it('surfaces a parser/backend error to the user', async () => {
        setFiles(app.pcapFile1, [{ name: 'a.pcap', size: 100 }]);
        app.pcapParser = { parse: vi.fn().mockRejectedValue(new Error('bad capture')) };
        const warn = vi.spyOn(app, 'showMessage');

        await app.startAnalysis();

        expect(warn).toHaveBeenCalledWith(expect.stringContaining('bad capture'), true);
    });
});

describe('startComparison', () => {
    it('reads the compare-card inputs (file 2 and file 3), not the analyse input', async () => {
        const summary = { protocolDistribution: {}, packetCount: 1, durationSeconds: 1 };
        // Analyse input deliberately left empty to prove it is not used here.
        setFiles(app.pcapFile1, []);
        setFiles(app.pcapFile2, [{ name: 'first.pcap', size: 10 }]);
        setFiles(app.pcapFile3, [{ name: 'second.pcap', size: 10 }]);
        app.pcapParser = { parse: vi.fn().mockResolvedValue(summary) };
        app.backend = { comparePcaps: vi.fn().mockResolvedValue({ overall_comparison_summary: 'x' }) };

        await app.startComparison();

        expect(app.backend.comparePcaps).toHaveBeenCalledWith(
            summary, 'first.pcap', summary, 'second.pcap', '@cf/google/gemma-4-26b-a4b-it'
        );
        expect(app.reportRenderer.renderComparisonReport).toHaveBeenCalled();
    });

    it('warns when fewer than two files are chosen', async () => {
        setFiles(app.pcapFile2, [{ name: 'only.pcap', size: 10 }]);
        setFiles(app.pcapFile3, []);
        app.backend = { comparePcaps: vi.fn() };
        const warn = vi.spyOn(app, 'showMessage');

        await app.startComparison();

        expect(warn).toHaveBeenCalled();
        expect(app.backend.comparePcaps).not.toHaveBeenCalled();
    });
});

describe('exports', () => {
    it('exportPDF delegates to the PDF exporter for an analysis report', () => {
        app.currentAnalysisData = { type: 'analysis', data: { summary: 's' }, fileName: 'a.pcap' };
        app.pdfExporter = { exportAnalysisReport: vi.fn(), exportComparisonReport: vi.fn() };

        app.exportPDF();

        expect(app.pdfExporter.exportAnalysisReport).toHaveBeenCalledWith({ summary: 's' }, 'a.pcap');
    });

    it('exportJSON confirms the download to the user', () => {
        app.currentAnalysisData = { type: 'analysis', data: { summary: 's' }, fileName: 'a.pcap' };
        const msg = vi.spyOn(app, 'showMessage');
        // Stub the anchor click so jsdom doesn't attempt a real navigation.
        vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

        app.exportJSON();

        expect(msg).toHaveBeenCalledWith(expect.stringContaining('JSON'), false);
    });

    it('exportPDF delegates to the comparison exporter for a comparison report', () => {
        app.currentAnalysisData = { type: 'comparison', data: { x: 1 }, file1Name: 'a.pcap', file2Name: 'b.pcap' };
        app.pdfExporter = { exportAnalysisReport: vi.fn(), exportComparisonReport: vi.fn() };

        app.exportPDF();

        expect(app.pdfExporter.exportComparisonReport).toHaveBeenCalledWith({ x: 1 }, 'a.pcap', 'b.pcap');
    });

    it('exportPDF reports a failure to the user', () => {
        app.currentAnalysisData = { type: 'analysis', data: {}, fileName: 'a.pcap' };
        app.pdfExporter = { exportAnalysisReport: vi.fn(() => { throw new Error('pdf fail'); }) };
        const msg = vi.spyOn(app, 'showMessage');

        app.exportPDF();

        expect(msg).toHaveBeenCalledWith(expect.stringContaining('Failed to generate PDF'), true);
    });

    it('exports are no-ops without analysis data', () => {
        app.currentAnalysisData = null;
        app.pdfExporter = { exportAnalysisReport: vi.fn() };
        app.exportPDF();
        expect(app.pdfExporter.exportAnalysisReport).not.toHaveBeenCalled();
    });
});
