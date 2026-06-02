// Main application logic
import { PcapParser } from './pcapParser.js';
import { ReportRenderer } from './reportRenderer.js';
import { PDFExporter } from './pdfExporter.js';
import { Backend } from './backend.js';

export class PCAPAnalyzerApp {
    constructor() {
        this.pcapParser = new PcapParser();
        this.reportRenderer = new ReportRenderer();
        this.pdfExporter = new PDFExporter();
        this.backend = new Backend();
        this.currentAnalysisData = null;
        // Guards against re-entrant runs when the user clicks repeatedly.
        this.isBusy = false;

        this.initializeDOMElements();
        this.bindEvents();
        this.populateLlmModels();
    }

    initializeDOMElements() {
        this.pcapFile1 = document.getElementById('pcap-file-1');
        this.pcapFile2 = document.getElementById('pcap-file-2');
        this.pcapFile3 = document.getElementById('pcap-file-3');
        this.llmModelSelect1 = document.getElementById('model-select-1');
        this.llmModelSelect2 = document.getElementById('model-select-2');
        this.startAnalysisBtn = document.getElementById('start-analysis-btn');
        this.startComparisonBtn = document.getElementById('start-comparison-btn');
        this.reportContainer = document.getElementById('report-container');
        this.loadingIndicator = document.getElementById('loading-indicator');
        this.messageBox = document.getElementById('message-box');
        this.messageText = document.getElementById('message-text');
        this.messageClose = document.getElementById('message-close');
        this.exportButtons = document.getElementById('export-buttons');
        this.exportPdfBtn = document.getElementById('export-pdf');
        this.exportJsonBtn = document.getElementById('export-json');
    }

    bindEvents() {
        this.startAnalysisBtn.addEventListener('click', () => this.startAnalysis());
        this.startComparisonBtn.addEventListener('click', () => this.startComparison());
        this.exportPdfBtn.addEventListener('click', () => this.exportPDF());
        this.exportJsonBtn.addEventListener('click', () => this.exportJSON());
        this.messageClose.addEventListener('click', () => this.hideMessage());
    }
    
    populateLlmModels() {
        const { llm_models, llm_settings } = window.pcapAnalyzerConfig;
        const select1 = this.llmModelSelect1;
        const select2 = this.llmModelSelect2;

        for (const key in llm_models) {
            if (Object.prototype.hasOwnProperty.call(llm_models, key)) {
                const option1 = document.createElement('option');
                option1.value = key;
                option1.textContent = llm_models[key].name;
                select1.appendChild(option1);

                const option2 = document.createElement('option');
                option2.value = key;
                option2.textContent = llm_models[key].name;
                select2.appendChild(option2);
            }
        }

        // Pre-select the configured defaults (falls back to the first option if absent).
        if (llm_settings?.default_llm_model_analysis) {
            select1.value = llm_settings.default_llm_model_analysis;
        }
        if (llm_settings?.default_llm_model_comparison) {
            select2.value = llm_settings.default_llm_model_comparison;
        }
    }

    // Toggle the busy state and disable the action buttons so rapid repeated
    // clicks can't launch overlapping analyses.
    setBusy(busy) {
        this.isBusy = busy;
        this.startAnalysisBtn.disabled = busy;
        this.startComparisonBtn.disabled = busy;
    }

    async startAnalysis() {
        if (this.isBusy) return; // ignore clicks while a run is in flight
        // The "Analyze a Single PCAP" card uses the first file input.
        const file = this.pcapFile1.files[0];
        const llmModelKey = this.llmModelSelect1.value;

        if (!file) {
            this.showMessage('Please select a PCAP file to analyze.');
            return;
        }

        this.setBusy(true);
        this.showLoading('Parsing capture and analyzing. This may take a moment...');
        this.hideReport();

        try {
            const summary = await this.pcapParser.parse(file);
            const result = await this.backend.analyzePcap(summary, file.name, llmModelKey);
            this.currentAnalysisData = {
                type: 'analysis',
                // Overlay the real, locally-parsed figures so the chart and stats
                // reflect the actual capture rather than the model's estimate.
                data: this.mergeRealStats(result, summary),
                fileName: file.name
            };
            this.renderReport(this.currentAnalysisData);
        } catch (error) {
            console.error('Analysis failed:', error);
            this.showMessage(`Analysis failed: ${error.message || 'An unknown error occurred during analysis.'}`, true);
        } finally {
            this.hideLoading();
            this.setBusy(false);
        }
    }

    async startComparison() {
        if (this.isBusy) return; // ignore clicks while a run is in flight
        // The "Compare Two PCAP Files" card uses the second and third file inputs.
        const file1 = this.pcapFile2.files[0];
        const file2 = this.pcapFile3.files[0];
        const llmModelKey = this.llmModelSelect2.value;

        if (!file1 || !file2) {
            this.showMessage('Please select two PCAP files for comparison.');
            return;
        }

        this.setBusy(true);
        this.showLoading('Parsing captures and comparing. This may take a moment...');
        this.hideReport();

        try {
            const [summary1, summary2] = await Promise.all([
                this.pcapParser.parse(file1),
                this.pcapParser.parse(file2),
            ]);
            const result = await this.backend.comparePcaps(
                summary1, file1.name, summary2, file2.name, llmModelKey
            );
            this.currentAnalysisData = {
                type: 'comparison',
                data: result || {},
                // Keep the real, locally-parsed figures for each capture so the
                // chart and stat tables reflect the actual captures, not estimates.
                capture1_stats: summary1,
                capture2_stats: summary2,
                file1Name: file1.name,
                file2Name: file2.name
            };
            this.renderReport(this.currentAnalysisData);
        } catch (error) {
            console.error('Comparison failed:', error);
            this.showMessage(`Comparison failed: ${error.message || 'An unknown error occurred during analysis.'}`, true);
        } finally {
            this.hideLoading();
            this.setBusy(false);
        }
    }

    // Replace the AI's estimated figures with the real ones from the parser, and
    // attach the full parsed summary so the report can show trustworthy stats.
    mergeRealStats(result, summary) {
        const data = result || {};
        return {
            ...data,
            protocol_distribution: summary.protocolDistribution,
            packetCount: summary.packetCount,
            duration: summary.durationSeconds,
            capture_stats: summary,
        };
    }
    
    renderReport(analysisData) {
        if (analysisData.type === 'analysis') {
            const renderResult = this.reportRenderer.renderAnalysisReport(analysisData.data, analysisData.fileName);
            this.reportContainer.innerHTML = renderResult.html;
            renderResult.postRender();
        } else if (analysisData.type === 'comparison') {
            const renderResult = this.reportRenderer.renderComparisonReport(
                analysisData.data,
                analysisData.file1Name,
                analysisData.file2Name,
                analysisData.capture1_stats,
                analysisData.capture2_stats
            );
            this.reportContainer.innerHTML = renderResult.html;
            renderResult.postRender();
        }
        this.exportButtons.classList.remove('hidden');
    }

    showLoading(message) {
        this.reportContainer.innerHTML = '';
        this.exportButtons.classList.add('hidden');
        this.loadingIndicator.classList.remove('hidden');
        this.loadingIndicator.querySelector('p').textContent = message;
    }

    hideLoading() {
        this.loadingIndicator.classList.add('hidden');
    }

    hideReport() {
        this.reportContainer.innerHTML = '';
        this.exportButtons.classList.add('hidden');
    }

    showMessage(message, isError = false) {
        this.messageText.textContent = message;
        this.messageBox.style.display = 'flex';
        this.messageBox.className = `message-box ${isError ? 'bg-red-500' : 'bg-green-500'}`;
        
        // Auto-hide after 5 seconds
        setTimeout(() => this.hideMessage(), 5000);
    }

    hideMessage() {
        this.messageBox.style.display = 'none';
    }

    exportPDF() {
        if (!this.currentAnalysisData) return;

        try {
            if (this.currentAnalysisData.type === 'analysis') {
                this.pdfExporter.exportAnalysisReport(
                    this.currentAnalysisData.data,
                    this.currentAnalysisData.fileName
                );
            } else {
                this.pdfExporter.exportComparisonReport(
                    this.currentAnalysisData.data,
                    this.currentAnalysisData.file1Name,
                    this.currentAnalysisData.file2Name
                );
            }

            setTimeout(() => {
                this.hideMessage();
                this.showMessage('PDF downloaded successfully!', false);
            }, 1000);

        } catch (error) {
            console.error('Error generating PDF:', error);
            this.showMessage('Failed to generate PDF. Please try again.', true);
        }
    }

    exportJSON() {
        if (!this.currentAnalysisData) return;

        const dataStr = JSON.stringify(this.currentAnalysisData, null, 2);
        const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);

        const exportFileDefaultName = `pcap-analysis-${Date.now()}.json`;

        const linkElement = document.createElement('a');
        linkElement.setAttribute('href', dataUri);
        linkElement.setAttribute('download', exportFileDefaultName);
        linkElement.click();

        this.showMessage('JSON report downloaded successfully', false);
    }
}

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.pcapAnalyzerApp = new PCAPAnalyzerApp();
});