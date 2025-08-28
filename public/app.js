// Main application logic

// The imports for the other classes are removed as they are no longer used in this file's scope
// They are now part of the separate, simplified script.js and will be used as part of the
// larger application context (e.g., in a backend or separate module).

export class PCAPAnalyzerApp {
    constructor() {
        this.currentAnalysisData = null;
        
        this.initializeDOMElements();
        this.bindEvents();
    }

    initializeDOMElements() {
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
        this.messageClose.addEventListener('click', () => this.hideMessage());
        this.exportPdfBtn.addEventListener('click', () => this.exportPDF());
        this.exportJsonBtn.addEventListener('click', () => this.exportJSON());
    }

    showMessage(message, isError = false) {
        this.messageText.textContent = message;
        if (isError) {
            this.messageBox.classList.remove('bg-green-500');
            this.messageBox.classList.add('bg-red-500');
        } else {
            this.messageBox.classList.remove('bg-red-500');
            this.messageBox.classList.add('bg-green-500');
        }
        this.messageBox.style.display = 'flex';
        setTimeout(() => this.hideMessage(), 5000); // Hide after 5 seconds
    }

    hideMessage() {
        this.messageBox.style.display = 'none';
    }

    renderReport(reportData, type, file1Name, file2Name) {
        if (!reportData) return;
        this.currentAnalysisData = { data: reportData, type, file1Name, file2Name };
        this.reportRenderer.renderReport(reportData, type, file1Name, file2Name);
        this.exportButtons.classList.remove('hidden');
    }

    exportPDF() {
        if (!this.currentAnalysisData) return;

        try {
            const reportElement = document.getElementById('report-container').firstChild;
            if (!reportElement) {
                this.showMessage('No report to export.', true);
                return;
            }

            const doc = new jspdf.jsPDF();
            doc.html(reportElement, {
                callback: function (doc) {
                    doc.save('pcap-report.pdf');
                },
                x: 15,
                y: 15,
                width: 170,
                windowWidth: 650
            });
            this.showMessage('PDF downloaded successfully!', false);
        } catch (error) {
            console.error('Error generating PDF:', error);
            this.showMessage('Failed to generate PDF. Please try again.', true);
        }
    }

    exportJSON() {
        if (!this.currentAnalysisData) return;
        
        const dataStr = JSON.stringify(this.currentAnalysisData.data, null, 2);
        const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
        
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
