// PDF export utilities
export class PDFExporter {
    constructor() {
        this.pdf = null;
    }

    initPDF() {
        this.pdf = new jspdf.jsPDF({
            orientation: 'portrait',
            unit: 'mm',
            format: 'a4'
        });
        
        this.pdf.setDrawColor(100, 100, 100);
        this.pdf.setFillColor(245, 245, 245);
        this.pdf.setTextColor(50, 50, 50);
        
        return this.pdf;
    }

    addTitle(title, yPosition = 20) {
        this.pdf.setFontSize(20);
        this.pdf.setFont(undefined, 'bold');
        this.pdf.text(title, 105, yPosition, { align: 'center' });
        this.pdf.setFont(undefined, 'normal');
        return yPosition + 10;
    }

    addSectionTitle(title, yPosition) {
        this.pdf.setFontSize(16);
        this.pdf.setFont(undefined, 'bold');
        this.pdf.text(title, 20, yPosition);
        this.pdf.setFont(undefined, 'normal');
        return yPosition + 8;
    }

    addContent(text, yPosition, maxWidth = 170) {
        this.pdf.setFontSize(12);
        const lines = this.pdf.splitTextToSize(text, maxWidth);
        this.pdf.text(lines, 20, yPosition);
        return yPosition + (lines.length * 7);
    }
    
    addBulletList(items, yPosition) {
        this.pdf.setFontSize(12);
        let currentY = yPosition;
        items.forEach(item => {
            const lines = this.pdf.splitTextToSize(`• ${item}`, 160);
            this.pdf.text(lines, 25, currentY);
            currentY += (lines.length * 7);
        });
        return currentY;
    }

    addPageNumber(page) {
        this.pdf.setFontSize(10);
        this.pdf.setTextColor(150, 150, 150);
        this.pdf.text(`Page ${page}`, 105, 280, { align: 'center' });
    }

    exportAnalysisReport(data, fileName) {
        this.initPDF();
        let yPosition = this.addTitle(`Analysis Report: ${fileName}`);
        let page = 1;

        // Summary
        yPosition = this.addSectionTitle("Summary", yPosition + 10);
        yPosition = this.addContent(data.summary || 'No summary available.', yPosition + 5);

        // Check for new page
        if (yPosition > 250) {
            this.addPageNumber(page);
            this.pdf.addPage();
            page++;
            yPosition = 20;
        }
        
        // Anomalies and Errors
        yPosition = this.addSectionTitle("Anomalies and Errors", yPosition + 10);
        if (data.anomalies_and_errors && data.anomalies_and_errors.length > 0) {
            yPosition = this.addBulletList(data.anomalies_and_errors, yPosition + 5);
        } else {
            yPosition = this.addContent("N/A", yPosition + 5);
        }
        
        // Check for new page
        if (yPosition > 250) {
            this.addPageNumber(page);
            this.pdf.addPage();
            page++;
            yPosition = 20;
        }

        // SIP/RTP Information
        yPosition = this.addSectionTitle("SIP/RTP Information", yPosition + 10);
        yPosition = this.addContent(data.sip_rtp_info || 'N/A', yPosition + 5);

        // Check for new page
        if (yPosition > 250) {
            this.addPageNumber(page);
            this.pdf.addPage();
            page++;
            yPosition = 20;
        }

        // Important Timestamps/Packets
        yPosition = this.addSectionTitle("Important Timestamps/Packets", yPosition + 10);
        yPosition = this.addContent(data.important_timestamps_packets || 'N/A', yPosition + 5);
        
        this.addPageNumber(page);
        this.pdf.save(`analysis-report-${fileName}.pdf`);
    }

    exportComparisonReport(data, file1Name, file2Name) {
        this.initPDF();
        let yPosition = this.addTitle(`Comparison Report: ${file1Name} vs ${file2Name}`);
        let page = 1;
        
        // Summary
        yPosition = this.addSectionTitle("Overall Comparison Summary", yPosition + 10);
        yPosition = this.addContent(data.overall_comparison_summary || 'No summary available.', yPosition + 5);
        
        // Check if we need a new page
        if (yPosition > 250) {
            this.addPageNumber(page);
            this.pdf.addPage();
            page++;
            yPosition = 20;
        }
        
        // Key Differences
        yPosition = this.addSectionTitle("Key Differences", yPosition + 10);
        if (data.key_differences && data.key_differences.length > 0) {
            yPosition = this.addBulletList(data.key_differences, yPosition + 5);
        } else {
            yPosition = this.addContent("No significant differences found.", yPosition + 5);
        }
        
        // Check if we need a new page
        if (yPosition > 250) {
            this.addPageNumber(page);
            this.pdf.addPage();
            page++;
            yPosition = 20;
        }
        
        // Key Similarities
        yPosition = this.addSectionTitle("Key Similarities", yPosition + 10);
        if (data.key_similarities && data.key_similarities.length > 0) {
            yPosition = this.addBulletList(data.key_similarities, yPosition + 5);
        } else {
            yPosition = this.addContent("No significant similarities found.", yPosition + 5);
        }

        // Check if we need a new page
        if (yPosition > 250) {
            this.addPageNumber(page);
            this.pdf.addPage();
            page++;
            yPosition = 20;
        }

        // Security Implications
        yPosition = this.addSectionTitle("Security Implications", yPosition + 10);
        if (data.security_implications && data.security_implications.length > 0) {
            yPosition = this.addBulletList(data.security_implications, yPosition + 5);
        } else {
            yPosition = this.addContent("N/A", yPosition + 5);
        }

        // Check if we need a new page
        if (yPosition > 250) {
            this.addPageNumber(page);
            this.pdf.addPage();
            page++;
            yPosition = 20;
        }

        // Important Timestamps
        yPosition = this.addSectionTitle("Important Timestamps/Packets", yPosition + 10);
        yPosition = this.addContent(data.important_timestamps_packets || 'N/A', yPosition + 5);
        
        // Add page number to the last page
        this.addPageNumber(page);
        
        // Save the PDF
        this.pdf.save(`comparison-report-${file1Name}-vs-${file2Name}.pdf`);
    }
}
