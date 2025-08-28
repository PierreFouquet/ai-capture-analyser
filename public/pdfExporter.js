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

    addBulletList(items, yPosition, maxWidth = 170) {
        this.pdf.setFontSize(12);
        let currentY = yPosition;
        
        items.forEach(item => {
            const bullet = "• ";
            const bulletWidth = this.pdf.getTextWidth(bullet);
            const text = bullet + item;
            const lines = this.pdf.splitTextToSize(text, maxWidth);
            
            // Handle first line with bullet
            this.pdf.text(bullet, 20, currentY + 5);
            this.pdf.text(lines[0].substring(bullet.length), 20 + bulletWidth, currentY + 5);
            
            // Handle remaining lines
            for (let i = 1; i < lines.length; i++) {
                currentY += 6;
                this.pdf.text(lines[i], 20 + bulletWidth, currentY + 5);
            }
            
            currentY += 8;
        });
        
        return currentY;
    }

    addHorizontalLine(yPosition) {
        this.pdf.setDrawColor(200, 200, 200);
        this.pdf.line(20, yPosition, 190, yPosition);
        return yPosition + 5;
    }

    addPageNumber(pageNumber) {
        this.pdf.setFontSize(10);
        this.pdf.text(`Page ${pageNumber}`, 105, 280, { align: 'center' });
    }

    exportAnalysisReport(data, fileName) {
        this.initPDF();
        let yPosition = 20;
        let page = 1;
        
        // Title
        yPosition = this.addTitle(`PCAP Analysis Report: ${fileName}`, yPosition);
        yPosition = this.addHorizontalLine(yPosition);
        
        // Summary section
        yPosition = this.addSectionTitle("Summary", yPosition + 10);
        yPosition = this.addContent(data.summary || 'No summary available.', yPosition + 5);
        
        // Check if we need a new page
        if (yPosition > 250) {
            this.addPageNumber(page);
            this.pdf.addPage();
            page++;
            yPosition = 20;
        }
        
        // Protocol Distribution
        yPosition = this.addSectionTitle("Protocol Distribution", yPosition + 10);
        const protocolText = Object.entries(data.protocolDistribution)
            .map(([protocol, percentage]) => `${protocol}: ${percentage}%`)
            .join(', ');
        yPosition = this.addContent(protocolText, yPosition + 5);
        
        // Check if we need a new page
        if (yPosition > 250) {
            this.addPageNumber(page);
            this.pdf.addPage();
            page++;
            yPosition = 20;
        }
        
        // Anomalies and Errors
        yPosition = this.addSectionTitle("Anomalies and Errors", yPosition + 10);
        if (data.anomalies && data.anomalies.length > 0) {
            yPosition = this.addBulletList(
                data.anomalies.map(a => `${a.time}: ${a.description} (${a.severity} severity)`),
                yPosition + 5
            );
        } else {
            yPosition = this.addContent("No significant anomalies detected.", yPosition + 5);
        }
        
        // Add page number to the last page
        this.addPageNumber(page);
        
        // Save the PDF
        this.pdf.save(`pcap-analysis-${fileName}-${new Date().toISOString().split('T')[0]}.pdf`);
    }

    exportComparisonReport(data, file1Name, file2Name) {
        this.initPDF();
        let yPosition = 20;
        let page = 1;
        
        // Title
        yPosition = this.addTitle(`PCAP Comparison Report: ${file1Name} vs ${file2Name}`, yPosition);
        yPosition = this.addHorizontalLine(yPosition);
        
        // Summary section
        yPosition = this.addSectionTitle("Comparison Summary", yPosition + 10);
        yPosition = this.addContent(data.summary || 'No summary available.', yPosition + 5);
        
        // Check if we need a new page
        if (yPosition > 250) {
            this.addPageNumber(page);
            this.pdf.addPage();
            page++;
            yPosition = 20;
        }
        
        // Key Differences
        yPosition = this.addSectionTitle("Key Differences", yPosition + 10);
        if (data.differences && data.differences.length > 0) {
            yPosition = this.addBulletList(data.differences, yPosition + 5);
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
        if (data.similarities && data.similarities.length > 0) {
            yPosition = this.addBulletList(data.similarities, yPosition + 5);
        } else {
            yPosition = this.addContent("No significant similarities found.", yPosition + 5);
        }
        
        // Add page number to the last page
        this.addPageNumber(page);
        
        // Save the PDF
        this.pdf.save(`pcap-comparison-${file1Name}-vs-${file2Name}-${new Date().toISOString().split('T')[0]}.pdf`);
    }
}