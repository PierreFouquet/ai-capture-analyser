// PDF export utilities
export class PDFExporter {
    constructor() {
        this.pdf = null;
        this.page = 1;
    }

    initPDF() {
        this.pdf = new jspdf.jsPDF({
            orientation: 'portrait',
            unit: 'mm',
            format: 'a4'
        });

        this.page = 1;
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

    // Render the AI's issues_and_recommendations: each entry is normally an
    // object { issue, likely_cause, suggested_resolution }; tolerate strings too.
    addIssues(issues, yPosition) {
        if (!Array.isArray(issues) || issues.length === 0) {
            return this.addContent('No issues identified.', yPosition);
        }
        let currentY = yPosition;
        issues.forEach(item => {
            if (item && typeof item === 'object') {
                currentY = this.addBulletList([`Issue: ${item.issue ?? 'Issue'}`], currentY);
                currentY = this.addContent(`Likely cause: ${item.likely_cause ?? 'Unknown'}`, currentY, 160);
                currentY = this.addContent(`Suggested fix: ${item.suggested_resolution ?? 'N/A'}`, currentY, 160);
            } else {
                currentY = this.addBulletList([String(item)], currentY);
            }
            currentY = this.checkPageBreak(currentY);
        });
        return currentY;
    }

    addPageNumber(page) {
        this.pdf.setFontSize(10);
        this.pdf.setTextColor(150, 150, 150);
        this.pdf.text(`Page ${page}`, 105, 280, { align: 'center' });
        this.pdf.setTextColor(50, 50, 50);
    }

    // Start a new page when the cursor nears the bottom margin.
    checkPageBreak(yPosition) {
        if (yPosition > 250) {
            this.addPageNumber(this.page);
            this.pdf.addPage();
            this.page++;
            return 20;
        }
        return yPosition;
    }

    // Top talkers pulled from the real parsed capture stats (analysis only).
    topTalkerLines(captureStats) {
        const top = captureStats?.endpoints?.top || [];
        return top.map(t => `${t.name} — ${t.count} packets`);
    }

    exportAnalysisReport(data, fileName) {
        this.initPDF();
        const safe = data || {};
        let yPosition = this.addTitle(`Analysis Report: ${fileName}`);

        // Summary
        yPosition = this.addSectionTitle("Summary", yPosition + 10);
        yPosition = this.addContent(safe.summary || 'No summary available.', yPosition + 5);
        yPosition = this.checkPageBreak(yPosition);

        // Traffic Health
        yPosition = this.addSectionTitle("Traffic Health", yPosition + 10);
        yPosition = this.addContent(safe.traffic_health || 'N/A', yPosition + 5);
        yPosition = this.checkPageBreak(yPosition);

        // Security Assessment
        yPosition = this.addSectionTitle("Security Assessment", yPosition + 10);
        yPosition = this.addContent(safe.security_assessment || 'N/A', yPosition + 5);
        yPosition = this.checkPageBreak(yPosition);

        // Top Talkers (from the real parsed stats, if present)
        const talkers = this.topTalkerLines(safe.capture_stats);
        if (talkers.length > 0) {
            yPosition = this.addSectionTitle("Top Talkers", yPosition + 10);
            yPosition = this.addBulletList(talkers, yPosition + 5);
            yPosition = this.checkPageBreak(yPosition);
        }

        // Anomalies and Errors
        yPosition = this.addSectionTitle("Anomalies and Errors", yPosition + 10);
        if (safe.anomalies_and_errors && safe.anomalies_and_errors.length > 0) {
            yPosition = this.addBulletList(safe.anomalies_and_errors, yPosition + 5);
        } else {
            yPosition = this.addContent("N/A", yPosition + 5);
        }
        yPosition = this.checkPageBreak(yPosition);

        // Issues and Recommendations
        yPosition = this.addSectionTitle("Issues and Recommendations", yPosition + 10);
        yPosition = this.addIssues(safe.issues_and_recommendations, yPosition + 5);
        yPosition = this.checkPageBreak(yPosition);

        // SIP/RTP Information
        yPosition = this.addSectionTitle("SIP/RTP Information", yPosition + 10);
        yPosition = this.addContent(safe.sip_rtp_info || 'N/A', yPosition + 5);
        yPosition = this.checkPageBreak(yPosition);

        // Important Timestamps/Packets
        yPosition = this.addSectionTitle("Important Timestamps/Packets", yPosition + 10);
        yPosition = this.addContent(safe.important_timestamps_packets || 'N/A', yPosition + 5);

        this.addPageNumber(this.page);
        this.pdf.save(`analysis-report-${fileName}.pdf`);
    }

    exportComparisonReport(data, file1Name, file2Name) {
        this.initPDF();
        const safe = data || {};
        let yPosition = this.addTitle(`Comparison Report: ${file1Name} vs ${file2Name}`);

        // Summary
        yPosition = this.addSectionTitle("Overall Comparison Summary", yPosition + 10);
        yPosition = this.addContent(safe.overall_comparison_summary || 'No summary available.', yPosition + 5);
        yPosition = this.checkPageBreak(yPosition);

        // Key Differences
        yPosition = this.addSectionTitle("Key Differences", yPosition + 10);
        if (safe.key_differences && safe.key_differences.length > 0) {
            yPosition = this.addBulletList(safe.key_differences, yPosition + 5);
        } else {
            yPosition = this.addContent("No significant differences found.", yPosition + 5);
        }
        yPosition = this.checkPageBreak(yPosition);

        // Key Similarities
        yPosition = this.addSectionTitle("Key Similarities", yPosition + 10);
        if (safe.key_similarities && safe.key_similarities.length > 0) {
            yPosition = this.addBulletList(safe.key_similarities, yPosition + 5);
        } else {
            yPosition = this.addContent("No significant similarities found.", yPosition + 5);
        }
        yPosition = this.checkPageBreak(yPosition);

        // Security Implications
        yPosition = this.addSectionTitle("Security Implications", yPosition + 10);
        if (safe.security_implications && safe.security_implications.length > 0) {
            yPosition = this.addBulletList(safe.security_implications, yPosition + 5);
        } else {
            yPosition = this.addContent("N/A", yPosition + 5);
        }
        yPosition = this.checkPageBreak(yPosition);

        // Issues and Recommendations
        yPosition = this.addSectionTitle("Issues and Recommendations", yPosition + 10);
        yPosition = this.addIssues(safe.issues_and_recommendations, yPosition + 5);
        yPosition = this.checkPageBreak(yPosition);

        // Important Timestamps
        yPosition = this.addSectionTitle("Important Timestamps/Packets", yPosition + 10);
        yPosition = this.addContent(safe.important_timestamps_packets || 'N/A', yPosition + 5);

        this.addPageNumber(this.page);
        this.pdf.save(`comparison-report-${file1Name}-vs-${file2Name}.pdf`);
    }
}
