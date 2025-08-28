// Report rendering utilities
// ChartRenderer is no longer needed here as the chart data is part of the LLM response
// and will be handled by the frontend.

export class ReportRenderer {
    renderAnalysisReport(data, fileName) {
        let anomaliesHtml = data.anomalies_and_errors.length > 0 ?
            `<ul>${data.anomalies_and_errors.map(item => `<li>${item}</li>`).join('')}</ul>` :
            '<p>N/A</p>';
        
        return `
            <div class="report-section fade-in">
                <h2 class="text-2xl font-bold text-gray-800 mb-6">Analysis Report: ${fileName}</h2>
                
                <div class="summary-card">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">Summary</h3>
                    <p>${data.summary}</p>
                </div>

                <div class="details-card">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">Anomalies and Errors</h3>
                    ${anomaliesHtml}
                </div>

                <div class="details-card">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">SIP/RTP Information</h3>
                    <p>${data.sip_rtp_info}</p>
                </div>

                <div class="details-card">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">Important Timestamps/Packets</h3>
                    <p>${data.important_timestamps_packets}</p>
                </div>
            </div>
        `;
    }

    renderComparisonReport(data, file1Name, file2Name) {
        let differencesHtml = data.key_differences.length > 0 ?
            `<ul>${data.key_differences.map(item => `<li>${item}</li>`).join('')}</ul>` :
            '<p>N/A</p>';
        
        let similaritiesHtml = data.key_similarities.length > 0 ?
            `<ul>${data.key_similarities.map(item => `<li>${item}</li>`).join('')}</ul>` :
            '<p>N/A</p>';
            
        let securityHtml = data.security_implications.length > 0 ?
            `<ul>${data.security_implications.map(item => `<li>${item}</li>`).join('')}</ul>` :
            '<p>N/A</p>';

        return `
            <div class="report-section fade-in">
                <h2 class="text-2xl font-bold text-gray-800 mb-6">Comparison Report: ${file1Name} vs ${file2Name}</h2>
                
                <div class="summary-card">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">Overall Summary</h3>
                    <p>${data.overall_comparison_summary}</p>
                </div>

                <div class="details-card">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">Key Differences</h3>
                    ${differencesHtml}
                </div>
                
                <div class="details-card">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">Key Similarities</h3>
                    ${similaritiesHtml}
                </div>

                <div class="details-card">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">Security Implications</h3>
                    ${securityHtml}
                </div>

                <div class="details-card">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">Important Timestamps/Packets</h3>
                    <p>${data.important_timestamps_packets}</p>
                </div>
            </div>
        `;
    }
}
