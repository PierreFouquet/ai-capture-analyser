// Report rendering utilities
import { ChartRenderer } from './chartRenderer.js';

export class ReportRenderer {
    constructor() {
        this.chartRenderer = new ChartRenderer();
    }

    renderAnalysisReport(data, fileName) {
        // Defensive programming: ensure data exists and has expected structure
        const safeData = data || {};
        const protocolDistribution = safeData.protocol_distribution || {};
        const anomalies = safeData.anomalies_and_errors || [];
        const sipRtpInfo = safeData.sip_rtp_info || 'N/A';
        const timestamps = safeData.important_timestamps_packets || 'N/A';
        const summary = safeData.summary || 'No summary available.';
        
        // Safely format numbers with fallbacks
        const packetCount = safeData.packetCount ? safeData.packetCount.toLocaleString() : 'N/A';
        const duration = safeData.duration ? `${safeData.duration}s` : 'N/A';

        const html = `
            <div class="report-analysis">
                <h3 class="text-xl font-semibold text-gray-800 mb-4">Analysis Report: ${fileName}</h3>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div class="bg-gray-50 p-4 rounded-lg">
                        <h4 class="font-medium text-gray-700 mb-2">Summary</h4>
                        <p class="text-gray-600">${summary}</p>
                    </div>
                    
                    <div class="bg-gray-50 p-4 rounded-lg">
                        <h4 class="font-medium text-gray-700 mb-2">Key Statistics</h4>
                        <ul class="text-gray-600">
                            <li>Packet Count: ${packetCount}</li>
                            <li>Duration: ${duration}</li>
                            <li>SIP/RTP Info: ${sipRtpInfo}</li>
                        </ul>
                    </div>
                </div>
                
                <div class="mb-6">
                    <h4 class="font-medium text-gray-700 mb-2">Protocol Distribution</h4>
                    <div class="h-64">
                        <canvas id="protocol-chart"></canvas>
                    </div>
                </div>
                
                <div class="mb-6">
                    <h4 class="font-medium text-gray-700 mb-2">Anomalies & Errors</h4>
                    ${anomalies.length > 0 ? 
                        `<ul class="list-disc list-inside text-gray-600">
                            ${anomalies.map(anomaly => `<li>${anomaly}</li>`).join('')}
                        </ul>` : 
                        '<p class="text-gray-600">No anomalies detected.</p>'
                    }
                </div>
                
                <div class="mb-6">
                    <h4 class="font-medium text-gray-700 mb-2">Important Timestamps/Packets</h4>
                    <p class="text-gray-600">${timestamps}</p>
                </div>
            </div>
        `;

        return {
            html,
            postRender: () => {
                // Only create chart if we have protocol data
                if (Object.keys(protocolDistribution).length > 0) {
                    this.chartRenderer.createProtocolChart(protocolDistribution, 'protocol-chart');
                }
            }
        };
    }

    renderComparisonReport(data, file1Name, file2Name) {
        // Defensive programming: ensure data exists and has expected structure
        const safeData = data || {};
        const keyDifferences = safeData.key_differences || [];
        const keySimilarities = safeData.key_similarities || [];
        const securityImplications = safeData.security_implications || [];
        const timestamps = safeData.important_timestamps_packets || 'N/A';
        const summary = safeData.overall_comparison_summary || 'No comparison summary available.';

        const html = `
            <div class="report-comparison">
                <h3 class="text-xl font-semibold text-gray-800 mb-4">Comparison Report: ${file1Name} vs ${file2Name}</h3>
                
                <div class="mb-6">
                    <h4 class="font-medium text-gray-700 mb-2">Overall Comparison Summary</h4>
                    <p class="text-gray-600">${summary}</p>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div class="bg-gray-50 p-4 rounded-lg">
                        <h4 class="font-medium text-gray-700 mb-2">Key Differences</h4>
                        ${keyDifferences.length > 0 ? 
                            `<ul class="list-disc list-inside text-gray-600">
                                ${keyDifferences.map(diff => `<li>${diff}</li>`).join('')}
                            </ul>` : 
                            '<p class="text-gray-600">No significant differences found.</p>'
                        }
                    </div>
                    
                    <div class="bg-gray-50 p-4 rounded-lg">
                        <h4 class="font-medium text-gray-700 mb-2">Key Similarities</h4>
                        ${keySimilarities.length > 0 ? 
                            `<ul class="list-disc list-inside text-gray-600">
                                ${keySimilarities.map(sim => `<li>${sim}</li>`).join('')}
                            </ul>` : 
                            '<p class="text-gray-600">No significant similarities found.</p>'
                        }
                    </div>
                </div>
                
                <div class="mb-6">
                    <h4 class="font-medium text-gray-700 mb-2">Security Implications</h4>
                    ${securityImplications.length > 0 ? 
                        `<ul class="list-disc list-inside text-gray-600">
                            ${securityImplications.map(impl => `<li>${impl}</li>`).join('')}
                        </ul>` : 
                        '<p class="text-gray-600">No security implications identified.</p>'
                    }
                </div>
                
                <div class="mb-6">
                    <h4 class="font-medium text-gray-700 mb-2">Important Timestamps/Packets</h4>
                    <p class="text-gray-600">${timestamps}</p>
                </div>
            </div>
        `;

        return {
            html,
            postRender: () => {
                // Comparison reports might not have protocol distribution charts
                // Add any post-render logic needed for comparison reports here
            }
        };
    }
}