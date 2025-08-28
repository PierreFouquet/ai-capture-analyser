// Report rendering utilities
import { ChartRenderer } from './chartRenderer.js';

export class ReportRenderer {
    constructor() {
        this.chartRenderer = new ChartRenderer();
    }

    renderAnalysisReport(data, fileName) {
        const html = `
            <div class="report-section fade-in">
                <h2 class="text-2xl font-bold text-gray-800 mb-6">Analysis Report: ${fileName}</h2>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div class="summary-card">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">Summary</h3>
                        <div class="flex flex-wrap mb-4">
                            <div class="w-1/2 mb-2">
                                <p class="text-sm text-gray-600">Total Packets</p>
                                <p class="text-lg font-semibold">${data.packetCount.toLocaleString()}</p>
                            </div>
                            <div class="w-1/2 mb-2">
                                <p class="text-sm text-gray-600">Duration</p>
                                <p class="text-lg font-semibold">${data.duration} seconds</p>
                            </div>
                            <div class="w-full">
                                <p class="text-sm text-gray-600">Overview</p>
                                <p class="text-base text-gray-800">${marked.parse(data.summary)}</p>
                            </div>
                        </div>
                    </div>
                    <div class="summary-card">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">Protocol Distribution</h3>
                        <div class="chart-container">
                            <canvas id="protocolChart"></canvas>
                        </div>
                    </div>
                </div>

                <div class="summary-card">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4">Timeline (Packets/Second)</h3>
                    <div class="chart-container">
                        <canvas id="timelineChart"></canvas>
                    </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div class="summary-card">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">Anomalies & Errors</h3>
                        <ul class="list-disc list-inside pl-5">
                            ${data.anomalies_and_errors && data.anomalies_and_errors.length > 0 ? 
                                data.anomalies_and_errors.map(anomaly => `<li class="text-gray-600 mb-2">${anomaly}</li>`).join('') :
                                '<li class="text-gray-600">No significant anomalies or errors found.</li>'
                            }
                        </ul>
                    </div>
                    <div class="summary-card">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">Details</h3>
                        <p class="text-gray-600 mb-2"><strong>SIP/RTP:</strong> ${data.sip_rtp_info || 'N/A'}</p>
                        <p class="text-gray-600"><strong>Important Timestamps:</strong> ${data.important_timestamps_packets || 'N/A'}</p>
                    </div>
                </div>
            </div>
        `;

        // The postRender function will be executed after the HTML is injected into the DOM
        const postRender = () => {
            this.chartRenderer.createProtocolChart(data.protocolDistribution, 'protocolChart');
            this.chartRenderer.createTimelineChart(data.timeline, 'timelineChart');
        };

        return { html, postRender };
    }

    renderComparisonReport(data, file1Name, file2Name) {
        const html = `
            <div class="report-section fade-in">
                <h2 class="text-2xl font-bold text-gray-800 mb-6">Comparison Report: ${file1Name} vs ${file2Name}</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div class="summary-card">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">Summary</h3>
                        <p class="text-gray-800">${data.overall_comparison_summary}</p>
                    </div>
                    <div class="summary-card">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">Protocol Distribution Comparison</h3>
                        <div class="chart-container">
                            <canvas id="comparisonChart"></canvas>
                        </div>
                    </div>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div class="summary-card">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">Protocol Distribution - ${file1Name}</h3>
                        <div class="chart-container">
                            <canvas id="protocolChart1"></canvas>
                        </div>
                    </div>
                    <div class="summary-card">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">Protocol Distribution - ${file2Name}</h3>
                        <div class="chart-container">
                            <canvas id="protocolChart2"></canvas>
                        </div>
                    </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div class="summary-card">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">Key Differences</h3>
                        <ul class="list-disc list-inside pl-5">
                            ${data.key_differences && data.key_differences.length > 0 ? 
                                data.key_differences.map(diff => `<li class="text-gray-600 mb-2">${diff}</li>`).join('') : 
                                '<li class="text-gray-600">No significant differences found.</li>'
                            }
                        </ul>
                    </div>
                    <div class="summary-card">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4">Key Similarities</h3>
                        <ul class="list-disc list-inside pl-5">
                            ${data.key_similarities && data.key_similarities.length > 0 ? 
                                data.key_similarities.map(sim => `<li class="text-gray-600 mb-2">${sim}</li>`).join('') : 
                                '<li class="text-gray-600">No significant similarities found.</li>'
                            }
                        </ul>
                    </div>
                </div>
            </div>
        `;
        
        return {
            html,
            postRender: () => {
                this.chartRenderer.createProtocolChart(data.file1.protocolDistribution, 'protocolChart1');
                this.chartRenderer.createProtocolChart(data.file2.protocolDistribution, 'protocolChart2');
                this.chartRenderer.createComparisonChart(
                    data.file1.protocolDistribution, 
                    data.file2.protocolDistribution, 
                    'comparisonChart',
                    file1Name,
                    file2Name
                );
            }
        };
    }
}
