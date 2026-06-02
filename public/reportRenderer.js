// Report rendering utilities
import { ChartRenderer } from './chartRenderer.js';
import { escapeHtml } from './escape.js';

export class ReportRenderer {
    constructor() {
        this.chartRenderer = new ChartRenderer();
    }

    // Render the AI's issues_and_recommendations list. Each entry is normally an
    // object { issue, likely_cause, suggested_resolution }, but tolerate plain
    // strings too. Everything is escaped before injection.
    renderIssues(issues) {
        if (!Array.isArray(issues) || issues.length === 0) {
            return '<p class="text-gray-600">No issues identified.</p>';
        }
        return `<ul class="list-disc list-inside text-gray-600 space-y-2">
            ${issues.map((item) => {
                if (item && typeof item === 'object') {
                    const issue = escapeHtml(item.issue ?? 'Issue');
                    const cause = escapeHtml(item.likely_cause ?? 'Unknown');
                    const fix = escapeHtml(item.suggested_resolution ?? 'N/A');
                    return `<li><span class="font-medium">${issue}</span><br>
                        <span class="text-gray-500">Likely cause:</span> ${cause}<br>
                        <span class="text-gray-500">Suggested fix:</span> ${fix}</li>`;
                }
                return `<li>${escapeHtml(item)}</li>`;
            }).join('')}
        </ul>`;
    }

    // Extra "Key Statistics" rows derived from the real parsed capture stats.
    renderCaptureStatRows(stats) {
        if (!stats) return '';
        const rows = [];
        if (stats.packetSizeBytes) {
            rows.push(`<li>Avg Packet Size: ${escapeHtml(stats.packetSizeBytes.average)} bytes</li>`);
        }
        if (stats.throughput && stats.throughput.packetsPerSecond != null) {
            rows.push(`<li>Throughput: ${escapeHtml(stats.throughput.packetsPerSecond)} packets/s</li>`);
        }
        if (stats.endpoints) {
            rows.push(`<li>Unique Hosts: ${escapeHtml(stats.endpoints.unique)}</li>`);
        }
        if (stats.conversations) {
            rows.push(`<li>Conversations: ${escapeHtml(stats.conversations.unique)}</li>`);
        }
        if (stats.tcpFlags) {
            const { syn, synAck, rst } = stats.tcpFlags;
            rows.push(`<li>TCP: ${escapeHtml(syn)} SYN / ${escapeHtml(synAck)} SYN-ACK / ${escapeHtml(rst)} RST</li>`);
        }
        return rows.join('');
    }

    // A "Top Talkers" section from the real parsed endpoint counts.
    renderTopTalkers(stats) {
        const top = stats?.endpoints?.top || [];
        if (top.length === 0) return '';
        return `
            <div class="mb-6">
                <h4 class="font-medium text-gray-700 mb-2">Top Talkers</h4>
                <ul class="list-disc list-inside text-gray-600">
                    ${top.map((t) => `<li>${escapeHtml(t.name)} — ${escapeHtml(t.count)} packets</li>`).join('')}
                </ul>
            </div>`;
    }

    renderAnalysisReport(data, fileName) {
        // Defensive programming: ensure data exists and has expected structure
        const safeData = data || {};
        const protocolDistribution = safeData.protocol_distribution || {};
        const anomalies = safeData.anomalies_and_errors || [];
        const sipRtpInfo = safeData.sip_rtp_info || 'N/A';
        const timestamps = safeData.important_timestamps_packets || 'N/A';
        const summary = safeData.summary || 'No summary available.';
        const trafficHealth = safeData.traffic_health || 'No connection-health assessment available.';
        const securityAssessment = safeData.security_assessment || 'No security assessment available.';
        const captureStats = safeData.capture_stats || null;

        // Safely format numbers with fallbacks (0 is a valid value, not "N/A").
        const packetCount = safeData.packetCount != null ? safeData.packetCount.toLocaleString() : 'N/A';
        const duration = safeData.duration != null ? `${safeData.duration}s` : 'N/A';

        const html = `
            <div class="report-analysis">
                <h3 class="text-xl font-semibold text-gray-800 mb-4">Analysis Report: ${escapeHtml(fileName)}</h3>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div class="bg-gray-50 p-4 rounded-lg">
                        <h4 class="font-medium text-gray-700 mb-2">Summary</h4>
                        <p class="text-gray-600">${escapeHtml(summary)}</p>
                    </div>

                    <div class="bg-gray-50 p-4 rounded-lg">
                        <h4 class="font-medium text-gray-700 mb-2">Key Statistics</h4>
                        <ul class="text-gray-600">
                            <li>Packet Count: ${escapeHtml(packetCount)}</li>
                            <li>Duration: ${escapeHtml(duration)}</li>
                            <li>SIP/RTP Info: ${escapeHtml(sipRtpInfo)}</li>
                            ${this.renderCaptureStatRows(captureStats)}
                        </ul>
                    </div>
                </div>

                <div class="mb-6">
                    <h4 class="font-medium text-gray-700 mb-2">Protocol Distribution</h4>
                    <div class="h-64">
                        <canvas id="protocol-chart"></canvas>
                    </div>
                </div>

                ${this.renderTopTalkers(captureStats)}

                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div class="bg-gray-50 p-4 rounded-lg">
                        <h4 class="font-medium text-gray-700 mb-2">Traffic Health</h4>
                        <p class="text-gray-600">${escapeHtml(trafficHealth)}</p>
                    </div>
                    <div class="bg-gray-50 p-4 rounded-lg">
                        <h4 class="font-medium text-gray-700 mb-2">Security Assessment</h4>
                        <p class="text-gray-600">${escapeHtml(securityAssessment)}</p>
                    </div>
                </div>

                <div class="mb-6">
                    <h4 class="font-medium text-gray-700 mb-2">Anomalies & Errors</h4>
                    ${anomalies.length > 0 ?
                        `<ul class="list-disc list-inside text-gray-600">
                            ${anomalies.map(anomaly => `<li>${escapeHtml(anomaly)}</li>`).join('')}
                        </ul>` :
                        '<p class="text-gray-600">No anomalies detected.</p>'
                    }
                </div>

                <div class="mb-6">
                    <h4 class="font-medium text-gray-700 mb-2">Issues & Recommendations</h4>
                    ${this.renderIssues(safeData.issues_and_recommendations)}
                </div>

                <div class="mb-6">
                    <h4 class="font-medium text-gray-700 mb-2">Important Timestamps/Packets</h4>
                    <p class="text-gray-600">${escapeHtml(timestamps)}</p>
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

    renderComparisonReport(data, file1Name, file2Name, stats1, stats2) {
        // Defensive programming: ensure data exists and has expected structure
        const safeData = data || {};
        const keyDifferences = safeData.key_differences || [];
        const keySimilarities = safeData.key_similarities || [];
        const securityImplications = safeData.security_implications || [];
        const timestamps = safeData.important_timestamps_packets || 'N/A';
        const summary = safeData.overall_comparison_summary || 'No comparison summary available.';

        // Draw the real protocol comparison chart only when we have both captures' stats.
        const dist1 = stats1?.protocolDistribution;
        const dist2 = stats2?.protocolDistribution;
        const showChart = !!(dist1 || dist2);

        const html = `
            <div class="report-comparison">
                <h3 class="text-xl font-semibold text-gray-800 mb-4">Comparison Report: ${escapeHtml(file1Name)} vs ${escapeHtml(file2Name)}</h3>

                <div class="mb-6">
                    <h4 class="font-medium text-gray-700 mb-2">Overall Comparison Summary</h4>
                    <p class="text-gray-600">${escapeHtml(summary)}</p>
                </div>

                ${showChart ? `
                <div class="mb-6">
                    <h4 class="font-medium text-gray-700 mb-2">Protocol Distribution</h4>
                    <div class="h-64">
                        <canvas id="comparison-chart"></canvas>
                    </div>
                </div>` : ''}

                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div class="bg-gray-50 p-4 rounded-lg">
                        <h4 class="font-medium text-gray-700 mb-2">Key Differences</h4>
                        ${keyDifferences.length > 0 ?
                            `<ul class="list-disc list-inside text-gray-600">
                                ${keyDifferences.map(diff => `<li>${escapeHtml(diff)}</li>`).join('')}
                            </ul>` :
                            '<p class="text-gray-600">No significant differences found.</p>'
                        }
                    </div>

                    <div class="bg-gray-50 p-4 rounded-lg">
                        <h4 class="font-medium text-gray-700 mb-2">Key Similarities</h4>
                        ${keySimilarities.length > 0 ?
                            `<ul class="list-disc list-inside text-gray-600">
                                ${keySimilarities.map(sim => `<li>${escapeHtml(sim)}</li>`).join('')}
                            </ul>` :
                            '<p class="text-gray-600">No significant similarities found.</p>'
                        }
                    </div>
                </div>

                <div class="mb-6">
                    <h4 class="font-medium text-gray-700 mb-2">Security Implications</h4>
                    ${securityImplications.length > 0 ?
                        `<ul class="list-disc list-inside text-gray-600">
                            ${securityImplications.map(impl => `<li>${escapeHtml(impl)}</li>`).join('')}
                        </ul>` :
                        '<p class="text-gray-600">No security implications identified.</p>'
                    }
                </div>

                <div class="mb-6">
                    <h4 class="font-medium text-gray-700 mb-2">Issues & Recommendations</h4>
                    ${this.renderIssues(safeData.issues_and_recommendations)}
                </div>

                <div class="mb-6">
                    <h4 class="font-medium text-gray-700 mb-2">Important Timestamps/Packets</h4>
                    <p class="text-gray-600">${escapeHtml(timestamps)}</p>
                </div>
            </div>
        `;

        return {
            html,
            postRender: () => {
                if (showChart) {
                    this.chartRenderer.createComparisonChart(
                        dist1 || {}, dist2 || {}, 'comparison-chart', file1Name, file2Name
                    );
                }
            }
        };
    }
}
