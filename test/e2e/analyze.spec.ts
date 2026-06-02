import { test, expect, type Page } from '@playwright/test';
import { fileURLToPath } from 'node:url';

// Real fixtures parsed by the actual in-browser PcapParser.
const VOIP = fileURLToPath(new URL('../fixtures/voip-call.pcap', import.meta.url));
const VOIP2 = fileURLToPath(new URL('../fixtures/voip-call-2.pcap', import.meta.url));

const ANALYSIS_REPORT = {
    summary: 'E2E analysis summary.',
    protocol_distribution: { TCP: 50, UDP: 50 }, // overridden by the real parse
    traffic_health: 'Connections look healthy in this capture.',
    security_assessment: 'No notable security concerns.',
    anomalies_and_errors: ['One retransmission observed'],
    issues_and_recommendations: [
        { issue: 'Occasional jitter', likely_cause: 'Network congestion', suggested_resolution: 'Prioritise RTP with QoS' },
    ],
    sip_rtp_info: 'SIP INVITE/BYE with one RTP stream.',
    important_timestamps_packets: 'Call setup at t=0.',
};

const COMPARISON_REPORT = {
    overall_comparison_summary: 'E2E comparison summary.',
    key_differences: ['Capture 2 has a second RTP stream'],
    key_similarities: ['Both are SIP/RTP calls'],
    security_implications: [],
    issues_and_recommendations: [
        { issue: 'Asymmetric audio', likely_cause: 'One-way media path', suggested_resolution: 'Check NAT traversal' },
    ],
    important_timestamps_packets: 'N/A',
};

// Mock the polling backend so no Worker/Workers AI is needed. The frontend still
// does the real upload, parse, render and export.
async function mockBackend(page: Page, result: unknown, { statusDelayMs = 0 } = {}) {
    await page.route('**/api/analyze/status', async (route) => {
        if (statusDelayMs) await new Promise((r) => setTimeout(r, statusDelayMs));
        await route.fulfill({ json: { status: 'complete', result } });
    });
    await page.route('**/api/analyze', async (route) => {
        await route.fulfill({ status: 202, json: { status: 'processing' } });
    });
}

test('analyses a real capture end-to-end and renders the expanded report', async ({ page }) => {
    await mockBackend(page, ANALYSIS_REPORT);
    await page.goto('/');

    await page.setInputFiles('#pcap-file-1', VOIP);
    await page.click('#start-analysis-btn');

    const report = page.locator('#report-container');
    await expect(report).toContainText('Analysis Report: voip-call.pcap');
    await expect(report).toContainText('E2E analysis summary.');

    // New expanded sections are present.
    await expect(report).toContainText('Traffic Health');
    await expect(report).toContainText('Connections look healthy');
    await expect(report).toContainText('Security Assessment');
    await expect(report).toContainText('Issues & Recommendations');
    await expect(report).toContainText('Occasional jitter');
    await expect(report).toContainText('Prioritise RTP with QoS');

    // Real, in-browser-parsed figures (the fixture is 10 packets: 2 SIP + 8 RTP).
    await expect(report).toContainText('Packet Count: 10');
    await expect(report).toContainText('Top Talkers');

    // The protocol chart canvas was rendered.
    await expect(report.locator('#protocol-chart')).toBeVisible();

    // Export buttons appear once a report exists.
    await expect(page.locator('#export-buttons')).toBeVisible();
});

test('JSON export contains the real capture_stats and the new AI fields', async ({ page }) => {
    await mockBackend(page, ANALYSIS_REPORT);
    await page.goto('/');
    await page.setInputFiles('#pcap-file-1', VOIP);
    await page.click('#start-analysis-btn');
    await expect(page.locator('#export-buttons')).toBeVisible();

    const [download] = await Promise.all([
        page.waitForEvent('download'),
        page.click('#export-json'),
    ]);
    const stream = await download.createReadStream();
    const chunks: Buffer[] = [];
    for await (const c of stream) chunks.push(c as Buffer);
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf-8'));

    expect(parsed.type).toBe('analysis');
    expect(parsed.data.traffic_health).toBe('Connections look healthy in this capture.');
    expect(parsed.data.issues_and_recommendations[0].suggested_resolution).toBe('Prioritise RTP with QoS');
    // Real parsed stats are present in the export, not just the PDF/UI.
    expect(parsed.data.capture_stats.packetCount).toBe(10);
    expect(parsed.data.capture_stats.sipRtp.rtpPackets).toBe(8);
    expect(parsed.data.capture_stats.endpoints.unique).toBeGreaterThan(0);
});

test('compares two real captures and renders the comparison chart', async ({ page }) => {
    await mockBackend(page, COMPARISON_REPORT);
    await page.goto('/');

    await page.setInputFiles('#pcap-file-2', VOIP);
    await page.setInputFiles('#pcap-file-3', VOIP2);
    await page.click('#start-comparison-btn');

    const report = page.locator('#report-container');
    await expect(report).toContainText('Comparison Report: voip-call.pcap vs voip-call-2.pcap');
    await expect(report).toContainText('E2E comparison summary.');
    await expect(report).toContainText('Issues & Recommendations');
    await expect(report).toContainText('Asymmetric audio');
    // The real protocol-comparison chart canvas was rendered.
    await expect(report.locator('#comparison-chart')).toBeVisible();
});

test('disables the action button while a run is in flight (no double-submit)', async ({ page }) => {
    // Delay the status response so we can observe the busy state.
    await mockBackend(page, ANALYSIS_REPORT, { statusDelayMs: 1500 });
    await page.goto('/');
    await page.setInputFiles('#pcap-file-1', VOIP);

    await page.click('#start-analysis-btn');
    // While processing, the button is disabled — repeat clicks can't re-trigger.
    await expect(page.locator('#start-analysis-btn')).toBeDisabled();

    // After completion it is re-enabled and the report is shown.
    await expect(page.locator('#report-container')).toContainText('E2E analysis summary.');
    await expect(page.locator('#start-analysis-btn')).toBeEnabled();
});

test('shows an error message when the backend reports failure', async ({ page }) => {
    await page.route('**/api/analyze/status', async (route) => {
        await route.fulfill({ json: { status: 'error', error: 'model exploded' } });
    });
    await page.route('**/api/analyze', async (route) => {
        await route.fulfill({ status: 202, json: { status: 'processing' } });
    });
    await page.goto('/');
    await page.setInputFiles('#pcap-file-1', VOIP);
    await page.click('#start-analysis-btn');

    await expect(page.locator('#message-box')).toContainText('model exploded');
});
