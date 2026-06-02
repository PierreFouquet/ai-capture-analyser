// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ChartRenderer } from '../public/chartRenderer.js';

// Capture the config every `new Chart(...)` is constructed with.
const charts = [];

class FakeChart {
    constructor(ctx, config) {
        this.ctx = ctx;
        this.config = config;
        this.destroyed = false;
        charts.push(this);
    }
    destroy() {
        this.destroyed = true;
    }
}

function addCanvas(id) {
    const canvas = document.createElement('canvas');
    canvas.id = id;
    canvas.getContext = () => ({}); // jsdom has no real 2d context
    document.body.appendChild(canvas);
    return canvas;
}

beforeEach(() => {
    charts.length = 0;
    vi.stubGlobal('Chart', FakeChart);
});

afterEach(() => {
    document.body.innerHTML = '';
    vi.unstubAllGlobals();
});

describe('createProtocolChart', () => {
    it('builds a doughnut chart from the protocol map', () => {
        addCanvas('protocol-chart');
        new ChartRenderer().createProtocolChart({ TCP: 60, UDP: 40 }, 'protocol-chart');

        expect(charts).toHaveLength(1);
        expect(charts[0].config.type).toBe('doughnut');
        expect(charts[0].config.data.labels).toEqual(['TCP', 'UDP']);
        expect(charts[0].config.data.datasets[0].data).toEqual([60, 40]);
    });

    it('does nothing when protocol data is missing', () => {
        addCanvas('protocol-chart');
        const result = new ChartRenderer().createProtocolChart(null, 'protocol-chart');
        expect(result).toBeUndefined();
        expect(charts).toHaveLength(0);
    });

    it('returns null when the canvas is absent', () => {
        const result = new ChartRenderer().createProtocolChart({ TCP: 1 }, 'missing');
        expect(result).toBeNull();
    });

    it('assigns a colour to every slice even with more protocols than the palette', () => {
        addCanvas('protocol-chart');
        const many = { TCP: 1, UDP: 1, SIP: 1, RTP: 1, DNS: 1, HTTP: 1, TLS: 1, ICMP: 1 }; // 8 > 6 colours
        new ChartRenderer().createProtocolChart(many, 'protocol-chart');
        const ds = charts[0].config.data.datasets[0];
        expect(ds.backgroundColor).toHaveLength(8);
        expect(ds.backgroundColor.every((c) => typeof c === 'string')).toBe(true);
        expect(ds.borderColor).toHaveLength(8);
    });
});

describe('createComparisonChart', () => {
    it('builds a grouped bar chart over the union of protocols', () => {
        addCanvas('cmp');
        new ChartRenderer().createComparisonChart({ TCP: 10 }, { UDP: 20 }, 'cmp', 'A', 'B');

        expect(charts[0].config.type).toBe('bar');
        expect(charts[0].config.data.labels.sort()).toEqual(['TCP', 'UDP']);
        expect(charts[0].config.data.datasets.map((d) => d.label)).toEqual(['A', 'B']);
    });

    it('returns null when the canvas is absent', () => {
        expect(new ChartRenderer().createComparisonChart({}, {}, 'nope', 'A', 'B')).toBeNull();
    });

    it('survives a one-sided null without throwing (regression)', () => {
        addCanvas('cmp');
        expect(() =>
            new ChartRenderer().createComparisonChart(null, { TCP: 10 }, 'cmp', 'A', 'B')
        ).not.toThrow();
        expect(charts[0].config.data.labels).toEqual(['TCP']);
        // The null side contributes 0 for every protocol.
        expect(charts[0].config.data.datasets[0].data).toEqual([0]);
        expect(charts[0].config.data.datasets[1].data).toEqual([10]);
    });
});

describe('createTimelineChart', () => {
    it('builds a line chart', () => {
        addCanvas('tl');
        new ChartRenderer().createTimelineChart({ '0s': 1, '5s': 2 }, 'tl');
        expect(charts[0].config.type).toBe('line');
    });

    it('returns null when the canvas is absent', () => {
        expect(new ChartRenderer().createTimelineChart({}, 'nope')).toBeNull();
    });

    it('tooltip formatter renders protocol percentages', () => {
        addCanvas('protocol-chart');
        new ChartRenderer().createProtocolChart({ TCP: 60 }, 'protocol-chart');
        const fmt = charts[0].config.options.plugins.tooltip.callbacks.label;
        expect(fmt({ label: 'TCP', raw: 60 })).toBe('TCP: 60.00%');
    });
});

describe('destroyChart', () => {
    it('destroys a chart instance and tolerates null', () => {
        const renderer = new ChartRenderer();
        const fake = new FakeChart({}, {});
        renderer.destroyChart(fake);
        expect(fake.destroyed).toBe(true);
        expect(() => renderer.destroyChart(null)).not.toThrow();
    });
});
