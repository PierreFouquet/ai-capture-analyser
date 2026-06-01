import { describe, it, expect } from 'vitest';
import { escapeHtml } from '../public/escape.js';

describe('escapeHtml', () => {
    it('escapes all HTML-significant characters', () => {
        expect(escapeHtml(`<script>"&'`)).toBe('&lt;script&gt;&quot;&amp;&#39;');
    });

    it('neutralises a script-injection payload', () => {
        const out = escapeHtml('<img src=x onerror=alert(1)>');
        expect(out).not.toContain('<img');
        expect(out).toContain('&lt;img');
    });

    it('coerces null/undefined to an empty string', () => {
        expect(escapeHtml(null)).toBe('');
        expect(escapeHtml(undefined)).toBe('');
    });

    it('stringifies non-string values', () => {
        expect(escapeHtml(42)).toBe('42');
    });
});
