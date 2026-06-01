// Escape a value for safe interpolation into an HTML string.
//
// The report HTML is assembled with template literals and injected via
// innerHTML, so every dynamic value (AI-generated text, user-supplied file
// names) must be escaped to prevent cross-site scripting.
export function escapeHtml(value) {
    return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}
