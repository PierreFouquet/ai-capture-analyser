# AI Capture Analyser

A [Cloudflare Worker](https://developers.cloudflare.com/workers/) that analyses and
compares network packet captures (`.pcap` / `.pcapng`) using
[Workers AI](https://developers.cloudflare.com/workers-ai/). Upload a capture and a
large language model produces a plain‑English report; upload two and it compares them.

## How it works

1. **The browser parses the capture.** `public/pcapParser.js` reads the file locally and
   extracts aggregate statistics (packet count, duration, protocol distribution, SIP/RTP
   signals). **Raw packets never leave your machine** — only the summary is sent on.
2. **The Worker prompts the model.** The summary is POSTed to `/api/analyze`. A
   [Durable Object](https://developers.cloudflare.com/durable-objects/) runs the chosen
   model via the `AI` binding, polling‑based so long‑running models don't time out the
   request. State is cleaned up automatically after 6 hours of inactivity.
3. **The report is rendered.** Protocol distribution is charted from the *real* parsed
   numbers; the narrative (summary, anomalies, SIP/RTP notes) comes from the model. Reports
   export to PDF or JSON.

## Models

All models are hosted on Cloudflare Workers AI (latest generation only). The selectable
list and default live in `public/config.js`; see [`src/config.ts`](src/config.ts) for the
server‑side prompts. Current line‑up: Moonshot Kimi K2.6, NVIDIA Nemotron 3, OpenAI
gpt‑oss 120b/20b, Google Gemma 4 (default), Meta Llama 4 Scout, Zhipu GLM‑4.7 Flash and
Qwen3 30b.

## Project layout

| Path | Purpose |
| --- | --- |
| `src/index.ts` | Worker entry + `AnalysisObject` Durable Object |
| `src/analysis.ts` | Pure, tested helpers (response parsing, prompt building) |
| `src/config.ts` | Server‑side prompt templates and schemas |
| `public/` | Static frontend (parser, UI, renderers, PDF export) |
| `test/` | Vitest suite for both the Worker and the frontend |

## Development

```bash
npm install        # install dev tooling (wrangler, vitest, typescript…)
npm run dev        # run locally with wrangler
npm test           # run the test suite
npm run typecheck  # type-check the Worker
```

The frontend libraries (Chart.js, jsPDF, Tailwind) are loaded from a CDN at runtime, so
there is no frontend build step.

## Deployment

Deployment is handled by Cloudflare's **GitHub integration** (Workers Builds): merging to
`main` automatically builds and releases the Worker — there is no manual deploy step. A
`deploy` script (`wrangler deploy`) is available only as a local fallback.

## License

MIT — see [LICENSE](LICENSE).
