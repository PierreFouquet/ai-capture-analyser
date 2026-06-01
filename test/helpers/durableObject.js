// In-memory fakes for the Durable Object runtime, so AnalysisObject can be
// exercised without the Workers platform.

/** A fake DurableObjectState backed by a Map, recording waitUntil promises. */
export function createFakeState(initial = {}) {
    const store = new Map(Object.entries(initial));
    const waited = [];
    let alarm = null;

    const storage = {
        async get(key) {
            return store.get(key);
        },
        async put(key, value) {
            if (typeof key === 'object' && key !== null) {
                for (const [k, v] of Object.entries(key)) store.set(k, v);
            } else {
                store.set(key, value);
            }
        },
        async delete(key) {
            store.delete(key);
        },
        async deleteAll() {
            store.clear();
        },
        async setAlarm(ts) {
            alarm = ts;
        },
        async getAlarm() {
            return alarm;
        },
    };

    return {
        storage,
        async blockConcurrencyWhile(fn) {
            return fn();
        },
        waitUntil(promise) {
            waited.push(promise);
        },
        // Test-only accessors.
        _store: store,
        _waited: waited,
        get _alarm() {
            return alarm;
        },
        async _settleBackground() {
            await Promise.allSettled(waited);
        },
    };
}

/** Build a fake Env with a stubbed AI binding. */
export function createFakeEnv(aiRun) {
    return {
        AI: { run: aiRun },
        ANALYSIS_OBJECT: {},
        ASSETS: {},
    };
}

/** Convenience for a JSON POST request to the Durable Object. */
export function jsonRequest(url, body) {
    return new Request(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
}

/** Flush pending microtasks (e.g. the constructor's async state restore). */
export const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
