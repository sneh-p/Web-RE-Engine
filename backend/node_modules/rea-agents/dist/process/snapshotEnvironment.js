/** Snapshot caller-selected variables using Node child-process key semantics. */
export const snapshotEnvironment = (environment, platform = process.platform) => {
    if (platform !== "win32")
        return Object.freeze({ ...environment });
    const snapshot = {};
    // Node sorts keys lexicographically and forwards the first case-insensitive
    // match on Windows. Canonical keys also make subsequent lookups deterministic.
    for (const key of Object.keys(environment).sort()) {
        const canonicalKey = key.toUpperCase();
        if (!Object.hasOwn(snapshot, canonicalKey))
            snapshot[canonicalKey] = environment[key];
    }
    return Object.freeze(snapshot);
};
