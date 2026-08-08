'use strict';
/**
 * Native Security-Agent tool engine — registry and dispatch.
 *
 * Lives in its own module so tool modules can `require('./registry')` to get
 * `register` without a circular dependency through `index.js`.
 *
 * Every tool here runs in-process (Node.js in Electron's main process), so
 * there is no per-invocation process spawn, no binary lookup, and no text-only
 * output. Tools return *structured* results the renderer renders as rich
 * cards/tables/code blocks, and fall back to plain text for terminal export.
 */

const util = require('./util');

const registry = new Map();

function register(tool) {
    if (!tool || typeof tool.run !== 'function') throw new Error(`Tool ${tool && tool.id} missing run()`);
    if (registry.has(tool.id)) throw new Error(`Tool already registered: ${tool.id}`);
    registry.set(tool.id, Object.freeze({
        id: tool.id,
        name: tool.name,
        description: tool.description || '',
        category: tool.category || 'General',
        run: tool.run,
    }));
    return tool;
}

function listTools() {
    return [...registry.values()].map(({ id, name, description, category }) => ({ id, name, description, category }));
}

function getTool(id) {
    return registry.get(id) || null;
}

/**
 * Run a native tool. Returns a structured result or throws.
 * @param {string} id tool id
 * @param {object} args tool-specific arguments (already validated by caller)
 */
function runTool(id, args) {
    const tool = registry.get(id);
    if (!tool) {
        return { ok: false, engine: 'native', error: `Native tool not found: ${id}` };
    }
    const started = Date.now();
    try {
        const out = tool.run(args || {});
        const result = (out && typeof out === 'object' && 'ok' in out) ? out : { ok: true, result: out };
        return Object.assign(result, { engine: 'native', tool: id, ms: Date.now() - started });
    } catch (err) {
        return {
            ok: false, engine: 'native', tool: id,
            error: String(err && err.message ? err.message : err),
            stack: err && err.stack,
            ms: Date.now() - started,
        };
    }
}

module.exports = { register, listTools, getTool, runTool, util };
