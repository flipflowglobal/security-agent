'use strict';
/**
 * Native Security-Agent tool engine — public entry point.
 *
 * Loads the registry and registers every native tool module. Each module
 * self-registers by requiring './registry' and calling register({...}).
 *
 * The exported API is identical to the old inline registry so existing
 * callers (main.js IPC handlers, tests) keep working unchanged.
 */

const { register, listTools, getTool, runTool, util } = require('./registry');

// Register every native tool module (each self-registers via register()).
require('./hash-id');
require('./password-strength');
require('./wordlist');
require('./payload');
require('./obfuscate');
require('./wireless');
require('./postexploit');

module.exports = { register, listTools, getTool, runTool, util };
