/*!
 * import.js - import for bmocha
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bmocha
 */

'use strict';

/*
 * Imports
 */

async function imports(url) {
  return import(url);
}

/*
 * Static
 */

imports.supported = process.execArgv.includes('--experimental-modules');

/*
 * Expose
 */

module.exports = imports;
