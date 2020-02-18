/*!
 * imports.js - import shim for bmocha
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bmocha
 */

'use strict';

/*
 * Imports
 */

let imports = null;

try {
  imports = require('./import');
} catch (e) {
  ;
}

/*
 * Fallback
 */

if (!imports) {
  imports = async function imports(url) {
    throw new Error('Not supported');
  };

  imports.supported = false;
}

/*
 * Helpers
 */

imports.pathToFileURL = function pathToFileURL(path) {
  const url = require('url');

  if (url.pathToFileURL)
    return url.pathToFileURL(path).href;

  return path;
};

/*
 * Expose
 */

module.exports = imports;
