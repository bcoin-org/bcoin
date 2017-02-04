/*!
 * lazy.js - lazy loading for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * Setup a lazy loader.
 * @alias module:utils.lazy
 * @param {Function} require
 * @param {Object} exports
 */

module.exports = function lazy(require, exports) {
  return function _require(name, path) {
    var cache;
    exports.__defineGetter__(name, function() {
      if (!cache)
        cache = require(path);
      return cache;
    });
  };
};
