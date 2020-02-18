/*!
 * router.js - router middleware for bweb
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bweb
 */

'use strict';

const assert = require('bsert');

/**
 * Router middleware.
 * @returns {Function}
 */

function router(routes) {
  assert(routes && typeof routes === 'object');
  assert(typeof routes.handle === 'function');
  return async (req, res) => {
    return routes.handle(req, res);
  };
}

/*
 * Expose
 */

module.exports = router;
