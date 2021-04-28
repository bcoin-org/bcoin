/*!
 * hook.js - hook object for bweb
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bweb
 */

'use strict';

const assert = require('bsert');

/**
 * Hook
 */

class Hook {
  /**
   * Create a hook.
   * @constructor
   * @ignore
   */

  constructor(path, handler) {
    assert(typeof path === 'string');
    assert(typeof handler === 'function' || typeof handler === 'object');
    assert(handler !== null);

    this.path = path;
    this.handler = handler;
    this.arity = 0;

    if (typeof handler === 'function')
      this.arity = handler.length;
  }

  isPrefix(pathname) {
    if (this.path === '/')
      return true;

    if (pathname.startsWith)
      return pathname.startsWith(this.path);

    return pathname.indexOf(this.path) === 0;
  }
}

/*
 * Expose
 */

module.exports = Hook;
