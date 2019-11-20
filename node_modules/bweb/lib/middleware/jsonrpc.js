/*!
 * jsonrpc.js - json-rpc middleware for bweb
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bweb
 */

'use strict';

const assert = require('bsert');

/**
 * JSON rpc middleware.
 * @param {Object} rpc
 * @returns {Function}
 */

function jsonRPC(rpc) {
  assert(rpc && typeof rpc === 'object');
  assert(typeof rpc.call === 'function');

  return async (req, res) => {
    if (req.method !== 'POST')
      return;

    if (req.pathname !== '/')
      return;

    if (req.body instanceof Array) {
      for (const request of req.body) {
        if (typeof request.method !== 'string')
          return;
      }
    } else {
      if (typeof req.body.method !== 'string')
        return;
    }

    let json = await rpc.call(req.body, req.query);

    if (json == null)
      json = null;

    json = JSON.stringify(json);
    json += '\n';

    res.setHeader('X-Long-Polling', '/?longpoll=1');

    res.send(200, json, 'application/json');
  };
}

/*
 * Expose
 */

module.exports = jsonRPC;
