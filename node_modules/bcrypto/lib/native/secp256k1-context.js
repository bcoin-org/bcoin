/*!
 * secp256k1-context.js - secp256k1 context for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const binding = require('./binding');

/*
 * Context
 */

let ctx = null;

function handle() {
  if (!ctx) {
    ctx = binding.secp256k1_create();
    binding.secp256k1_randomize(ctx, binding.entropy(32));
  }
  return ctx;
}

/*
 * Expose
 */

module.exports = handle;
