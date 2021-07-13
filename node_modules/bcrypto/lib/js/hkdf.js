/*!
 * hkdf.js - hkdf for bcrypto
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/HKDF
 *   https://tools.ietf.org/html/rfc5869
 */

'use strict';

const assert = require('../internal/assert');

/**
 * HKDF
 */

function extract(hash, ikm, salt) {
  assert(hash && typeof hash.id === 'string');

  if (ikm == null)
    ikm = Buffer.alloc(0);

  if (salt == null)
    salt = Buffer.alloc(hash.size, 0x00);

  return hash.mac(ikm, salt);
}

function expand(hash, prk, info, len) {
  if (info == null)
    info = Buffer.alloc(0);

  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(prk));
  assert(Buffer.isBuffer(info));
  assert((len >>> 0) === len);

  if (prk.length !== hash.size)
    throw new RangeError('Invalid PRK length.');

  const blocks = Math.ceil(len / hash.size);

  if (blocks > 255)
    throw new RangeError('Invalid output length.');

  const out = Buffer.alloc(blocks * hash.size);
  const ctr = Buffer.from([0]);
  const mac = hash.hmac();

  let prev = Buffer.alloc(0);
  let pos = 0;

  for (let i = 0; i < blocks; i++) {
    ctr[0] += 1;

    mac.init(prk);
    mac.update(prev);
    mac.update(info);
    mac.update(ctr);

    prev = mac.final();
    pos += prev.copy(out, pos);
  }

  return out.slice(0, len);
}

function derive(hash, ikm, salt, info, len) {
  const prk = extract(hash, ikm, salt);
  return expand(hash, prk, info, len);
}

/*
 * Expose
 */

exports.native = 0;
exports.extract = extract;
exports.expand = expand;
exports.derive = derive;
