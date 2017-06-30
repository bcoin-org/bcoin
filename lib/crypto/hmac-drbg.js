/*!
 * hmac-drbg.js - hmac-drbg implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 * Parts of this software based on hmac-drbg.
 */

'use strict';

const assert = require('assert');
const digest = require('./digest');

/*
 * Constants
 */

const HASH_ALG = 'sha256';
const HASH_SIZE = 32;
const RESEED_INTERVAL = 0x1000000000000;
const POOL33 = Buffer.allocUnsafe(HASH_SIZE + 1);
const POOL112 = Buffer.allocUnsafe(HASH_SIZE * 2 + 48);
const POOL145 = Buffer.allocUnsafe(POOL33.length + POOL112.length);

/**
 * HmacDRBG
 * @constructor
 */

function HmacDRBG(entropy, nonce, pers) {
  if (!(this instanceof HmacDRBG))
    return new HmacDRBG(entropy, nonce, pers);

  this.K = Buffer.allocUnsafe(HASH_SIZE);
  this.V = Buffer.allocUnsafe(HASH_SIZE);
  this.rounds = 0;

  this.init(entropy, nonce, pers);
}

HmacDRBG.prototype.init = function init(entropy, nonce, pers) {
  for (let i = 0; i < this.V.length; i++) {
    this.K[i] = 0x00;
    this.V[i] = 0x01;
  }

  this.reseed(entropy, nonce, pers);
};

HmacDRBG.prototype.reseed = function reseed(entropy, nonce, pers) {
  let seed = POOL112;

  assert(Buffer.isBuffer(entropy));
  assert(Buffer.isBuffer(nonce));
  assert(Buffer.isBuffer(pers));

  assert(entropy.length === HASH_SIZE);
  assert(nonce.length === HASH_SIZE);
  assert(pers.length === 48);

  entropy.copy(seed, 0);
  nonce.copy(seed, HASH_SIZE);
  pers.copy(seed, HASH_SIZE * 2);

  this.update(seed);
  this.rounds = 1;
};

HmacDRBG.prototype.iterate = function iterate() {
  let data = POOL33;

  this.V.copy(data, 0);
  data[HASH_SIZE] = 0x00;

  this.K = digest.hmac(HASH_ALG, data, this.K);
  this.V = digest.hmac(HASH_ALG, this.V, this.K);
};

HmacDRBG.prototype.update = function update(seed) {
  let data = POOL145;

  assert(Buffer.isBuffer(seed));
  assert(seed.length === HASH_SIZE * 2 + 48);

  this.V.copy(data, 0);
  data[HASH_SIZE] = 0x00;
  seed.copy(data, HASH_SIZE + 1);

  this.K = digest.hmac(HASH_ALG, data, this.K);
  this.V = digest.hmac(HASH_ALG, this.V, this.K);

  data[HASH_SIZE] = 0x01;

  this.K = digest.hmac(HASH_ALG, data, this.K);
  this.V = digest.hmac(HASH_ALG, this.V, this.K);
};

HmacDRBG.prototype.generate = function generate(len) {
  let data = Buffer.allocUnsafe(len);
  let pos = 0;

  if (this.rounds > RESEED_INTERVAL)
    throw new Error('Reseed is required.');

  while (pos < len) {
    this.V = digest.hmac(HASH_ALG, this.V, this.K);
    this.V.copy(data, pos);
    pos += HASH_SIZE;
  }

  this.iterate();
  this.rounds++;

  return data;
};

/*
 * Expose
 */

module.exports = HmacDRBG;
