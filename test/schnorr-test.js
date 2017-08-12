/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const secp256k1 = require('../lib/crypto/secp256k1');
const digest = require('../lib/crypto/digest');
const schnorr = require('../lib/crypto/schnorr');

describe('Schnorr', function() {
  it('should do proper schnorr', () => {
    const key = secp256k1.generatePrivateKey();
    const pub = secp256k1.publicKeyCreate(key, true);
    const msg = digest.hash256(Buffer.from('foo', 'ascii'));
    const sig = schnorr.sign(msg, key);
    assert.strictEqual(schnorr.verify(msg, sig, pub), true);
    assert.bufferEqual(schnorr.recover(sig, msg), pub);
  });
});
