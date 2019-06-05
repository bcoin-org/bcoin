/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const Headers = require('../lib/primitives/headers');
const assert = require('bsert');
const common = require('./util/common');

const block1 = common.readBlock('block1');
const headers1 = common.readFile('headers1.raw');

describe('Headers', function() {
  it('should match headers size', () => {
    const headers = new Headers();

    assert.strictEqual(headers.getSize(), 81);
  });

  it('should match block1 headers from block', () => {
    const [blockOne] = block1.getBlock();
    const headers = Headers.fromBlock(blockOne);

    assert.strictEqual(headers.time, 1231469665);
    assert.strictEqual(headers.bits, 486604799);
    assert.strictEqual(headers.nonce, 2573394689);
    assert.strictEqual(headers.version, 1);

    assert.strictEqual(headers.prevBlock.toString('hex'),
      '6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000');
    assert.strictEqual(headers.merkleRoot.toString('hex'),
      '982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e');
    assert.strictEqual(headers.rhash(),
      '00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048');

    assert(headers.verifyBody());
    assert(headers.verifyPOW());
  });

  it('should match block1 headers from raw', () => {
    const headers = Headers.fromRaw(headers1);

    assert.strictEqual(headers.time, 1231469665);
    assert.strictEqual(headers.bits, 486604799);
    assert.strictEqual(headers.nonce, 2573394689);
    assert.strictEqual(headers.version, 1);

    assert.strictEqual(headers.prevBlock.toString('hex'),
      '6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000');
    assert.strictEqual(headers.merkleRoot.toString('hex'),
      '982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e');
    assert.strictEqual(headers.rhash(),
      '00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048');

    assert(headers.verifyBody());
    assert(headers.verifyPOW());
  });
});
