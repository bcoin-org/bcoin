/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const Validator = require('bval');
const {encoding} = require('bufio');
const assert = require('bsert');
const Amount = require('../lib/btc/amount');
const fixed = require('../lib/utils/fixed');

describe('Utils', function() {
  it('should convert satoshi to btc', () => {
    assert.strictEqual(Amount.btc(5460), '0.0000546');
    assert.strictEqual(Amount.btc(54678 * 1000000), '546.78');
    assert.strictEqual(Amount.btc(5460 * 10000000), '546.0');
  });

  it('should convert btc to satoshi', () => {
    assert.strictEqual(Amount.value('0.0000546'), 5460);
    assert.strictEqual(Amount.value('546.78'), 54678 * 1000000);
    assert.strictEqual(Amount.value('546'), 5460 * 10000000);
    assert.strictEqual(Amount.value('546.0'), 5460 * 10000000);
    assert.strictEqual(Amount.value('546.0000'), 5460 * 10000000);

    assert.doesNotThrow(() => {
      Amount.value('546.00000000000000000');
    });

    assert.throws(() => {
      Amount.value('546.00000000000000001');
    });

    assert.doesNotThrow(() => {
      Amount.value('90071992.54740991');
    });

    assert.doesNotThrow(() => {
      Amount.value('090071992.547409910');
    });

    assert.throws(() => {
      Amount.value('90071992.54740992');
    });

    assert.throws(() => {
      Amount.value('190071992.54740991');
    });

    assert.strictEqual(0.15645647 * 1e8, 15645646.999999998);
    assert.strictEqual(parseFloat('0.15645647') * 1e8, 15645646.999999998);
    assert.strictEqual(15645647 / 1e8, 0.15645647);

    assert.strictEqual(fixed.decode('0.15645647', 8), 15645647);
    assert.strictEqual(fixed.encode(15645647, 8), '0.15645647');
    assert.strictEqual(fixed.fromFloat(0.15645647, 8), 15645647);
    assert.strictEqual(fixed.toFloat(15645647, 8), 0.15645647);
  });

  it('should write/read new varints', () => {
    /*
     * 0:         [0x00]  256:        [0x81 0x00]
     * 1:         [0x01]  16383:      [0xFE 0x7F]
     * 127:       [0x7F]  16384:      [0xFF 0x00]
     * 128:  [0x80 0x00]  16511: [0x80 0xFF 0x7F]
     * 255:  [0x80 0x7F]  65535: [0x82 0xFD 0x7F]
     * 2^32:           [0x8E 0xFE 0xFE 0xFF 0x00]
     */

    let b = Buffer.alloc(1, 0xff);
    encoding.writeVarint2(b, 0, 0);
    assert.strictEqual(encoding.readVarint2(b, 0).value, 0);
    assert.strictEqual(b.toString('hex'), '00');

    b = Buffer.alloc(1, 0xff);
    encoding.writeVarint2(b, 1, 0);
    assert.strictEqual(encoding.readVarint2(b, 0).value, 1);
    assert.strictEqual(b.toString('hex'), '01');

    b = Buffer.alloc(1, 0xff);
    encoding.writeVarint2(b, 127, 0);
    assert.strictEqual(encoding.readVarint2(b, 0).value, 127);
    assert.strictEqual(b.toString('hex'), '7f');

    b = Buffer.alloc(2, 0xff);
    encoding.writeVarint2(b, 128, 0);
    assert.strictEqual(encoding.readVarint2(b, 0).value, 128);
    assert.strictEqual(b.toString('hex'), '8000');

    b = Buffer.alloc(2, 0xff);
    encoding.writeVarint2(b, 255, 0);
    assert.strictEqual(encoding.readVarint2(b, 0).value, 255);
    assert.strictEqual(b.toString('hex'), '807f');

    b = Buffer.alloc(2, 0xff);
    encoding.writeVarint2(b, 16383, 0);
    assert.strictEqual(encoding.readVarint2(b, 0).value, 16383);
    assert.strictEqual(b.toString('hex'), 'fe7f');

    b = Buffer.alloc(2, 0xff);
    encoding.writeVarint2(b, 16384, 0);
    assert.strictEqual(encoding.readVarint2(b, 0).value, 16384);
    assert.strictEqual(b.toString('hex'), 'ff00');

    b = Buffer.alloc(3, 0xff);
    encoding.writeVarint2(b, 16511, 0);
    assert.strictEqual(encoding.readVarint2(b, 0).value, 16511);
    assert.strictEqual(b.slice(0, 2).toString('hex'), 'ff7f');
    // assert.strictEqual(b.toString('hex'), '80ff7f');

    b = Buffer.alloc(3, 0xff);
    encoding.writeVarint2(b, 65535, 0);
    assert.strictEqual(encoding.readVarint2(b, 0).value, 65535);
    assert.strictEqual(b.toString('hex'), '82fe7f');
    // assert.strictEqual(b.toString('hex'), '82fd7f');

    b = Buffer.alloc(5, 0xff);
    encoding.writeVarint2(b, Math.pow(2, 32), 0);
    assert.strictEqual(encoding.readVarint2(b, 0).value, Math.pow(2, 32));
    assert.strictEqual(b.toString('hex'), '8efefeff00');
  });

  it('should validate integers 0 and 1 as booleans', () => {
    const validator = new Validator({
      shouldBeTrue: 1,
      shouldBeFalse: 0
    });
    assert.strictEqual(validator.bool('shouldBeTrue'), true);
    assert.strictEqual(validator.bool('shouldBeFalse'), false);
  });
});
