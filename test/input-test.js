/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const bio = require('bufio');
const util = require('../lib/utils/util');
const Input = require('../lib/primitives/input');
const assert = require('bsert');
const common = require('./util/common');

// Take input rawbytes from the raw data format
// p2pkh
const tx1 = common.readTX('tx1');
const input1 = tx1.getRaw().slice(5, 154);

// multisig
const tx2 = common.readTX('tx3');
const input2 = tx2.getRaw().slice(152, 339);

// p2sh multisig
const tx3 = common.readTX('tx4');
const input3 = tx3.getRaw().slice(5, 266);

// test files: https://github.com/bitcoinjs/bip69/blob/master/test/fixtures.json
const bip69tests = require('./data/bip69/bip69.json');

describe('Input', function() {
  it('should return same raw', () => {
    [input1, input2, input3].forEach((rawinput) => {
      const raw = rawinput.slice();
      const input = Input.fromRaw(raw);

      assert.bufferEqual(raw, input.toRaw());
    });
  });

  it('should return same raw on fromReader', () => {
    [input1, input2, input3].forEach((rawinput) => {
      const raw = rawinput.slice();
      const input = Input.fromReader(bio.read(raw));

      assert.bufferEqual(raw, input.toRaw());
    });
  });

  it('should parse p2pkh input', () => {
    const raw = input1.slice();
    const rawprevout = raw.slice(0, 36);
    const rawscript = raw.slice(37, 145);

    const input = Input.fromRaw(raw);

    const type = input.getType();
    const addr = input.getAddress().toBase58('main');
    const prevout = input.prevout.toRaw();

    assert.strictEqual(type, 'pubkeyhash');
    assert.strictEqual(addr, '1PM9ZgAV8Z4df1md2zRTF98tPjzTAfk2a6');
    assert.strictEqual(input.isCoinbase(), false);

    assert.strictEqual(input.isFinal(), true);
    assert.strictEqual(input.isRBF(), false);
    assert.strictEqual(input.getSize(), raw.length);

    assert.bufferEqual(input.script.toRaw(), rawscript);
    assert.bufferEqual(prevout, rawprevout);
  });

  it('should parse multisig input', () => {
    const raw = input2.slice();
    const rawprevout = raw.slice(0, 36);
    const rawscript = raw.slice(37, 183);

    const input = Input.fromRaw(raw);

    const type = input.getType();
    const addr = input.getAddress();
    const prevout = input.prevout.toRaw();

    assert.strictEqual(type, 'multisig');
    assert.strictEqual(addr, null);
    assert.strictEqual(input.isCoinbase(), false);

    assert.strictEqual(input.isFinal(), true);
    assert.strictEqual(input.isRBF(), false);
    assert.strictEqual(input.getSize(), raw.length);

    assert.bufferEqual(input.script.toRaw(), rawscript);
    assert.bufferEqual(prevout, rawprevout);
  });

  it('should parse p2sh multisig input', () => {
    const raw = input3.slice();

    const rawprevout = raw.slice(0, 36);
    const rawscript = raw.slice(37, 257);
    const rawredeem = raw.slice(186, 257);

    const input = Input.fromRaw(raw);

    const type = input.getType();
    const subtype = input.getSubtype();
    const addr = input.getAddress().toBase58('main');
    const prevout = input.prevout.toRaw();
    const redeem = input.getRedeem().toRaw();

    assert.strictEqual(type, 'scripthash');
    assert.strictEqual(subtype, 'multisig');
    assert.strictEqual(addr, '3416sTvfjDT8YPJ6PywJE1Pm2GgWiv2guz');
    assert.strictEqual(input.isCoinbase(), false);

    assert.strictEqual(input.isFinal(), false);
    assert.strictEqual(input.isRBF(), true);
    assert.strictEqual(input.getSize(), raw.length);

    assert.bufferEqual(input.script.toRaw(), rawscript);
    assert.bufferEqual(prevout, rawprevout);
    assert.bufferEqual(redeem, rawredeem);
  });

  // it('should parse p2wpkh')

  it('should parse coinbase input', () => {
    const rawprevout = Buffer.from('' +
      // prevout hash
      '0000000000000000000000000000000000000000' +
      '000000000000000000000000' +
      // prevout index
      'ffffffff', 'hex');

    const rawscript = Buffer.from('' +
      // length
      '50' +
      // raw script
      '0332f906047b20c6582f4254432e434f4d2f42436' +
      'f696e2ffabe6d6d911d3dbdeb854243e6eb04631d' +
      '017fd183eb54a78e06e9e0dc22f38e765fa267010' +
      '00000000000002503d49ad942020000000000', 'hex');

    const sequence = Buffer.from('ffffffff', 'hex');

    const raw = Buffer.alloc(40 + rawscript.length);

    rawprevout.copy(raw, 0);
    rawscript.copy(raw, 36);
    sequence.copy(raw, raw.length - 4);

    const input = Input.fromRaw(raw);

    const type = input.getType();
    const prevout = input.prevout.toRaw();

    assert.strictEqual(type, 'coinbase');
    assert.strictEqual(input.isCoinbase(), true);

    assert.strictEqual(input.isFinal(), true);
    assert.strictEqual(input.isRBF(), false);
    assert.strictEqual(input.getSize(), raw.length);

    assert.bufferEqual(input.script.toRaw(), rawscript.slice(1));
    assert.bufferEqual(prevout, rawprevout);
  });

  it('should check zero signature script', () => {
    const rawprevout = Buffer.from('' +
      '759104b6b99f9f20d3de9e7ddbb2ac84cd8a8af2' +
      'd7a6cdc46ac9fbdc0a388b3c' +
      'ffffffff', 'hex');
    const rawscript = Buffer.from('00', 'hex');
    const sequence = Buffer.from('ffffffff', 'hex');

    const raw = Buffer.alloc(41);

    rawprevout.copy(raw, 0);
    rawscript.copy(raw, 36);
    sequence.copy(raw, raw.length - 4);

    const input = Input.fromRaw(raw);

    const type = input.getType();
    const prevout = input.prevout.toRaw();

    assert.strictEqual(type, 'nonstandard');
    assert.strictEqual(input.isCoinbase(), false);

    assert.strictEqual(input.isFinal(), true);
    assert.strictEqual(input.isRBF(), false);
    assert.strictEqual(input.getSize(), raw.length);

    assert.bufferEqual(input.script.toRaw(), rawscript.slice(1));
    assert.bufferEqual(prevout, rawprevout);
  });

  it('should be the same from same raw', () => {
    const raw = input1.slice();
    const inputObject1 = Input.fromRaw(raw);
    const inputObject2 = Input.fromRaw(raw);
    const equals = inputObject1.equals(inputObject2);

    assert.strictEqual(equals, true);
  });

  it('should clone input correctly', () => {
    const raw = input1.slice();
    const inputObject1 = Input.fromRaw(raw);
    const inputObject2 = inputObject1.clone();
    const equals = inputObject1.equals(inputObject2);

    assert.strictEqual(inputObject1 !== inputObject2, true);
    assert.strictEqual(equals, true);
  });

  it('should create input from Options', () => {
    const raw = input3.slice();
    const rawscript = raw.slice(37, 257);

    const options = {
      prevout: {
        hash: Buffer.from(
              '8759d7397a86d6c42dfe2c55612e523d' +
              '171e51708fec9e289118deb5ba994001', 'hex'),
        index: 1
      },
      script: rawscript,
      sequence: 0
    };

    const inputRaw = Input.fromRaw(raw);
    const inputOptions = Input.fromOptions(options);

    assert.strictEqual(inputRaw.equals(inputOptions), true);
  });

  describe('BIP69', () => {
    bip69tests.inputs.forEach((test) => {
      it(`should sort: ${test.description}`, () => {
        const inputs = test.inputs.map((prevout, i) => {
          const input = Input.fromOptions({
            prevout: {
              hash: util.fromRev(prevout.txId),
              index: prevout.vout
            }
          });

          // to compare indexes
          input.i = i;

          return input;
        });

        const expected = test.expected;

        inputs.sort((a, b) => {
          return a.compare(b);
        });

        assert.deepStrictEqual(inputs.map(input => input.i), expected);
      });
    });
  });
});
