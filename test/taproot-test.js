
/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const TX = require('../lib/primitives/tx');
const {TaggedHash} = require('../lib/utils/taggedhash');
const Script = require('../lib/script/script');
const common = require('./util/common');

// Test data from https://github.com/pinheadmz/bitcoin/tree/taproottest-0.21.1
const taprootTXs = require('./data/taproot_test_vectors.json');

function* getTests(success = true) {
  for (const test of taprootTXs) {
    const tx = TX.fromRaw(Buffer.from(test.tx, 'hex'));

    // Produce test cases where all inputs are consensus-valid
    // (some may still be non-standard)
    const inputs = [];
    for (let i = 0; i < test.inputs.length; i++) {
      const input = test.inputs[i].success;
      input.comment = test.inputs[i].comment;
      input.standard = test.inputs[i].standard;
      inputs.push(input);
      tx.inputs[i].script = Script.fromJSON(input.scriptSig);
      tx.inputs[i].witness.fromString(input.witness);
    }

    yield {tx, inputs, prevouts: test.prevouts, mandatory: true};

    // ALSO produce test cases where one input is invalid and the rest are valid
    if (!success) {
      for (let fail = 0; fail < test.inputs.length; fail++) {
        if (!test.inputs[fail].fail)
          continue;

        const tx = TX.fromRaw(Buffer.from(test.tx, 'hex'));
        const inputs = [];
        for (let i = 0; i < test.inputs.length; i++) {
          const input = i === fail ?
              test.inputs[i].fail
            : test.inputs[i].success;
          input.comment = test.inputs[i].comment;
          input.standard = test.inputs[i].standard;
          inputs.push(input);
          tx.inputs[i].script = Script.fromJSON(input.scriptSig);
          tx.inputs[i].witness.fromString(input.witness);
        }

        yield {tx, inputs, prevouts: test.prevouts, mandatory: false};
      }
    }
  }
}

describe('Taproot', function() {
  it('should create a generic tagged hash', () => {
    // Without 'bytes' argument
    const testHash1 = new TaggedHash('test');
    const digest1 = testHash1.digest(Buffer.alloc(32, 12));

    // With 'bytes' argument
    const testHash2 = new TaggedHash('test', Buffer.alloc(32, 12));
    assert.bufferEqual(digest1, testHash2);

    // Test vector created with
    // https://github.com/bitcoin/bitcoin/blob/0.21/
    //   test/functional/test_framework/key.py#L17-L21
    // TaggedHash('test', bytearray([12]*32)).hex()
    assert.bufferEqual(
      digest1,
      Buffer.from(
        'f88d26c35028f6e63b5cfc3fc67b4a3ae6da9c48d9f0be94df97a94ab64d5a68',
        'hex'
      )
    );
  });

  describe('Get Annex', () => {
    it('should not find annex in pre-taproot TXs', () => {
      // None of the legacy or SegWit TXs in ./data are Taproot-spenders
      for (let i = 1; i < 11; i++) {
        const txContext = common.readTX(`tx${i}`);
        const [tx] = txContext.getTX();
        for (const input of tx.inputs) {
          const witness = input.witness;
          assert.strictEqual(witness.getAnnex(), null);
        }
      }
    });

    for (const test of getTests()) {
      for (let i = 0; i < test.tx.inputs.length; i++) {
        it(test.inputs[i].comment, () => {
          const expected = test.inputs[i].annex;
          const actual = test.tx.inputs[i].witness.getAnnex();

          if (expected === null)
            assert.strictEqual(actual, null);
          else
            assert.bufferEqual(Buffer.from(expected, 'hex'), actual);
        });
      }
    }
  });

  describe('Get Spend Type', () => {
    for (const test of getTests()) {
      for (let i = 0; i < test.tx.inputs.length; i++) {
        if (test.inputs[i].mode !== 'taproot')
          continue;

        it(test.inputs[i].comment, () => {
          const spendtype = test.tx.inputs[i].witness.getSpendType();

          if (test.inputs[i].annex != null)
            assert(spendtype & (1 << 0));

          if (test.inputs[i].annex == null)
            assert(~spendtype & (1 << 0));

          if (test.inputs[i].script != null)
            assert(spendtype & (1 << 1));

          if (test.inputs[i].script == null)
            assert(~spendtype & (1 << 1));
        });
      }
    }
  });

  describe('Get Tapleaf', () => {
    for (const test of getTests()) {
      for (let i = 0; i < test.tx.inputs.length; i++) {
        if (test.inputs[i].mode !== 'taproot')
          continue;

        it(test.inputs[i].comment, () => {
          const actual = test.tx.inputs[i].witness.getTapleaf();
          const expected = test.inputs[i].script;

          if (test.inputs[i].script == null)
            assert(actual == null);
          else
            assert.bufferEqual(Buffer.from(expected, 'hex'), actual);
        });
      }
    }
  });

  describe('Get Control Block', () => {
    for (const test of getTests()) {
      for (let i = 0; i < test.tx.inputs.length; i++) {
        if (test.inputs[i].mode !== 'taproot')
          continue;

        it(test.inputs[i].comment, () => {
          const actual = test.tx.inputs[i].witness.getControlBlock();

          if (test.inputs[i].script == null)
            assert(!actual);
          else
            assert(actual);
        });
      }
    }
  });
});
