'use strict';

const assert = require('bsert');
const Block = require('../lib/primitives/block');
const Opcode = require('../lib/script/opcode');
const Script = require('../lib/script/script');
const Golomb = require('../lib/golomb/golomb');
const testVector = require('./data/filter-valid.json').slice(2);

describe('Golomb test', function() {
  it('should match all valid input & output scripts', function() {
    const OP_RETURN = Opcode.fromSymbol('return');

    for (const testCase of testVector) {
      // Building an array of raw items from the test vector data
      const items = []; // Corresponds to the L vector in the BIP-158
      const [, hash, blk, prevScripts, , filter] = testCase;
      const block = Block.fromRaw(Buffer.from(blk, 'hex'));
      if (prevScripts.length > 0) {
        const scripts = prevScripts.filter(str => str.length > 0).map(str => Script.fromRaw(str, 'hex'));
        // Adding previous output scripts
        items.push(...scripts);
      }
      block.txs.forEach((tx) => {
        tx.outputs.forEach((out) => {
          // Only adding output script of length > 0 and which don't contain OP_RETURN
          if (out.script.length > 0 && !out.script.toArray().find(element => OP_RETURN.equals(element))) {
            items.push(out.script);
          }
        });
      });
      // Building a filter instance & actually performing the test with the relevant items
      const golomb = Golomb.fromRaw(Buffer.from(filter, 'hex'));
      // The key are the first 16 bytes from the block hash in little endian
      const key = Buffer.from(hash, 'hex').reverse();
      for (const script of items) {
        const matches = golomb.match(key, script.toRaw());
        assert.equal(matches, true, 'The data must match the provided filter');
      }
    }
  });
});
