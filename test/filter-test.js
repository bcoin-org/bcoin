/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const Block = require('../lib/primitives/block');
const Script = require('../lib/script/script');
const Output = require('../lib/primitives/output');
const Outpoint = require('../lib/primitives/outpoint');
const CoinView = require('../lib/coins/coinview');

const GCSFilter = require('golomb');
const random = require('bcrypto/lib/random');

const filterTests = require('../test/data/filter-valid.json');

describe('BIP158 Filters', function() {
  for (const json of filterTests) {
    if (json.length === 1) {
      continue;
    }

    const height = json[0];
    it(`should match basic block filter for block ${height}`, async () => {
      const hash = json[1];
      const raw = json[2];

      const block = Block.fromRaw(raw, 'hex');
      assert.strictEqual(hash, block.rhash());

      const view = new CoinView();
      for (const raw of json[3]) {
        const hash = random.randomBytes(32);

        const output = new Output();
        output.script = Script.fromRaw(raw, 'hex');
        view.addOutput(new Outpoint(hash, 0), output);
      }

      const filter = GCSFilter.fromBlock(block, view);
      assert.strictEqual(filter.toRaw().toString('hex'), json[5]);

      const header = filter.header(Buffer.from(json[4], 'hex').reverse());
      assert.strictEqual(header.reverse().toString('hex'), json[6]);
    });
  }
});
