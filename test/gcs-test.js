/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const GCSFilter = require('golomb');
const bcoin = require('../../bcoin');

const genesis = bcoin.Block.fromRaw(
  bcoin.networks.testnet.genesisBlock, 'hex');
const basic = GCSFilter.fromBlock(genesis);
const hash = genesis.hash();
const key = hash.slice(0, 16);

describe('Compact Filters', function() {
  it('should build regular filter', () => {
    const expected = Buffer.from('84134c0da400', 'hex');
    assert.bufferEqual(basic.data, expected);
  });

  it('should match tx against filter', () => {
    assert.ok(basic.match(key, genesis.txs[0].hash()));
  });

  it('should fail missing tx on filter', () => {
    assert.ok(!basic.match(key, Buffer.alloc(32)));
  });
});
