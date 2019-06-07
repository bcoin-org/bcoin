/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Chain = require('../lib/blockchain/chain');
const ChainEntry = require('../lib/blockchain/chainentry');
const Network = require('../lib/protocol/network');
const BlockStore = require('../lib/blockstore/level');

const network = Network.get('main');

function random(max) {
  return Math.floor(Math.random() * max);
}

const blocks = new BlockStore({
  memory: true,
  network
});

const chain = new Chain({
  memory: true,
  network,
  blocks
});

describe('Difficulty', function() {
  it('should open chain', async () => {
    await blocks.open();
    await chain.open();
  });

  it('should get next work', async () => {
    const prev = new ChainEntry();
    prev.time = 1262152739;
    prev.bits = 0x1d00ffff;
    prev.height = 32255;
    const first = new ChainEntry();
    first.time = 1261130161;
    assert.strictEqual(chain.retarget(prev, first), 0x1d00d86a);
  });

  it('should get next work pow limit', async () => {
    const prev = new ChainEntry();
    prev.time = 1233061996;
    prev.bits = 0x1d00ffff;
    prev.height = 2015;
    const first = new ChainEntry();
    first.time = 1231006505;
    assert.strictEqual(chain.retarget(prev, first), 0x1d00ffff);
  });

  it('should get next work lower limit actual', async () => {
    const prev = new ChainEntry();
    prev.time = 1279297671;
    prev.bits = 0x1c05a3f4;
    prev.height = 68543;
    const first = new ChainEntry();
    first.time = 1279008237;
    assert.strictEqual(chain.retarget(prev, first), 0x1c0168fd);
  });

  it('should get next work upper limit actual', async () => {
    const prev = new ChainEntry();
    prev.time = 1269211443;
    prev.bits = 0x1c387f6f;
    prev.height = 46367;
    const first = new ChainEntry();
    first.time = 1263163443;
    assert.strictEqual(chain.retarget(prev, first), 0x1d00e1fd);
  });

  it('should get block proof equivalent time', async () => {
    const blocks = [];
    for (let i = 0; i < 10000; i++) {
      const prev = new ChainEntry();
      prev.height = i;
      prev.time = 1269211443 + i * network.pow.targetSpacing;
      prev.bits = 0x207fffff;
      if (i > 0)
        prev.chainwork = prev.getProof().addn(blocks[i-1].chainwork.toNumber());
      blocks[i] = prev;
    }

    chain.tip = blocks[blocks.length - 1];
    for (let j = 0; j < 1000; j++) {
      const p1 = blocks[random(blocks.length)];
      const p2 = blocks[random(blocks.length)];

      const tdiff = chain.getProofTime(p1, p2);
      assert.ok(tdiff ===  p1.time - p2.time);
    }
  });
});
