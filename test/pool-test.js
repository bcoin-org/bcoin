/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const FullNode = require('../lib/node/fullnode');
const SPVNode = require('../lib/node/spvnode');

const full = new FullNode({
  network: 'regtest'
});

const spv = new SPVNode({
  network: 'regtest'
});

const dummyHash = '0123456789abcdef'.repeat(4);

describe('Pool', function() {
  it('should check if a tx exists without adding it to the filter', () => {
    assert(!spv.pool.hasTX(dummyHash));
    assert(!spv.pool.hasTX(dummyHash));
  });

  it('should check if a tx exists without adding it to the mempool', () => {
    assert(!full.pool.hasTX(dummyHash));
    assert(!full.pool.hasTX(dummyHash));
  });
});
