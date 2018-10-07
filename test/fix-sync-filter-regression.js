/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const bcoin = require('..');
const SPVNode = bcoin.SPVNode;
const WalletDB = bcoin.wallet.WalletDB;
const NodeClient = bcoin.wallet.NodeClient;
const assert = require('./util/assert');
const _ = require('lodash');

const network = bcoin.Network.get().toString();

const spvnode = new SPVNode({
  network: network
});

const walletdb = new WalletDB({
  network: network,
  client: new NodeClient(spvnode)
});

describe('NodeClient.setFilter() regression test', function() {
  before(async () => {
    await spvnode.open();
  });

  after(async () => {
    await spvnode.close();
    await walletdb.close();
  });

  it('should have the same spvFilter before '
  + 'and after walletdb.open() in spvnode', async () => {
    const initialSpvFilter = _.clone(spvnode.pool.spvFilter);
    await walletdb.open();
    assert.deepEqual(initialSpvFilter, spvnode.pool.spvFilter);
  });
});
