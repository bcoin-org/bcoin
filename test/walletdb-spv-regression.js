/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const bcoin = require('..');
const SPVNode = bcoin.SPVNode;
const WalletDB = bcoin.wallet.WalletDB;
const NodeClient = bcoin.wallet.NodeClient;
const assert = require('./util/assert');

let wallet, account;

const spvnode = new SPVNode({});

const walletdb = new WalletDB({
  client: new NodeClient(spvnode)
  // Should work without next line
  // spv: spvnode.spv
});

describe('WalletDB with SPV client regression test', function() {
  before(async () => {
    await spvnode.open();
    await walletdb.open();
    wallet = await walletdb.create();
    account = await wallet.getAccount('default');
  });

  after(async () => {
    await spvnode.close();
    await walletdb.close();
  });

  it('should have an spvFilter of valid size and with the '
    + 'address of the default account added', async () => {
    assert(spvnode.pool.spvFilter.isWithinConstraints());
    assert(spvnode.pool.spvFilter.test(account.receiveAddress().getHash()));
    assert(spvnode.pool.spvFilter.test(account.changeAddress().getHash()));
  });
});
