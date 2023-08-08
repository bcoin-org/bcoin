/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const SPVNode = require('../lib/node/spvnode');
const Input = require('../lib/primitives/input');
const Outpoint = require('../lib/primitives/outpoint');
const MTX = require('../lib/primitives/mtx');
const random = require('bcrypto/lib/random');

function dummyInput() {
  const hash = random.randomBytes(32);
  return Input.fromOutpoint(new Outpoint(hash, 0));
}

const node = new SPVNode({
  network: 'regtest',
  plugins: [require('../lib/wallet/plugin')]
});

const {wdb} = node.require('walletdb');

let wallet = null;

describe.only('SPV Node', function() {
  this.timeout(process.browser ? 20000 : 5000);

  if (process.browser)
    return;

  it('should open node', async () => {
    await node.open();
  });

  it('should open walletdb', async () => {
    wallet = await wdb.create();
  });

  it('should wake listeners of \'tx\' when sending', async () => {
    let notified = false;
    const notifier = () => {
      notified = true;
    };
    node.on('tx', notifier);

    const mtx = new MTX();
    mtx.addInput(dummyInput());
    mtx.addOutput(await wallet.receiveAddress(), 5460);

    await node.sendTX(mtx.toTX());

    assert(notified);
    node.removeListener('tx', notifier);
  });

  it('should cleanup', async () => {
    await node.close();
  });
});
