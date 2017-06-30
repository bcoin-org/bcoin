'use strict';

const encoding = require('bcoin/lib/utils/encoding');
const co = require('bcoin/lib/utils/co');
const Outpoint = require('bcoin/lib/primitives/outpoint');
const MTX = require('bcoin/lib/primitives/mtx');
const HTTP = require('bcoin/lib/http');
const FullNode = require('bcoin/lib/node/fullnode');
const plugin = require('bcoin/lib/wallet/plugin');
let node, wallet;

node = new FullNode({
  network: 'regtest',
  apiKey: 'foo',
  walletAuth: true,
  db: 'memory'
});

node.use(plugin);

wallet = new HTTP.Wallet({
  network: 'regtest',
  apiKey: 'foo'
});

async function main() {
  let wdb = node.require('walletdb');
  let w, acct, hash, balance, tx;

  await node.open();

  w = await wallet.create({ id: 'test' });

  console.log('Wallet:');
  console.log(w);

  // Fund default account.
  await fundWallet(wdb, w.account.receiveAddress);

  balance = await wallet.getBalance();

  console.log('Balance:');
  console.log(balance);

  acct = await wallet.createAccount('foo');

  console.log('Account:');
  console.log(acct);

  // Send to our new account.
  hash = await sendTX(acct.receiveAddress, 10000);

  console.log('Sent TX:');
  console.log(hash);

  tx = await wallet.getTX(hash);

  console.log('Sent TX details:');
  console.log(tx);

  await callNodeApi();
}

async function fundWallet(wdb, addr) {
  let tx;

  // Coinbase
  tx = new MTX();
  tx.addOutpoint(new Outpoint(encoding.NULL_HASH, 0));
  tx.addOutput(addr, 50460);
  tx.addOutput(addr, 50460);
  tx.addOutput(addr, 50460);
  tx.addOutput(addr, 50460);
  tx = tx.toTX();

  wallet.once('balance', (balance) => {
    console.log('New Balance:');
    console.log(balance);
  });

  wallet.once('address', (receive) => {
    console.log('New Receiving Address:');
    console.log(receive);
  });

  wallet.once('tx', (details) => {
    console.log('New Wallet TX:');
    console.log(details);
  });

  await wdb.addTX(tx);
  await co.timeout(300);
}

async function sendTX(addr, value) {
  let options, tx;

  options = {
    rate: 10000,
    outputs: [{
      value: value,
      address: addr
    }]
  };

  tx = await wallet.send(options);

  return tx.hash;
}

async function callNodeApi() {
  let info = await wallet.client.getInfo();
  let json;

  console.log('Server Info:');
  console.log(info);

  json = await wallet.client.rpc.execute('getblocktemplate', []);

  console.log('Block Template (RPC):');
  console.log(json);
}

main();
