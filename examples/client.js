'use strict';

var encoding = require('bcoin/lib/utils/encoding');
var co = require('bcoin/lib/utils/co');
var Address = require('bcoin/lib/primitives/address');
var Outpoint = require('bcoin/lib/primitives/outpoint');
var MTX = require('bcoin/lib/primitives/mtx');
var HTTP = require('bcoin/lib/http');
var FullNode = require('bcoin/lib/node/fullnode');
var plugin = require('bcoin/lib/wallet/plugin');
var node, wallet, walletdb, addr, hash;

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
  var wdb = node.require('walletdb');
  var w, acct, info, hash, balance, tx;

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
  var tx, balance, receive, details;

  // Coinbase
  tx = new MTX();
  tx.addOutpoint(new Outpoint(encoding.NULL_HASH, 0));
  tx.addOutput(addr, 50460);
  tx.addOutput(addr, 50460);
  tx.addOutput(addr, 50460);
  tx.addOutput(addr, 50460);
  tx = tx.toTX();

  wallet.once('balance', function(balance) {
    console.log('New Balance:');
    console.log(balance);
  });

  wallet.once('address', function(receive) {
    console.log('New Receiving Address:');
    console.log(receive);
  });

  wallet.once('tx', function(details) {
    console.log('New Wallet TX:');
    console.log(details);
  });

  await wdb.addTX(tx);
  await co.timeout(300);
}

async function sendTX(addr, value) {
  var options, tx;

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
  var info = await wallet.client.getInfo();
  var json;

  console.log('Server Info:');
  console.log(info);

  json = await wallet.client.rpc.execute('getblocktemplate', []);

  console.log('Block Template (RPC):');
  console.log(json);
}

main();
