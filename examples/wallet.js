'use strict';

var crypto = require('bcoin/lib/crypto/crypto');
var WalletDB = require('bcoin/lib/wallet/walletdb');
var MTX = require('bcoin/lib/primitives/mtx');
var Outpoint = require('bcoin/lib/primitives/outpoint');
var walletdb;

function dummy() {
  var hash = crypto.randomBytes(32).toString('hex');
  return new Outpoint(hash, 0);
}

walletdb = new WalletDB({
  network: 'testnet',
  db: 'memory'
});

async function main() {
  var wallet, acct, mtx, tx, wtx;

  await walletdb.open();

  wallet = await walletdb.create();

  console.log('Created wallet');
  console.log(wallet);

  acct = await wallet.createAccount({
    name: 'foo'
  });

  console.log('Created account');
  console.log(acct);

  mtx = new MTX();
  mtx.addOutpoint(dummy());
  mtx.addOutput(acct.getReceive(), 50460);
  tx = mtx.toTX();

  await walletdb.addTX(tx);

  wtx = await wallet.getTX(tx.hash('hex'));

  console.log('Added transaction');
  console.log(wtx);
}

main();
