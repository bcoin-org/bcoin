'use strict';

const random = require('bcoin/lib/crypto/random');
const WalletDB = require('bcoin/lib/wallet/walletdb');
const MTX = require('bcoin/lib/primitives/mtx');
const Outpoint = require('bcoin/lib/primitives/outpoint');
let walletdb;

function dummy() {
  let hash = random.randomBytes(32).toString('hex');
  return new Outpoint(hash, 0);
}

walletdb = new WalletDB({
  network: 'testnet',
  db: 'memory'
});

async function main() {
  let wallet, acct, mtx, tx, wtx;

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
