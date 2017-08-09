'use strict';

const bcoin = require('../..');
const random = bcoin.crypto.random;
const WalletDB = bcoin.walletdb;
const MTX = bcoin.mtx;
const Outpoint = bcoin.outpoint;

function dummy() {
  const hash = random.randomBytes(32).toString('hex');
  return new Outpoint(hash, 0);
}

const walletdb = new WalletDB({
  network: 'testnet',
  db: 'memory'
});

(async () => {
  await walletdb.open();

  const wallet = await walletdb.create();

  console.log('Created wallet');
  console.log(wallet);

  const acct = await wallet.createAccount({
    name: 'foo'
  });

  console.log('Created account');
  console.log(acct);

  const mtx = new MTX();
  mtx.addOutpoint(dummy());
  mtx.addOutput(acct.getReceive(), 50460);

  const tx = mtx.toTX();

  await walletdb.addTX(tx);

  const wtx = await wallet.getTX(tx.hash('hex'));

  console.log('Added transaction');
  console.log(wtx);
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
