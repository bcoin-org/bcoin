'use strict';

const bcoin = require('../..');
const random = require('bcrypto/lib/random');

function dummy() {
  const hash = random.randomBytes(32).toString('hex');
  return new bcoin.Outpoint(hash, 0);
}

const walletdb = new bcoin.wallet.WalletDB({
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

  const mtx = new bcoin.MTX();
  mtx.addOutpoint(dummy());
  mtx.addOutput(acct.receiveAddress(), 50460);

  const tx = mtx.toTX();

  await walletdb.addTX(tx);

  const wtx = await wallet.getTX(tx.hash('hex'));

  console.log('Added transaction');
  console.log(wtx);
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
