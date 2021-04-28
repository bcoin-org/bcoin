'use strict';

const bcoin = require('../..');
const random = require('bcrypto/lib/random');

function dummy() {
  const hash = random.randomBytes(32);
  return new bcoin.Outpoint(hash, 0);
}

const walletdb = new bcoin.wallet.WalletDB({
  network: 'testnet',
  memory: true
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

  wallet.on('tx', (tx) => {
    console.log('Received transaciton:\n', tx);
  });

  await walletdb.addTX(tx);
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
