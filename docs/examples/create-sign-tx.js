'use strict';

/* eslint new-cap: "off" */

const bcoin = require('../..');
const assert = require('assert');

(async () => {
  const master = bcoin.hd.generate();
  const key = master.derivePath('m/44\'/0\'/0\'/0/0');
  const keyring = new bcoin.wallet.WalletKey(key.privateKey);
  const cb = new bcoin.MTX();

  cb.addInput({
    prevout: new bcoin.Outpoint(),
    script: new bcoin.Script(),
    sequence: 0xffffffff
  });

  // Send 50,000 satoshis to ourselves.
  cb.addOutput({
    address: keyring.getAddress(),
    value: 50000
  });

  // Our available coins.
  const coins = [];

  // Convert the coinbase output to a Coin
  // object and add it to our available coins.
  // In reality you might get these coins from a wallet.
  const coin = bcoin.Coin.fromTX(cb, 0, -1);
  coins.push(coin);

  // Create our redeeming transaction.
  const mtx = new bcoin.MTX();

  // Send 10,000 satoshis to ourself.
  mtx.addOutput({
    address: keyring.getAddress(),
    value: 10000
  });

  // Now that we've created the output, we can do some coin selection (the
  // output must be added first so we know how much money is needed and also so
  // we can accurately estimate the size for fee calculation).

  // Select coins from our array and add inputs.
  // Calculate fee and add a change output.
  await mtx.fund(coins, {
    // Use a rate of 10,000 satoshis per kb.
    // With the `fullnode` object, you can
    // use the fee estimator for this instead
    // of blindly guessing.
    rate: 10000,
    // Send the change back to ourselves.
    changeAddress: keyring.getAddress()
  });

  // Sign input 0
  mtx.sign(keyring);

  // The transaction should now verify.
  assert(mtx.verify());

  // Commit our transaction and make it immutable.
  // This turns it from an MTX into a TX.
  const tx = mtx.toTX();

  // The transaction should still verify.
  // Regular transactions require a coin
  // viewpoint to be passed in.
  assert(tx.verify(mtx.view));

  console.log(mtx);
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
