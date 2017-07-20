## TX creation

Normal transactions in bcoin are immutable. The primary TX object contains a
bunch of consensus and policy checking methods. A lot of it is for internal use
and pretty boring for users of this library.

Bcoin also offers a mutable transaction object (MTX). Mutable transactions
inherit from the TX object, but can also be signed and modified.

``` js
var bcoin = require('bcoin');
var assert = require('assert');

// Create an HD master keypair.
var master = bcoin.hd.generate();

// Derive another private hd key (we don't want to use our master key!).
var key = master.derive('m/44/0/0/0/0');

// Create a "keyring" object. A keyring object is basically a key manager that
// is also able to tell you info such as: your redeem script, your scripthash,
// your program hash, your pubkey hash, your scripthash program hash, etc.
// In this case, we'll make it simple and just add one key for a
// pubkeyhash address. `getPublicKey` returns the non-hd public key.
var keyring = new bcoin.keyring(key.privateKey);

console.log(keyring.getAddress());

// Create a fake coinbase for our funding.
var cb = new bcoin.mtx();

// Add a typical coinbase input
cb.addInput({
  prevout: new bcoin.outpoint(),
  script: new bcoin.script(),
  sequence: 0xffffffff
});

// Send 50,000 satoshis to ourself.
cb.addOutput({
  address: keyring.getAddress(),
  value: 50000
});

// Create our redeeming transaction.
var mtx = new bcoin.mtx();

// Add output 0 from our coinbase as an input.
mtx.addTX(cb, 0);

// Send 10,000 satoshis to ourself,
// creating a fee of 40,000 satoshis.
mtx.addOutput({
  address: keyring.getAddress(),
  value: 10000
});

// Sign input 0: pass in our keyring.
mtx.sign(keyring);

// The transaction should now verify.
assert(mtx.verify());
assert(mtx.getFee() === 40000);

// Commit our transaction and make it immutable.
// This turns it from an MTX into a TX object.
var tx = mtx.toTX();

// The transaction should still verify.
// Regular transactions require a coin
// viewpoint to be passed in.
assert(tx.verify(mtx.view));
assert(tx.getFee(mtx.view) === 40000);
```

### Coin Selection

The above method works, but is pretty contrived. In reality, you probably
wouldn't select inputs and calculate the fee by hand. You would want a
change output added. Bcoin has a nice method of dealing with this.

Let's try it more realistically:

``` js
var bcoin = require('bcoin');
var assert = require('assert');

var master = bcoin.hd.generate();
var key = master.derive('m/44/0/0/0/0');
var keyring = new bcoin.keyring(key.privateKey);
var cb = new bcoin.mtx();

cb.addInput({
  prevout: new bcoin.outpoint(),
  script: new bcoin.script(),
  sequence: 0xffffffff
});

// Send 50,000 satoshis to ourselves.
cb.addOutput({
  address: keyring.getAddress(),
  value: 50000
});

// Our available coins.
var coins = [];

// Convert the coinbase output to a Coin
// object and add it to our available coins.
// In reality you might get these coins from a wallet.
var coin = bcoin.coin.fromTX(cb, 0, -1);
coins.push(coin);

// Create our redeeming transaction.
var mtx = new bcoin.mtx();

// Send 10,000 satoshis to ourself.
mtx.addOutput({
  address: keyring.getAddress(),
  value: 10000
});

// Now that we've created the output, we can do some coin selection (the output
// must be added first so we know how much money is needed and also so we can
// accurately estimate the size for fee calculation).

// Select coins from our array and add inputs.
// Calculate fee and add a change output.
mtx.fund(coins, {
  // Use a rate of 10,000 satoshis per kb.
  // With the `fullnode` object, you can
  // use the fee estimator for this instead
  // of blindly guessing.
  rate: 10000,
  // Send the change back to ourselves.
  changeAddress: keyring.getAddress()
}).then(function() {
  // Sign input 0
  mtx.sign(keyring);

  // The transaction should now verify.
  assert(mtx.verify());

  // Commit our transaction and make it immutable.
  // This turns it from an MTX into a TX.
  var tx = mtx.toTX();

  // The transaction should still verify.
  // Regular transactions require a coin
  // viewpoint to be passed in.
  assert(tx.verify(mtx.view));
});
```