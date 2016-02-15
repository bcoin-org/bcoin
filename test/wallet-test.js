var assert = require('assert');
var bn = require('bn.js');
var bcoin = require('../');
var constants = bcoin.protocol.constants;

describe('Wallet', function() {
  it('should generate new key and address', function() {
    var w = bcoin.wallet();
    var addr = w.getAddress();
    assert(addr);
    assert(bcoin.address.validate(addr));
  });

  it('should validate existing address', function() {
    assert(bcoin.address.validate('1KQ1wMNwXHUYj1nV2xzsRcKUH8gVFpTFUc'));
  });

  it('should fail to validate invalid address', function() {
    assert(!bcoin.address.validate('1KQ1wMNwXHUYj1nv2xzsRcKUH8gVFpTFUc'));
  });

  it('should sign/verify TX', function() {
    var w = bcoin.wallet();

    // Input transcation
    var src = bcoin.tx({
      outputs: [{
        value: 5460 * 2,
        address: w.getAddress()
      }, {
        value: 5460 * 2,
        address: w.getAddress() + 'x'
      }]
    });
    assert(w.ownOutput(src));
    assert.equal(w.ownOutput(src).reduce(function(acc, out) {
      return acc.iadd(out.value);
    }, new bn(0)).toString(10), 5460 * 2);

    var tx = bcoin.tx()
      .input(src, 0)
      .out(w.getAddress(), 5460);

    w.sign(tx);
    assert(tx.verify());
  });

  it('should multisign/verify TX', function() {
    var w = bcoin.wallet({
      derivation: 'bip44',
      type: 'multisig',
      m: 1,
      n: 2
    });
    var k2 = bcoin.hd.priv().deriveAccount44(0).hdPublicKey;
    w.addKey(k2);

    // Input transcation
    var src = bcoin.tx({
      outputs: [{
        value: 5460 * 2,
        m: 1,
        keys: [ w.getPublicKey(), k2.derive('m/0/0').publicKey ]
      }, {
        value: 5460 * 2,
        address: w.getAddress() + 'x'
      }]
    });
    assert(w.ownOutput(src));
    assert.equal(w.ownOutput(src).reduce(function(acc, out) {
      return acc.iadd(out.value);
    }, new bn(0)).toString(10), 5460 * 2);

    var tx = bcoin.tx()
      .input(src, 0)
      .out(w.getAddress(), 5460);

    var maxSize = tx.maxSize();
    w.sign(tx);
    assert(tx.render().length <= maxSize);
    assert(tx.verify());
  });

  it('should have TX pool and be serializable', function() {
    var w = bcoin.wallet();
    var f = bcoin.wallet();

    // Coinbase
    var t1 = bcoin.tx().out(w, 50000).out(w, 1000);
    // balance: 51000
    w.sign(t1);
    var t2 = bcoin.tx().input(t1, 0) // 50000
                       .out(w, 24000)
                       .out(w, 24000);
    // balance: 49000
    w.sign(t2);
    var t3 = bcoin.tx().input(t1, 1) // 1000
                       .input(t2, 0) // 24000
                       .out(w, 23000);
    // balance: 47000
    w.sign(t3);
    var t4 = bcoin.tx().input(t2, 1) // 24000
                       .input(t3, 0) // 23000
                       .out(w, 11000)
                       .out(w, 11000);
    // balance: 22000
    w.sign(t4);
    var f1 = bcoin.tx().input(t4, 1) // 11000
                       .out(f, 10000);
    // balance: 11000
    w.sign(f1);
    var fake = bcoin.tx().input(t1, 1) // 1000 (already redeemed)
                         .out(w, 500);
    // Script inputs but do not sign
    w.scriptInputs(fake);
    // Fake signature
    fake.inputs[0].script[0] = [0,0,0,0,0,0,0,0,0];
    // balance: 11000

    // Just for debugging
    t1.hint = 't1';
    t2.hint = 't2';
    t3.hint = 't3';
    t4.hint = 't4';
    f1.hint = 'f1';
    fake.hint = 'fake';

    // Fake TX should temporarly change output
    w.addTX(fake);

    w.addTX(t4);
    assert.equal(w.balance().toString(10), '22500');
    w.addTX(t1);
    assert.equal(w.balance().toString(10), '73000');
    w.addTX(t2);
    assert.equal(w.balance().toString(10), '47000');
    w.addTX(t3);
    assert.equal(w.balance().toString(10), '22000');
    w.addTX(f1);
    assert.equal(w.balance().toString(10), '11000');
    assert(w.all().some(function(tx) {
      return tx.hash('hex') === f1.hash('hex');
    }));

    var w2 = bcoin.wallet.fromJSON(w.toJSON());
    assert.equal(w2.balance().toString(10), '11000');
    assert(w2.all().some(function(tx) {
      return tx.hash('hex') === f1.hash('hex');
    }));
  });

  it('should fill tx with inputs', function(cb) {
    var w1 = bcoin.wallet();
    var w2 = bcoin.wallet();

    // Coinbase
    var t1 = bcoin.tx().out(w1, 5460).out(w1, 5460).out(w1, 5460).out(w1, 5460);

    // Fake TX should temporarly change output
    w1.addTX(t1);

    // Create new transaction
    var t2 = bcoin.tx().out(w2, 5460);
    assert(w1.fill(t2));
    w1.sign(t2);
    assert(t2.verify());

    assert.equal(t2.funds('in').toString(10), 16380);
    // If change < dust and is added to outputs:
    // assert.equal(t2.funds('out').toString(10), 6380);
    // If change < dust and is added to fee:
    assert.equal(t2.funds('out').toString(10), 5460);

    // Create new transaction
    var t3 = bcoin.tx().out(w2, 15000);
    assert(!w1.fill(t3));
    assert.equal(t3.requiredFunds.toString(10), 25000);

    cb();
  });

  it('should sign multiple inputs using different keys', function(cb) {
    var w1 = bcoin.wallet();
    var w2 = bcoin.wallet();
    var to = bcoin.wallet();

    // Coinbase
    var t1 = bcoin.tx().out(w1, 5460).out(w1, 5460).out(w1, 5460).out(w1, 5460);
    // Fake TX should temporarly change output
    w1.addTX(t1);
    // Coinbase
    var t2 = bcoin.tx().out(w2, 5460).out(w2, 5460).out(w2, 5460).out(w2, 5460);
    // Fake TX should temporarly change output
    w2.addTX(t2);

    // Create our tx with an output
    var tx = bcoin.tx();
    tx.out(to, 5460);

    var cost = tx.funds('out');
    var total = cost.add(new bn(constants.tx.minFee));

    var unspent1 = w1.unspent();
    var unspent2 = w2.unspent();

    // Add dummy output (for `left`) to calculate maximum TX size
    tx.out(w1, new bn(0));

    // Add our unspent inputs to sign
    tx.input(unspent1[0]);
    tx.input(unspent1[1]);
    tx.input(unspent2[0]);

    var left = tx.funds('in').sub(total);
    if (left.cmpn(constants.tx.dustThreshold) < 0) {
      tx.outputs[tx.outputs.length - 2].value.iadd(left);
      left = new bn(0);
    }
    if (left.cmpn(0) === 0)
      tx.outputs.pop();
    else
      tx.outputs[tx.outputs.length - 1].value = left;

    // Sign transaction
    assert.equal(w1.sign(tx), 2);
    assert.equal(w2.sign(tx), 1);

    // Verify
    assert.equal(tx.verify(), true);

    // Sign transaction using `inputs` and `off` params.
    tx.inputs.length = 0;
    tx.input(unspent1[1]);
    tx.input(unspent1[2]);
    tx.input(unspent2[1]);
    assert.equal(w1.sign(tx, 'all'), 2);
    assert.equal(w2.sign(tx, 'all'), 1);

    // Verify
    assert.equal(tx.verify(), true);

    cb();
  });

  it('should verify 2-of-3 p2sh tx', function(cb) {
    // Create 3 2-of-3 wallets with our pubkeys as "shared keys"
    var w1 = bcoin.wallet({
      derivation: 'bip44',
      type: 'multisig',
      m: 2,
      n: 3
    });

    var w2 = bcoin.wallet({
      derivation: 'bip44',
      type: 'multisig',
      m: 2,
      n: 3
    });

    var w3 = bcoin.wallet({
      derivation: 'bip44',
      type: 'multisig',
      m: 2,
      n: 3
    });

    var receive = bcoin.wallet();

    w1.addKey(w2);
    w1.addKey(w3);
    w2.addKey(w1);
    w2.addKey(w3);
    w3.addKey(w1);
    w3.addKey(w2);

    w3 = bcoin.wallet.fromJSON(w3.toJSON());

    // Our p2sh address
    var addr = w1.getAddress();
    assert.equal(w1.getAddress(), addr);
    assert.equal(w2.getAddress(), addr);
    assert.equal(w3.getAddress(), addr);

    // Add a shared unspent transaction to our wallets
    var utx = bcoin.tx();
    utx.output({ address: addr, value: 5460 * 10 });

    // Simulate a confirmation
    utx.ps = 0;
    utx.ts = 1;
    utx.height = 1;

    assert.equal(w1.receiveDepth, 1);

    w1.addTX(utx);
    w2.addTX(utx);
    w3.addTX(utx);

    assert.equal(w1.receiveDepth, 2);
    assert.equal(w1.changeDepth, 1);

    assert(w1.getAddress() !== addr);
    addr = w1.getAddress();
    assert.equal(w1.getAddress(), addr);
    assert.equal(w2.getAddress(), addr);
    assert.equal(w3.getAddress(), addr);

    // Create a tx requiring 2 signatures
    var send = bcoin.tx();
    send.output({ address: receive.getAddress(), value: 5460 });
    assert(!send.verify());
    var result = w1.fill(send, { m: w1.m, n: w1.n });
    assert(result);
    w1.sign(send);

    // console.log(bcoin.script.format(send.inputs[0]));

    assert(!send.verify());
    w2.sign(send);

    assert(send.verify());

    assert.equal(w1.changeDepth, 1);
    var change = w1.changeAddress.getAddress();
    assert.equal(w1.changeAddress.getAddress(), change);
    assert.equal(w2.changeAddress.getAddress(), change);
    assert.equal(w3.changeAddress.getAddress(), change);

    // Simulate a confirmation
    send.ps = 0;
    send.ts = 1;
    send.height = 1;

    w1.addTX(send);
    w2.addTX(send);
    w3.addTX(send);

    assert.equal(w1.receiveDepth, 2);
    assert.equal(w1.changeDepth, 2);

    assert(w1.getAddress() === addr);
    assert(w1.changeAddress.getAddress() !== change);
    change = w1.changeAddress.getAddress();
    assert.equal(w1.changeAddress.getAddress(), change);
    assert.equal(w2.changeAddress.getAddress(), change);
    assert.equal(w3.changeAddress.getAddress(), change);

    send.inputs[0].script[2] = [];
    assert(!send.verify(null, true));
    assert.equal(send.getFee().toNumber(), 10000);

    w3 = bcoin.wallet.fromJSON(w3.toJSON());
    assert.equal(w3.receiveDepth, 2);
    assert.equal(w3.changeDepth, 2);
    assert.equal(w3.getAddress(), addr);
    assert.equal(w3.changeAddress.getAddress(), change);

    cb();
  });
});
