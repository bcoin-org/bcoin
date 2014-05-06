var assert = require('assert');
var bn = require('bn.js');
var bcoin = require('../');

describe('Wallet', function() {
  it('should generate new key and address', function() {
    var w = bcoin.wallet();
    var addr = w.getAddress();
    assert(addr);
    assert(bcoin.wallet.validateAddress(addr));
  });

  it('should validate existing address', function() {
    assert(bcoin.wallet.validateAddress('1KQ1wMNwXHUYj1nV2xzsRcKUH8gVFpTFUc'));
  });

  it('should fail to validate invalid address', function() {
    assert(!bcoin.wallet.validateAddress('1KQ1wMNwXHUYj1nv2xzsRcKUH8gVFpTFUc'));
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
    assert(w.own(src));
    assert.equal(w.own(src).reduce(function(acc, out) {
      return acc.iadd(out.value);
    }, new bn(0)).toString(10), 5460 * 2);

    var tx = bcoin.tx()
      .input(src, 0)
      .out(w.getAddress(), 5460);

    w.sign(tx);
    assert(tx.verify());
  });

  it('should multisign/verify TX', function() {
    var w = bcoin.wallet();

    // Input transcation
    var src = bcoin.tx({
      outputs: [{
        value: 5460 * 2,
        minSignatures: 1,
        address: [ w.getPublicKey(), w.getPublicKey().concat(1) ]
      }, {
        value: 5460 * 2,
        address: w.getAddress() + 'x'
      }]
    });
    assert(w.own(src));
    assert.equal(w.own(src).reduce(function(acc, out) {
      return acc.iadd(out.value);
    }, new bn(0)).toString(10), 5460 * 2);

    var tx = bcoin.tx()
      .input(src, 0)
      .out(w.getAddress(), 5460);

    w.sign(tx);
    assert(tx.verify());
  });

  it('should have TX pool', function() {
    var w = bcoin.wallet();

    // Coinbase
    var t1 = bcoin.tx().out(w, 50000).out(w, 1000);
    var t2 = bcoin.tx().input(t1.hash(), 0)
                       .out(w, 24000)
                       .out(w, 24000);
    var t3 = bcoin.tx().input(t1.hash(), 1)
                       .input(t2.hash(), 0)
                       .out(w, 23000);
    var t4 = bcoin.tx().input(t2.hash(), 1)
                       .input(t3.hash(), 0)
                       .out(w, 22000);
    w.addTX(t4);
    assert.equal(w.balance().toString(10), '22000');
    w.addTX(t1);
    assert.equal(w.balance().toString(10), '73000');
    w.addTX(t2);
    assert.equal(w.balance().toString(10), '47000');
    w.addTX(t3);
    assert.equal(w.balance().toString(10), '22000');
  });
});
