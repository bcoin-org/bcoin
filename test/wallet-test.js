var assert = require('assert');
var bn = require('bn.js');
var bcoin = require('../');
var constants = bcoin.protocol.constants;
var utils = bcoin.utils;

var dummyInput = {
  prevout: {
    hash: constants.zeroHash,
    index: 0
  },
  output: {
    version: 1,
    height: 0,
    value: constants.maxMoney.clone(),
    script: [],
    hash: constants.zeroHash,
    index: 0,
    spent: false
  },
  script: [],
  sequence: 0xffffffff
};

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

  function p2pkh(program, bullshitNesting) {
    var flags = bcoin.protocol.constants.flags.STANDARD_VERIFY_FLAGS;

    if (program)
      flags |= bcoin.protocol.constants.flags.VERIFY_WITNESS;

    var w = bcoin.wallet({ program: program });

    // Input transcation
    var src = bcoin.mtx({
      outputs: [{
        value: 5460 * 2,
        address: bullshitNesting
          ? w.getProgramAddress()
          : w.getAddress()
      }, {
        value: 5460 * 2,
        address: bcoin.address.compileData(new Buffer([]))
      }]
    });
    src.addInput(dummyInput);
    assert(w.ownOutput(src));
    assert(w.ownOutput(src.outputs[0]));
    assert(!w.ownOutput(src.outputs[1]));

    var tx = bcoin.mtx()
      .addInput(src, 0)
      .addOutput(w.getAddress(), 5460);

    w.sign(tx);
    assert(tx.verify(null, true, flags));
  }

  it('should sign/verify pubkeyhash tx', function() {
    p2pkh(false, false);
  });

  it('should sign/verify witnesspubkeyhash tx', function() {
    p2pkh(true, false);
  });

  it('should sign/verify witnesspubkeyhash tx with bullshit nesting', function() {
    p2pkh(true, true);
  });

  it('should multisign/verify TX', function() {
    var w = bcoin.wallet({
      derivation: 'bip44',
      type: 'multisig',
      m: 1,
      n: 2
    });
    var k2 = bcoin.hd.fromSeed().deriveAccount44(0).hdPublicKey;
    w.addKey(k2);

    // Input transcation
    var src = bcoin.mtx({
      outputs: [{
        value: 5460 * 2,
        m: 1,
        keys: [ w.getPublicKey(), k2.derive('m/0/0').publicKey ]
      }, {
        value: 5460 * 2,
        address: bcoin.address.compileData(new Buffer([]))
      }]
    });
    src.addInput(dummyInput);
    assert(w.ownOutput(src));
    assert(w.ownOutput(src.outputs[0]));
    assert(!w.ownOutput(src.outputs[1]));

    var tx = bcoin.mtx()
      .addInput(src, 0)
      .addOutput(w.getAddress(), 5460);

    var maxSize = tx.maxSize();
    w.sign(tx);
    assert(tx.render().length <= maxSize);
    assert(tx.verify());
  });

  it('should have TX pool and be serializable', function() {
    var w = bcoin.wallet();
    var f = bcoin.wallet();

    // Coinbase
    var t1 = bcoin.mtx().addOutput(w, 50000).addOutput(w, 1000);
    t1.addInput(dummyInput);
    // balance: 51000
    w.sign(t1);
    var t2 = bcoin.mtx().addInput(t1, 0) // 50000
                       .addOutput(w, 24000)
                       .addOutput(w, 24000);
    // balance: 49000
    w.sign(t2);
    var t3 = bcoin.mtx().addInput(t1, 1) // 1000
                       .addInput(t2, 0) // 24000
                       .addOutput(w, 23000);
    // balance: 47000
    w.sign(t3);
    var t4 = bcoin.mtx().addInput(t2, 1) // 24000
                       .addInput(t3, 0) // 23000
                       .addOutput(w, 11000)
                       .addOutput(w, 11000);
    // balance: 22000
    w.sign(t4);
    var f1 = bcoin.mtx().addInput(t4, 1) // 11000
                       .addOutput(f, 10000);
    // balance: 11000
    w.sign(f1);
    var fake = bcoin.mtx().addInput(t1, 1) // 1000 (already redeemed)
                         .addOutput(w, 500);
    // Script inputs but do not sign
    w.scriptInputs(fake);
    // Fake signature
    fake.inputs[0].script[0] = new Buffer([0,0,0,0,0,0,0,0,0]);
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
    var t1 = bcoin.mtx().addOutput(w1, 5460).addOutput(w1, 5460).addOutput(w1, 5460).addOutput(w1, 5460);

    // Fake TX should temporarly change output
    w1.addTX(t1);

    // Create new transaction
    var t2 = bcoin.mtx().addOutput(w2, 5460);
    assert(w1.fill(t2));
    w1.sign(t2);
    assert(t2.verify());

    assert.equal(t2.getInputValue().toString(10), 16380);
    // If change < dust and is added to outputs:
    // assert.equal(t2.getOutputValue().toString(10), 6380);
    // If change < dust and is added to fee:
    assert.equal(t2.getOutputValue().toString(10), 5460);

    // Create new transaction
    var t3 = bcoin.mtx().addOutput(w2, 15000);
    try {
      w1.fill(t3);
    } catch (e) {
      var err = e;
    }
    assert(err);
    assert.equal(err.requiredFunds.toString(10), 25000);

    cb();
  });

  it('should sign multiple inputs using different keys', function(cb) {
    var w1 = bcoin.wallet();
    var w2 = bcoin.wallet();
    var to = bcoin.wallet();

    // Coinbase
    var t1 = bcoin.mtx().addOutput(w1, 5460).addOutput(w1, 5460).addOutput(w1, 5460).addOutput(w1, 5460);
    t1.addInput(dummyInput);
    // Fake TX should temporarly change output
    w1.addTX(t1);
    // Coinbase
    var t2 = bcoin.mtx().addOutput(w2, 5460).addOutput(w2, 5460).addOutput(w2, 5460).addOutput(w2, 5460);
    t2.addInput(dummyInput);
    // Fake TX should temporarly change output
    w2.addTX(t2);

    // Create our tx with an output
    var tx = bcoin.mtx();
    tx.addOutput(to, 5460);

    var cost = tx.getOutputValue();
    var total = cost.add(new bn(constants.tx.minFee));

    var unspent1 = w1.unspent();
    var unspent2 = w2.unspent();

    // Add dummy output (for `left`) to calculate maximum TX size
    tx.addOutput(w1, new bn(0));

    // Add our unspent inputs to sign
    tx.addInput(unspent1[0]);
    tx.addInput(unspent1[1]);
    tx.addInput(unspent2[0]);

    var left = tx.getInputValue().sub(total);
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
    tx.addInput(unspent1[1]);
    tx.addInput(unspent1[2]);
    tx.addInput(unspent2[1]);
    assert.equal(w1.sign(tx, 'all'), 2);
    assert.equal(w2.sign(tx, 'all'), 1);

    // Verify
    assert.equal(tx.verify(), true);

    cb();
  });

  function multisig(program, bullshitNesting, cb) {
    var flags = bcoin.protocol.constants.flags.STANDARD_VERIFY_FLAGS;

    if (program)
      flags |= bcoin.protocol.constants.flags.VERIFY_WITNESS;

    // Create 3 2-of-3 wallets with our pubkeys as "shared keys"
    var w1 = bcoin.wallet({
      program: program,
      derivation: 'bip44',
      type: 'multisig',
      m: 2,
      n: 3
    });

    var w2 = bcoin.wallet({
      program: program,
      derivation: 'bip44',
      type: 'multisig',
      m: 2,
      n: 3
    });

    var w3 = bcoin.wallet({
      program: program,
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

    var paddr = w1.getProgramAddress();
    assert.equal(w1.getProgramAddress(), paddr);
    assert.equal(w2.getProgramAddress(), paddr);
    assert.equal(w3.getProgramAddress(), paddr);

    // Add a shared unspent transaction to our wallets
    var utx = bcoin.mtx();
    if (bullshitNesting)
      utx.addOutput({ address: paddr, value: 5460 * 10 });
    else
      utx.addOutput({ address: addr, value: 5460 * 10 });

    utx.addInput(dummyInput);

    assert(w1.ownOutput(utx.outputs[0]));

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
    var send = bcoin.mtx();
    send.addOutput({ address: receive.getAddress(), value: 5460 });
    assert(!send.verify(null, true, flags));
    var result = w1.fill(send, { m: w1.m, n: w1.n });
    assert(result);
    w1.sign(send);

    assert(!send.verify(null, true, flags));
    w2.sign(send);

    assert(send.verify(null, true, flags));

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

    if (program)
      send.inputs[0].witness[2] = new Buffer([]);
    else
      send.inputs[0].script[2] = 0;

    assert(!send.verify(null, true, flags));
    assert.equal(send.getFee().toNumber(), 10000);

    w3 = bcoin.wallet.fromJSON(w3.toJSON());
    assert.equal(w3.receiveDepth, 2);
    assert.equal(w3.changeDepth, 2);
    assert.equal(w3.getAddress(), addr);
    assert.equal(w3.changeAddress.getAddress(), change);

    cb();
  }

  it('should verify 2-of-3 scripthash tx', function(cb) {
    multisig(false, false, cb);
  });

  it('should verify 2-of-3 witnessscripthash tx', function(cb) {
    multisig(true, false, cb);
  });

  it('should verify 2-of-3 witnessscripthash tx with bullshit nesting', function(cb) {
    multisig(true, true, cb);
  });

  var coinbase = '010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2c027156266a24aa21a9edb1e139795984903d6629ddedf3763fb9bc582fd68a46b1f8c7c57f9fbcc7fc900101ffffffff02887d102a0100000023210290dd626747729e1cc445cb9a11cfb7e78ea896db9f5c335e6730491d9ee7474dac0000000000000000266a24aa21a9edb1e139795984903d6629ddedf3763fb9bc582fd68a46b1f8c7c57f9fbcc7fc900120000000000000000000000000000000000000000000000000000000000000000000000000';
  var chash = 'ba0cb2bf1aa19e4643208f7b38798a3deaa3320968d2cb1e42c5802a7baaba99';
  var wpkh = '0100000001fc8f4ccd25b285bcae9f305d2ec3feb79a71384bab0303f810b58089b9c6e084000000006a473044022036548e256acfbc6a77f322d32ae0f11cb20a05a240d72550bda9d8cf169b35e90220303ad1a60d8297a12501dbebc46ec39c7652ac3d75ff394b8d4c3cbdaf3279c7012103f85883e08a3581b636bbafee55f337b6bf4467826a280fda5bf0533368e99b73ffffffff0200ba1dd2050000001976a91443cec67a63867420c0c934ffbbf89f14729304f988acf0cbf01907000000160014e7b8143685eb4eb03810c8ffb7c4a74d5f23161c00000000';
  var whash = 'a72943c0131d655ff3d272f202d4f6ad2cf378eba9416c9b8028920d71d8f90a';
  var w2hash = 'c532af06b9a81d9171618fb0b30075ddb3a6fca68c9b89536e6e34b0beddcc23';

  // https://segnet.smartbit.com.au/tx/c532af06b9a81d9171618fb0b30075ddb3a6fca68c9b89536e6e34b0beddcc23
  var w2pkh = new Buffer(bcoin.fs.readFileSync(__dirname + '/wtx.hex', 'ascii').trim(), 'hex');

  it('should have a wtxid', function(cb) {
    var src = bcoin.mtx({
      outputs: [{
        value: 5460 * 2,
        address: bcoin.address.compileData(new Buffer([]))
      }]
    });
    src.addInput(dummyInput);
    var t = bcoin.protocol.parser.parseWitnessTX(new Buffer(coinbase, 'hex'));
    var t = new bcoin.tx(bcoin.protocol.parser.parseWitnessTX(new Buffer(w2pkh, 'hex')));
    delete t._raw;
    delete t._hash;
    delete t._whash;
    cb();
  });
});
