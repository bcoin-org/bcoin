// var assert = require('assert');
var bn = require('bn.js');
var bcoin = require('../');
var utils = bcoin.utils;
var assert = utils.assert;

describe('HD', function() {
  var phrase = 'volume doll flush federal inflict tomato result property total curtain shield aisle';

  var seed = '5559092716434b83f158bffb51337a944529ae30d7e62d46d3be0c66fa4b36e8d60ccfd2c976b831885dc9df9ac3716ee4bf90003f25621070a49cbea58f528b';

  var master_priv = 'xprv9s21ZrQH143K35zTejeVRhkXgegDFUVpoh8Mxs2BQmXEB4w9SZ1CuoJPuQ2KGQrS1ZF3Pk7V7KWHn7FqR2JbAE9Bh8PURnrFnrmArj4kxos';
  var master_pub = 'xpub661MyMwAqRbcFa4vkmBVnqhGEgWhewDgAv3xmFRny74D3sGHz6KTTbcskg2vZEMbEwxc4oaR435oczhSu4GdNwhwiVewcewU8A1Rr6HehAU';

  var child1_priv = 'xprv9v414VeuxMoGt3t7jzkPni79suCfkgFwjxG38X2wgfg2mrYtV4Bhj3prhDDCcBiJrz9n4xLYoDtBFRuQmreVLKzmiZAqvbGpx5q4yHfzfah';
  var child1_pub = 'xpub693MU1BonjMa6Xxar2HQ9r3tRw3AA8yo7BBdvuSZF1D1eet32bVxGr9LYViWMtaLfQaa2StXeUmDG5VELFkU9pc3yfTzCk61WQJdR6ezj7a';

  var child2_pub = 'xpub693MU1BonjMa8MMoz9opJhrFejcXcGmhMP9gzySLsip4Dz1UrSLT4i2pAimHDyM2onW2H2L2HkbwrZqoizQLMoErXu8mPYxDf8tJUBAfBuT';

  var child3_priv = 'xprv9v414VeuxMoGusHLt8GowZuX6hn3Cp3qzAE6Cb2jKPH5MBgLJu2CWuiLKTdWV8WoNFYvpCcBfbpWfeyEQ8zytZW5qy39roTcugBGUkeAvCc';
  var child3_pub = 'xpub693MU1BonjMa8MMoz9opJhrFejcXcGmhMP9gzySLsip4Dz1UrSLT4i2pAimHDyM2onW2H2L2HkbwrZqoizQLMoErXu8mPYxDf8tJUBAfBuT';

  var child4_priv = 'xprv9v414VeuxMoGyViVYuzEN5vLDzff3nkrH5Bf4KzD1iTeY855Q4cCc6xPPNoc6MJcsqqRQiGqR977cEEGK2mhVp7ALKHqY1icEw3Q9UmfQ1v';
  var child4_pub = 'xpub693MU1BonjMaBynxewXEjDs4n2W9TFUheJ7FriPpa3zdQvQDwbvT9uGsEebvioAcYbtRUU7ge4yVgj8WDLrwtwuXKTWiieFoYX2B1JYUEfK';

  var child5_priv = 'xprv9xaK29Nm86ytEwsV9YSsL3jWYR6KtZYY3cKdjAbxHrwKyxH9YWoxvqKwtgQmExGpxAEDrwB4WK9YG1iukth3XiSgsxXLK1W3NB31gLee8fi';
  var child5_pub = 'xpub6BZfReuexUYBTRwxFZyshBgF6SvpJ2GPQqFEXZ1ZrCUJrkcJ648DUdeRjx9QiNQxQvPcHYV3rGkvuExFQbVRS4kU5ynx4fAsWWhHgyPh1pP';

  var child6_priv = 'xprv9xaK29Nm86ytGx9uDhNKUBjvbJ1sAEM11aYxGQS66Rmg6oHwy7HbB6kWwMHvukzdbPpGhfNXhZgePWFHm1DCh5PACPFywJJKr1AnUJTLjUc';
  var child6_pub = 'xpub6BZfReuexUYBVSENKiuKqKgf9KrMZh4rNoUZ4nqhemJeybd6Webqiu4zndBwa9UB4Jvr5jB5Bcgng6reXAKCuDiVm7zhzJ13BUDBiM8HidZ';

  var master, child1, child2, child3, child4, child5, child6;

  it('should create a pbkdf2 seed', function() {
    var checkSeed = utils.toHex(bcoin.utils.pbkdf2(phrase, 'mnemonic' + 'foo', 2048, 64));
    assert.equal(checkSeed, seed);
  });

  it('should create master private key', function() {
    var s = new bcoin.hd.seed();
    s.seed = new Buffer(seed, 'hex');
    master = bcoin.hd.priv.fromSeed(s);
    assert.equal(master.xprivkey, master_priv);
    assert.equal(master.xpubkey, master_pub);
  });

  it('should derive(0) child from master', function() {
    child1 = master.derive(0);
    assert.equal(child1.xprivkey, child1_priv);
    assert.equal(child1.xpubkey, child1_pub);
  });

  it('should derive(1) child from master public key', function() {
    child2 = master.hdPublicKey.derive(1);
    assert.equal(child2.xpubkey, child2_pub);
  });

  it('should derive(1) child from master', function() {
    child3 = master.derive(1);
    assert.equal(child3.xprivkey, child3_priv);
    assert.equal(child3.xpubkey, child3_pub);
  });

  it('should derive(2) child from master', function() {
    child4 = master.derive(2);
    assert.equal(child4.xprivkey, child4_priv);
    assert.equal(child4.xpubkey, child4_pub);
  });

  it('should derive(0) child from child(2)', function() {
    child5 = child4.derive(0);
    assert.equal(child5.xprivkey, child5_priv);
    assert.equal(child5.xpubkey, child5_pub);
  });

  it('should derive(1) child from child(2)', function() {
    child6 = child4.derive(1);
    assert.equal(child6.xprivkey, child6_priv);
    assert.equal(child6.xpubkey, child6_pub);
  });

  it('should deserialize master private key', function() {
    bcoin.hd.priv.parse(master.xprivkey);
  });

  it('should deserialize master public key', function() {
    bcoin.hd.pub.parse(master.hdPublicKey.xpubkey);
  });

  it('should deserialize and reserialize', function() {
    var key = bcoin.hd.fromSeed();
    assert.equal(bcoin.hd.fromJSON(key.toJSON()).xprivkey, key.xprivkey);
  });

  it('should create an hd seed', function() {
    var seed = new bcoin.hd.seed({
      // I have the same combination on my luggage:
      entropy: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
      passphrase: 'foo'
    });
  });
});
