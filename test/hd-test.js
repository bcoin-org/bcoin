'use strict';

var BN = require('bn.js');
var bcoin = require('../').set('main');
var util = bcoin.util;
var base58 = require('../lib/utils/base58');
var crypto = require('../lib/crypto/crypto');
var assert = require('assert');

// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
var vector1 = {
  'seed': '000102030405060708090a0b0c0d0e0f',
  'm': {
    'pub': 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
    'prv': 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
  },
  'm/0\'': {
    'pub': 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
    'prv': 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'
  },
  'm/0\'/1': {
    'pub': 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',
    'prv': 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'
  },
  'm/0\'/1/2\'': {
    'pub': 'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',
    'prv': 'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM'
  },
  'm/0\'/1/2\'/2': {
    'pub': 'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',
    'prv': 'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334'
  },
  'm/0\'/1/2\'/2/1000000000': {
    'pub': 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
    'prv': 'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76'
  }
};

var vector2 = {
  'seed': 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
  'm': {
    'pub': 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',
    'prv': 'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U'
  },
  'm/0': {
    'pub': 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',
    'prv': 'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt'
  },
  'm/0/2147483647\'': {
    'pub': 'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a',
    'prv': 'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9'
  },
  'm/0/2147483647\'/1': {
    'pub': 'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon',
    'prv': 'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef'
  },
  'm/0/2147483647\'/1/2147483646\'': {
    'pub': 'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',
    'prv': 'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc'
  },
  'm/0/2147483647\'/1/2147483646\'/2': {
    'pub': 'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt',
    'prv': 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j'
  },
};

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
    var checkSeed = crypto.pbkdf2(
      phrase, 'mnemonic' + 'foo', 2048, 64, 'sha512').toString('hex');
    assert.equal(checkSeed, seed);
  });

  it('should create master private key', function() {
    master = bcoin.hd.PrivateKey.fromSeed(new Buffer(seed, 'hex'));
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

  it('should derive correctly when private key has leading zeros', function() {
    var key = 'xprv9s21ZrQH143K3ckY9DgU79uMTJkQRLdbCCVDh81SnxTgPzLLGax6uHeBULTtaEtcAvKjXfT7ZWtHzKjTpujMkUd9dDb8msDeAfnJxrgAYhr';
    var hdkey = bcoin.hd.PrivateKey.fromBase58(key);
    assert.equal(hdkey.privateKey.toString('hex'), '00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd');
    var child = hdkey.derivePath('m/44\'/0\'/0\'/0/0\'');
    assert.equal(child.privateKey.toString('hex'), '3348069561d2a0fb925e74bf198762acc47dce7db27372257d2d959a9e6f8aeb');
  });

  it('should deserialize master private key', function() {
    bcoin.hd.PrivateKey.fromBase58(master.xprivkey);
  });

  it('should deserialize master public key', function() {
    bcoin.hd.PublicKey.fromBase58(master.hdPublicKey.xpubkey);
  });

  it('should deserialize and reserialize', function() {
    var key = bcoin.hd.fromMnemonic();
    assert.equal(bcoin.hd.fromJSON(key.toJSON()).xprivkey, key.xprivkey);
  });

  function ub58(data) {
    return base58.decode(data).toString('hex');
  }

  function equal(a, b) {
    assert.equal(a, b);
    assert.equal(ub58(a), ub58(b));
  }

  [vector1, vector2].forEach(function(vector) {
    var seed = vector.seed;
    var m = vector.m;
    var master;
    delete vector.seed;
    delete vector.m;
    it('should create from a seed', function() {
      master = bcoin.hd.PrivateKey.fromSeed(new Buffer(seed, 'hex'));
      equal(master.xprivkey, m.prv);
      equal(master.xpubkey, m.pub);
    });
    Object.keys(vector).forEach(function(path) {
      var data = vector[path];
      var xpriv = data.prv;
      var xpub = data.pub;
      it('should derive ' + path + ' from master', function() {
        var key = master.derive(path);
        equal(key.xprivkey, xpriv);
        equal(key.xpubkey, xpub);
      });
    });
  });
});
