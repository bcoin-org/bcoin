'use strict';

var assert = require('assert');
var HD = require('../lib/hd');
var base58 = require('../lib/utils/base58');
var crypto = require('../lib/crypto/crypto');
var vectors = require('./data/hd.json');
var vector1 = vectors.vector1;
var vector2 = vectors.vector2;

function ub58(data) {
  return base58.decode(data).toString('hex');
}

function equal(a, b) {
  assert.equal(a, b);
  assert.equal(ub58(a), ub58(b));
}

describe('HD', function() {
  var master, child1, child2, child3, child4, child5, child6;

  it('should create a pbkdf2 seed', function() {
    var seed = crypto.pbkdf2(vectors.phrase, 'mnemonicfoo', 2048, 64, 'sha512');
    assert.equal(seed.toString('hex'), vectors.seed);
  });

  it('should create master private key', function() {
    master = HD.PrivateKey.fromSeed(new Buffer(vectors.seed, 'hex'));
    assert.equal(master.toBase58(), vectors.master_priv);
    assert.equal(master.toPublic().toBase58(), vectors.master_pub);
  });

  it('should derive(0) child from master', function() {
    child1 = master.derive(0);
    assert.equal(child1.toBase58(), vectors.child1_priv);
    assert.equal(child1.toPublic().toBase58(), vectors.child1_pub);
  });

  it('should derive(1) child from master public key', function() {
    child2 = master.toPublic().derive(1);
    assert.equal(child2.toBase58(), vectors.child2_pub);
  });

  it('should derive(1) child from master', function() {
    child3 = master.derive(1);
    assert.equal(child3.toBase58(), vectors.child3_priv);
    assert.equal(child3.toPublic().toBase58(), vectors.child3_pub);
  });

  it('should derive(2) child from master', function() {
    child4 = master.derive(2);
    assert.equal(child4.toBase58(), vectors.child4_priv);
    assert.equal(child4.toPublic().toBase58(), vectors.child4_pub);
  });

  it('should derive(0) child from child(2)', function() {
    child5 = child4.derive(0);
    assert.equal(child5.toBase58(), vectors.child5_priv);
    assert.equal(child5.toPublic().toBase58(), vectors.child5_pub);
  });

  it('should derive(1) child from child(2)', function() {
    child6 = child4.derive(1);
    assert.equal(child6.toBase58(), vectors.child6_priv);
    assert.equal(child6.toPublic().toBase58(), vectors.child6_pub);
  });

  it('should derive correctly when private key has leading zeros', function() {
    var key = HD.PrivateKey.fromBase58(vectors.zero_priv);
    var child;

    assert.equal(key.privateKey.toString('hex'),
      '00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd');

    child = key.derivePath('m/44\'/0\'/0\'/0/0\'');
    assert.equal(child.privateKey.toString('hex'),
      '3348069561d2a0fb925e74bf198762acc47dce7db27372257d2d959a9e6f8aeb');
  });

  it('should deserialize master private key', function() {
    HD.PrivateKey.fromBase58(master.toBase58());
  });

  it('should deserialize master public key', function() {
    HD.PublicKey.fromBase58(master.toPublic().toBase58());
  });

  it('should deserialize and reserialize', function() {
    var key = HD.generate();
    assert.equal(HD.fromJSON(key.toJSON()).toBase58(), key.toBase58());
  });

  [vector1, vector2].forEach(function(vector) {
    var master;

    it('should create from a seed', function() {
      master = HD.PrivateKey.fromSeed(new Buffer(vector.seed, 'hex'));
      equal(master.toBase58(), vector.m.prv);
      equal(master.toPublic().toBase58(), vector.m.pub);
    });

    Object.keys(vector).forEach(function(path) {
      var kp = vector[path];

      if (path === 'seed' || path === 'm')
        return;

      it('should derive ' + path + ' from master', function() {
        var key = master.derivePath(path);
        equal(key.toBase58(), kp.prv);
        equal(key.toPublic().toBase58(), kp.pub);
      });
    });
  });
});
