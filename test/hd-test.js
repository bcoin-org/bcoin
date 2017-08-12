/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const HD = require('../lib/hd');
const base58 = require('../lib/utils/base58');
const pbkdf2 = require('../lib/crypto/pbkdf2');
const vectors = require('./data/hd.json');
const vector1 = vectors.vector1;
const vector2 = vectors.vector2;

let master = null;
let child = null;

function base58Equal(a, b) {
  assert.strictEqual(a, b);
  assert.bufferEqual(base58.decode(a), base58.decode(b));
}

describe('HD', function() {
  it('should create a pbkdf2 seed', () => {
    const seed = pbkdf2.derive(
      vectors.phrase, 'mnemonicfoo', 2048, 64, 'sha512');
    assert.strictEqual(seed.toString('hex'), vectors.seed);
  });

  it('should create master private key', () => {
    const seed = Buffer.from(vectors.seed, 'hex');
    const key = HD.PrivateKey.fromSeed(seed);
    assert.strictEqual(key.toBase58(), vectors.master_priv);
    assert.strictEqual(key.toPublic().toBase58(), vectors.master_pub);
    master = key;
  });

  it('should derive(0) child from master', () => {
    const child1 = master.derive(0);
    assert.strictEqual(child1.toBase58(), vectors.child1_priv);
    assert.strictEqual(child1.toPublic().toBase58(), vectors.child1_pub);
  });

  it('should derive(1) child from master public key', () => {
    const child2 = master.toPublic().derive(1);
    assert.strictEqual(child2.toBase58(), vectors.child2_pub);
  });

  it('should derive(1) child from master', () => {
    const child3 = master.derive(1);
    assert.strictEqual(child3.toBase58(), vectors.child3_priv);
    assert.strictEqual(child3.toPublic().toBase58(), vectors.child3_pub);
  });

  it('should derive(2) child from master', () => {
    const child4 = master.derive(2);
    assert.strictEqual(child4.toBase58(), vectors.child4_priv);
    assert.strictEqual(child4.toPublic().toBase58(), vectors.child4_pub);
    child = child4;
  });

  it('should derive(0) child from child(2)', () => {
    const child5 = child.derive(0);
    assert.strictEqual(child5.toBase58(), vectors.child5_priv);
    assert.strictEqual(child5.toPublic().toBase58(), vectors.child5_pub);
  });

  it('should derive(1) child from child(2)', () => {
    const child6 = child.derive(1);
    assert.strictEqual(child6.toBase58(), vectors.child6_priv);
    assert.strictEqual(child6.toPublic().toBase58(), vectors.child6_pub);
  });

  it('should derive correctly when private key has leading zeros', () => {
    const key = HD.PrivateKey.fromBase58(vectors.zero_priv);

    assert.strictEqual(key.privateKey.toString('hex'),
      '00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd');

    const child = key.derivePath('m/44\'/0\'/0\'/0/0\'');
    assert.strictEqual(child.privateKey.toString('hex'),
      '3348069561d2a0fb925e74bf198762acc47dce7db27372257d2d959a9e6f8aeb');
  });

  it('should deserialize master private key', () => {
    HD.PrivateKey.fromBase58(master.toBase58());
  });

  it('should deserialize master public key', () => {
    HD.PublicKey.fromBase58(master.toPublic().toBase58());
  });

  it('should deserialize and reserialize json', () => {
    const key = HD.generate();
    const json = key.toJSON();
    base58Equal(HD.fromJSON(json).toBase58(), key.toBase58());
  });

  for (const vector of [vector1, vector2]) {
    let master = null;

    it('should create from a seed', () => {
      const seed = Buffer.from(vector.seed, 'hex');
      const key = HD.PrivateKey.fromSeed(seed);
      const pub = key.toPublic();

      base58Equal(key.toBase58(), vector.m.prv);
      base58Equal(pub.toBase58(), vector.m.pub);

      master = key;
    });

    for (const path of Object.keys(vector)) {
      if (path === 'seed' || path === 'm')
        continue;

      const kp = vector[path];

      it(`should derive ${path} from master`, () => {
        const key = master.derivePath(path);
        const pub = key.toPublic();
        base58Equal(key.toBase58(), kp.prv);
        base58Equal(pub.toBase58(), kp.pub);
      });
    }
  }
});
