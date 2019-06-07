/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const {base58} = require('bstring');
const pbkdf2 = require('bcrypto/lib/pbkdf2');
const sha512 = require('bcrypto/lib/sha512');
const assert = require('bsert');
const HD = require('../lib/hd');
const vectors = require('./data/hd.json');
const vector1 = vectors.vector1;
const vector2 = vectors.vector2;
const nodejsUtil = require('util');

let master = null;
let child = null;

function base58Equal(a, b) {
  assert.strictEqual(a, b);
  assert.bufferEqual(base58.decode(a), base58.decode(b));
}

describe('HD', function() {
  it('should create a pbkdf2 seed', () => {
    const seed = pbkdf2.derive(sha512,
      Buffer.from(vectors.phrase),
      Buffer.from('mnemonicfoo'),
      2048,
      64);
    assert.strictEqual(seed.toString('hex'), vectors.seed);
  });

  it('should create master private key', () => {
    const seed = Buffer.from(vectors.seed, 'hex');
    const key = HD.PrivateKey.fromSeed(seed);
    assert.strictEqual(key.toBase58('main'), vectors.master_priv);
    assert.strictEqual(key.toPublic().toBase58('main'), vectors.master_pub);
    master = key;
  });

  it('should derive(0) child from master', () => {
    const child1 = master.derive(0);
    assert.strictEqual(child1.toBase58('main'), vectors.child1_priv);
    assert.strictEqual(child1.toPublic().toBase58('main'), vectors.child1_pub);
  });

  it('should derive(1) child from master public key', () => {
    const child2 = master.toPublic().derive(1);
    assert.strictEqual(child2.toBase58('main'), vectors.child2_pub);
  });

  it('should derive(1) child from master', () => {
    const child3 = master.derive(1);
    assert.strictEqual(child3.toBase58('main'), vectors.child3_priv);
    assert.strictEqual(child3.toPublic().toBase58('main'), vectors.child3_pub);
  });

  it('should derive(2) child from master', () => {
    const child4 = master.derive(2);
    assert.strictEqual(child4.toBase58('main'), vectors.child4_priv);
    assert.strictEqual(child4.toPublic().toBase58('main'), vectors.child4_pub);
    child = child4;
  });

  it('should derive(0) child from child(2)', () => {
    const child5 = child.derive(0);
    assert.strictEqual(child5.toBase58('main'), vectors.child5_priv);
    assert.strictEqual(child5.toPublic().toBase58('main'), vectors.child5_pub);
  });

  it('should derive(1) child from child(2)', () => {
    const child6 = child.derive(1);
    assert.strictEqual(child6.toBase58('main'), vectors.child6_priv);
    assert.strictEqual(child6.toPublic().toBase58('main'), vectors.child6_pub);
  });

  it('should derive correctly when private key has leading zeros', () => {
    const key = HD.PrivateKey.fromBase58(vectors.zero_priv, 'main');

    assert.strictEqual(key.privateKey.toString('hex'),
      '00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd');

    const child = key.derivePath('m/44\'/0\'/0\'/0/0\'');
    assert.strictEqual(child.privateKey.toString('hex'),
      '3348069561d2a0fb925e74bf198762acc47dce7db27372257d2d959a9e6f8aeb');
  });

  it('should deserialize master private key', () => {
    HD.PrivateKey.fromBase58(master.toBase58('main'), 'main');
  });

  it('should deserialize master public key', () => {
    HD.PublicKey.fromBase58(master.toPublic().toBase58('main'), 'main');
  });

  it('should deserialize and reserialize json', () => {
    const key = HD.generate();
    const json = key.toJSON();
    base58Equal(
      HD.fromJSON(json, 'main').toBase58('main'),
      key.toBase58('main'));
  });

  it('should inspect Mnemonic', () => {
    const mne = new HD.Mnemonic();
    const fmt = nodejsUtil.format(mne);
    assert(typeof fmt === 'string');
    assert(fmt.includes('Mnemonic'));
    assert.strictEqual(fmt.split(' ').length, 13);
  });

  for (const vector of [vector1, vector2]) {
    let master = null;

    it('should create from a seed', () => {
      const seed = Buffer.from(vector.seed, 'hex');
      const key = HD.PrivateKey.fromSeed(seed);
      const pub = key.toPublic();

      base58Equal(key.toBase58('main'), vector.m.prv);
      base58Equal(pub.toBase58('main'), vector.m.pub);

      master = key;
    });

    for (const path of Object.keys(vector)) {
      if (path === 'seed' || path === 'm')
        continue;

      const kp = vector[path];

      it(`should derive ${path} from master`, () => {
        const key = master.derivePath(path);
        const pub = key.toPublic();
        base58Equal(key.toBase58('main'), kp.prv);
        base58Equal(pub.toBase58('main'), kp.pub);
      });
    }
  }
});
