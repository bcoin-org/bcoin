/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const bdb = require('../');
const vectors = require('./data/vectors.json');

describe('BDB', function() {
  const num = (Math.random() * 0x100000000) >>> 0;
  const dbpath = `/tmp/bdb-test-${num}.db`;
  const tkey = bdb.key('t', ['hash160', 'uint32']);
  const prefix = bdb.key('r');

  let db = null;

  before(async () => {
    db = bdb.create(dbpath);
    await db.open();
    assert.equal(db.location, dbpath);
    assert.equal(db.loading, false);
    assert.equal(db.loaded, true);
  });

  after(async () => {
    await db.close();
    assert.equal(db.loaded, false);
  });

  it('put and get key and value', async () => {
    const batch = db.batch();
    const hash = Buffer.alloc(20, 0x11);

    batch.put(tkey.encode(hash, 12), Buffer.from('foo'));

    await batch.write();

    const value = await db.get(tkey.encode(hash, 12));
    assert.equal(value.toString('utf8'), 'foo');
  });

  it('put and get key and value into bucket', async () => {
    const bucket = db.bucket(prefix.encode());
    const batch = bucket.batch();
    const hash = Buffer.alloc(20, 0x11);

    batch.put(tkey.encode(hash, 9), Buffer.from('foo'));

    await batch.write();

    const value = await bucket.get(tkey.encode(hash, 9));
    assert.equal(value.toString('utf8'), 'foo');
  });

  it('iterate over keys and values in a bucket', async () => {
    const mkey = bdb.key('m', ['hash160', 'uint32']);

    const bucket = db.bucket(prefix.encode());

    const batch = bucket.batch();

    for (let i = 0; i < vectors.length; i++) {
      const vector = vectors[i];
      const key = mkey.encode(Buffer.from(vector.key[0], 'hex'), vector.key[1]);
      const value = Buffer.from(vector.value, 'hex');
      batch.put(key, value);
    }

    await batch.write();

    const iter = bucket.iterator({
      gte: mkey.min(),
      lte: mkey.max(),
      values: true
    });

    let total = 0;

    await iter.each((key, value) => {
      const [hash, index] = mkey.decode(key);
      assert.equal(hash.toString('hex'), vectors[total].key[0]);
      assert.equal(index, vectors[total].key[1]);
      assert.equal(value.toString('hex'), vectors[total].value);
      total++;
    });

    assert.equal(total, 3);
  });

  it('delete key and value', async () => {
    const hash = Buffer.alloc(20, 0x11);
    const key = tkey.encode(hash, 99);

    const batch = db.batch();
    batch.put(key, Buffer.from('foo'));
    await batch.write();

    const value = await db.get(key);
    assert.equal(value.toString('utf8'), 'foo');

    await db.del(key);

    const value2 = await db.get(key);
    assert.equal(value2, null);
  });

  describe('get keys in range', function() {
    let nkey, bucket = null;

    before(async () => {
      nkey = bdb.key('n', ['hash160', 'uint32']);
      bucket = db.bucket(prefix.encode());

      const batch = bucket.batch();

      for (let i = 0; i < vectors.length; i++) {
        const vector = vectors[i];

        const key = nkey.encode(Buffer.from(vector.key[0], 'hex'),
                                vector.key[1]);

        const value = Buffer.from(vector.value, 'hex');

        batch.put(key, value);
      }

      await batch.write();
    });

    it('in standard order', async () => {
      const keys = await bucket.keys({
        gte: nkey.min(),
        lte: nkey.max()
      });

      assert.equal(keys.length, 3);

      for (let i = 0; i < keys.length; i++) {
        const [hash, index] = nkey.decode(keys[i]);
        assert.equal(hash.toString('hex'), vectors[i].key[0]);
        assert.equal(index, vectors[i].key[1]);
      }
    });

    it('in reverse order', async () => {
      const keys = await bucket.keys({
        gte: nkey.min(),
        lte: nkey.max(),
        reverse: true
      });

      assert.equal(keys.length, 3);

      keys.reverse();

      for (let i = 0; i < keys.length; i++) {
        const [hash, index] = nkey.decode(keys[i]);
        assert.equal(hash.toString('hex'), vectors[i].key[0]);
        assert.equal(index, vectors[i].key[1]);
      }
    });
  });
});
