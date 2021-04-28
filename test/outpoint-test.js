/* eslint-env mocha */

'use strict';

const Outpoint = require('../lib/primitives/outpoint');
const assert = require('bsert');
const common = require('./util/common');
const util = require('../lib/utils/util');
const TX = require('../lib/primitives/tx');
const nodejsUtil = require('util');
const OUTPOINT_SIZE = 36;

describe('Outpoint', () => {
  let raw1, tx1, out1;
  beforeEach(() => {
    tx1 = common.readTX('tx1').getRaw();
    raw1 = tx1.slice(5, 5+OUTPOINT_SIZE);
    out1 = Outpoint.fromRaw(raw1);
  });

  it('should clone the outpoint correctly', () => {
    const out1 = Outpoint.fromRaw(raw1);
    const clone = out1.clone();
    const equals = out1.equals(clone);

    assert.strictEqual(out1 !== clone, true);
    assert.strictEqual(equals, true);
  });

  it('should create outpoint from options object', () => {
    const options = {};
    options.hash = out1.hash;
    options.index = out1.index;

    const newOut = Outpoint.fromOptions(options);
    assert(newOut.equals(out1), true);
  });

  it('should check hash and index are equal', () => {
    const out1Clone = Outpoint.fromOptions(Object.assign(out1, {}));

    assert(out1Clone.hash === out1.hash);
    assert(out1Clone.index === out1.index);
  });

  it('should compare the indexes between outpoints', () => {
    const out1RevHash = out1.clone();
    out1RevHash.hash = Buffer.from(out1RevHash.hash);
    out1RevHash.hash[0] = 0;

    const out1AdjIndex = out1.clone();
    out1AdjIndex.index += 1;

    const index1 = out1.index;
    const index2 = out1AdjIndex.index;
    // assert that it compares txid first
    assert(out1.compare(out1RevHash) !== 0, 'txid wasn\'t compared correctly');
    assert(out1.compare(out1) === 0);
    assert(out1.compare(out1AdjIndex) === index1 - index2);
  });

  it('should detect if the outpoint is null', () => {
    const rawHash = '00000000000000000000000000000000000000000000' +
    '00000000000000000000';
    const rawIndex = 'ffffffff';
    const nullOut = Outpoint.fromRaw(Buffer.from(rawHash + rawIndex, 'hex'));
    assert(nullOut.isNull(), true);
  });

  it('should retrieve little endian hash', () => {
    assert.strictEqual(out1.rhash(), util.revHex(out1.hash));
    assert.strictEqual(out1.txid(), util.revHex(out1.hash));
  });

  it('should serialize to a key suitable for hash table', () => {
    const expected = out1.toRaw();
    const actual = out1.toKey();
    assert.bufferEqual(expected, actual);
  });

  it('should inject properties from hash table key', () => {
    const key = out1.toKey();
    const fromKey = Outpoint.fromKey(key);
    assert(out1.equals(fromKey), true);
  });

  it('should return a size of 36', () => {
    assert(out1.getSize() === OUTPOINT_SIZE, true);
  });

  it('should create an outpoint from JSON', () => {
    const json = {
      hash: out1.txid(),
      index: out1.index
    };
    const fromJSON = Outpoint.fromJSON(json);

    assert.deepEqual(out1, fromJSON);
  });

  it('should return an object with reversed hash', () => {
    const hash = out1.hash;
    const index = out1.index;

    const expected = {
      hash: util.revHex(hash),
      index
    };
    assert.deepEqual(expected, out1.toJSON());
  });

  it('should instantiate an outpoint from a tx', () => {
    const tx = TX.fromRaw(tx1);
    const index = 0;
    const fromTX = Outpoint.fromTX(tx, index);

    assert.bufferEqual(fromTX.hash, tx.hash());
    assert.strictEqual(fromTX.index, index);
  });

  it('should inspect Outpoint', () => {
    const outpoint = new Outpoint();
    const fmt = nodejsUtil.format(outpoint);
    assert(typeof fmt === 'string');
    assert(fmt.includes('Outpoint'));
    assert(fmt.includes(
      '0000000000000000000000000000000000000000000000000000000000000000'));
  });
});
