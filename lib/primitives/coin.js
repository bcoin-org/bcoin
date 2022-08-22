/*!
 * coin.js - coin object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const util = require('../utils/util');
const Amount = require('../btc/amount');
const Output = require('./output');
const Network = require('../protocol/network');
const consensus = require('../protocol/consensus');
const Outpoint = require('./outpoint');
const {inspectSymbol} = require('../utils');
const {encoding} = require('bufio');

/**
 * Coin
 * Represents an unspent output.
 * @alias module:primitives.Coin
 * @extends Output
 * @property {Number} version
 * @property {Number} height
 * @property {Amount} value
 * @property {Script} script
 * @property {Boolean} coinbase
 * @property {Hash} hash
 * @property {Number} index
 */

class Coin extends Output {
  /**
   * Create a coin.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();

    this.version = 1;
    this.height = -1;
    this.coinbase = false;
    this.hash = consensus.ZERO_HASH;
    this.index = 0;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject options into coin.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    assert(options, 'Coin data is required.');

    if (options.version != null) {
      assert((options.version >>> 0) === options.version,
        'Version must be a uint32.');
      this.version = options.version;
    }

    if (options.height != null) {
      if (options.height !== -1) {
        assert((options.height >>> 0) === options.height,
          'Height must be a uint32.');
        this.height = options.height;
      } else {
        this.height = -1;
      }
    }

    if (options.value != null) {
      assert(Number.isSafeInteger(options.value) && options.value >= 0,
        'Value must be a uint64.');
      this.value = options.value;
    }

    if (options.script)
      this.script.fromOptions(options.script);

    if (options.coinbase != null) {
      assert(typeof options.coinbase === 'boolean',
        'Coinbase must be a boolean.');
      this.coinbase = options.coinbase;
    }

    if (options.hash != null) {
      assert(Buffer.isBuffer(options.hash));
      this.hash = options.hash;
    }

    if (options.index != null) {
      assert((options.index >>> 0) === options.index,
        'Index must be a uint32.');
      this.index = options.index;
    }

    return this;
  }

  /**
   * Instantiate Coin from options object.
   * @private
   * @param {Object} options
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Clone the coin.
   * @private
   * @returns {Coin}
   */

  clone() {
    assert(false, 'Coins are not cloneable.');
  }

  /**
   * Calculate number of confirmations since coin was created.
   * @param {Number?} height - Current chain height. Network
   * height is used if not passed in.
   * @return {Number}
   */

  getDepth(height) {
    assert(typeof height === 'number', 'Must pass a height.');

    if (this.height === -1)
      return 0;

    if (height === -1)
      return 0;

    if (height < this.height)
      return 0;

    return height - this.height + 1;
  }

  /**
   * Serialize coin to a key
   * suitable for a hash table.
   * @returns {String}
   */

  toKey() {
    return Outpoint.toKey(this.hash, this.index);
  }

  /**
   * Inject properties from hash table key.
   * @private
   * @param {String} key
   * @returns {Coin}
   */

  fromKey(key) {
    const {hash, index} = Outpoint.fromKey(key);
    this.hash = hash;
    this.index = index;
    return this;
  }

  /**
   * Instantiate coin from hash table key.
   * @param {String} key
   * @returns {Coin}
   */

  static fromKey(key) {
    return new this().fromKey(key);
  }

  /**
   * Get little-endian hash.
   * @returns {Hash}
   */

  rhash() {
    return util.revHex(this.hash);
  }

  /**
   * Get little-endian hash.
   * @returns {Hash}
   */

  txid() {
    return this.rhash();
  }

  /**
   * Convert the coin to a more user-friendly object.
   * @returns {Object}
   */

 [inspectSymbol]() {
    return {
      type: this.getType(),
      version: this.version,
      height: this.height,
      value: Amount.btc(this.value),
      script: this.script,
      coinbase: this.coinbase,
      hash: this.hash ? util.revHex(this.hash) : null,
      index: this.index,
      address: this.getAddress()
    };
  }

  /**
   * Convert the coin to an object suitable
   * for JSON serialization.
   * @returns {Object}
   */

  toJSON() {
    return this.getJSON();
  }

  /**
   * Convert the coin to an object suitable
   * for JSON serialization. Note that the hash
   * will be reversed to abide by bitcoind's legacy
   * of little-endian uint256s.
   * @param {Network} network
   * @param {Boolean} minimal
   * @returns {Object}
   */

  getJSON(network, minimal) {
    let addr = this.getAddress();

    network = Network.get(network);

    if (addr)
      addr = addr.toString(network);

    return {
      version: this.version,
      height: this.height,
      value: this.value,
      script: this.script.toJSON(),
      address: addr,
      coinbase: this.coinbase,
      hash: !minimal ? this.rhash() : undefined,
      index: !minimal ? this.index : undefined
    };
  }

  /**
   * Inject JSON properties into coin.
   * @private
   * @param {Object} json
   */

  fromJSON(json) {
    assert(json, 'Coin data required.');
    assert((json.version >>> 0) === json.version, 'Version must be a uint32.');
    assert(json.height === -1 || (json.height >>> 0) === json.height,
      'Height must be a uint32.');
    assert(Number.isSafeInteger(json.value) && json.value >= 0,
      'Value must be a uint64.');
    assert(typeof json.coinbase === 'boolean', 'Coinbase must be a boolean.');

    this.version = json.version;
    this.height = json.height;
    this.value = json.value;
    this.script.fromJSON(json.script);
    this.coinbase = json.coinbase;

    if (json.hash != null) {
      assert(typeof json.hash === 'string', 'Hash must be a string.');
      assert(json.hash.length === 64, 'Hash must be a string.');
      assert((json.index >>> 0) === json.index, 'Index must be a uint32.');
      this.hash = util.fromRev(json.hash);
      this.index = json.index;
    }

    return this;
  }

  /**
   * Instantiate an Coin from a jsonified coin object.
   * @param {Object} json - The jsonified coin object.
   * @returns {Coin}
   */

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  /**
   * Calculate size of coin.
   * @returns {Number}
   */

  getSize() {
    return 17 + this.script.getVarSize();
  }

  /**
   * Estimate spending size.
   * @param {Function?} getAccount - Returns account that can spend
   * from a given address.
   * @returns {Number}
   */

  async estimateSpendingSize(getAccount) {
    let total = 0;

    // Outpoint (hash and index) + sequence
    total += 32 + 4 + 4;

    const scale = consensus.WITNESS_SCALE_FACTOR;

    // Previous output script.
    const script = this.script;

    // P2PK
    if (script.isPubkey()) {
      // varint script size
      total += 1;
      // OP_PUSHDATA0 [signature]
      total += 1 + 73;
      return total;
    }

    // P2PKH
    if (script.isPubkeyhash()) {
      // varint script size
      total += 1;
      // OP_PUSHDATA0 [signature]
      total += 1 + 73;
      // OP_PUSHDATA0 [key]
      total += 1 + 33;
      return total;
    }

    // Multisig
    let [m] = script.getMultisig();
    if (m !== -1) {
      let size = 0;
      // Bare Multisig
      // OP_0
      size += 1;
      // OP_PUSHDATA0 [signature] ...
      size += (1 + 73) * m;
      // varint len
      size += encoding.sizeVarint(size);
      total += size;
      return total;
    }

    // P2WPKH
    if (script.isWitnessPubkeyhash()) {
      let size = 0;
      // legacy script size (0x00)
      total += 1;
      // varint-items-len
      size += 1;
      // varint-len [signature]
      size += 1 + 73;
      // varint-len [key]
      size += 1 + 33;
      // vsize
      size = (size + scale - 1) / scale | 0;
      total += size;
      return total;
    }

    // Assume 2-of-3 multisig for P2SH
    m = 2;
    let n = 3;
    let type = 1;
    let witness = false;

    // check if getAccount is defined
    if (getAccount) {
      const account = await getAccount(script.getAddress());
      // if account is defined,
      // update m, n, type and witness
      if (account) {
        m = account.m;
        n = account.n;
        type = account.type;
        witness = account.witness;
      }
    }

    // P2SH
    if (script.isScripthash()) {
      let size = 0;
      if (!witness) {
        // Multisig
        // OP_0
        size += 1;
        // varint-len [signature] ...
        size += (1 + 73) * m;
        // script (OP_PUSHDATA1, varint length)
        size += 1 + 1;
        // OP_2
        size += 1;
        // varint [pubkey] ...
        size += (1 + 33) * n;
        // OP_3 OP_CHECKMULTISIG
        size += 1 + 1;
        total += size;
      } else {
        // 0 = PubKeyHash, 1 = Multisig
        if (type) {
          // Multisig

          // scriptSig (varint-len, OP_0, varint-len, scriptHash)
          total += 1 + 1 + 1 + 32;

          // OP_0
          size += 1;
          // OP_PUSHDATA0 [signature] ...
          size += (1 + 73) * m;
          // script (OP_PUSHDATA1, varint length)
          size += 1 + 1;
          // OP_2
          size += 1;
          // [pubkey] ...
          size += (1 + 33) * n;
          // OP_3 OP_CHECKMULTISIG
          size += 1 + 1;
          // vsize
          size = (size + scale - 1) / scale | 0;
          total += size;
        } else {
          // PubKeyHash

          // scriptSig (varint-len, OP_0, varint-len, pubKeyHash)
          total += 1 + 1 + 1 + 32;

          // varint script size
          size += 1;
          // OP_PUSHDATA0 [signature]
          size += 1 + 73;
          // OP_PUSHDATA0 [key]
          size += 1 + 33;
          // vsize
          size = (size + scale - 1) / scale | 0;
          total += size;
        }
      }
      return total;
    }

    // P2WSH
    if (script.isWitnessScripthash()) {
      // legacy script size (0x00)
      total += 1;
      let size = 0;
      // varint-items-len
      size += 1;
      // OP_0
      size += 1;
      // OP_PUSHDATA0 [signature] ...
      size += (1 + 73) * m;
      // script (OP_PUSHDATA1, varint length)
      size += 1 + 1;
      // OP_2
      size += 1;
      // [pubkey] ...
      size += (1 + 33) * n;
      // OP_3 OP_CHECKMULTISIG
      size += 1 + 1;
      // vsize
      size = (size + scale - 1) / scale | 0;
      total += size;
      return total;
    }

    // Unknown.
    // Assume it's a P2PKH :(
    total += 110;
    return total;
  }

  /**
   * Write the coin to a buffer writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    let height = this.height;

    if (height === -1)
      height = 0x7fffffff;

    bw.writeU32(this.version);
    bw.writeU32(height);
    bw.writeI64(this.value);
    bw.writeVarBytes(this.script.toRaw());
    bw.writeU8(this.coinbase ? 1 : 0);

    return bw;
  }

  /**
   * Serialize the coin.
   * @returns {Buffer|String}
   */

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  /**
   * Inject properties from serialized buffer writer.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.version = br.readU32();
    this.height = br.readU32();
    this.value = br.readI64();
    this.script.fromRaw(br.readVarBytes());
    this.coinbase = br.readU8() === 1;

    if (this.height === 0x7fffffff)
      this.height = -1;

    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate a coin from a buffer reader.
   * @param {BufferReader} br
   * @returns {Coin}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate a coin from a serialized Buffer.
   * @param {Buffer} data
   * @param {String?} enc - Encoding, can be `'hex'` or null.
   * @returns {Coin}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }

  /**
   * Inject properties from TX.
   * @param {TX} tx
   * @param {Number} index
   * @param {Number} height
   * @returns {Coin}
   */

  fromTX(tx, index, height) {
    assert(typeof index === 'number');
    assert(typeof height === 'number');
    assert(index >= 0 && index < tx.outputs.length);
    this.version = tx.version;
    this.height = height;
    this.value = tx.outputs[index].value;
    this.script = tx.outputs[index].script;
    this.coinbase = tx.isCoinbase();
    this.hash = tx.hash();
    this.index = index;
    return this;
  }

  /**
   * Instantiate a coin from a TX
   * @param {TX} tx
   * @param {Number} index - Output index.
   * @param {Number} height
   * @returns {Coin}
   */

  static fromTX(tx, index, height) {
    return new this().fromTX(tx, index, height);
  }

  /**
   * Test an object to see if it is a Coin.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isCoin(obj) {
    return obj instanceof Coin;
  }
}

/*
 * Expose
 */

module.exports = Coin;
