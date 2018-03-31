/*!
 * account.js - account object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const bio = require('bufio');
const binary = require('../utils/binary');
const Path = require('./path');
const common = require('./common');
const Script = require('../script/script');
const WalletKey = require('./walletkey');
const {HDPublicKey} = require('../hd/hd');

/**
 * Account
 * Represents a BIP44 Account belonging to a {@link Wallet}.
 * Note that this object does not enforce locks. Any method
 * that does a write is internal API only and will lead
 * to race conditions if used elsewhere.
 * @alias module:wallet.Account
 */

class Account {
  /**
   * Create an account.
   * @constructor
   * @param {Object} options
   */

  constructor(wdb, options) {
    assert(wdb, 'Database is required.');

    this.wdb = wdb;
    this.network = wdb.network;

    this.wid = 0;
    this.id = null;
    this.accountIndex = 0;
    this.name = null;
    this.initialized = false;
    this.witness = wdb.options.witness === true;
    this.watchOnly = false;
    this.type = Account.types.PUBKEYHASH;
    this.m = 1;
    this.n = 1;
    this.receiveDepth = 0;
    this.changeDepth = 0;
    this.nestedDepth = 0;
    this.lookahead = 10;
    this.accountKey = null;
    this.keys = [];

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    assert(options, 'Options are required.');
    assert((options.wid >>> 0) === options.wid);
    assert(common.isName(options.id), 'Bad Wallet ID.');
    assert(HDPublicKey.isHDPublicKey(options.accountKey),
      'Account key is required.');
    assert((options.accountIndex >>> 0) === options.accountIndex,
      'Account index is required.');

    this.wid = options.wid;
    this.id = options.id;

    if (options.accountIndex != null) {
      assert((options.accountIndex >>> 0) === options.accountIndex);
      this.accountIndex = options.accountIndex;
    }

    if (options.name != null) {
      assert(common.isName(options.name), 'Bad account name.');
      this.name = options.name;
    }

    if (options.initialized != null) {
      assert(typeof options.initialized === 'boolean');
      this.initialized = options.initialized;
    }

    if (options.witness != null) {
      assert(typeof options.witness === 'boolean');
      this.witness = options.witness;
    }

    if (options.watchOnly != null) {
      assert(typeof options.watchOnly === 'boolean');
      this.watchOnly = options.watchOnly;
    }

    if (options.type != null) {
      if (typeof options.type === 'string') {
        this.type = Account.types[options.type.toUpperCase()];
        assert(this.type != null);
      } else {
        assert(typeof options.type === 'number');
        this.type = options.type;
        assert(Account.typesByVal[this.type]);
      }
    }

    if (options.m != null) {
      assert((options.m & 0xff) === options.m);
      this.m = options.m;
    }

    if (options.n != null) {
      assert((options.n & 0xff) === options.n);
      this.n = options.n;
    }

    if (options.receiveDepth != null) {
      assert((options.receiveDepth >>> 0) === options.receiveDepth);
      this.receiveDepth = options.receiveDepth;
    }

    if (options.changeDepth != null) {
      assert((options.changeDepth >>> 0) === options.changeDepth);
      this.changeDepth = options.changeDepth;
    }

    if (options.nestedDepth != null) {
      assert((options.nestedDepth >>> 0) === options.nestedDepth);
      this.nestedDepth = options.nestedDepth;
    }

    if (options.lookahead != null) {
      assert((options.lookahead >>> 0) === options.lookahead);
      assert(options.lookahead >= 0);
      assert(options.lookahead <= Account.MAX_LOOKAHEAD);
      this.lookahead = options.lookahead;
    }

    this.accountKey = options.accountKey;

    if (this.n > 1)
      this.type = Account.types.MULTISIG;

    if (!this.name)
      this.name = this.accountIndex.toString(10);

    if (this.m < 1 || this.m > this.n)
      throw new Error('m ranges between 1 and n');

    if (options.keys) {
      assert(Array.isArray(options.keys));
      for (const key of options.keys)
        this.pushKey(key);
    }

    return this;
  }

  /**
   * Instantiate account from options.
   * @param {WalletDB} wdb
   * @param {Object} options
   * @returns {Account}
   */

  static fromOptions(wdb, options) {
    return new this(wdb).fromOptions(options);
  }

  /**
   * Attempt to intialize the account (generating
   * the first addresses along with the lookahead
   * addresses). Called automatically from the
   * walletdb.
   * @returns {Promise}
   */

  async init(b) {
    // Waiting for more keys.
    if (this.keys.length !== this.n - 1) {
      assert(!this.initialized);
      this.save(b);
      return;
    }

    assert(this.receiveDepth === 0);
    assert(this.changeDepth === 0);
    assert(this.nestedDepth === 0);

    this.initialized = true;

    await this.initDepth(b);
  }

  /**
   * Add a public account key to the account (multisig).
   * Does not update the database.
   * @param {HDPublicKey} key - Account (bip44)
   * key (can be in base58 form).
   * @throws Error on non-hdkey/non-accountkey.
   */

  pushKey(key) {
    if (typeof key === 'string')
      key = HDPublicKey.fromBase58(key, this.network);

    if (!HDPublicKey.isHDPublicKey(key))
      throw new Error('Must add HD keys to wallet.');

    if (!key.isAccount())
      throw new Error('Must add HD account keys to BIP44 wallet.');

    if (this.type !== Account.types.MULTISIG)
      throw new Error('Cannot add keys to non-multisig wallet.');

    if (key.equals(this.accountKey))
      throw new Error('Cannot add own key.');

    const index = binary.insert(this.keys, key, cmp, true);

    if (index === -1)
      return false;

    if (this.keys.length > this.n - 1) {
      binary.remove(this.keys, key, cmp);
      throw new Error('Cannot add more keys.');
    }

    return true;
  }

  /**
   * Remove a public account key to the account (multisig).
   * Does not update the database.
   * @param {HDPublicKey} key - Account (bip44)
   * key (can be in base58 form).
   * @throws Error on non-hdkey/non-accountkey.
   */

  spliceKey(key) {
    if (typeof key === 'string')
      key = HDPublicKey.fromBase58(key, this.network);

    if (!HDPublicKey.isHDPublicKey(key))
      throw new Error('Must add HD keys to wallet.');

    if (!key.isAccount())
      throw new Error('Must add HD account keys to BIP44 wallet.');

    if (this.type !== Account.types.MULTISIG)
      throw new Error('Cannot remove keys from non-multisig wallet.');

    if (this.keys.length === this.n - 1)
      throw new Error('Cannot remove key.');

    return binary.remove(this.keys, key, cmp);
  }

  /**
   * Add a public account key to the account (multisig).
   * Saves the key in the wallet database.
   * @param {HDPublicKey} key
   * @returns {Promise}
   */

  async addSharedKey(b, key) {
    const result = this.pushKey(key);

    if (await this.hasDuplicate()) {
      this.spliceKey(key);
      throw new Error('Cannot add a key from another account.');
    }

    // Try to initialize again.
    await this.init(b);

    return result;
  }

  /**
   * Ensure accounts are not sharing keys.
   * @private
   * @returns {Promise}
   */

  async hasDuplicate() {
    if (this.keys.length !== this.n - 1)
      return false;

    const ring = this.deriveReceive(0);
    const hash = ring.getScriptHash('hex');

    return this.wdb.hasPath(this.wid, hash);
  }

  /**
   * Remove a public account key from the account (multisig).
   * Remove the key from the wallet database.
   * @param {HDPublicKey} key
   * @returns {Promise}
   */

  removeSharedKey(b, key) {
    const result = this.spliceKey(key);

    if (!result)
      return false;

    this.save(b);

    return true;
  }

  /**
   * Create a new receiving address (increments receiveDepth).
   * @returns {Promise} - Returns {@link WalletKey}
   */

  createReceive(b) {
    return this.createKey(b, 0);
  }

  /**
   * Create a new change address (increments receiveDepth).
   * @returns {Promise} - Returns {@link WalletKey}
   */

  createChange(b) {
    return this.createKey(b, 1);
  }

  /**
   * Create a new change address (increments receiveDepth).
   * @returns {Promise} - Returns {@link WalletKey}
   */

  createNested(b) {
    return this.createKey(b, 2);
  }

  /**
   * Create a new address (increments depth).
   * @param {Boolean} change
   * @returns {Promise} - Returns {@link WalletKey}.
   */

  async createKey(b, branch) {
    let key, lookahead;

    switch (branch) {
      case 0:
        key = this.deriveReceive(this.receiveDepth);
        lookahead = this.deriveReceive(this.receiveDepth + this.lookahead);
        await this.saveKey(b, lookahead);
        this.receiveDepth += 1;
        this.receive = key;
        break;
      case 1:
        key = this.deriveChange(this.changeDepth);
        lookahead = this.deriveReceive(this.changeDepth + this.lookahead);
        await this.saveKey(b, lookahead);
        this.changeDepth += 1;
        this.change = key;
        break;
      case 2:
        key = this.deriveNested(this.nestedDepth);
        lookahead = this.deriveNested(this.nestedDepth + this.lookahead);
        await this.saveKey(b, lookahead);
        this.nestedDepth += 1;
        this.nested = key;
        break;
      default:
        throw new Error(`Bad branch: ${branch}.`);
    }

    this.save(b);

    return key;
  }

  /**
   * Derive a receiving address at `index`. Do not increment depth.
   * @param {Number} index
   * @returns {WalletKey}
   */

  deriveReceive(index, master) {
    return this.deriveKey(0, index, master);
  }

  /**
   * Derive a change address at `index`. Do not increment depth.
   * @param {Number} index
   * @returns {WalletKey}
   */

  deriveChange(index, master) {
    return this.deriveKey(1, index, master);
  }

  /**
   * Derive a nested address at `index`. Do not increment depth.
   * @param {Number} index
   * @returns {WalletKey}
   */

  deriveNested(index, master) {
    if (!this.witness)
      throw new Error('Cannot derive nested on non-witness account.');

    return this.deriveKey(2, index, master);
  }

  /**
   * Derive an address from `path` object.
   * @param {Path} path
   * @param {MasterKey} master
   * @returns {WalletKey}
   */

  derivePath(path, master) {
    switch (path.keyType) {
      case Path.types.HD: {
        return this.deriveKey(path.branch, path.index, master);
      }
      case Path.types.KEY: {
        assert(this.type === Account.types.PUBKEYHASH);

        let data = path.data;

        if (path.encrypted) {
          data = master.decipher(data, path.hash);
          if (!data)
            return null;
        }

        return WalletKey.fromImport(this, data);
      }
      case Path.types.ADDRESS: {
        return null;
      }
      default: {
        throw new Error('Bad key type.');
      }
    }
  }

  /**
   * Derive an address at `index`. Do not increment depth.
   * @param {Number} branch
   * @param {Number} index
   * @returns {WalletKey}
   */

  deriveKey(branch, index, master) {
    assert(typeof branch === 'number');

    const keys = [];

    let key;
    if (master && master.key && !this.watchOnly) {
      const type = this.network.keyPrefix.coinType;
      key = master.key.deriveAccount(44, type, this.accountIndex);
      key = key.derive(branch).derive(index);
    } else {
      key = this.accountKey.derive(branch).derive(index);
    }

    const ring = WalletKey.fromHD(this, key, branch, index);

    switch (this.type) {
      case Account.types.PUBKEYHASH:
        break;
      case Account.types.MULTISIG:
        keys.push(key.publicKey);

        for (const shared of this.keys) {
          const key = shared.derive(branch).derive(index);
          keys.push(key.publicKey);
        }

        ring.script = Script.fromMultisig(this.m, this.n, keys);

        break;
    }

    return ring;
  }

  /**
   * Save the account to the database. Necessary
   * when address depth and keys change.
   * @returns {Promise}
   */

  save(b) {
    return this.wdb.saveAccount(b, this);
  }

  /**
   * Save addresses to path map.
   * @param {WalletKey[]} rings
   * @returns {Promise}
   */

  saveKey(b, ring) {
    return this.wdb.saveKey(b, this.wid, ring);
  }

  /**
   * Save paths to path map.
   * @param {Path[]} rings
   * @returns {Promise}
   */

  savePath(b, path) {
    return this.wdb.savePath(b, this.wid, path);
  }

  /**
   * Initialize address depths (including lookahead).
   * @returns {Promise}
   */

  async initDepth(b) {
    // Receive Address
    this.receiveDepth = 1;

    for (let i = 0; i <= this.lookahead; i++) {
      const key = this.deriveReceive(i);
      await this.saveKey(b, key);
    }

    // Change Address
    this.changeDepth = 1;

    for (let i = 0; i <= this.lookahead; i++) {
      const key = this.deriveChange(i);
      await this.saveKey(b, key);
    }

    // Nested Address
    if (this.witness) {
      this.nestedDepth = 1;

      for (let i = 0; i <= this.lookahead; i++) {
        const key = this.deriveNested(i);
        await this.saveKey(b, key);
      }
    }

    this.save(b);
  }

  /**
   * Allocate new lookahead addresses if necessary.
   * @param {Number} receiveDepth
   * @param {Number} changeDepth
   * @param {Number} nestedDepth
   * @returns {Promise} - Returns {@link WalletKey}.
   */

  async syncDepth(b, receive, change, nested) {
    let derived = false;
    let result = null;

    if (receive > this.receiveDepth) {
      const depth = this.receiveDepth + this.lookahead;

      assert(receive <= depth + 1);

      for (let i = depth; i < receive + this.lookahead; i++) {
        const key = this.deriveReceive(i);
        await this.saveKey(b, key);
        result = key;
      }

      this.receiveDepth = receive;

      derived = true;
    }

    if (change > this.changeDepth) {
      const depth = this.changeDepth + this.lookahead;

      assert(change <= depth + 1);

      for (let i = depth; i < change + this.lookahead; i++) {
        const key = this.deriveChange(i);
        await this.saveKey(b, key);
      }

      this.changeDepth = change;

      derived = true;
    }

    if (this.witness && nested > this.nestedDepth) {
      const depth = this.nestedDepth + this.lookahead;

      assert(nested <= depth + 1);

      for (let i = depth; i < nested + this.lookahead; i++) {
        const key = this.deriveNested(i);
        await this.saveKey(b, key);
        result = key;
      }

      this.nestedDepth = nested;

      derived = true;
      result = this.nested;
    }

    if (derived)
      this.save(b);

    return result;
  }

  /**
   * Allocate new lookahead addresses.
   * @param {Number} lookahead
   * @returns {Promise}
   */

  async setLookahead(b, lookahead) {
    if (lookahead === this.lookahead)
      return;

    if (lookahead < this.lookahead) {
      const diff = this.lookahead - lookahead;

      this.receiveDepth += diff;
      this.changeDepth += diff;

      if (this.witness)
        this.nestedDepth += diff;

      this.lookahead = lookahead;

      this.save(b);

      return;
    }

    {
      const depth = this.receiveDepth + this.lookahead;
      const target = this.receiveDepth + lookahead;

      for (let i = depth; i < target; i++) {
        const key = this.deriveReceive(i);
        await this.saveKey(b, key);
      }
    }

    {
      const depth = this.changeDepth + this.lookahead;
      const target = this.changeDepth + lookahead;

      for (let i = depth; i < target; i++) {
        const key = this.deriveChange(i);
        await this.saveKey(b, key);
      }
    }

    if (this.witness) {
      const depth = this.nestedDepth + this.lookahead;
      const target = this.nestedDepth + lookahead;

      for (let i = depth; i < target; i++) {
        const key = this.deriveNested(i);
        await this.saveKey(b, key);
      }
    }

    this.lookahead = lookahead;
    this.save(b);
  }

  /**
   * Get current receive key.
   * @returns {WalletKey}
   */

  receiveKey() {
    if (!this.initialized)
      return null;

    return this.deriveReceive(this.receiveDepth - 1);
  }

  /**
   * Get current change key.
   * @returns {WalletKey}
   */

  changeKey() {
    if (!this.initialized)
      return null;

    return this.deriveChange(this.changeDepth - 1);
  }

  /**
   * Get current nested key.
   * @returns {WalletKey}
   */

  nestedKey() {
    if (!this.initialized)
      return null;

    if (!this.witness)
      return null;

    return this.deriveNested(this.nestedDepth - 1);
  }

  /**
   * Get current receive address.
   * @returns {Address}
   */

  receiveAddress() {
    const key = this.receiveKey();

    if (!key)
      return null;

    return key.getAddress();
  }

  /**
   * Get current change address.
   * @returns {Address}
   */

  changeAddress() {
    const key = this.changeKey();

    if (!key)
      return null;

    return key.getAddress();
  }

  /**
   * Get current nested address.
   * @returns {Address}
   */

  nestedAddress() {
    const key = this.nestedKey();

    if (!key)
      return null;

    return key.getAddress();
  }

  /**
   * Convert the account to a more inspection-friendly object.
   * @returns {Object}
   */

  inspect() {
    const receive = this.receiveAddress();
    const change = this.changeAddress();
    const nested = this.nestedAddress();

    return {
      id: this.id,
      wid: this.wid,
      name: this.name,
      network: this.network.type,
      initialized: this.initialized,
      witness: this.witness,
      watchOnly: this.watchOnly,
      type: Account.typesByVal[this.type].toLowerCase(),
      m: this.m,
      n: this.n,
      accountIndex: this.accountIndex,
      receiveDepth: this.receiveDepth,
      changeDepth: this.changeDepth,
      nestedDepth: this.nestedDepth,
      lookahead: this.lookahead,
      receiveAddress: receive ? receive.toString(this.network) : null,
      changeAddress: change ? change.toString(this.network) : null,
      nestedAddress: nested ? nested.toString(this.network) : null,
      accountKey: this.accountKey.toBase58(this.network),
      keys: this.keys.map(key => key.toBase58(this.network))
    };
  }

  /**
   * Convert the account to an object suitable for
   * serialization.
   * @returns {Object}
   */

  toJSON(balance) {
    const receive = this.receiveAddress();
    const change = this.changeAddress();
    const nested = this.nestedAddress();

    return {
      name: this.name,
      initialized: this.initialized,
      witness: this.witness,
      watchOnly: this.watchOnly,
      type: Account.typesByVal[this.type].toLowerCase(),
      m: this.m,
      n: this.n,
      accountIndex: this.accountIndex,
      receiveDepth: this.receiveDepth,
      changeDepth: this.changeDepth,
      nestedDepth: this.nestedDepth,
      lookahead: this.lookahead,
      receiveAddress: receive ? receive.toString(this.network) : null,
      changeAddress: change ? change.toString(this.network) : null,
      nestedAddress: nested ? nested.toString(this.network) : null,
      accountKey: this.accountKey.toBase58(this.network),
      keys: this.keys.map(key => key.toBase58(this.network)),
      balance: balance ? balance.toJSON(true) : null
    };
  }

  /**
   * Calculate serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;
    size += 92;
    size += this.keys.length * 74;
    return size;
  }

  /**
   * Serialize the account.
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    const bw = bio.write(size);

    let flags = 0;

    if (this.initialized)
      flags |= 1;

    if (this.witness)
      flags |= 2;

    bw.writeU8(flags);
    bw.writeU8(this.type);
    bw.writeU8(this.m);
    bw.writeU8(this.n);
    bw.writeU32(this.receiveDepth);
    bw.writeU32(this.changeDepth);
    bw.writeU32(this.nestedDepth);
    bw.writeU8(this.lookahead);
    writeKey(this.accountKey, bw);
    bw.writeU8(this.keys.length);

    for (const key of this.keys)
      writeKey(key, bw);

    return bw.render();
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   * @returns {Object}
   */

  fromRaw(data) {
    const br = bio.read(data);
    const flags = br.readU8();

    this.initialized = (flags & 1) !== 0;
    this.witness = (flags & 2) !== 0;
    this.type = br.readU8();
    this.m = br.readU8();
    this.n = br.readU8();
    this.receiveDepth = br.readU32();
    this.changeDepth = br.readU32();
    this.nestedDepth = br.readU32();
    this.lookahead = br.readU8();
    this.accountKey = readKey(br);

    assert(this.type < Account.typesByVal.length);

    const count = br.readU8();

    for (let i = 0; i < count; i++) {
      const key = readKey(br);
      binary.insert(this.keys, key, cmp, true);
    }

    return this;
  }

  /**
   * Instantiate a account from serialized data.
   * @param {WalletDB} data
   * @param {Buffer} data
   * @returns {Account}
   */

  static fromRaw(wdb, data) {
    return new this(wdb).fromRaw(data);
  }

  /**
   * Test an object to see if it is a Account.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isAccount(obj) {
    return obj instanceof Account;
  }
}

/**
 * Account types.
 * @enum {Number}
 * @default
 */

Account.types = {
  PUBKEYHASH: 0,
  MULTISIG: 1
};

/**
 * Account types by value.
 * @const {Object}
 */

Account.typesByVal = [
  'PUBKEYHASH',
  'MULTISIG'
];

/**
 * Default address lookahead.
 * @const {Number}
 */

Account.MAX_LOOKAHEAD = 40;

/*
 * Helpers
 */

function cmp(a, b) {
  return a.compare(b);
}

function writeKey(key, bw) {
  bw.writeU8(key.depth);
  bw.writeU32BE(key.parentFingerPrint);
  bw.writeU32BE(key.childIndex);
  bw.writeBytes(key.chainCode);
  bw.writeBytes(key.publicKey);
}

function readKey(br) {
  const key = new HDPublicKey();
  key.depth = br.readU8();
  key.parentFingerPrint = br.readU32BE();
  key.childIndex = br.readU32BE();
  key.chainCode = br.readBytes(32);
  key.publicKey = br.readBytes(33);
  return key;
}

/*
 * Expose
 */

module.exports = Account;
