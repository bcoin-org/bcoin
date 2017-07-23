/*!
 * account.js - account object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const util = require('../utils/util');
const assert = require('assert');
const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const encoding = require('../utils/encoding');
const Path = require('./path');
const common = require('./common');
const Script = require('../script/script');
const WalletKey = require('./walletkey');
const HD = require('../hd/hd');

/**
 * Represents a BIP44 Account belonging to a {@link Wallet}.
 * Note that this object does not enforce locks. Any method
 * that does a write is internal API only and will lead
 * to race conditions if used elsewhere.
 * @alias module:wallet.Account
 * @constructor
 * @param {Object} options
 * @param {WalletDB} options.db
 * @param {HDPublicKey} options.accountKey
 * @param {Boolean?} options.witness - Whether to use witness programs.
 * @param {Number} options.accountIndex - The BIP44 account index.
 * @param {Number?} options.receiveDepth - The index of the _next_ receiving
 * address.
 * @param {Number?} options.changeDepth - The index of the _next_ change
 * address.
 * @param {String?} options.type - Type of wallet (pubkeyhash, multisig)
 * (default=pubkeyhash).
 * @param {Number?} options.m - `m` value for multisig.
 * @param {Number?} options.n - `n` value for multisig.
 * @param {String?} options.wid - Wallet ID
 * @param {String?} options.name - Account name
 */

function Account(db, options) {
  if (!(this instanceof Account))
    return new Account(db, options);

  assert(db, 'Database is required.');

  this.db = db;
  this.network = db.network;
  this.wallet = null;

  this.receive = null;
  this.change = null;
  this.nested = null;

  this.wid = 0;
  this.id = null;
  this.name = null;
  this.initialized = false;
  this.witness = this.db.options.witness === true;
  this.watchOnly = false;
  this.type = Account.types.PUBKEYHASH;
  this.m = 1;
  this.n = 1;
  this.accountIndex = 0;
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
 * @const {RevMap}
 */

Account.typesByVal = {
  0: 'pubkeyhash',
  1: 'multisig'
};

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

Account.prototype.fromOptions = function fromOptions(options) {
  assert(options, 'Options are required.');
  assert(util.isNumber(options.wid));
  assert(common.isName(options.id), 'Bad Wallet ID.');
  assert(HD.isHD(options.accountKey), 'Account key is required.');
  assert(util.isNumber(options.accountIndex), 'Account index is required.');

  this.wid = options.wid;
  this.id = options.id;

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
    assert(util.isNumber(options.m));
    this.m = options.m;
  }

  if (options.n != null) {
    assert(util.isNumber(options.n));
    this.n = options.n;
  }

  if (options.accountIndex != null) {
    assert(util.isNumber(options.accountIndex));
    this.accountIndex = options.accountIndex;
  }

  if (options.receiveDepth != null) {
    assert(util.isNumber(options.receiveDepth));
    this.receiveDepth = options.receiveDepth;
  }

  if (options.changeDepth != null) {
    assert(util.isNumber(options.changeDepth));
    this.changeDepth = options.changeDepth;
  }

  if (options.nestedDepth != null) {
    assert(util.isNumber(options.nestedDepth));
    this.nestedDepth = options.nestedDepth;
  }

  if (options.lookahead != null) {
    assert(util.isNumber(options.lookahead));
    assert(options.lookahead >= 0);
    assert(options.lookahead <= Account.MAX_LOOKAHEAD);
    this.lookahead = options.lookahead;
  }

  this.accountKey = options.accountKey;

  if (this.n > 1)
    this.type = Account.types.MULTISIG;

  if (!this.name)
    this.name = this.accountIndex + '';

  if (this.m < 1 || this.m > this.n)
    throw new Error('m ranges between 1 and n');

  if (options.keys) {
    assert(Array.isArray(options.keys));
    for (let key of options.keys)
      this.pushKey(key);
  }

  return this;
};

/**
 * Instantiate account from options.
 * @param {WalletDB} db
 * @param {Object} options
 * @returns {Account}
 */

Account.fromOptions = function fromOptions(db, options) {
  return new Account(db).fromOptions(options);
};

/*
 * Default address lookahead.
 * @const {Number}
 */

Account.MAX_LOOKAHEAD = 40;

/**
 * Attempt to intialize the account (generating
 * the first addresses along with the lookahead
 * addresses). Called automatically from the
 * walletdb.
 * @returns {Promise}
 */

Account.prototype.init = async function init() {
  // Waiting for more keys.
  if (this.keys.length !== this.n - 1) {
    assert(!this.initialized);
    this.save();
    return;
  }

  assert(this.receiveDepth === 0);
  assert(this.changeDepth === 0);
  assert(this.nestedDepth === 0);

  this.initialized = true;

  await this.initDepth();
};

/**
 * Open the account (done after retrieval).
 * @returns {Promise}
 */

Account.prototype.open = function open() {
  if (!this.initialized)
    return Promise.resolve();

  if (this.receive)
    return Promise.resolve();

  this.receive = this.deriveReceive(this.receiveDepth - 1);
  this.change = this.deriveChange(this.changeDepth - 1);

  if (this.witness)
    this.nested = this.deriveNested(this.nestedDepth - 1);

  return Promise.resolve();
};

/**
 * Add a public account key to the account (multisig).
 * Does not update the database.
 * @param {HDPublicKey} key - Account (bip44)
 * key (can be in base58 form).
 * @throws Error on non-hdkey/non-accountkey.
 */

Account.prototype.pushKey = function pushKey(key) {
  let index;

  if (typeof key === 'string')
    key = HD.PublicKey.fromBase58(key, this.network);

  assert(key.network === this.network,
    'Network mismatch for account key.');

  if (!HD.isPublic(key))
    throw new Error('Must add HD keys to wallet.');

  if (!key.isBIP44())
    throw new Error('Must add HD account keys to BIP44 wallet.');

  if (this.type !== Account.types.MULTISIG)
    throw new Error('Cannot add keys to non-multisig wallet.');

  if (key.equal(this.accountKey))
    throw new Error('Cannot add own key.');

  index = util.binaryInsert(this.keys, key, cmp, true);

  if (index === -1)
    return false;

  if (this.keys.length > this.n - 1) {
    util.binaryRemove(this.keys, key, cmp);
    throw new Error('Cannot add more keys.');
  }

  return true;
};

/**
 * Remove a public account key to the account (multisig).
 * Does not update the database.
 * @param {HDPublicKey} key - Account (bip44)
 * key (can be in base58 form).
 * @throws Error on non-hdkey/non-accountkey.
 */

Account.prototype.spliceKey = function spliceKey(key) {
  if (typeof key === 'string')
    key = HD.PublicKey.fromBase58(key, this.network);

  assert(key.network === this.network,
    'Network mismatch for account key.');

  if (!HD.isPublic(key))
    throw new Error('Must add HD keys to wallet.');

  if (!key.isBIP44())
    throw new Error('Must add HD account keys to BIP44 wallet.');

  if (this.type !== Account.types.MULTISIG)
    throw new Error('Cannot remove keys from non-multisig wallet.');

  if (this.keys.length === this.n - 1)
    throw new Error('Cannot remove key.');

  return util.binaryRemove(this.keys, key, cmp);
};

/**
 * Add a public account key to the account (multisig).
 * Saves the key in the wallet database.
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Account.prototype.addSharedKey = async function addSharedKey(key) {
  let result = this.pushKey(key);
  let exists = await this._hasDuplicate();

  if (exists) {
    this.spliceKey(key);
    throw new Error('Cannot add a key from another account.');
  }

  // Try to initialize again.
  await this.init();

  return result;
};

/**
 * Ensure accounts are not sharing keys.
 * @private
 * @returns {Promise}
 */

Account.prototype._hasDuplicate = function _hasDuplicate() {
  let ring, hash;

  if (this.keys.length !== this.n - 1)
    return false;

  ring = this.deriveReceive(0);
  hash = ring.getScriptHash('hex');

  return this.wallet.hasAddress(hash);
};

/**
 * Remove a public account key from the account (multisig).
 * Remove the key from the wallet database.
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Account.prototype.removeSharedKey = function removeSharedKey(key) {
  let result = this.spliceKey(key);

  if (!result)
    return false;

  this.save();

  return true;
};

/**
 * Create a new receiving address (increments receiveDepth).
 * @returns {WalletKey}
 */

Account.prototype.createReceive = function createReceive() {
  return this.createKey(0);
};

/**
 * Create a new change address (increments receiveDepth).
 * @returns {WalletKey}
 */

Account.prototype.createChange = function createChange() {
  return this.createKey(1);
};

/**
 * Create a new change address (increments receiveDepth).
 * @returns {WalletKey}
 */

Account.prototype.createNested = function createNested() {
  return this.createKey(2);
};

/**
 * Create a new address (increments depth).
 * @param {Boolean} change
 * @returns {Promise} - Returns {@link WalletKey}.
 */

Account.prototype.createKey = async function createKey(branch) {
  let key, lookahead;

  switch (branch) {
    case 0:
      key = this.deriveReceive(this.receiveDepth);
      lookahead = this.deriveReceive(this.receiveDepth + this.lookahead);
      await this.saveKey(lookahead);
      this.receiveDepth++;
      this.receive = key;
      break;
    case 1:
      key = this.deriveChange(this.changeDepth);
      lookahead = this.deriveReceive(this.changeDepth + this.lookahead);
      await this.saveKey(lookahead);
      this.changeDepth++;
      this.change = key;
      break;
    case 2:
      key = this.deriveNested(this.nestedDepth);
      lookahead = this.deriveNested(this.nestedDepth + this.lookahead);
      await this.saveKey(lookahead);
      this.nestedDepth++;
      this.nested = key;
      break;
    default:
      throw new Error(`Bad branch: ${branch}.`);
  }

  this.save();

  return key;
};

/**
 * Derive a receiving address at `index`. Do not increment depth.
 * @param {Number} index
 * @returns {WalletKey}
 */

Account.prototype.deriveReceive = function deriveReceive(index, master) {
  return this.deriveKey(0, index, master);
};

/**
 * Derive a change address at `index`. Do not increment depth.
 * @param {Number} index
 * @returns {WalletKey}
 */

Account.prototype.deriveChange = function deriveChange(index, master) {
  return this.deriveKey(1, index, master);
};

/**
 * Derive a nested address at `index`. Do not increment depth.
 * @param {Number} index
 * @returns {WalletKey}
 */

Account.prototype.deriveNested = function deriveNested(index, master) {
  if (!this.witness)
    throw new Error('Cannot derive nested on non-witness account.');

  return this.deriveKey(2, index, master);
};

/**
 * Derive an address from `path` object.
 * @param {Path} path
 * @param {MasterKey} master
 * @returns {WalletKey}
 */

Account.prototype.derivePath = function derivePath(path, master) {
  let data = path.data;
  let ring;

  switch (path.keyType) {
    case Path.types.HD:
      return this.deriveKey(path.branch, path.index, master);
    case Path.types.KEY:
      assert(this.type === Account.types.PUBKEYHASH);

      if (path.encrypted) {
        data = master.decipher(data, path.hash);
        if (!data)
          return;
      }

      ring = WalletKey.fromImport(this, data);

      return ring;
    case Path.types.ADDRESS:
      return;
    default:
      assert(false, 'Bad key type.');
  }
};

/**
 * Derive an address at `index`. Do not increment depth.
 * @param {Number} branch - Whether the address on the change branch.
 * @param {Number} index
 * @returns {WalletKey}
 */

Account.prototype.deriveKey = function deriveKey(branch, index, master) {
  let keys = [];
  let key, shared, ring;

  assert(typeof branch === 'number');

  if (master && master.key && !this.watchOnly) {
    key = master.key.deriveBIP44(this.accountIndex);
    key = key.derive(branch).derive(index);
  } else {
    key = this.accountKey.derive(branch).derive(index);
  }

  ring = WalletKey.fromHD(this, key, branch, index);

  switch (this.type) {
    case Account.types.PUBKEYHASH:
      break;
    case Account.types.MULTISIG:
      keys.push(key.publicKey);

      for (shared of this.keys) {
        shared = shared.derive(branch).derive(index);
        keys.push(shared.publicKey);
      }

      ring.script = Script.fromMultisig(this.m, this.n, keys);

      break;
  }

  return ring;
};

/**
 * Save the account to the database. Necessary
 * when address depth and keys change.
 * @returns {Promise}
 */

Account.prototype.save = function save() {
  return this.db.saveAccount(this);
};

/**
 * Save addresses to path map.
 * @param {WalletKey[]} rings
 * @returns {Promise}
 */

Account.prototype.saveKey = function saveKey(ring) {
  return this.db.saveKey(this.wallet, ring);
};

/**
 * Save paths to path map.
 * @param {Path[]} rings
 * @returns {Promise}
 */

Account.prototype.savePath = function savePath(path) {
  return this.db.savePath(this.wallet, path);
};

/**
 * Initialize address depths (including lookahead).
 * @returns {Promise}
 */

Account.prototype.initDepth = async function initDepth() {
  // Receive Address
  this.receive = this.deriveReceive(0);
  this.receiveDepth = 1;

  await this.saveKey(this.receive);

  // Lookahead
  for (let i = 0; i < this.lookahead; i++) {
    let key = this.deriveReceive(i + 1);
    await this.saveKey(key);
  }

  // Change Address
  this.change = this.deriveChange(0);
  this.changeDepth = 1;

  await this.saveKey(this.change);

  // Lookahead
  for (let i = 0; i < this.lookahead; i++) {
    let key = this.deriveChange(i + 1);
    await this.saveKey(key);
  }

  // Nested Address
  if (this.witness) {
    this.nested = this.deriveNested(0);
    this.nestedDepth = 1;

    await this.saveKey(this.nested);

    // Lookahead
    for (let i = 0; i < this.lookahead; i++) {
      let key = this.deriveNested(i + 1);
      await this.saveKey(key);
    }
  }

  this.save();
};

/**
 * Allocate new lookahead addresses if necessary.
 * @param {Number} receiveDepth
 * @param {Number} changeDepth
 * @param {Number} nestedDepth
 * @returns {Promise} - Returns {@link WalletKey}.
 */

Account.prototype.syncDepth = async function syncDepth(receive, change, nested) {
  let derived = false;
  let result = null;

  if (receive > this.receiveDepth) {
    let depth = this.receiveDepth + this.lookahead;

    assert(receive <= depth + 1);

    for (let i = depth; i < receive + this.lookahead; i++) {
      let key = this.deriveReceive(i);
      await this.saveKey(key);
    }

    this.receive = this.deriveReceive(receive - 1);
    this.receiveDepth = receive;

    derived = true;
    result = this.receive;
  }

  if (change > this.changeDepth) {
    let depth = this.changeDepth + this.lookahead;

    assert(change <= depth + 1);

    for (let i = depth; i < change + this.lookahead; i++) {
      let key = this.deriveChange(i);
      await this.saveKey(key);
    }

    this.change = this.deriveChange(change - 1);
    this.changeDepth = change;

    derived = true;
  }

  if (this.witness && nested > this.nestedDepth) {
    let depth = this.nestedDepth + this.lookahead;

    assert(nested <= depth + 1);

    for (let i = depth; i < nested + this.lookahead; i++) {
      let key = this.deriveNested(i);
      await this.saveKey(key);
    }

    this.nested = this.deriveNested(nested - 1);
    this.nestedDepth = nested;

    derived = true;
    result = this.nested;
  }

  if (derived)
    this.save();

  return result;
};

/**
 * Allocate new lookahead addresses.
 * @param {Number} lookahead
 * @returns {Promise}
 */

Account.prototype.setLookahead = async function setLookahead(lookahead) {
  let depth, target;

  if (lookahead === this.lookahead) {
    this.db.logger.warning(
      'Lookahead is not changing for: %s/%s.',
      this.id, this.name);
    return;
  }

  if (lookahead < this.lookahead) {
    let diff = this.lookahead - lookahead;

    this.receiveDepth += diff;
    this.receive = this.deriveReceive(this.receiveDepth - 1);

    this.changeDepth += diff;
    this.change = this.deriveChange(this.changeDepth - 1);

    if (this.witness) {
      this.nestedDepth += diff;
      this.nested = this.deriveNested(this.nestedDepth - 1);
    }

    this.lookahead = lookahead;

    this.save();

    return;
  }

  depth = this.receiveDepth + this.lookahead;
  target = this.receiveDepth + lookahead;

  for (let i = depth; i < target; i++) {
    let key = this.deriveReceive(i);
    await this.saveKey(key);
  }

  depth = this.changeDepth + this.lookahead;
  target = this.changeDepth + lookahead;

  for (let i = depth; i < target; i++) {
    let key = this.deriveChange(i);
    await this.saveKey(key);
  }

  if (this.witness) {
    let depth = this.nestedDepth + this.lookahead;
    let target = this.nestedDepth + lookahead;

    for (let i = depth; i < target; i++) {
      let key = this.deriveNested(i);
      await this.saveKey(key);
    }
  }

  this.lookahead = lookahead;
  this.save();
};

/**
 * Get current receive address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

Account.prototype.getAddress = function getAddress(enc) {
  return this.getReceive(enc);
};

/**
 * Get current receive address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

Account.prototype.getReceive = function getReceive(enc) {
  if (!this.receive)
    return;
  return this.receive.getAddress(enc);
};

/**
 * Get current change address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

Account.prototype.getChange = function getChange(enc) {
  if (!this.change)
    return;
  return this.change.getAddress(enc);
};

/**
 * Get current nested address.
 * @param {String?} enc - `"base58"` or `null`.
 * @returns {Address|Base58Address}
 */

Account.prototype.getNested = function getNested(enc) {
  if (!this.nested)
    return;
  return this.nested.getAddress(enc);
};

/**
 * Convert the account to a more inspection-friendly object.
 * @returns {Object}
 */

Account.prototype.inspect = function inspect() {
  return {
    wid: this.wid,
    name: this.name,
    network: this.network,
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
    address: this.initialized
      ? this.receive.getAddress()
      : null,
    nestedAddress: this.initialized && this.nested
      ? this.nested.getAddress()
      : null,
    accountKey: this.accountKey.toBase58(),
    keys: this.keys.map((key) => {
      return key.toBase58();
    })
  };
};

/**
 * Convert the account to an object suitable for
 * serialization.
 * @returns {Object}
 */

Account.prototype.toJSON = function toJSON(minimal) {
  return {
    wid: minimal ? undefined : this.wid,
    id: minimal ? undefined : this.id,
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
    receiveAddress: this.receive
      ? this.receive.getAddress('string')
      : null,
    nestedAddress: this.nested
      ? this.nested.getAddress('string')
      : null,
    changeAddress: this.change
      ? this.change.getAddress('string')
      : null,
    accountKey: this.accountKey.toBase58(),
    keys: this.keys.map((key) => {
      return key.toBase58();
    })
  };
};

/**
 * Calculate serialization size.
 * @returns {Number}
 */

Account.prototype.getSize = function getSize() {
  let size = 0;
  size += encoding.sizeVarString(this.name, 'ascii');
  size += 105;
  size += this.keys.length * 82;
  return size;
};

/**
 * Serialize the account.
 * @returns {Buffer}
 */

Account.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  let bw = new StaticWriter(size);

  bw.writeVarString(this.name, 'ascii');
  bw.writeU8(this.initialized ? 1 : 0);
  bw.writeU8(this.witness ? 1 : 0);
  bw.writeU8(this.type);
  bw.writeU8(this.m);
  bw.writeU8(this.n);
  bw.writeU32(this.accountIndex);
  bw.writeU32(this.receiveDepth);
  bw.writeU32(this.changeDepth);
  bw.writeU32(this.nestedDepth);
  bw.writeU8(this.lookahead);
  bw.writeBytes(this.accountKey.toRaw());
  bw.writeU8(this.keys.length);

  for (let key of this.keys)
    bw.writeBytes(key.toRaw());

  return bw.render();
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {Object}
 */

Account.prototype.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data);
  let count;

  this.name = br.readVarString('ascii');
  this.initialized = br.readU8() === 1;
  this.witness = br.readU8() === 1;
  this.type = br.readU8();
  this.m = br.readU8();
  this.n = br.readU8();
  this.accountIndex = br.readU32();
  this.receiveDepth = br.readU32();
  this.changeDepth = br.readU32();
  this.nestedDepth = br.readU32();
  this.lookahead = br.readU8();
  this.accountKey = HD.PublicKey.fromRaw(br.readBytes(82));

  assert(Account.typesByVal[this.type]);

  count = br.readU8();

  for (let i = 0; i < count; i++) {
    let key = HD.PublicKey.fromRaw(br.readBytes(82));
    this.pushKey(key);
  }

  return this;
};

/**
 * Instantiate a account from serialized data.
 * @param {WalletDB} data
 * @param {Buffer} data
 * @returns {Account}
 */

Account.fromRaw = function fromRaw(db, data) {
  return new Account(db).fromRaw(data);
};

/**
 * Test an object to see if it is a Account.
 * @param {Object} obj
 * @returns {Boolean}
 */

Account.isAccount = function isAccount(obj) {
  return obj
    && typeof obj.receiveDepth === 'number'
    && obj.deriveKey === 'function';
};

/*
 * Helpers
 */

function cmp(key1, key2) {
  return key1.compare(key2);
}

/*
 * Expose
 */

module.exports = Account;
