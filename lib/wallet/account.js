/*!
 * account.js - account object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var Network = require('../protocol/network');
var utils = require('../utils/utils');
var co = require('../utils/co');
var assert = require('assert');
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');
var Path = require('./path');
var Script = require('../script/script');
var WalletKey = require('./walletkey');
var HD = require('../hd/hd');

/**
 * Represents a BIP44 Account belonging to a {@link Wallet}.
 * Note that this object does not enforce locks. Any method
 * that does a write is internal API only and will lead
 * to race conditions if used elsewhere.
 * @exports Account
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
  this.lookahead = Account.MAX_LOOKAHEAD;

  this.receive = null;
  this.change = null;
  this.nested = null;

  this.wid = 0;
  this.id = null;
  this.name = null;
  this.witness = this.db.options.witness;
  this.accountKey = null;
  this.accountIndex = 0;
  this.receiveDepth = 0;
  this.changeDepth = 0;
  this.nestedDepth = 0;
  this.type = Account.types.PUBKEYHASH;
  this.m = 1;
  this.n = 1;
  this.keys = [];
  this.initialized = false;
  this.watchOnly = false;

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
  var i;

  assert(options, 'Options are required.');
  assert(utils.isNumber(options.wid));
  assert(utils.isName(options.id), 'Bad Wallet ID.');
  assert(HD.isHD(options.accountKey), 'Account key is required.');
  assert(utils.isNumber(options.accountIndex), 'Account index is required.');

  this.wid = options.wid;
  this.id = options.id;

  if (options.name != null) {
    assert(utils.isName(options.name), 'Bad account name.');
    this.name = options.name;
  }

  if (options.witness != null) {
    assert(typeof options.witness === 'boolean');
    this.witness = options.witness;
  }

  this.accountKey = options.accountKey;

  if (options.accountIndex != null) {
    assert(utils.isNumber(options.accountIndex));
    this.accountIndex = options.accountIndex;
  }

  if (options.receiveDepth != null) {
    assert(utils.isNumber(options.receiveDepth));
    this.receiveDepth = options.receiveDepth;
  }

  if (options.changeDepth != null) {
    assert(utils.isNumber(options.changeDepth));
    this.changeDepth = options.changeDepth;
  }

  if (options.nestedDepth != null) {
    assert(utils.isNumber(options.nestedDepth));
    this.nestedDepth = options.nestedDepth;
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
    assert(utils.isNumber(options.m));
    this.m = options.m;
  }

  if (options.n != null) {
    assert(utils.isNumber(options.n));
    this.n = options.n;
  }

  if (options.initialized != null) {
    assert(typeof options.initialized === 'boolean');
    this.initialized = options.initialized;
  }

  if (options.watchOnly != null) {
    assert(typeof options.watchOnly === 'boolean');
    this.watchOnly = options.watchOnly;
  }

  if (this.n > 1)
    this.type = Account.types.MULTISIG;

  if (this.m < 1 || this.m > this.n)
    throw new Error('m ranges between 1 and n');

  if (!this.name)
    this.name = this.accountIndex + '';

  if (options.keys) {
    assert(Array.isArray(options.keys));
    for (i = 0; i < options.keys.length; i++)
      this.pushKey(options.keys[i]);
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

Account.MAX_LOOKAHEAD = 10;

/**
 * Attempt to intialize the account (generating
 * the first addresses along with the lookahead
 * addresses). Called automatically from the
 * walletdb.
 * @returns {Promise}
 */

Account.prototype.init = co(function* init() {
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
  yield this.setDepth(1, 1, 1);
});

/**
 * Open the account (done after retrieval).
 * @returns {Promise}
 */

Account.prototype.open = function open() {
  if (!this.initialized)
    return Promise.resolve(null);

  this.receive = this.deriveReceive(this.receiveDepth - 1);
  this.change = this.deriveChange(this.changeDepth - 1);

  if (this.witness)
    this.nested = this.deriveNested(this.nestedDepth - 1);

  return Promise.resolve(null);
};

/**
 * Add a public account key to the account (multisig).
 * Does not update the database.
 * @param {HDPublicKey} key - Account (bip44)
 * key (can be in base58 form).
 * @throws Error on non-hdkey/non-accountkey.
 */

Account.prototype.pushKey = function pushKey(key) {
  var index;

  if (HD.isExtended(key))
    key = HD.fromBase58(key);

  if (!HD.isPublic(key))
    throw new Error('Must add HD keys to wallet.');

  if (!key.isAccount44())
    throw new Error('Must add HD account keys to BIP44 wallet.');

  if (key.equal(this.accountKey))
    throw new Error('Cannot add own key.');

  index = utils.binaryInsert(this.keys, key, cmp, true);

  if (index === -1)
    return false;

  if (this.keys.length > this.n - 1) {
    utils.binaryRemove(this.keys, key, cmp);
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
  if (HD.isExtended(key))
    key = HD.fromBase58(key);

  if (!HD.isHDPublicKey(key))
    throw new Error('Must add HD keys to wallet.');

  if (!key.isAccount44())
    throw new Error('Must add HD account keys to BIP44 wallet.');

  if (key.equal(this.accountKey))
    throw new Error('Cannot remove own key.');

  if (this.keys.length === this.n - 1)
    throw new Error('Cannot remove key.');

  return utils.binaryRemove(this.keys, key, cmp);
};

/**
 * Add a public account key to the account (multisig).
 * Saves the key in the wallet database.
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Account.prototype.addKey = co(function* addKey(key) {
  var result = false;
  var exists;

  try {
    result = this.pushKey(key);
  } catch (e) {
    throw e;
  }

  exists = yield this._checkKeys();

  if (exists) {
    this.spliceKey(key);
    throw new Error('Cannot add a key from another account.');
  }

  // Try to initialize again.
  yield this.init();

  return result;
});

/**
 * Ensure accounts are not sharing keys.
 * @private
 * @returns {Promise}
 */

Account.prototype._checkKeys = co(function* _checkKeys() {
  var ring, hash;

  if (this.initialized || this.type !== Account.types.MULTISIG)
    return false;

  if (this.keys.length !== this.n - 1)
    return false;

  ring = this.deriveReceive(0);
  hash = ring.getScriptHash('hex');

  return yield this.db.hasAddress(this.wid, hash);
});

/**
 * Remove a public account key from the account (multisig).
 * Remove the key from the wallet database.
 * @param {HDPublicKey} key
 * @returns {Promise}
 */

Account.prototype.removeKey = function removeKey(key) {
  var result = false;

  try {
    result = this.spliceKey(key);
  } catch (e) {
    return Promise.reject(e);
  }

  this.save();

  return Promise.resolve(result);
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

Account.prototype.createKey = co(function* createKey(branch) {
  var ring, lookahead;

  switch (branch) {
    case 0:
      ring = this.deriveReceive(this.receiveDepth);
      lookahead = this.deriveReceive(this.receiveDepth + this.lookahead);
      yield this.saveKey(ring);
      yield this.saveKey(lookahead);
      this.receiveDepth++;
      this.receive = ring;
      break;
    case 1:
      ring = this.deriveChange(this.changeDepth);
      lookahead = this.deriveChange(this.changeDepth + this.lookahead);
      yield this.saveKey(ring);
      yield this.saveKey(lookahead);
      this.changeDepth++;
      this.change = ring;
      break;
    case 2:
      ring = this.deriveNested(this.nestedDepth);
      lookahead = this.deriveNested(this.nestedDepth + this.lookahead);
      yield this.saveKey(ring);
      yield this.saveKey(lookahead);
      this.nestedDepth++;
      this.nested = ring;
      break;
    default:
      throw new Error('Bad branch: ' + branch);
  }

  this.save();

  return ring;
});

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
  var data = path.data;
  var ring;

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

      ring = WalletKey.fromImport(this, data, this.network);

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
  var keys = [];
  var i, key, shared, ring;

  assert(typeof branch === 'number');

  if (master && master.key && !this.watchOnly) {
    key = master.key.deriveAccount44(this.accountIndex);
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

      for (i = 0; i < this.keys.length; i++) {
        shared = this.keys[i];
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
  return this.db.saveKey(this.wid, ring);
};

/**
 * Save paths to path map.
 * @param {Path[]} rings
 * @returns {Promise}
 */

Account.prototype.savePath = function savePath(path) {
  return this.db.savePath(this.wid, path);
};

/**
 * Set change and receiving depth (depth is the index of the _next_ address).
 * Allocate all addresses up to depth. Note that this also allocates
 * new lookahead addresses.
 * @param {Number} depth
 * @returns {Promise} - Returns {@link WalletKey}, {@link WalletKey}.
 */

Account.prototype.setDepth = co(function* setDepth(receiveDepth, changeDepth, nestedDepth) {
  var i = -1;
  var receive, change, nested, lookahead;

  if (receiveDepth > this.receiveDepth) {
    for (i = this.receiveDepth; i < receiveDepth; i++) {
      receive = this.deriveReceive(i);
      yield this.saveKey(receive);
    }

    for (i = receiveDepth; i < receiveDepth + this.lookahead; i++) {
      lookahead = this.deriveReceive(i);
      yield this.saveKey(lookahead);
    }

    this.receive = receive;
    this.receiveDepth = receiveDepth;
  }

  if (changeDepth > this.changeDepth) {
    for (i = this.changeDepth; i < changeDepth; i++) {
      change = this.deriveChange(i);
      yield this.saveKey(change);
    }

    for (i = changeDepth; i < changeDepth + this.lookahead; i++) {
      lookahead = this.deriveChange(i);
      yield this.saveKey(lookahead);
    }

    this.change = change;
    this.changeDepth = changeDepth;
  }

  if (this.witness && nestedDepth > this.nestedDepth) {
    for (i = this.nestedDepth; i < nestedDepth; i++) {
      nested = this.deriveNested(i);
      yield this.saveKey(nested);
    }

    for (i = nestedDepth; i < nestedDepth + this.lookahead; i++) {
      lookahead = this.deriveNested(i);
      yield this.saveKey(lookahead);
    }

    this.nested = nested;
    this.nestedDepth = nestedDepth;
  }

  if (i === -1)
    return;

  this.save();

  return receive || nested;
});

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
    watchOnly: this.watchOnly,
    type: Account.typesByVal[this.type].toLowerCase(),
    m: this.m,
    n: this.n,
    address: this.initialized
      ? this.receive.getAddress()
      : null,
    nestedAddress: this.initialized && this.nested
      ? this.nested.getAddress()
      : null,
    witness: this.witness,
    accountIndex: this.accountIndex,
    receiveDepth: this.receiveDepth,
    changeDepth: this.changeDepth,
    nestedDepth: this.nestedDepth,
    accountKey: this.accountKey.xpubkey,
    keys: this.keys.map(function(key) {
      return key.xpubkey;
    })
  };
};

/**
 * Convert the account to an object suitable for
 * serialization.
 * @returns {Object}
 */

Account.prototype.toJSON = function toJSON() {
  return {
    network: this.network.type,
    wid: this.wid,
    name: this.name,
    initialized: this.initialized,
    watchOnly: this.watchOnly,
    type: Account.typesByVal[this.type].toLowerCase(),
    m: this.m,
    n: this.n,
    witness: this.witness,
    accountIndex: this.accountIndex,
    receiveDepth: this.receiveDepth,
    changeDepth: this.changeDepth,
    nestedDepth: this.nestedDepth,
    receiveAddress: this.receive
      ? this.receive.getAddress('base58')
      : null,
    nestedAddress: this.nested
      ? this.nested.getAddress('base58')
      : null,
    changeAddress: this.change
      ? this.change.getAddress('base58')
      : null,
    accountKey: this.accountKey.xpubkey,
    keys: this.keys.map(function(key) {
      return key.xpubkey;
    })
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 */

Account.prototype.fromJSON = function fromJSON(json) {
  var i, key;

  assert.equal(json.network, this.network.type);
  assert(utils.isNumber(json.wid));
  assert(utils.isName(json.id), 'Bad wallet ID.');
  assert(utils.isName(json.name), 'Bad account name.');
  assert(typeof json.initialized === 'boolean');
  assert(typeof json.watchOnly === 'boolean');
  assert(typeof json.type === 'string');
  assert(utils.isNumber(json.m));
  assert(utils.isNumber(json.n));
  assert(typeof json.witness === 'boolean');
  assert(utils.isNumber(json.accountIndex));
  assert(utils.isNumber(json.receiveDepth));
  assert(utils.isNumber(json.changeDepth));
  assert(utils.isNumber(json.nestedDepth));
  assert(Array.isArray(json.keys));

  this.wid = json.wid;
  this.name = json.name;
  this.initialized = json.initialized;
  this.watchOnly = json.watchOnly;
  this.type = Account.types[json.type.toUpperCase()];
  this.m = json.m;
  this.n = json.n;
  this.witness = json.witness;
  this.accountIndex = json.accountIndex;
  this.receiveDepth = json.receiveDepth;
  this.changeDepth = json.changeDepth;
  this.nestedDepth = json.nestedDepth;
  this.accountKey = HD.fromBase58(json.accountKey);

  assert(this.type != null);

  for (i = 0; i < json.keys.length; i++) {
    key = HD.fromBase58(json.keys[i]);
    this.pushKey(key);
  }

  return this;
};

/**
 * Serialize the account.
 * @returns {Buffer}
 */

Account.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);
  var i, key;

  p.writeU32(this.network.magic);
  p.writeVarString(this.name, 'ascii');
  p.writeU8(this.initialized ? 1 : 0);
  p.writeU8(this.type);
  p.writeU8(this.m);
  p.writeU8(this.n);
  p.writeU8(this.witness ? 1 : 0);
  p.writeU32(this.accountIndex);
  p.writeU32(this.receiveDepth);
  p.writeU32(this.changeDepth);
  p.writeU32(this.nestedDepth);
  p.writeBytes(this.accountKey.toRaw());
  p.writeU8(this.keys.length);

  for (i = 0; i < this.keys.length; i++) {
    key = this.keys[i];
    p.writeBytes(key.toRaw());
  }

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {Object}
 */

Account.prototype.fromRaw = function fromRaw(data) {
  var p = new BufferReader(data);
  var i, count, key;

  this.network = Network.fromMagic(p.readU32());
  this.name = p.readVarString('ascii');
  this.initialized = p.readU8() === 1;
  this.type = p.readU8();
  this.m = p.readU8();
  this.n = p.readU8();
  this.witness = p.readU8() === 1;
  this.accountIndex = p.readU32();
  this.receiveDepth = p.readU32();
  this.changeDepth = p.readU32();
  this.nestedDepth = p.readU32();
  this.accountKey = HD.fromRaw(p.readBytes(82));

  assert(Account.typesByVal[this.type]);

  count = p.readU8();

  for (i = 0; i < count; i++) {
    key = HD.fromRaw(p.readBytes(82));
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
 * Instantiate a Account from a
 * jsonified account object.
 * @param {WalletDB} db
 * @param {Object} json - The jsonified account object.
 * @returns {Account}
 */

Account.fromJSON = function fromJSON(db, json) {
  return new Account(db).fromJSON(json);
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
