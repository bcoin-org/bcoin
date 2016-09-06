/*!
 * account.js - account object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var utils = require('../utils/utils');
var assert = utils.assert;
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');

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

  this.receiveAddress = null;
  this.changeAddress = null;

  this.wid = 0;
  this.id = null;
  this.name = null;
  this.witness = this.db.options.witness;
  this.accountKey = null;
  this.accountIndex = 0;
  this.receiveDepth = 0;
  this.changeDepth = 0;
  this.type = Account.types.PUBKEYHASH;
  this.m = 1;
  this.n = 1;
  this.keys = [];
  this.initialized = false;

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
  assert(bcoin.hd.isHD(options.accountKey), 'Account key is required.');
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

Account.MAX_LOOKAHEAD = 5;

/**
 * Attempt to intialize the account (generating
 * the first addresses along with the lookahead
 * addresses). Called automatically from the
 * walletdb.
 * @param {Function} callback
 */

Account.prototype.init = function init(callback) {
  // Waiting for more keys.
  if (this.keys.length !== this.n - 1) {
    assert(!this.initialized);
    this.save();
    return callback();
  }

  assert(this.receiveDepth === 0);
  assert(this.changeDepth === 0);

  this.initialized = true;
  this.setDepth(1, 1, callback);
};

/**
 * Open the account (done after retrieval).
 * @param {Function} callback
 */

Account.prototype.open = function open(callback) {
  if (!this.initialized)
    return callback();

  this.receiveAddress = this.deriveReceive(this.receiveDepth - 1);
  this.changeAddress = this.deriveChange(this.changeDepth - 1);

  callback();
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

  if (bcoin.hd.isExtended(key))
    key = bcoin.hd.fromBase58(key);

  if (!bcoin.hd.isPublic(key))
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
  if (bcoin.hd.isExtended(key))
    key = bcoin.hd.fromBase58(key);

  if (!bcoin.hd.isHDPublicKey(key))
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
 * @param {Function} callback
 */

Account.prototype.addKey = function addKey(key, callback) {
  var self = this;
  var result = false;

  try {
    result = this.pushKey(key);
  } catch (e) {
    return callback(e);
  }

  this._checkKeys(function(err, exists) {
    if (err)
      return callback(err);

    if (exists) {
      self.spliceKey(key);
      return callback(new Error('Cannot add a key from another account.'));
    }

    // Try to initialize again.
    self.init(function(err) {
      if (err)
        return callback(err);

      callback(null, result);
    });
  });
};

/**
 * Ensure accounts are not sharing keys.
 * @private
 * @param {Function} callback
 */

Account.prototype._checkKeys = function _checkKeys(callback) {
  var self = this;
  var ring, hash;

  if (this.initialized || this.type !== Account.types.MULTISIG)
    return callback(null, false);

  if (this.keys.length !== this.n - 1)
    return callback(null, false);

  ring = this.deriveReceive(0);
  hash = ring.getScriptHash('hex');

  this.db.getAddressPaths(hash, function(err, paths) {
    if (err)
      return callback(err);

    if (!paths)
      return callback(null, false);

    callback(null, paths[self.wid] != null);
  });
};

/**
 * Remove a public account key from the account (multisig).
 * Remove the key from the wallet database.
 * @param {HDPublicKey} key
 * @param {Function} callback
 */

Account.prototype.removeKey = function removeKey(key, callback) {
  var result = false;

  try {
    result = this.spliceKey(key);
  } catch (e) {
    return callback(e);
  }

  this.save();

  callback(null, result);
};

/**
 * Create a new receiving address (increments receiveDepth).
 * @returns {KeyRing}
 */

Account.prototype.createReceive = function createReceive(callback) {
  return this.createAddress(false, callback);
};

/**
 * Create a new change address (increments receiveDepth).
 * @returns {KeyRing}
 */

Account.prototype.createChange = function createChange(callback) {
  return this.createAddress(true, callback);
};

/**
 * Create a new address (increments depth).
 * @param {Boolean} change
 * @param {Function} callback - Returns [Error, {@link KeyRing}].
 */

Account.prototype.createAddress = function createAddress(change, callback) {
  var self = this;
  var ring, lookahead;

  if (typeof change === 'function') {
    callback = change;
    change = false;
  }

  if (change) {
    ring = this.deriveChange(this.changeDepth);
    lookahead = this.deriveChange(this.changeDepth + this.lookahead);
    this.changeDepth++;
    this.changeAddress = ring;
  } else {
    ring = this.deriveReceive(this.receiveDepth);
    lookahead = this.deriveReceive(this.receiveDepth + this.lookahead);
    this.receiveDepth++;
    this.receiveAddress = ring;
  }

  this.saveAddress([ring, lookahead], function(err) {
    if (err)
      return callback(err);

    self.save();

    callback(null, ring);
  });
};

/**
 * Derive a receiving address at `index`. Do not increment depth.
 * @param {Number} index
 * @returns {KeyRing}
 */

Account.prototype.deriveReceive = function deriveReceive(index, master) {
  return this.deriveAddress(false, index, master);
};

/**
 * Derive a change address at `index`. Do not increment depth.
 * @param {Number} index
 * @returns {KeyRing}
 */

Account.prototype.deriveChange = function deriveChange(index, master) {
  return this.deriveAddress(true, index, master);
};

/**
 * Derive an address from `path` object.
 * @param {Path} path
 * @param {MasterKey} master
 * @returns {KeyRing}
 */

Account.prototype.derivePath = function derivePath(path, master) {
  var ring, script, raw;

  // Imported key.
  if (path.index === -1) {
    assert(path.imported);
    assert(this.type === Account.types.PUBKEYHASH);

    raw = path.imported;

    if (path.encrypted)
      raw = master.decipher(raw, path.hash);

    if (!raw)
      return;

    ring = bcoin.keyring.fromRaw(raw, this.network);
    ring.path = path;

    return ring;
  }

  // Custom redeem script.
  if (path.script)
    script = bcoin.script.fromRaw(path.script);

  ring = this.deriveAddress(path.change, path.index, master, script);

  return ring;
};

/**
 * Derive an address at `index`. Do not increment depth.
 * @param {Boolean} change - Whether the address on the change branch.
 * @param {Number} index
 * @returns {KeyRing}
 */

Account.prototype.deriveAddress = function deriveAddress(change, index, master, script) {
  var keys = [];
  var i, key, shared, ring;

  change = +change;

  if (master && master.key) {
    key = master.key.deriveAccount44(this.accountIndex);
    key = key.derive(change).derive(index);
  } else {
    key = this.accountKey.derive(change).derive(index);
  }

  ring = bcoin.keyring.fromPublic(key.publicKey, this.network);
  ring.witness = this.witness;

  if (script) {
    // Custom redeem script.
    assert(this.type === Account.types.PUBKEYHASH);
    ring.script = script;
  } else {
    switch (this.type) {
      case Account.types.PUBKEYHASH:
        break;
      case Account.types.MULTISIG:
        keys.push(key.publicKey);

        for (i = 0; i < this.keys.length; i++) {
          shared = this.keys[i];
          shared = shared.derive(change).derive(index);
          keys.push(shared.publicKey);
        }

        ring.script = bcoin.script.fromMultisig(this.m, this.n, keys);

        break;
    }
  }

  if (key.privateKey)
    ring.privateKey = key.privateKey;

  ring.path = bcoin.path.fromAccount(this, ring, change, index);

  return ring;
};

/**
 * Save the account to the database. Necessary
 * when address depth and keys change.
 * @param {Function} callback
 */

Account.prototype.save = function save() {
  return this.db.saveAccount(this);
};

/**
 * Save addresses to path map.
 * @param {KeyRing[]} rings
 * @param {Function} callback
 */

Account.prototype.saveAddress = function saveAddress(rings, callback) {
  return this.db.saveAddress(this.wid, rings, callback);
};

/**
 * Set change and receiving depth (depth is the index of the _next_ address).
 * Allocate all addresses up to depth. Note that this also allocates
 * new lookahead addresses.
 * @param {Number} depth
 * @param {Function} callback - Returns [Error, {@link KeyRing}, {@link KeyRing}].
 */

Account.prototype.setDepth = function setDepth(receiveDepth, changeDepth, callback) {
  var self = this;
  var rings = [];
  var i, receive, change;

  if (receiveDepth > this.receiveDepth) {
    for (i = this.receiveDepth; i < receiveDepth; i++) {
      receive = this.deriveReceive(i);
      rings.push(receive);
    }

    for (i = receiveDepth; i < receiveDepth + this.lookahead; i++)
      rings.push(this.deriveReceive(i));

    this.receiveAddress = receive;
    this.receiveDepth = receiveDepth;
  }

  if (changeDepth > this.changeDepth) {
    for (i = this.changeDepth; i < changeDepth; i++) {
      change = this.deriveChange(i);
      rings.push(change);
    }

    for (i = changeDepth; i < changeDepth + this.lookahead; i++)
      rings.push(this.deriveChange(i));

    this.changeAddress = change;
    this.changeDepth = changeDepth;
  }

  if (rings.length === 0)
    return callback();

  this.saveAddress(rings, function(err) {
    if (err)
      return callback(err);

    self.save();

    callback(null, receive, change);
  });
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
    type: Account.typesByVal[this.type].toLowerCase(),
    m: this.m,
    n: this.n,
    address: this.initialized
      ? this.receiveAddress.getAddress()
      : null,
    programAddress: this.initialized
      ? this.receiveAddress.getProgramAddress()
      : null,
    witness: this.witness,
    accountIndex: this.accountIndex,
    receiveDepth: this.receiveDepth,
    changeDepth: this.changeDepth,
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
    type: Account.typesByVal[this.type].toLowerCase(),
    m: this.m,
    n: this.n,
    witness: this.witness,
    accountIndex: this.accountIndex,
    receiveDepth: this.receiveDepth,
    changeDepth: this.changeDepth,
    receiveAddress: this.receiveAddress
      ? this.receiveAddress.getAddress('base58')
      : null,
    programAddress: this.receiveAddress
      ? this.receiveAddress.getProgramAddress('base58')
      : null,
    changeAddress: this.changeAddress
      ? this.changeAddress.getAddress('base58')
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
  assert(typeof json.type === 'string');
  assert(utils.isNumber(json.m));
  assert(utils.isNumber(json.n));
  assert(typeof json.witness === 'boolean');
  assert(utils.isNumber(json.accountIndex));
  assert(utils.isNumber(json.receiveDepth));
  assert(utils.isNumber(json.changeDepth));
  assert(Array.isArray(json.keys));

  this.wid = json.wid;
  this.name = json.name;
  this.initialized = json.initialized;
  this.type = Account.types[json.type.toUpperCase()];
  this.m = json.m;
  this.n = json.n;
  this.witness = json.witness;
  this.accountIndex = json.accountIndex;
  this.receiveDepth = json.receiveDepth;
  this.changeDepth = json.changeDepth;
  this.accountKey = bcoin.hd.fromBase58(json.accountKey);

  assert(this.type != null);

  for (i = 0; i < json.keys.length; i++) {
    key = bcoin.hd.fromBase58(json.keys[i]);
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
  p.writeVarString(this.name, 'utf8');
  p.writeU8(this.initialized ? 1 : 0);
  p.writeU8(this.type);
  p.writeU8(this.m);
  p.writeU8(this.n);
  p.writeU8(this.witness ? 1 : 0);
  p.writeU32(this.accountIndex);
  p.writeU32(this.receiveDepth);
  p.writeU32(this.changeDepth);
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

  this.network = bcoin.network.fromMagic(p.readU32());
  this.name = p.readVarString('utf8');
  this.initialized = p.readU8() === 1;
  this.type = p.readU8();
  this.m = p.readU8();
  this.n = p.readU8();
  this.witness = p.readU8() === 1;
  this.accountIndex = p.readU32();
  this.receiveDepth = p.readU32();
  this.changeDepth = p.readU32();
  this.accountKey = bcoin.hd.fromRaw(p.readBytes(82));

  assert(Account.typesByVal[this.type]);

  count = p.readU8();

  for (i = 0; i < count; i++) {
    key = bcoin.hd.fromRaw(p.readBytes(82));
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
    && obj.deriveAddress === 'function';
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
