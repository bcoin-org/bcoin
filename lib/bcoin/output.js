/**
 * output.js - output object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var bcoin = require('../bcoin');
var inherits = require('inherits');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;

/**
 * Output
 */

function Output(options) {
  var value;

  if (!(this instanceof Output))
    return new Output(options);

  value = options.value;

  if (typeof value === 'number' && (value | 0) === value)
    value = new bn(value);

  this.value = utils.satoshi(value || new bn(0));
  this.script = options.script ? options.script.slice() : [];

  // For safety: do not allow usage of
  // Numbers, do not allow negative values.
  assert(typeof value !== 'number');
  assert(!this.value.isNeg())
  assert(this.value.bitLength() <= 63);
  assert(!(this.value.toArray('be', 8)[0] & 0x80));

  if (options.script && options.script._raw)
    utils.hidden(this.script, '_raw', options.script._raw);
}

Output.prototype.__defineGetter__('data', function() {
  var data;

  if (this._data)
    return this._data;

  data = Output.getData(this);

  if (this.script.length)
    utils.hidden(this, '_data', data);

  return data;
});

Output.prototype.__defineGetter__('type', function() {
  return this.data.type;
});

Output.prototype.__defineGetter__('signature', function() {
  return this.signatures[0];
});

Output.prototype.__defineGetter__('key', function() {
  return this.keys[0];
});

Output.prototype.__defineGetter__('hash160', function() {
  return this.data.scriptHash || this.hashes[0];
});

Output.prototype.__defineGetter__('id', function() {
  return this.address || this.getID();
});

Output.prototype.__defineGetter__('address', function() {
  return this.data.scriptAddress || this.addresses[0];
});

Output.prototype.__defineGetter__('signatures', function() {
  return this.data.signatures || [];
});

Output.prototype.__defineGetter__('keys', function() {
  return this.data.keys || [];
});

Output.prototype.__defineGetter__('hashes', function() {
  return this.data.hashes || [];
});

Output.prototype.__defineGetter__('addresses', function() {
  return this.data.addresses || [];
});

Output.prototype.__defineGetter__('scriptHash', function() {
  return this.data.scriptHash;
});

Output.prototype.__defineGetter__('scriptAddress', function() {
  return this.data.scriptAddress;
});

Output.prototype.__defineGetter__('m', function() {
  return this.data.m || 1;
});

Output.prototype.__defineGetter__('n', function() {
  return this.data.n || this.m;
});

Output.prototype.__defineGetter__('locktime', function() {
  return bcoin.script.getLocktime(this.script);
});

Output.prototype.__defineGetter__('flags', function() {
  return this.data.flags;
});

Output.prototype.__defineGetter__('text', function() {
  return this.data.text;
});

// Legacy
Output.prototype.__defineGetter__('addr', function() {
  return this.address;
});

Output.prototype.__defineGetter__('addrs', function() {
  return this.addresses;
});

Output.prototype.__defineGetter__('pub', function() {
  return this.key;
});

Output.prototype.__defineGetter__('pubs', function() {
  return this.keys;
});

Output.prototype.__defineGetter__('sig', function() {
  return this.signature;
});

Output.prototype.__defineGetter__('sigs', function() {
  return this.signatures;
});

Output.prototype.__defineGetter__('scriptaddr', function() {
  return this.scriptAddress;
});

// Schema and defaults for data object:
// {
//   type: String,
//   subtype: String,
//   side: 'output',
//   signatures: Array,
//   keys: Array,
//   hashes: Array,
//   addresses: Array,
//   redeem: Array,
//   scriptHash: Array,
//   scriptAddress: String,
//   m: Number,
//   n: Number,
//   height: Number,
//   flags: Array,
//   text: String,
//   locktime: Number,
//   value: bn,
//   script: Array,
//   seq: Number,
//   prev: String,
//   index: Number,
//   none: Boolean
// }

Output.getData = function getData(output) {
  var def;

  assert(output instanceof Output);

  def = {
    side: 'output',
    value: output.value,
    script: output.script
  };

  return utils.merge(def, bcoin.script.getOutputData(output.script));
};

Output.prototype.getData = function getData() {
  return Output.getData(this);
};

Output.prototype.getAddresses = function getAddresses() {
  return this.getData().addresses;
};

Output.prototype.getScriptAddress = function getScriptAddress() {
  return this.getData().scriptAddress;
};

Output.prototype.getKeyAddress = function getKeyAddress() {
  return this.getData().addresses[0];
};

Output.prototype.getAddress = function getAddress() {
  var data = this.getData();

  if (data.scriptAddress)
    return data.scriptAddress;

  return data.addresses[0];
};

Output.prototype.getID = function getID() {
  var data = bcoin.script.encode(this.script);
  var hash = utils.toHex(utils.ripesha(data));
  return '[' + this.type + ':' + hash.slice(0, 7) + ']';
};

Output.prototype.testScript = function testScript(key, hash, keys, scriptHash, type) {
  if (!type || type === 'pubkey') {
    if (key) {
      if (bcoin.script.isPubkey(this.script, key))
        return true;
    }
  }

  if (!type || type === 'pubkeyhash') {
    if (hash) {
      if (bcoin.script.isPubkeyhash(this.script, hash))
        return true;
    }
  }

  if (!type || type === 'multisig') {
    if (keys) {
      if (bcoin.script.isMultisig(this.script, keys))
        return true;
    }
  }

  if (!type || type === 'scripthash') {
    if (scriptHash) {
      if (bcoin.script.isScripthash(this.script, scriptHash))
        return true;
    }
  }

  return false;
};

Output.prototype.test = function test(addressTable) {
  var data = this.getData();
  var i;

  if (data.scriptAddress) {
    if (addressTable[data.scriptAddress] != null)
      return true;
  }

  for (i = 0; i < data.addresses.length; i++) {
    if (addressTable[data.addresses[i]] != null)
      return true;
  }

  return false;
};

Output.prototype.getSigops = function getSigops(accurate) {
  return bcoin.script.getSigops(this.script, accurate);
};

Output.prototype.inspect = function inspect() {
  return {
    type: this.type,
    address: this.address,
    keys: this.keys.map(utils.toHex),
    hashes: this.hashes.map(utils.toHex),
    addresses: this.addresses,
    scriptAddress: this.scriptAddress,
    m: this.m,
    n: this.n,
    text: this.text,
    locktime: this.locktime,
    value: utils.btc(this.value),
    script: bcoin.script.format(this.script)
  };
};

// This is basically a UTXO/Coin object. It is immutable once instantiated. It
// needs to store 5 properties: the tx hash, output index, output value, output
// script, and the block height the transaction was mined (to later calculate
// age).

function Prevout(tx, index) {
  var options;

  if (!(this instanceof Prevout))
    return new Prevout(tx, index);

  if (tx instanceof Prevout)
    return tx;

  if (tx instanceof bcoin.tx) {
    this.hash = tx.hash('hex');
    this.index = index;
    this.value = tx.outputs[index].value;
    this.script = tx.outputs[index].script;
    this.height = tx.getHeight();
  } else {
    options = tx;
    this.hash = options.hash;
    this.index = options.index;
    this.value = options.value;
    this.script = options.script;
    this.height = options.height;
  }

  if (utils.isBuffer(this.hash))
    this.hash = utils.toHex(this.hash);

  assert(typeof this.hash === 'string');
  assert(utils.isFinite(this.index));
  assert(this.value instanceof bn);
  assert(Array.isArray(this.script));
  assert(utils.isFinite(this.height));

  Object.freeze(this);
}

inherits(Prevout, Output);

Prevout.prototype.__defineGetter__('chain', function() {
  return this._chain || bcoin.chain.global;
});

Prevout.prototype.getConfirmations = function getConfirmations() {
  var top;

  if (!this.chain)
    return 0;

  top = this.chain.height();

  if (this.height === -1)
    return 0;

  return top - this.height + 1;
};

Prevout.prototype.__defineGetter__('confirmations', function() {
  return this.getConfirmations();
});

Prevout.prototype.getAge = function getAge() {
  var age = this.getConfirmations();

  if (age === -1)
    age = 0;

  if (age !== 0)
    age += 1;

  return age;
};

Prevout.prototype.__defineGetter__('age', function() {
  return this.getAge();
});

Prevout.prototype.toJSON = function toJSON() {
  return {
    hash: this.hash,
    index: this.index,
    value: utils.btc(this.value),
    script: utils.toHex(bcoin.script.encode(this.script)),
    height: this.height
  };
};

Prevout.fromJSON = function fromJSON(json) {
  return new Prevout({
    hash: json.hash,
    index: json.index,
    value: utils.satoshi(json.value),
    script: bcoin.script.decode(utils.toArray(json.script, 'hex')),
    height: json.height
  });
};

/**
 * Expose
 */

exports = Output;
exports.prev = Prevout;
module.exports = exports;
