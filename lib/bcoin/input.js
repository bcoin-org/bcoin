/**
 * input.js - input object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;

/**
 * Input
 */

function Input(options) {
  var prevout;

  if (!(this instanceof Input))
    return new Input(options);

  assert(typeof options.script !== 'string');

  prevout = options.prevout || options.out;

  this.prevout = {
    hash: prevout.hash,
    index: prevout.index
  };

  if (options.output)
    this.output = bcoin.coin(options.output);

  if (Buffer.isBuffer(this.prevout.hash))
    this.prevout.hash = utils.toHex(this.prevout.hash);

  this.script = options.script ? options.script.slice() : [];
  this.sequence = options.sequence == null ? 0xffffffff : options.sequence;
  this._size = options._size || 0;
  this._offset = options._offset || 0;

  if (options.script && options.script._raw)
    utils.hidden(this.script, '_raw', options.script._raw);
}

Input.prototype.__defineGetter__('data', function() {
  var data;

  if (this._data)
    return this._data;

  data = Input.getData(this);

  if (this.script.length && this.output)
    utils.hidden(this, '_data', data);

  return data;
});

Input.prototype.__defineGetter__('type', function() {
  return this.data.type;
});

Input.prototype.__defineGetter__('subtype', function() {
  return this.data.subtype;
});

Input.prototype.__defineGetter__('signature', function() {
  return this.signatures[0];
});

Input.prototype.__defineGetter__('key', function() {
  return this.keys[0];
});

Input.prototype.__defineGetter__('hash160', function() {
  return this.data.scriptHash || this.hashes[0];
});

Input.prototype.__defineGetter__('id', function() {
  return this.address || this.getID();
});

Input.prototype.__defineGetter__('address', function() {
  return this.data.address;
});

Input.prototype.__defineGetter__('signatures', function() {
  return this.data.signatures || [];
});

Input.prototype.__defineGetter__('keys', function() {
  return this.data.keys || [];
});

Input.prototype.__defineGetter__('hashes', function() {
  return this.data.hashes || [];
});

Input.prototype.__defineGetter__('addresses', function() {
  return this.data.addresses || [];
});

Input.prototype.__defineGetter__('redeem', function() {
  return this.data.redeem;
});

Input.prototype.__defineGetter__('scriptHash', function() {
  return this.data.scriptHash;
});

Input.prototype.__defineGetter__('scriptAddress', function() {
  return this.data.scriptAddress;
});

Input.prototype.__defineGetter__('m', function() {
  return this.data.m || 1;
});

Input.prototype.__defineGetter__('n', function() {
  return this.data.n || this.m;
});

Input.prototype.__defineGetter__('locktime', function() {
  if (!this.output)
    return 0;
  return this.output.locktime;
});

Input.prototype.__defineGetter__('flags', function() {
  return this.data.flags;
});

Input.prototype.__defineGetter__('text', function() {
  return this.data.text;
});

Input.prototype.__defineGetter__('value', function() {
  if (!this.output)
    return;
  return this.output.value;
});

// Schema and defaults for data object:
// {
//   type: String,
//   subtype: String,
//   side: 'input',
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

Input.getData = function getData(input) {
  var def, data;

  assert(input instanceof Input);

  def = {
    side: 'input',
    value: new bn(0),
    script: input.script,
    seq: input.seq
  };

  def.prev = input.prevout.hash;
  def.index = input.prevout.index;

  if (input.isCoinbase()) {
    data = bcoin.script.getCoinbaseData(input.script);
    return utils.merge(def, data, {
      type: 'coinbase',
      none: true
    });
  }

  if (input.output) {
    data = bcoin.script.getInputData(input.script, input.output.script);
    data.value = input.output.value;
    return utils.merge(def, data);
  }

  return utils.merge(def, bcoin.script.getInputData(input.script));
};

Input.prototype.getData = function getData() {
  return Input.getData(this);
};

Input.prototype.getType = function getType() {
  var prev = this.output ? this.output.script : null;
  if (this.isCoinbase())
    return 'coinbase';
  return bcoin.script.getInputType(this.script, prev);
};

Input.prototype.getAddress = function getAddress() {
  var prev = this.output ? this.output.script : null;
  if (this.isCoinbase())
    return;
  return bcoin.script.getInputAddress(this.script, prev);
};

Input.prototype.isRBF = function isRBF() {
  return this.sequence === 0xffffffff - 1;
};

Input.prototype.isFinal = function isFinal() {
  return this.sequence === 0xffffffff;
};

Input.prototype.getID = function getID() {
  var data = bcoin.script.encode(this.script);
  var hash = utils.toHex(utils.ripesha(data));
  return '[' + this.type + ':' + hash.slice(0, 7) + ']';
};

Input.prototype.getLocktime = function getLocktime() {
  var output, redeem, lock, type;

  assert(this.output);

  output = this.output;
  redeem = output.script;

  if (bcoin.script.isScripthash(redeem))
    redeem = bcoin.script.getRedeem(this.script);

  if (redeem[1] !== 'checklocktimeverify')
    return;

  return bcoin.script.getLocktime(redeem);
};

Input.prototype.isCoinbase = function isCoinbase() {
  return +this.prevout.hash === 0;
};

Input.prototype.testScript = function testScript(key, redeem, type) {
  // if (!type || type === 'pubkey') {
  //   if (key) {
  //     if (bcoin.script.isPubkeyInput(this.script, key, tx, i))
  //       return true;
  //   }
  // }

  if (!type || type === 'pubkeyhash') {
    if (key) {
      if (bcoin.script.isPubkeyhashInput(this.script, key))
        return true;
    }
  }

  // if (!type || type === 'multisig') {
  //   if (keys) {
  //     if (bcoin.script.isMultisigInput(input.script, keys, tx, i))
  //       return true;
  //   }
  // }

  if (!type || type === 'scripthash') {
    if (redeem) {
      if (bcoin.script.isScripthashInput(this.script, redeem))
        return true;
    }
  }

  return false;
};

Input.prototype.test = function test(addressTable) {
  var address = this.getAddress();

  if (!address)
    return false;

  if (typeof addressTable === 'string')
    addressTable = [addressTable];

  if (Array.isArray(addressTable)) {
    addressTable = addressTable.reduce(function(out, address) {
      out[address] = true;
      return out;
    }, {});
  }

  if (addressTable[address] != null)
    return true;

  return false;
};

Input.prototype.getSigops = function getSigops(scriptHash, accurate) {
  var n = bcoin.script.getSigops(this.script, accurate);
  if (scriptHash && !this.isCoinbase())
    n += bcoin.script.getScripthashSigops(this.script);
  return n;
};

Input.prototype.inspect = function inspect() {
  var output = this.output
    ? this.output.inspect()
    : { type: 'unknown', value: '0.0' };

  output.hash = this.prevout.hash;
  output.rhash = utils.revHex(this.prevout.hash);
  output.index = this.prevout.index;

  return {
    type: this.type,
    subtype: this.subtype,
    address: this.address,
    keys: this.keys.map(utils.toHex),
    hashes: this.hashes.map(utils.toHex),
    addresses: this.addresses,
    scriptAddress: this.scriptAddress,
    signatures: this.signatures.map(utils.toHex),
    text: this.text,
    locktime: this.locktime,
    value: utils.btc(output.value),
    script: bcoin.script.format(this.script),
    redeem: this.redeem ? bcoin.script.format(this.redeem) : null,
    seq: this.seq,
    output: output
  };
};

Input.prototype.toJSON = function toJSON() {
  return {
    prevout: {
      hash: utils.revHex(this.prevout.hash),
      index: this.prevout.index
    },
    output: this.output ? this.output.toJSON() : null,
    script: utils.toHex(bcoin.script.encode(this.script)),
    sequence: this.sequence
  };
};

Input._fromJSON = function _fromJSON(json) {
  return {
    prevout: {
      hash: utils.revHex(json.prevout.hash),
      index: json.prevout.index
    },
    output: json.output ? bcoin.coin._fromJSON(json.output) : null,
    script: bcoin.script.decode(new Buffer(json.script, 'hex')),
    sequence: json.sequence
  };
};

Input.fromJSON = function fromJSON(json) {
  return new Input(Input._fromJSON(json));
};

Input.prototype.toCompact = function toCompact() {
  return {
    type: 'input',
    input: this.toRaw('hex')
  };
};

Input._fromCompact = function _fromCompact(json) {
  return Input._fromRaw(json.input, 'hex');
};

Input.fromCompact = function fromCompact(json) {
  return new Input(Input._fromCompact(json));
};

Input.prototype.toRaw = function toRaw(enc) {
  var data = bcoin.protocol.framer.input(this);

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

Input._fromRaw = function _fromRaw(data, enc) {
  var parser = new bcoin.protocol.parser();

  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  data = parser.parseInput(data);

  return data;
};

Input.fromRaw = function fromRaw(data, enc) {
  return new Input(Input._fromRaw(data, enc));
};

/**
 * Expose
 */

module.exports = Input;
