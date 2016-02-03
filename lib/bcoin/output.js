/**
 * output.js - output object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var bcoin = require('../bcoin');
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

  this.tx = options.tx;
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

  if (!this.tx || this.tx.ps === 0) {
    if (this.script.length && this.value.cmpn(0) > 0)
      utils.hidden(this, '_data', data);
  }

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

Output.prototype.__defineGetter__('hash', function() {
  return this.data.scriptHash || this.hashes[0];
});

Output.prototype.__defineGetter__('address', function() {
  return this.data.scriptAddress || this.addresses[0] || this.getID();
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

  if (!output || !output.script)
    return;

  def = {
    side: 'output',
    value: output.value,
    script: output.script
  };

  return utils.merge(def, bcoin.script.getOutputData(output.script));
};

Output.prototype.getID = function getID() {
  var data = bcoin.script.encode(this.script);
  var hash = utils.toHex(utils.ripesha(data));
  return '[' + this.type + ':' + hash.slice(0, 7) + ']';
};

Output.prototype.createScript = function createScript(options) {
  return this.tx.scriptOutput(this, options);
};

Output.prototype.test = function test(addressTable, collect) {
  return this.tx.testOutputs(addressTable, this, collect);
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
    script: bcoin.script.format(this.script)[0]
  };
};

/**
 * Expose
 */

module.exports = Output;
