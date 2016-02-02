/**
 * input.js - input object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var bcoin = require('../bcoin');
var utils = bcoin.utils;
var constants = bcoin.protocol.constants;

/**
 * Input
 */

function Input(options) {
  var prevout;

  if (!(this instanceof Input))
    return new Input(options);

  prevout = options.prevout || options.out;

  this.prevout = {
    tx: prevout.tx || null,
    hash: prevout.hash,
    index: prevout.index
  };

  if (utils.isBuffer(this.prevout.hash))
    this.prevout.hash = utils.toHex(this.prevout.hash);

  this.script = options.script ? options.script.slice() : [];
  this.sequence = options.sequence == null ? 0xffffffff : options.sequence;

  // Legacy
  if (options.seq != null)
    this.sequence = options.seq;

  if (options.script && options.script._raw)
    utils.hidden(this.script, '_raw', options.script._raw);
}

// Legacy
Input.prototype.__defineSetter__('seq', function(sequence) {
  return this.sequence = sequence;
});

Input.prototype.__defineGetter__('seq', function() {
  return this.sequence;
});

Input.prototype.__defineSetter__('out', function(prevout) {
  return this.prevout = prevout;
});

Input.prototype.__defineGetter__('out', function() {
  return this.prevout;
});

Input.prototype.__defineGetter__('data', function() {
  var data;

  if (this._data)
    return this._data;

  data = Input.getData(this);

  if (this.script.length && this.prevout.tx)
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

Input.prototype.__defineGetter__('hash', function() {
  return this.data.scripthash || this.hashes[0];
});

Input.prototype.__defineGetter__('address', function() {
  return this.data.scriptaddress || this.addresses[0] || this.getID();
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

Input.prototype.__defineGetter__('scripthash', function() {
  return this.data.scripthash;
});

Input.prototype.__defineGetter__('scriptaddress', function() {
  return this.data.scriptaddress;
});

Input.prototype.__defineGetter__('m', function() {
  return this.data.m || 1;
});

Input.prototype.__defineGetter__('n', function() {
  return this.data.n || this.m;
});

Input.prototype.__defineGetter__('lockTime', function() {
  if (!this.output)
    return 0;
  return this.output.lockTime;
});

Input.prototype.__defineGetter__('flags', function() {
  return this.data.flags;
});

Input.prototype.__defineGetter__('text', function() {
  return this.data.text;
});

Input.prototype.__defineGetter__('output', function() {
  if (!this.prevout.tx)
    return;
  return this.prevout.tx.outputs[this.prevout.index];
});

Input.prototype.__defineGetter__('value', function() {
  if (!this.output)
    return new bn(0);
  return this.output.value;
});

Input.prototype.__defineGetter__('tx', function() {
  return this.prevout.tx;
});

Input.prototype.__defineGetter__('addr', function() {
  return this.address;
});

Input.prototype.__defineGetter__('addrs', function() {
  return this.addresses;
});

Input.prototype.__defineGetter__('pub', function() {
  return this.key;
});

Input.prototype.__defineGetter__('pubs', function() {
  return this.keys;
});

Input.prototype.__defineGetter__('sig', function() {
  return this.signature;
});

Input.prototype.__defineGetter__('sigs', function() {
  return this.signatures;
});

Input.prototype.__defineGetter__('scriptaddr', function() {
  return this.scriptaddress;
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
//   scripthash: Array,
//   scriptaddress: String,
//   m: Number,
//   n: Number,
//   height: Number,
//   flags: Array,
//   text: String,
//   lockTime: Number,
//   value: bn,
//   script: Array,
//   seq: Number,
//   prev: String,
//   index: Number,
//   none: Boolean
// }

Input.getData = function getData(input) {
  var def, data, output;

  if (!input || !input.script)
    return;

  def = {
    side: 'input',
    value: new bn(0),
    script: input.script,
    seq: input.seq
  };

  if (input.prevout) {
    def.prev = input.prevout.hash;
    def.index = input.prevout.index;
  }

  if (input.prevout && +input.prevout.hash === 0) {
    data = bcoin.script.getCoinbaseData(input.script);
    return utils.merge(def, data, {
      type: 'coinbase',
      none: true
    });
  }

  if (input.prevout && input.prevout.tx) {
    output = input.prevout.tx.outputs[input.prevout.index];
    if (output) {
      data = bcoin.script.getInputData(input.script, output.script);
      data.value = output.value;
      return utils.merge(def, data);
    }
  }

  return utils.merge(def, bcoin.script.getInputData(input.script));
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

  assert(this.prevout.tx);

  output = this.prevout.tx.outputs[this.prevout.index];
  redeem = output.script;

  if (bcoin.script.isScripthash(redeem))
    redeem = bcoin.script.getRedeem(this.script);

  if (redeem[1] !== 'checklocktimeverify')
    return;

  return bcoin.script.getLocktime(redeem);
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
    scriptaddress: this.scriptaddress,
    signatures: this.signatures.map(utils.toHex),
    text: this.text,
    lockTime: this.lockTime,
    value: utils.btc(output.value),
    script: bcoin.script.format(this.script)[0],
    redeem: this.redeem ? bcoin.script.format(this.redeem)[0] : null,
    seq: this.seq,
    output: output
  };
};

/**
 * Expose
 */

module.exports = Input;
