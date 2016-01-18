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
  if (!(this instanceof Input))
    return new Input(options);

  this.out = {
    tx: options.out.tx || null,
    hash: options.out.hash,
    index: options.out.index
  };

  if (typeof this.out.hash !== 'string')
    this.out.hash = utils.toHex(this.out.hash);

  this.script = options.script ? options.script.slice() : [];
  this.seq = options.seq === undefined ? 0xffffffff : options.seq;

  if (options.script && options.script._raw)
    utils.hidden(this.script, '_raw', options.script._raw);
}

Input.prototype.__defineGetter__('data', function() {
  var data;

  if (this._data)
    return this._data;

  data = Input.getData(this);

  if (this.script.length && this.out.tx)
    utils.hidden(this, '_data', data);

  return data;
});

Input.prototype.__defineGetter__('type', function() {
  return this.data.type;
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
  return this.data.scriptaddress || this.addresses[0] || this._id;
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

Input.prototype.__defineGetter__('scriptaddress', function() {
  return this.data.scriptaddress;
});

Input.prototype.__defineGetter__('m', function() {
  return this.data.m || 1;
});

Input.prototype.__defineGetter__('n', function() {
  return this.data.n || this.m;
});

Input.prototype.__defineGetter__('lock', function() {
  if (!this.output)
    return 0;
  return this.output.lock;
});

Input.prototype.__defineGetter__('lockType', function() {
  if (!this.output)
    return 'height';
  return this.output.lockType;
});

Input.prototype.__defineGetter__('text', function() {
  return this.data.text;
});

Input.prototype.__defineGetter__('output', function() {
  if (!this.out.tx)
    return;
  return this.out.tx.outputs[this.out.index];
});

Input.prototype.__defineGetter__('value', function() {
  if (!this.output)
    return new bn(0);
  return this.output.value;
});

Input.prototype.__defineGetter__('tx', function() {
  return this.out.tx;
});

Input.prototype.__defineGetter__('_id', function() {
  var data = [].concat(
    this.out.hash,
    this.out.index,
    bcoin.script.encode(this.script),
    this.seq
  );
  var hash = utils.toHex(utils.dsha256(data));
  return '[' + this.type + ':' + hash.slice(0, 7) + ']';
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
//   lock: Number,
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

  if (input.out) {
    def.prev = input.out.hash;
    def.index = input.out.index;
  }

  if (input.out && +input.out.hash === 0) {
    data = bcoin.script.coinbase(input.script);
    return utils.merge(def, data, {
      type: 'coinbase',
      none: true
    });
  }

  if (input.out && input.out.tx) {
    output = input.out.tx.outputs[input.out.index];
    if (output) {
      data = bcoin.script.getData(input.script, output.script);
      data.value = output.value;
      return utils.merge(def, data);
    }
  }

  return utils.merge(def, bcoin.script.getInputData(input.script));
};

Input.prototype.inspect = function inspect() {
  var output = this.output
    ? this.output.inspect()
    : { type: 'unknown', value: '0.0' };

  output.hash = this.out.hash;
  output.rhash = utils.revHex(this.out.hash);
  output.index = this.out.index;

  return {
    type: this.type,
    subtype: this.data.subtype,
    address: this.address,
    addresses: this.addresses,
    signatures: this.signatures.map(utils.toHex),
    keys: this.keys.map(utils.toHex),
    text: this.text,
    lock: this.lock,
    lockType: this.lockType,
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
