/*!
 * packets.js - worker packets for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var BufferReader = require('../utils/reader');
var Script = require('../script/script');
var Witness = require('../script/witness');
var Coin = require('../primitives/coin');

/*
 * Constants
 */

var packetTypes = {
  EVENT: 0,
  LOG: 1,
  ERROR: 2,
  ERRORRESULT: 3,
  VERIFY: 4,
  VERIFYRESULT: 5,
  SIGN: 6,
  SIGNRESULT: 7,
  VERIFYINPUT: 8,
  VERIFYINPUTRESULT: 9,
  SIGNINPUT: 10,
  SIGNINPUTRESULT: 11,
  ECVERIFY: 12,
  ECVERIFYRESULT: 13,
  ECSIGN: 14,
  ECSIGNRESULT: 15,
  MINE: 16,
  MINERESULT: 17,
  SCRYPT: 18,
  SCRYPTRESULT: 19
};

/**
 * Packet
 * @constructor
 */

function Packet() {
  this.id = ++Packet.id >>> 0;
  this.error = null;
}

Packet.id = 0;

Packet.prototype.cmd = -1;

Packet.prototype.toRaw = function toRaw() {
  throw new Error('Abstract method.');
};

/**
 * EventPacket
 * @constructor
 */

function EventPacket(items) {
  Packet.call(this);
  this.items = items || [];
}

util.inherits(EventPacket, Packet);

EventPacket.prototype.cmd = packetTypes.EVENT;

EventPacket.prototype.toRaw = function toRaw(bw) {
  bw.writeVarString(JSON.stringify(this.items), 'utf8');
};

EventPacket.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var packet = new EventPacket();
  packet.items = JSON.parse(br.readVarString('utf8'));
  return packet;
};

/**
 * LogPacket
 * @constructor
 */

function LogPacket(items) {
  Packet.call(this);
  this.items = items || [];
}

util.inherits(LogPacket, Packet);

LogPacket.prototype.cmd = packetTypes.LOG;

LogPacket.prototype.toRaw = function toRaw(bw) {
  bw.writeVarString(JSON.stringify(this.items), 'utf8');
};

LogPacket.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var packet = new LogPacket();
  packet.items = JSON.parse(br.readVarString('utf8'));
  return packet;
};

/**
 * ErrorPacket
 * @constructor
 */

function ErrorPacket(error) {
  Packet.call(this);
  this.error = error || new Error();
}

util.inherits(ErrorPacket, Packet);

ErrorPacket.prototype.cmd = packetTypes.ERROR;

ErrorPacket.prototype.toRaw = function toRaw(bw) {
  bw.writeVarString(this.error.message + '', 'utf8');
  bw.writeVarString(this.error.stack + '', 'utf8');
  bw.writeVarString((this.error.type || ''), 'utf8');
};

ErrorPacket.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var packet = new ErrorPacket();
  packet.error.message = br.readVarString('utf8');
  packet.error.stack = br.readVarString('utf8');
  packet.error.type = br.readVarString('utf8');
  return packet;
};

/**
 * ErrorResultPacket
 * @constructor
 */

function ErrorResultPacket(error) {
  Packet.call(this);
  this.error = error || new Error();
}

util.inherits(ErrorResultPacket, Packet);

ErrorResultPacket.prototype.cmd = packetTypes.ERRORRESULT;

ErrorResultPacket.prototype.toRaw = function toRaw(bw) {
  bw.writeVarString(this.error.message + '', 'utf8');
  bw.writeVarString(this.error.stack + '', 'utf8');
  bw.writeVarString((this.error.type || ''), 'utf8');
};

ErrorResultPacket.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var packet = new ErrorResultPacket();
  packet.error.message = br.readVarString('utf8');
  packet.error.stack = br.readVarString('utf8');
  packet.error.type = br.readVarString('utf8');
  return packet;
};

/**
 * VerifyPacket
 * @constructor
 */

function VerifyPacket(tx, flags) {
  Packet.call(this);
  this.tx = tx || null;
  this.flags = flags != null ? flags : null;
}

util.inherits(VerifyPacket, Packet);

VerifyPacket.prototype.cmd = packetTypes.VERIFY;

VerifyPacket.prototype.toRaw = function(bw) {
  frameTX(this.tx, bw);
  bw.writeU32(this.flags);
};

VerifyPacket.fromRaw = function fromRaw(TX, data) {
  var br = new BufferReader(data, true);
  var packet = new VerifyPacket();
  packet.tx = parseTX(TX, br);
  packet.flags = br.readU32();
  return packet;
};

/**
 * VerifyResultPacket
 * @constructor
 */

function VerifyResultPacket(value) {
  Packet.call(this);
  this.value = value;
}

util.inherits(VerifyResultPacket, Packet);

VerifyResultPacket.prototype.cmd = packetTypes.VERIFYRESULT;

VerifyResultPacket.prototype.toRaw = function toRaw(bw) {
  bw.writeU8(this.value ? 1 : 0);
};

VerifyResultPacket.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var packet = new VerifyResultPacket();
  packet.value = br.readU8() === 1;
  return packet;
};

/**
 * SignPacket
 * @constructor
 */

function SignPacket(tx, rings, type) {
  Packet.call(this);
  this.tx = tx || null;
  this.rings = rings || [];
  this.type = type != null ? type : null;
}

util.inherits(SignPacket, Packet);

SignPacket.prototype.cmd = packetTypes.SIGN;

SignPacket.prototype.toRaw = function toRaw(bw) {
  var i, ring;

  frameTX(this.tx, bw);

  bw.writeU32(this.rings.length);

  for (i = 0; i < this.rings.length; i++) {
    ring = this.rings[i];
    bw.writeBytes(ring.toRaw());
  }

  bw.write8(this.type != null ? this.type : -1);
};

SignPacket.fromRaw = function fromRaw(MTX, KeyRing, data) {
  var br = new BufferReader(data, true);
  var packet = new SignPacket();
  var i, count, ring;

  packet.tx = parseTX(MTX, br);

  count = br.readU32();

  for (i = 0; i < count; i++) {
    ring = KeyRing.fromRaw(br);
    packet.rings.push(ring);
  }

  packet.type = br.read8();

  if (packet.type === -1)
    packet.type = null;

  return packet;
};

/**
 * SignResultPacket
 * @constructor
 */

function SignResultPacket(total, witness, script) {
  Packet.call(this);
  this.total = total || 0;
  this.script = script || [];
  this.witness = witness || [];
}

util.inherits(SignResultPacket, Packet);

SignResultPacket.prototype.cmd = packetTypes.SIGNRESULT;

SignResultPacket.fromTX = function fromTX(tx, total) {
  var packet = new SignResultPacket(total);
  var i, input;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    packet.script.push(input.script);
    packet.witness.push(input.witness);
  }

  return packet;
};

SignResultPacket.prototype.toRaw = function toRaw(bw) {
  var i;

  assert(this.script.length === this.witness.length);

  bw.writeVarint(this.total);
  bw.writeVarint(this.script.length);

  for (i = 0; i < this.script.length; i++) {
    this.script[i].toRaw(bw);
    this.witness[i].toRaw(bw);
  }
};

SignResultPacket.prototype.inject = function inject(tx) {
  var i, input;

  assert(this.script.length === tx.inputs.length);
  assert(this.witness.length === tx.inputs.length);

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    input.script = this.script[i];
    input.witness = this.witness[i];
  }
};

SignResultPacket.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var packet = new SignResultPacket();
  var i, count;

  packet.total = br.readVarint();

  count = br.readVarint();

  for (i = 0; i < count; i++) {
    packet.script.push(Script.fromRaw(br));
    packet.witness.push(Witness.fromRaw(br));
  }

  return packet;
};

/**
 * VerifyInputPacket
 * @constructor
 */

function VerifyInputPacket(tx, index, flags) {
  Packet.call(this);
  this.tx = tx || null;
  this.index = index;
  this.flags = flags != null ? flags : null;
}

util.inherits(VerifyInputPacket, Packet);

VerifyInputPacket.prototype.cmd = packetTypes.VERIFYINPUT;

VerifyInputPacket.prototype.toRaw = function toRaw(bw) {
  frameTX(this.tx, bw);
  bw.writeU32(this.index);
  bw.write32(this.flags != null ? this.flags : -1);
};

VerifyInputPacket.fromRaw = function fromRaw(TX, data) {
  var br = new BufferReader(data, true);
  var packet = new VerifyInputPacket();

  packet.tx = parseTX(TX, br);
  packet.index = br.readU32();
  packet.flags = br.read32();

  if (packet.flags === -1)
    packet.flags = null;

  return packet;
};

/**
 * VerifyInputResultPacket
 * @constructor
 */

function VerifyInputResultPacket(value) {
  Packet.call(this);
  this.value = value;
}

util.inherits(VerifyInputResultPacket, Packet);

VerifyInputResultPacket.prototype.cmd = packetTypes.VERIFYINPUTRESULT;

VerifyInputResultPacket.prototype.toRaw = function toRaw(bw) {
  bw.writeU8(this.value ? 1 : 0);
};

VerifyInputResultPacket.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var packet = new VerifyInputResultPacket();
  packet.value = br.readU8() === 1;
  return packet;
};

/**
 * SignInputPacket
 * @constructor
 */

function SignInputPacket(tx, index, rings, type) {
  Packet.call(this);
  this.tx = tx || null;
  this.index = index;
  this.rings = rings || [];
  this.type = type != null ? type : null;
}

util.inherits(SignInputPacket, Packet);

SignInputPacket.prototype.cmd = packetTypes.SIGNINPUT;

SignInputPacket.prototype.toRaw = function toRaw(bw) {
  var i, ring;

  frameTX(this.tx, bw);
  bw.writeU32(this.index);

  bw.writeU32(this.rings.length);

  for (i = 0; i < this.rings.length; i++) {
    ring = this.rings[i];
    bw.writeBytes(ring.toRaw());
  }

  bw.write8(this.type != null ? this.type : -1);
};

SignInputPacket.fromRaw = function fromRaw(MTX, KeyRing, data) {
  var br = new BufferReader(data, true);
  var packet = new SignInputPacket();
  var i, count, ring;

  packet.tx = parseTX(MTX, br);
  packet.index = br.readU32();

  count = br.readU32();

  for (i = 0; i < count; i++) {
    ring = KeyRing.fromRaw(br);
    packet.rings.push(ring);
  }

  packet.type = br.read8();

  if (packet.type === -1)
    packet.type = null;

  return packet;
};


/**
 * SignInputResultPacket
 * @constructor
 */

function SignInputResultPacket(value, witness, script) {
  Packet.call(this);
  this.value = value || false;
  this.script = script || null;
  this.witness = witness || null;
}

util.inherits(SignInputResultPacket, Packet);

SignInputResultPacket.prototype.cmd = packetTypes.SIGNINPUTRESULT;

SignInputResultPacket.fromTX = function fromTX(tx, i, value) {
  var packet = new SignInputResultPacket(value);
  var input = tx.inputs[i];

  assert(input);

  packet.script = input.script;
  packet.witness = input.witness;

  return packet;
};

SignInputResultPacket.prototype.toRaw = function toRaw(bw) {
  bw.writeU8(this.value ? 1 : 0);
  this.script.toRaw(bw);
  this.witness.toRaw(bw);
};

SignInputResultPacket.prototype.inject = function inject(tx, i) {
  var input = tx.inputs[i];
  assert(input);
  input.script = this.script;
  input.witness = this.witness;
};

SignInputResultPacket.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var packet = new SignInputResultPacket();
  packet.value = br.readU8() === 1;
  packet.script = Script.fromRaw(br);
  packet.witness = Witness.fromRaw(br);
  return packet;
};


/**
 * ECVerifyPacket
 * @constructor
 */

function ECVerifyPacket(msg, sig, key) {
  Packet.call(this);
  this.msg = msg || null;
  this.sig = sig || null;
  this.key = key || null;
}

util.inherits(ECVerifyPacket, Packet);

ECVerifyPacket.prototype.cmd = packetTypes.ECVERIFY;

ECVerifyPacket.prototype.toRaw = function(bw) {
  bw.writeVarBytes(this.msg);
  bw.writeVarBytes(this.sig);
  bw.writeVarBytes(this.key);
};

ECVerifyPacket.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var packet = new ECVerifyPacket();
  packet.msg = br.readVarBytes();
  packet.sig = br.readVarBytes();
  packet.key = br.readVarBytes();
  return packet;
};

/**
 * ECVerifyResultPacket
 * @constructor
 */

function ECVerifyResultPacket(value) {
  Packet.call(this);
  this.value = value;
}

util.inherits(ECVerifyResultPacket, Packet);

ECVerifyResultPacket.prototype.cmd = packetTypes.ECVERIFYRESULT;

ECVerifyResultPacket.prototype.toRaw = function toRaw(bw) {
  bw.writeU8(this.value ? 1 : 0);
};

ECVerifyResultPacket.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var packet = new ECVerifyResultPacket();
  packet.value = br.readU8() === 1;
  return packet;
};

/**
 * ECSignPacket
 * @constructor
 */

function ECSignPacket(msg, key) {
  Packet.call(this);
  this.msg = msg || null;
  this.key = key || null;
}

util.inherits(ECSignPacket, Packet);

ECSignPacket.prototype.cmd = packetTypes.ECSIGN;

ECSignPacket.prototype.toRaw = function(bw) {
  bw.writeVarBytes(this.msg);
  bw.writeVarBytes(this.key);
};

ECSignPacket.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var packet = new ECSignPacket();
  packet.msg = br.readVarBytes();
  packet.key = br.readVarBytes();
  return packet;
};

/**
 * ECSignResultPacket
 * @constructor
 */

function ECSignResultPacket(sig) {
  Packet.call(this);
  this.sig = sig;
}

util.inherits(ECSignResultPacket, Packet);

ECSignResultPacket.prototype.cmd = packetTypes.ECSIGNRESULT;

ECSignResultPacket.prototype.toRaw = function toRaw(bw) {
  bw.writeVarBytes(this.sig);
};

ECSignResultPacket.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var packet = new ECSignResultPacket();
  packet.sig = br.readVarBytes();
  return packet;
};

/**
 * MinePacket
 * @constructor
 */

function MinePacket(data, target, min, max) {
  Packet.call(this);
  this.data = data || null;
  this.target = target || null;
  this.min = min != null ? min : -1;
  this.max = max != null ? max : -1;
}

util.inherits(MinePacket, Packet);

MinePacket.prototype.cmd = packetTypes.MINE;

MinePacket.prototype.toRaw = function(bw) {
  bw.writeBytes(this.data);
  bw.writeBytes(this.target);
  bw.writeU32(this.min);
  bw.writeU32(this.max);
};

MinePacket.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var packet = new MinePacket();
  packet.data = br.readBytes(80);
  packet.target = br.readBytes(32);
  packet.min = br.readU32();
  packet.max = br.readU32();
  return packet;
};

/**
 * MineResultPacket
 * @constructor
 */

function MineResultPacket(nonce) {
  Packet.call(this);
  this.nonce = nonce != null ? nonce : -1;
}

util.inherits(MineResultPacket, Packet);

MineResultPacket.prototype.cmd = packetTypes.MINERESULT;

MineResultPacket.prototype.toRaw = function toRaw(bw) {
  bw.writeU32(this.nonce);
};

MineResultPacket.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var packet = new MineResultPacket();
  packet.nonce = br.readU32();
  if ((packet.nonce >> 0) === -1)
    packet.nonce = -1;
  return packet;
};

/**
 * ScryptPacket
 * @constructor
 */

function ScryptPacket(passwd, salt, N, r, p, len) {
  Packet.call(this);
  this.passwd = passwd || null;
  this.salt = salt || null;
  this.N = N != null ? N : -1;
  this.r = r != null ? r : -1;
  this.p = p != null ? p : -1;
  this.len = len != null ? len : -1;
}

util.inherits(ScryptPacket, Packet);

ScryptPacket.prototype.cmd = packetTypes.SCRYPT;

ScryptPacket.prototype.toRaw = function(bw) {
  bw.writeVarBytes(this.passwd);
  bw.writeVarBytes(this.salt);
  bw.writeU32(this.N);
  bw.writeU32(this.r);
  bw.writeU32(this.p);
  bw.writeU32(this.len);
};

ScryptPacket.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var packet = new ScryptPacket();
  packet.passwd = br.readVarBytes();
  packet.salt = br.readVarBytes();
  packet.N = br.readU32();
  packet.r = br.readU32();
  packet.p = br.readU32();
  packet.len = br.readU32();
  return packet;
};

/**
 * ScryptResultPacket
 * @constructor
 */

function ScryptResultPacket(key) {
  Packet.call(this);
  this.key = key || null;
}

util.inherits(ScryptResultPacket, Packet);

ScryptResultPacket.prototype.cmd = packetTypes.SCRYPTRESULT;

ScryptResultPacket.prototype.toRaw = function toRaw(bw) {
  bw.writeVarBytes(this.key);
};

ScryptResultPacket.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var packet = new ScryptResultPacket();
  packet.key = br.readVarBytes();
  return packet;
};

/*
 * Helpers
 */

function frameTX(tx, bw) {
  var i, input;

  tx.toRaw(bw);

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];

    if (!input.coin) {
      bw.writeU8(0);
      continue;
    }

    bw.writeU8(1);
    bw.writeVarint(input.coin.value);
    input.coin.script.toRaw(bw);
  }
}

function parseTX(TX, br) {
  var tx = TX.fromRaw(br);
  var i, input, prevout, coin;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;

    if (br.readU8() === 0)
      continue;

    coin = new Coin();
    coin.value = br.readVarint();
    coin.script.fromRaw(br);

    coin.hash = prevout.hash;
    coin.index = prevout.index;

    input.coin = coin;
  }

  return tx;
}

/*
 * Expose
 */

exports.types = packetTypes;
exports.EventPacket = EventPacket;
exports.LogPacket = LogPacket;
exports.ErrorPacket = ErrorPacket;
exports.ErrorResultPacket = ErrorResultPacket;
exports.VerifyPacket = VerifyPacket;
exports.VerifyResultPacket = VerifyResultPacket;
exports.SignPacket = SignPacket;
exports.SignResultPacket = SignResultPacket;
exports.VerifyInputPacket = VerifyInputPacket;
exports.VerifyInputResultPacket = VerifyInputResultPacket;
exports.SignInputPacket = SignInputPacket;
exports.SignInputResultPacket = SignInputResultPacket;
exports.ECVerifyPacket = ECVerifyPacket;
exports.ECVerifyResultPacket = ECVerifyResultPacket;
exports.ECSignPacket = ECSignPacket;
exports.ECSignResultPacket = ECSignResultPacket;
exports.MinePacket = MinePacket;
exports.MineResultPacket = MineResultPacket;
exports.ScryptPacket = ScryptPacket;
exports.ScryptResultPacket = ScryptResultPacket;
