/*!
 * packets.js - worker packets for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module workers/packets
 */

const assert = require('assert');
const util = require('../utils/util');
const BufferReader = require('../utils/reader');
const encoding = require('../utils/encoding');
const Script = require('../script/script');
const Witness = require('../script/witness');
const Output = require('../primitives/output');
const MTX = require('../primitives/mtx');
const TX = require('../primitives/tx');
const KeyRing = require('../primitives/keyring');
const CoinView = require('../coins/coinview');
const {ScriptError} = require('../script/common');

/*
 * Constants
 */

const packetTypes = {
  ENV: 0,
  EVENT: 1,
  LOG: 2,
  ERROR: 3,
  ERRORRESULT: 4,
  CHECK: 5,
  CHECKRESULT: 6,
  SIGN: 7,
  SIGNRESULT: 8,
  CHECKINPUT: 9,
  CHECKINPUTRESULT: 10,
  SIGNINPUT: 11,
  SIGNINPUTRESULT: 12,
  ECVERIFY: 13,
  ECVERIFYRESULT: 14,
  ECSIGN: 15,
  ECSIGNRESULT: 16,
  MINE: 17,
  MINERESULT: 18,
  SCRYPT: 19,
  SCRYPTRESULT: 20
};

/**
 * Packet
 * @constructor
 */

function Packet() {
  this.id = ++Packet.id >>> 0;
}

Packet.id = 0;

Packet.prototype.cmd = -1;

Packet.prototype.toWriter = function toWriter() {
  throw new Error('Abstract method.');
};

/**
 * EnvPacket
 * @constructor
 */

function EnvPacket(env) {
  Packet.call(this);
  this.env = env || {};
  this.json = JSON.stringify(this.env);
}

util.inherits(EnvPacket, Packet);

EnvPacket.prototype.cmd = packetTypes.ENV;

EnvPacket.prototype.getSize = function getSize() {
  return encoding.sizeVarString(this.json, 'utf8');
};

EnvPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeVarString(this.json, 'utf8');
};

EnvPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new EnvPacket();
  packet.json = br.readVarString('utf8');
  packet.env = JSON.parse(packet.json);
  return packet;
};

/**
 * EventPacket
 * @constructor
 */

function EventPacket(items) {
  Packet.call(this);
  this.items = items || [];
  this.json = JSON.stringify(this.items);
}

util.inherits(EventPacket, Packet);

EventPacket.prototype.cmd = packetTypes.EVENT;

EventPacket.prototype.getSize = function getSize() {
  return encoding.sizeVarString(this.json, 'utf8');
};

EventPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeVarString(this.json, 'utf8');
};

EventPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new EventPacket();
  packet.json = br.readVarString('utf8');
  packet.items = JSON.parse(packet.json);
  return packet;
};

/**
 * LogPacket
 * @constructor
 */

function LogPacket(text) {
  Packet.call(this);
  this.text = text || '';
}

util.inherits(LogPacket, Packet);

LogPacket.prototype.cmd = packetTypes.LOG;

LogPacket.prototype.getSize = function getSize() {
  return encoding.sizeVarString(this.text, 'utf8');
};

LogPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeVarString(this.text, 'utf8');
};

LogPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new LogPacket();
  packet.text = br.readVarString('utf8');
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

ErrorPacket.prototype.getSize = function getSize() {
  let size = 0;

  size += encoding.sizeVarString(this.error.message + '', 'utf8');
  size += encoding.sizeVarString(this.error.stack + '', 'utf8');
  size += encoding.sizeVarString(this.error.type || '', 'utf8');

  switch (typeof this.error.code) {
    case 'number':
      size += 1;
      size += 4;
      break;
    case 'string':
      size += 1;
      size += encoding.sizeVarString(this.error.code, 'utf8');
      break;
    default:
      size += 1;
      break;
  }

  return size;
};

ErrorPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeVarString(this.error.message + '', 'utf8');
  bw.writeVarString(this.error.stack + '', 'utf8');
  bw.writeVarString(this.error.type || '', 'utf8');

  switch (typeof this.error.code) {
    case 'number':
      bw.writeU8(2);
      bw.write32(this.error.code);
      break;
    case 'string':
      bw.writeU8(1);
      bw.writeVarString(this.error.code, 'utf8');
      break;
    default:
      bw.writeU8(0);
      break;
  }
};

ErrorPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new ErrorPacket();

  packet.error.message = br.readVarString('utf8');
  packet.error.stack = br.readVarString('utf8');
  packet.error.type = br.readVarString('utf8');

  switch (br.readU8()) {
    case 2:
      packet.error.code = br.read32();
      break;
    case 1:
      packet.error.code = br.readVarString('utf8');
      break;
    default:
      packet.error.code = null;
      break;
  }

  return packet;
};

/**
 * ErrorResultPacket
 * @constructor
 */

function ErrorResultPacket(error) {
  ErrorPacket.call(this, error);
}

util.inherits(ErrorResultPacket, ErrorPacket);

ErrorResultPacket.prototype.cmd = packetTypes.ERRORRESULT;

/**
 * CheckPacket
 * @constructor
 */

function CheckPacket(tx, view, flags) {
  Packet.call(this);
  this.tx = tx || null;
  this.view = view || null;
  this.flags = flags != null ? flags : null;
}

util.inherits(CheckPacket, Packet);

CheckPacket.prototype.cmd = packetTypes.CHECK;

CheckPacket.prototype.getSize = function getSize() {
  return this.tx.getSize() + this.view.getSize(this.tx) + 4;
};

CheckPacket.prototype.toWriter = function toWriter(bw) {
  this.tx.toWriter(bw);
  this.view.toWriter(bw, this.tx);
  bw.write32(this.flags != null ? this.flags : -1);
};

CheckPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new CheckPacket();

  packet.tx = TX.fromReader(br);
  packet.view = CoinView.fromReader(br, packet.tx);
  packet.flags = br.read32();

  if (packet.flags === -1)
    packet.flags = null;

  return packet;
};

/**
 * CheckResultPacket
 * @constructor
 */

function CheckResultPacket(error) {
  Packet.call(this);
  this.error = error || null;
}

util.inherits(CheckResultPacket, Packet);

CheckResultPacket.prototype.cmd = packetTypes.CHECKRESULT;

CheckResultPacket.prototype.getSize = function getSize() {
  let err = this.error;
  let size = 0;

  if (!err) {
    size += 1;
    return size;
  }

  size += 1;
  size += encoding.sizeVarString(err.code, 'utf8');
  size += encoding.sizeVarString(err.message, 'utf8');
  size += encoding.sizeVarString(err.stack + '', 'utf8');
  size += 1;
  size += 4;

  return size;
};

CheckResultPacket.prototype.toWriter = function toWriter(bw) {
  let err = this.error;

  if (!err) {
    bw.writeU8(0);
    return;
  }

  bw.writeU8(1);
  bw.writeVarString(err.code, 'utf8');
  bw.writeVarString(err.message, 'utf8');
  bw.writeVarString(err.stack + '', 'utf8');
  bw.writeU8(err.op === -1 ? 0xff : err.op);
  bw.writeU32(err.ip === -1 ? 0xffffffff : err.ip);
};

CheckResultPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new CheckResultPacket();
  let err;

  if (br.readU8() === 0)
    return packet;

  err = new ScriptError('');
  err.code = br.readVarString('utf8');
  err.message = br.readVarString('utf8');
  err.stack = br.readVarString('utf8');
  err.op = br.readU8();
  err.ip = br.readU32();

  if (err.op === 0xff)
    err.op = -1;

  if (err.ip === 0xffffffff)
    err.ip = -1;

  packet.error = err;

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
  this.type = type != null ? type : 1;
}

util.inherits(SignPacket, Packet);

SignPacket.prototype.cmd = packetTypes.SIGN;

SignPacket.prototype.getSize = function getSize() {
  let size = 0;

  size += this.tx.getSize();
  size += this.tx.view.getSize(this.tx);
  size += encoding.sizeVarint(this.rings.length);

  for (let ring of this.rings)
    size += ring.getSize();

  size += 1;

  return size;
};

SignPacket.prototype.toWriter = function toWriter(bw) {
  this.tx.toWriter(bw);
  this.tx.view.toWriter(bw, this.tx);

  bw.writeVarint(this.rings.length);

  for (let ring of this.rings)
    ring.toWriter(bw);

  bw.writeU8(this.type);
};

SignPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new SignPacket();
  let count;

  packet.tx = MTX.fromReader(br);
  packet.tx.view.fromReader(br, packet.tx);

  count = br.readVarint();

  for (let i = 0; i < count; i++) {
    let ring = KeyRing.fromReader(br);
    packet.rings.push(ring);
  }

  packet.type = br.readU8();

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
  let packet = new SignResultPacket(total);

  for (let input of tx.inputs) {
    packet.script.push(input.script);
    packet.witness.push(input.witness);
  }

  return packet;
};

SignResultPacket.prototype.getSize = function getSize() {
  let size = 0;

  size += encoding.sizeVarint(this.total);
  size += encoding.sizeVarint(this.script.length);

  for (let i = 0; i < this.script.length; i++) {
    let script = this.script[i];
    let witness = this.witness[i];
    size += script.getVarSize();
    size += witness.getVarSize();
  }

  return size;
};

SignResultPacket.prototype.toWriter = function toWriter(bw) {
  assert(this.script.length === this.witness.length);

  bw.writeVarint(this.total);
  bw.writeVarint(this.script.length);

  for (let i = 0; i < this.script.length; i++) {
    this.script[i].toWriter(bw);
    this.witness[i].toWriter(bw);
  }
};

SignResultPacket.prototype.inject = function inject(tx) {
  assert(this.script.length === tx.inputs.length);
  assert(this.witness.length === tx.inputs.length);

  for (let i = 0; i < tx.inputs.length; i++) {
    let input = tx.inputs[i];
    input.script = this.script[i];
    input.witness = this.witness[i];
  }
};

SignResultPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new SignResultPacket();
  let count;

  packet.total = br.readVarint();

  count = br.readVarint();

  for (let i = 0; i < count; i++) {
    packet.script.push(Script.fromReader(br));
    packet.witness.push(Witness.fromReader(br));
  }

  return packet;
};

/**
 * CheckInputPacket
 * @constructor
 */

function CheckInputPacket(tx, index, coin, flags) {
  Packet.call(this);
  this.tx = tx || null;
  this.index = index;
  this.coin = coin || null;
  this.flags = flags != null ? flags : null;
}

util.inherits(CheckInputPacket, Packet);

CheckInputPacket.prototype.cmd = packetTypes.CHECKINPUT;

CheckInputPacket.prototype.getSize = function getSize() {
  let size = 0;
  size += this.tx.getSize();
  size += encoding.sizeVarint(this.index);
  size += encoding.sizeVarint(this.coin.value);
  size += this.coin.script.getVarSize();
  size += 4;
  return size;
};

CheckInputPacket.prototype.toWriter = function toWriter(bw) {
  this.tx.toWriter(bw);
  bw.writeVarint(this.index);
  bw.writeVarint(this.coin.value);
  this.coin.script.toWriter(bw);
  bw.write32(this.flags != null ? this.flags : -1);
};

CheckInputPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new CheckInputPacket();

  packet.tx = TX.fromReader(br);
  packet.index = br.readVarint();

  packet.coin = new Output();
  packet.coin.value = br.readVarint();
  packet.coin.script.fromReader(br);

  packet.flags = br.read32();

  if (packet.flags === -1)
    packet.flags = null;

  return packet;
};

/**
 * CheckInputResultPacket
 * @constructor
 */

function CheckInputResultPacket(error) {
  CheckResultPacket.call(this, error);
}

util.inherits(CheckInputResultPacket, CheckResultPacket);

CheckInputResultPacket.prototype.cmd = packetTypes.CHECKINPUTRESULT;

CheckInputResultPacket.fromRaw = function fromRaw(data) {
  let p = CheckResultPacket.fromRaw(data);
  let packet = new CheckInputResultPacket();
  packet.error = p.error;
  return packet;
};

/**
 * SignInputPacket
 * @constructor
 */

function SignInputPacket(tx, index, coin, ring, type) {
  Packet.call(this);
  this.tx = tx || null;
  this.index = index;
  this.coin = coin || null;
  this.ring = ring || null;
  this.type = type != null ? type : 1;
}

util.inherits(SignInputPacket, Packet);

SignInputPacket.prototype.cmd = packetTypes.SIGNINPUT;

SignInputPacket.prototype.getSize = function getSize() {
  let size = 0;
  size += this.tx.getSize();
  size += encoding.sizeVarint(this.index);
  size += encoding.sizeVarint(this.coin.value);
  size += this.coin.script.getVarSize();
  size += this.ring.getSize();
  size += 1;
  return size;
};

SignInputPacket.prototype.toWriter = function toWriter(bw) {
  this.tx.toWriter(bw);
  bw.writeVarint(this.index);
  bw.writeVarint(this.coin.value);
  this.coin.script.toWriter(bw);
  this.ring.toWriter(bw);
  bw.writeU8(this.type);
};

SignInputPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new SignInputPacket();

  packet.tx = MTX.fromReader(br);
  packet.index = br.readVarint();

  packet.coin = new Output();
  packet.coin.value = br.readVarint();
  packet.coin.script.fromReader(br);

  packet.ring = KeyRing.fromReader(br);
  packet.type = br.readU8();

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
  let packet = new SignInputResultPacket(value);
  let input = tx.inputs[i];

  assert(input);

  packet.script = input.script;
  packet.witness = input.witness;

  return packet;
};

SignInputResultPacket.prototype.getSize = function getSize() {
  return 1 + this.script.getVarSize() + this.witness.getVarSize();
};

SignInputResultPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeU8(this.value ? 1 : 0);
  this.script.toWriter(bw);
  this.witness.toWriter(bw);
};

SignInputResultPacket.prototype.inject = function inject(tx, i) {
  let input = tx.inputs[i];
  assert(input);
  input.script = this.script;
  input.witness = this.witness;
};

SignInputResultPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new SignInputResultPacket();
  packet.value = br.readU8() === 1;
  packet.script = Script.fromReader(br);
  packet.witness = Witness.fromReader(br);
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

ECVerifyPacket.prototype.getSize = function getSize() {
  let size = 0;
  size += encoding.sizeVarBytes(this.msg);
  size += encoding.sizeVarBytes(this.sig);
  size += encoding.sizeVarBytes(this.key);
  return size;
};

ECVerifyPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeVarBytes(this.msg);
  bw.writeVarBytes(this.sig);
  bw.writeVarBytes(this.key);
};

ECVerifyPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new ECVerifyPacket();
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

ECVerifyResultPacket.prototype.getSize = function getSize() {
  return 1;
};

ECVerifyResultPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeU8(this.value ? 1 : 0);
};

ECVerifyResultPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new ECVerifyResultPacket();
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

ECSignPacket.prototype.getSize = function getSize() {
  let size = 0;
  size += encoding.sizeVarBytes(this.msg);
  size += encoding.sizeVarBytes(this.key);
  return size;
};

ECSignPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeVarBytes(this.msg);
  bw.writeVarBytes(this.key);
};

ECSignPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new ECSignPacket();
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

ECSignResultPacket.prototype.getSize = function getSize() {
  return encoding.sizeVarBytes(this.sig);
};

ECSignResultPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeVarBytes(this.sig);
};

ECSignResultPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new ECSignResultPacket();
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

MinePacket.prototype.getSize = function getSize() {
  return 120;
};

MinePacket.prototype.toWriter = function toWriter(bw) {
  bw.writeBytes(this.data);
  bw.writeBytes(this.target);
  bw.writeU32(this.min);
  bw.writeU32(this.max);
};

MinePacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new MinePacket();
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

MineResultPacket.prototype.getSize = function getSize() {
  return 4;
};

MineResultPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeU32(this.nonce);
};

MineResultPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new MineResultPacket();
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

ScryptPacket.prototype.getSize = function getSize() {
  let size = 0;
  size += encoding.sizeVarBytes(this.passwd);
  size += encoding.sizeVarBytes(this.salt);
  size += 16;
  return size;
};

ScryptPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeVarBytes(this.passwd);
  bw.writeVarBytes(this.salt);
  bw.writeU32(this.N);
  bw.writeU32(this.r);
  bw.writeU32(this.p);
  bw.writeU32(this.len);
};

ScryptPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new ScryptPacket();
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

ScryptResultPacket.prototype.getSize = function getSize() {
  return encoding.sizeVarBytes(this.key);
};

ScryptResultPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeVarBytes(this.key);
};

ScryptResultPacket.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data, true);
  let packet = new ScryptResultPacket();
  packet.key = br.readVarBytes();
  return packet;
};

/*
 * Expose
 */

exports.types = packetTypes;
exports.EnvPacket = EnvPacket;
exports.EventPacket = EventPacket;
exports.LogPacket = LogPacket;
exports.ErrorPacket = ErrorPacket;
exports.ErrorResultPacket = ErrorResultPacket;
exports.CheckPacket = CheckPacket;
exports.CheckResultPacket = CheckResultPacket;
exports.SignPacket = SignPacket;
exports.SignResultPacket = SignResultPacket;
exports.CheckInputPacket = CheckInputPacket;
exports.CheckInputResultPacket = CheckInputResultPacket;
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
