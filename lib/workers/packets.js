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
const BufferReader = require('../utils/reader');
const encoding = require('../utils/encoding');
const Script = require('../script/script');
const Witness = require('../script/witness');
const Output = require('../primitives/output');
const MTX = require('../primitives/mtx');
const TX = require('../primitives/tx');
const KeyRing = require('../primitives/keyring');
const CoinView = require('../coins/coinview');
const ScriptError = require('../script/scripterror');

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

Packet.prototype.getSize = function getSize() {
  throw new Error('Abstract method.');
};

Packet.prototype.toWriter = function toWriter() {
  throw new Error('Abstract method.');
};

Packet.prototype.fromRaw = function fromRaw() {
  throw new Error('Abstract method.');
};

Packet.fromRaw = function fromRaw() {
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

Object.setPrototypeOf(EnvPacket.prototype, Packet.prototype);

EnvPacket.prototype.cmd = packetTypes.ENV;

EnvPacket.prototype.getSize = function getSize() {
  return encoding.sizeVarString(this.json, 'utf8');
};

EnvPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeVarString(this.json, 'utf8');
  return bw;
};

EnvPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);
  this.json = br.readVarString('utf8');
  this.env = JSON.parse(this.json);
  return this;
};

EnvPacket.fromRaw = function fromRaw(data) {
  return new EnvPacket().fromRaw(data);
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

Object.setPrototypeOf(EventPacket.prototype, Packet.prototype);

EventPacket.prototype.cmd = packetTypes.EVENT;

EventPacket.prototype.getSize = function getSize() {
  return encoding.sizeVarString(this.json, 'utf8');
};

EventPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeVarString(this.json, 'utf8');
  return bw;
};

EventPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);
  this.json = br.readVarString('utf8');
  this.items = JSON.parse(this.json);
  return this;
};

EventPacket.fromRaw = function fromRaw(data) {
  return new EventPacket().fromRaw(data);
};

/**
 * LogPacket
 * @constructor
 */

function LogPacket(text) {
  Packet.call(this);
  this.text = text || '';
}

Object.setPrototypeOf(LogPacket.prototype, Packet.prototype);

LogPacket.prototype.cmd = packetTypes.LOG;

LogPacket.prototype.getSize = function getSize() {
  return encoding.sizeVarString(this.text, 'utf8');
};

LogPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeVarString(this.text, 'utf8');
  return bw;
};

LogPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);
  this.text = br.readVarString('utf8');
  return this;
};

LogPacket.fromRaw = function fromRaw(data) {
  return new LogPacket().fromRaw(data);
};

/**
 * ErrorPacket
 * @constructor
 */

function ErrorPacket(error) {
  Packet.call(this);
  this.error = error || new Error();
}

Object.setPrototypeOf(ErrorPacket.prototype, Packet.prototype);

ErrorPacket.prototype.cmd = packetTypes.ERROR;

ErrorPacket.prototype.getSize = function getSize() {
  const err = this.error;

  let size = 0;

  size += encoding.sizeVarString(stringify(err.message), 'utf8');
  size += encoding.sizeVarString(stringify(err.stack), 'utf8');
  size += encoding.sizeVarString(stringify(err.type), 'utf8');

  switch (typeof err.code) {
    case 'number':
      size += 1;
      size += 4;
      break;
    case 'string':
      size += 1;
      size += encoding.sizeVarString(err.code, 'utf8');
      break;
    default:
      size += 1;
      break;
  }

  return size;
};

ErrorPacket.prototype.toWriter = function toWriter(bw) {
  const err = this.error;

  bw.writeVarString(stringify(err.message), 'utf8');
  bw.writeVarString(stringify(err.stack), 'utf8');
  bw.writeVarString(stringify(err.type), 'utf8');

  switch (typeof err.code) {
    case 'number':
      bw.writeU8(2);
      bw.writeI32(err.code);
      break;
    case 'string':
      bw.writeU8(1);
      bw.writeVarString(err.code, 'utf8');
      break;
    default:
      bw.writeU8(0);
      break;
  }

  return bw;
};

ErrorPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);
  const err = this.error;

  err.message = br.readVarString('utf8');
  err.stack = br.readVarString('utf8');
  err.type = br.readVarString('utf8');

  switch (br.readU8()) {
    case 2:
      err.code = br.readI32();
      break;
    case 1:
      err.code = br.readVarString('utf8');
      break;
    default:
      err.code = null;
      break;
  }

  return this;
};

ErrorPacket.fromRaw = function fromRaw(data) {
  return new ErrorPacket().fromRaw(data);
};

/**
 * ErrorResultPacket
 * @constructor
 */

function ErrorResultPacket(error) {
  ErrorPacket.call(this, error);
}

Object.setPrototypeOf(ErrorResultPacket.prototype, ErrorPacket.prototype);

ErrorResultPacket.prototype.cmd = packetTypes.ERRORRESULT;

ErrorResultPacket.fromRaw = function fromRaw(data) {
  return new ErrorResultPacket().fromRaw(data);
};

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

Object.setPrototypeOf(CheckPacket.prototype, Packet.prototype);

CheckPacket.prototype.cmd = packetTypes.CHECK;

CheckPacket.prototype.getSize = function getSize() {
  return this.tx.getSize() + this.view.getSize(this.tx) + 4;
};

CheckPacket.prototype.toWriter = function toWriter(bw) {
  this.tx.toWriter(bw);
  this.view.toWriter(bw, this.tx);
  bw.writeI32(this.flags != null ? this.flags : -1);
  return bw;
};

CheckPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);

  this.tx = TX.fromReader(br);
  this.view = CoinView.fromReader(br, this.tx);
  this.flags = br.readI32();

  if (this.flags === -1)
    this.flags = null;

  return this;
};

CheckPacket.fromRaw = function fromRaw(data) {
  return new CheckPacket().fromRaw(data);
};

/**
 * CheckResultPacket
 * @constructor
 */

function CheckResultPacket(error) {
  Packet.call(this);
  this.error = error || null;
}

Object.setPrototypeOf(CheckResultPacket.prototype, Packet.prototype);

CheckResultPacket.prototype.cmd = packetTypes.CHECKRESULT;

CheckResultPacket.prototype.getSize = function getSize() {
  const err = this.error;

  let size = 0;

  if (!err) {
    size += 1;
    return size;
  }

  size += 1;
  size += encoding.sizeVarString(stringify(err.message), 'utf8');
  size += encoding.sizeVarString(stringify(err.stack), 'utf8');
  size += encoding.sizeVarString(stringify(err.code), 'utf8');
  size += 1;
  size += 4;

  return size;
};

CheckResultPacket.prototype.toWriter = function toWriter(bw) {
  const err = this.error;

  if (!err) {
    bw.writeU8(0);
    return bw;
  }

  bw.writeU8(1);
  bw.writeVarString(stringify(err.message), 'utf8');
  bw.writeVarString(stringify(err.stack), 'utf8');
  bw.writeVarString(stringify(err.code), 'utf8');
  bw.writeU8(err.op === -1 ? 0xff : err.op);
  bw.writeU32(err.ip === -1 ? 0xffffffff : err.ip);

  return bw;
};

CheckResultPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);

  if (br.readU8() === 0)
    return this;

  const err = new ScriptError('');

  err.message = br.readVarString('utf8');
  err.stack = br.readVarString('utf8');
  err.code = br.readVarString('utf8');
  err.op = br.readU8();
  err.ip = br.readU32();

  if (err.op === 0xff)
    err.op = -1;

  if (err.ip === 0xffffffff)
    err.ip = -1;

  this.error = err;

  return this;
};

CheckResultPacket.fromRaw = function fromRaw(data) {
  return new CheckResultPacket().fromRaw(data);
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

Object.setPrototypeOf(SignPacket.prototype, Packet.prototype);

SignPacket.prototype.cmd = packetTypes.SIGN;

SignPacket.prototype.getSize = function getSize() {
  let size = 0;

  size += this.tx.getSize();
  size += this.tx.view.getSize(this.tx);
  size += encoding.sizeVarint(this.rings.length);

  for (const ring of this.rings)
    size += ring.getSize();

  size += 1;

  return size;
};

SignPacket.prototype.toWriter = function toWriter(bw) {
  this.tx.toWriter(bw);
  this.tx.view.toWriter(bw, this.tx);

  bw.writeVarint(this.rings.length);

  for (const ring of this.rings)
    ring.toWriter(bw);

  bw.writeU8(this.type);

  return bw;
};

SignPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);

  this.tx = MTX.fromReader(br);
  this.tx.view.fromReader(br, this.tx);

  const count = br.readVarint();

  for (let i = 0; i < count; i++) {
    const ring = KeyRing.fromReader(br);
    this.rings.push(ring);
  }

  this.type = br.readU8();

  return this;
};

SignPacket.fromRaw = function fromRaw(data) {
  return new SignPacket().fromRaw(data);
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

Object.setPrototypeOf(SignResultPacket.prototype, Packet.prototype);

SignResultPacket.prototype.cmd = packetTypes.SIGNRESULT;

SignResultPacket.prototype.fromTX = function fromTX(tx, total) {
  this.total = total;

  for (const input of tx.inputs) {
    this.script.push(input.script);
    this.witness.push(input.witness);
  }

  return this;
};

SignResultPacket.fromTX = function fromTX(tx, total) {
  return new SignResultPacket().fromTX(tx, total);
};

SignResultPacket.prototype.getSize = function getSize() {
  let size = 0;

  size += encoding.sizeVarint(this.total);
  size += encoding.sizeVarint(this.script.length);

  for (let i = 0; i < this.script.length; i++) {
    const script = this.script[i];
    const witness = this.witness[i];
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

  return bw;
};

SignResultPacket.prototype.inject = function inject(tx) {
  assert(this.script.length === tx.inputs.length);
  assert(this.witness.length === tx.inputs.length);

  for (let i = 0; i < tx.inputs.length; i++) {
    const input = tx.inputs[i];
    input.script = this.script[i];
    input.witness = this.witness[i];
  }
};

SignResultPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);

  this.total = br.readVarint();

  const count = br.readVarint();

  for (let i = 0; i < count; i++) {
    this.script.push(Script.fromReader(br));
    this.witness.push(Witness.fromReader(br));
  }

  return this;
};

SignResultPacket.fromRaw = function fromRaw(data) {
  return new SignResultPacket().fromRaw(data);
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

Object.setPrototypeOf(CheckInputPacket.prototype, Packet.prototype);

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
  bw.writeI32(this.flags != null ? this.flags : -1);
  return bw;
};

CheckInputPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);

  this.tx = TX.fromReader(br);
  this.index = br.readVarint();

  this.coin = new Output();
  this.coin.value = br.readVarint();
  this.coin.script.fromReader(br);

  this.flags = br.readI32();

  if (this.flags === -1)
    this.flags = null;

  return this;
};

CheckInputPacket.fromRaw = function fromRaw(data) {
  return new CheckInputPacket().fromRaw(data);
};

/**
 * CheckInputResultPacket
 * @constructor
 */

function CheckInputResultPacket(error) {
  CheckResultPacket.call(this, error);
}

Object.setPrototypeOf(
  CheckInputResultPacket.prototype,
  CheckResultPacket.prototype);

CheckInputResultPacket.prototype.cmd = packetTypes.CHECKINPUTRESULT;

CheckInputResultPacket.fromRaw = function fromRaw(data) {
  return new CheckInputResultPacket().fromRaw(data);
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

Object.setPrototypeOf(SignInputPacket.prototype, Packet.prototype);

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
  return bw;
};

SignInputPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);

  this.tx = MTX.fromReader(br);
  this.index = br.readVarint();

  this.coin = new Output();
  this.coin.value = br.readVarint();
  this.coin.script.fromReader(br);

  this.ring = KeyRing.fromReader(br);
  this.type = br.readU8();

  return this;
};

SignInputPacket.fromRaw = function fromRaw(data) {
  return new SignInputPacket().fromRaw(data);
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

Object.setPrototypeOf(SignInputResultPacket.prototype, Packet.prototype);

SignInputResultPacket.prototype.cmd = packetTypes.SIGNINPUTRESULT;

SignInputResultPacket.prototype.fromTX = function fromTX(tx, i, value) {
  const input = tx.inputs[i];

  assert(input);

  this.value = value;
  this.script = input.script;
  this.witness = input.witness;

  return this;
};

SignInputResultPacket.fromTX = function fromTX(tx, i, value) {
  return new SignInputResultPacket().fromTX(tx, i, value);
};

SignInputResultPacket.prototype.getSize = function getSize() {
  return 1 + this.script.getVarSize() + this.witness.getVarSize();
};

SignInputResultPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeU8(this.value ? 1 : 0);
  this.script.toWriter(bw);
  this.witness.toWriter(bw);
  return bw;
};

SignInputResultPacket.prototype.inject = function inject(tx, i) {
  const input = tx.inputs[i];
  assert(input);
  input.script = this.script;
  input.witness = this.witness;
};

SignInputResultPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);
  this.value = br.readU8() === 1;
  this.script = Script.fromReader(br);
  this.witness = Witness.fromReader(br);
  return this;
};

SignInputResultPacket.fromRaw = function fromRaw(data) {
  return new SignInputResultPacket().fromRaw(data);
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

Object.setPrototypeOf(ECVerifyPacket.prototype, Packet.prototype);

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
  return bw;
};

ECVerifyPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);
  this.msg = br.readVarBytes();
  this.sig = br.readVarBytes();
  this.key = br.readVarBytes();
  return this;
};

ECVerifyPacket.fromRaw = function fromRaw(data) {
  return new ECVerifyPacket().fromRaw(data);
};

/**
 * ECVerifyResultPacket
 * @constructor
 */

function ECVerifyResultPacket(value) {
  Packet.call(this);
  this.value = value;
}

Object.setPrototypeOf(ECVerifyResultPacket.prototype, Packet.prototype);

ECVerifyResultPacket.prototype.cmd = packetTypes.ECVERIFYRESULT;

ECVerifyResultPacket.prototype.getSize = function getSize() {
  return 1;
};

ECVerifyResultPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeU8(this.value ? 1 : 0);
  return bw;
};

ECVerifyResultPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);
  this.value = br.readU8() === 1;
  return this;
};

ECVerifyResultPacket.fromRaw = function fromRaw(data) {
  return new ECVerifyResultPacket().fromRaw(data);
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

Object.setPrototypeOf(ECSignPacket.prototype, Packet.prototype);

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
  return bw;
};

ECSignPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);
  this.msg = br.readVarBytes();
  this.key = br.readVarBytes();
  return this;
};

ECSignPacket.fromRaw = function fromRaw(data) {
  return new ECSignPacket().fromRaw(data);
};

/**
 * ECSignResultPacket
 * @constructor
 */

function ECSignResultPacket(sig) {
  Packet.call(this);
  this.sig = sig;
}

Object.setPrototypeOf(ECSignResultPacket.prototype, Packet.prototype);

ECSignResultPacket.prototype.cmd = packetTypes.ECSIGNRESULT;

ECSignResultPacket.prototype.getSize = function getSize() {
  return encoding.sizeVarBytes(this.sig);
};

ECSignResultPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeVarBytes(this.sig);
  return bw;
};

ECSignResultPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);
  this.sig = br.readVarBytes();
  return this;
};

ECSignResultPacket.fromRaw = function fromRaw(data) {
  return new ECSignResultPacket().fromRaw(data);
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

Object.setPrototypeOf(MinePacket.prototype, Packet.prototype);

MinePacket.prototype.cmd = packetTypes.MINE;

MinePacket.prototype.getSize = function getSize() {
  return 120;
};

MinePacket.prototype.toWriter = function toWriter(bw) {
  bw.writeBytes(this.data);
  bw.writeBytes(this.target);
  bw.writeU32(this.min);
  bw.writeU32(this.max);
  return bw;
};

MinePacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);
  this.data = br.readBytes(80);
  this.target = br.readBytes(32);
  this.min = br.readU32();
  this.max = br.readU32();
  return this;
};

MinePacket.fromRaw = function fromRaw(data) {
  return new MinePacket().fromRaw(data);
};

/**
 * MineResultPacket
 * @constructor
 */

function MineResultPacket(nonce) {
  Packet.call(this);
  this.nonce = nonce != null ? nonce : -1;
}

Object.setPrototypeOf(MineResultPacket.prototype, Packet.prototype);

MineResultPacket.prototype.cmd = packetTypes.MINERESULT;

MineResultPacket.prototype.getSize = function getSize() {
  return 5;
};

MineResultPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeU8(this.nonce !== -1 ? 1 : 0);
  bw.writeU32(this.nonce);
  return bw;
};

MineResultPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);
  this.nonce = -1;
  if (br.readU8() === 1)
    this.nonce = br.readU32();
  return this;
};

MineResultPacket.fromRaw = function fromRaw(data) {
  return new MineResultPacket().fromRaw(data);
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

Object.setPrototypeOf(ScryptPacket.prototype, Packet.prototype);

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
  return bw;
};

ScryptPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);
  this.passwd = br.readVarBytes();
  this.salt = br.readVarBytes();
  this.N = br.readU32();
  this.r = br.readU32();
  this.p = br.readU32();
  this.len = br.readU32();
  return this;
};

ScryptPacket.fromRaw = function fromRaw(data) {
  return new ScryptPacket().fromRaw(data);
};

/**
 * ScryptResultPacket
 * @constructor
 */

function ScryptResultPacket(key) {
  Packet.call(this);
  this.key = key || null;
}

Object.setPrototypeOf(ScryptResultPacket.prototype, Packet.prototype);

ScryptResultPacket.prototype.cmd = packetTypes.SCRYPTRESULT;

ScryptResultPacket.prototype.getSize = function getSize() {
  return encoding.sizeVarBytes(this.key);
};

ScryptResultPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeVarBytes(this.key);
  return bw;
};

ScryptResultPacket.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);
  this.key = br.readVarBytes();
  return this;
};

ScryptResultPacket.fromRaw = function fromRaw(data) {
  return new ScryptResultPacket().fromRaw(data);
};

/*
 * Helpers
 */

function stringify(value) {
  if (typeof value !== 'string')
    return '';
  return value;
}

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
