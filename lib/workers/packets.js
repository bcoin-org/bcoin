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
const bio = require('bufio');
const Script = require('../script/script');
const Witness = require('../script/witness');
const Output = require('../primitives/output');
const MTX = require('../primitives/mtx');
const TX = require('../primitives/tx');
const KeyRing = require('../primitives/keyring');
const CoinView = require('../coins/coinview');
const ScriptError = require('../script/scripterror');
const {encoding} = bio;

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
 */

class Packet {
  constructor() {
    this.id = ++Packet.id >>> 0;
    this.cmd = -1;
  }

  getSize() {
    throw new Error('Abstract method.');
  }

  toWriter() {
    throw new Error('Abstract method.');
  }

  fromRaw() {
    throw new Error('Abstract method.');
  }

  static fromRaw() {
    throw new Error('Abstract method.');
  }
}

Packet.id = 0;

/**
 * EnvPacket
 */

class EnvPacket extends Packet {
  constructor(env) {
    super();
    this.cmd = packetTypes.ENV;
    this.env = env || {};
    this.json = JSON.stringify(this.env);
  }

  getSize() {
    return encoding.sizeVarString(this.json, 'utf8');
  }

  toWriter(bw) {
    bw.writeVarString(this.json, 'utf8');
    return bw;
  }

  fromRaw(data) {
    const br = bio.read(data, true);
    this.json = br.readVarString('utf8');
    this.env = JSON.parse(this.json);
    return this;
  }

  static fromRaw(data) {
    return new EnvPacket().fromRaw(data);
  }
}

/**
 * EventPacket
 */

class EventPacket extends Packet {
  constructor(items) {
    super();
    this.cmd = packetTypes.EVENT;
    this.items = items || [];
    this.json = JSON.stringify(this.items);
  }

  getSize() {
    return encoding.sizeVarString(this.json, 'utf8');
  }

  toWriter(bw) {
    bw.writeVarString(this.json, 'utf8');
    return bw;
  }

  fromRaw(data) {
    const br = bio.read(data, true);
    this.json = br.readVarString('utf8');
    this.items = JSON.parse(this.json);
    return this;
  }

  static fromRaw(data) {
    return new EventPacket().fromRaw(data);
  }
}

/**
 * LogPacket
 */

class LogPacket extends Packet {
  constructor(text) {
    super();
    this.cmd = packetTypes.LOG;
    this.text = text || '';
  }

  getSize() {
    return encoding.sizeVarString(this.text, 'utf8');
  }

  toWriter(bw) {
    bw.writeVarString(this.text, 'utf8');
    return bw;
  }

  fromRaw(data) {
    const br = bio.read(data, true);
    this.text = br.readVarString('utf8');
    return this;
  }

  static fromRaw(data) {
    return new LogPacket().fromRaw(data);
  }
}

/**
 * ErrorPacket
 */

class ErrorPacket extends Packet {
  constructor(error) {
    super();
    this.cmd = packetTypes.ERROR;
    this.error = error || new Error();
  }

  getSize() {
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
  }

  toWriter(bw) {
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
  }

  fromRaw(data) {
    const br = bio.read(data, true);
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
  }

  static fromRaw(data) {
    return new ErrorPacket().fromRaw(data);
  }
}

/**
 * ErrorResultPacket
 */

class ErrorResultPacket extends ErrorPacket {
  constructor(error) {
    super(error);
    this.cmd = packetTypes.ERRORRESULT;
  }

  static fromRaw(data) {
    return new ErrorResultPacket().fromRaw(data);
  }
}

/**
 * CheckPacket
 */

class CheckPacket extends Packet {
  constructor(tx, view, flags) {
    super();
    this.cmd = packetTypes.CHECK;
    this.tx = tx || null;
    this.view = view || null;
    this.flags = flags != null ? flags : null;
  }

  getSize() {
    return this.tx.getSize() + this.view.getSize(this.tx) + 4;
  }

  toWriter(bw) {
    this.tx.toWriter(bw);
    this.view.toWriter(bw, this.tx);
    bw.writeI32(this.flags != null ? this.flags : -1);
    return bw;
  }

  fromRaw(data) {
    const br = bio.read(data, true);

    this.tx = TX.fromReader(br);
    this.view = CoinView.fromReader(br, this.tx);
    this.flags = br.readI32();

    if (this.flags === -1)
      this.flags = null;

    return this;
  }

  static fromRaw(data) {
    return new CheckPacket().fromRaw(data);
  }
}

/**
 * CheckResultPacket
 */

class CheckResultPacket extends Packet {
  constructor(error) {
    super();
    this.cmd = packetTypes.CHECKRESULT;
    this.error = error || null;
  }

  getSize() {
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
  }

  toWriter(bw) {
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
  }

  fromRaw(data) {
    const br = bio.read(data, true);

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
  }

  static fromRaw(data) {
    return new CheckResultPacket().fromRaw(data);
  }
}

/**
 * SignPacket
 */

class SignPacket extends Packet {
  constructor(tx, rings, type) {
    super();
    this.cmd = packetTypes.SIGN;
    this.tx = tx || null;
    this.rings = rings || [];
    this.type = type != null ? type : 1;
  }

  getSize() {
    let size = 0;

    size += this.tx.getSize();
    size += this.tx.view.getSize(this.tx);
    size += encoding.sizeVarint(this.rings.length);

    for (const ring of this.rings)
      size += ring.getSize();

    size += 1;

    return size;
  }

  toWriter(bw) {
    this.tx.toWriter(bw);
    this.tx.view.toWriter(bw, this.tx);

    bw.writeVarint(this.rings.length);

    for (const ring of this.rings)
      ring.toWriter(bw);

    bw.writeU8(this.type);

    return bw;
  }

  fromRaw(data) {
    const br = bio.read(data, true);

    this.tx = MTX.fromReader(br);
    this.tx.view.fromReader(br, this.tx);

    const count = br.readVarint();

    for (let i = 0; i < count; i++) {
      const ring = KeyRing.fromReader(br);
      this.rings.push(ring);
    }

    this.type = br.readU8();

    return this;
  }

  static fromRaw(data) {
    return new SignPacket().fromRaw(data);
  }
}

/**
 * SignResultPacket
 */

class SignResultPacket extends Packet {
  constructor(total, witness, script) {
    super();
    this.cmd = packetTypes.SIGNRESULT;
    this.total = total || 0;
    this.script = script || [];
    this.witness = witness || [];
  }

  fromTX(tx, total) {
    this.total = total;

    for (const input of tx.inputs) {
      this.script.push(input.script);
      this.witness.push(input.witness);
    }

    return this;
  }

  static fromTX(tx, total) {
    return new SignResultPacket().fromTX(tx, total);
  }

  getSize() {
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
  }

  toWriter(bw) {
    assert(this.script.length === this.witness.length);

    bw.writeVarint(this.total);
    bw.writeVarint(this.script.length);

    for (let i = 0; i < this.script.length; i++) {
      this.script[i].toWriter(bw);
      this.witness[i].toWriter(bw);
    }

    return bw;
  }

  inject(tx) {
    assert(this.script.length === tx.inputs.length);
    assert(this.witness.length === tx.inputs.length);

    for (let i = 0; i < tx.inputs.length; i++) {
      const input = tx.inputs[i];
      input.script = this.script[i];
      input.witness = this.witness[i];
    }
  }

  fromRaw(data) {
    const br = bio.read(data, true);

    this.total = br.readVarint();

    const count = br.readVarint();

    for (let i = 0; i < count; i++) {
      this.script.push(Script.fromReader(br));
      this.witness.push(Witness.fromReader(br));
    }

    return this;
  }

  static fromRaw(data) {
    return new SignResultPacket().fromRaw(data);
  }
}

/**
 * CheckInputPacket
 */

class CheckInputPacket extends Packet {
  constructor(tx, index, coin, flags) {
    super();
    this.cmd = packetTypes.CHECKINPUT;
    this.tx = tx || null;
    this.index = index;
    this.coin = coin || null;
    this.flags = flags != null ? flags : null;
  }

  getSize() {
    let size = 0;
    size += this.tx.getSize();
    size += encoding.sizeVarint(this.index);
    size += encoding.sizeVarint(this.coin.value);
    size += this.coin.script.getVarSize();
    size += 4;
    return size;
  }

  toWriter(bw) {
    this.tx.toWriter(bw);
    bw.writeVarint(this.index);
    bw.writeVarint(this.coin.value);
    this.coin.script.toWriter(bw);
    bw.writeI32(this.flags != null ? this.flags : -1);
    return bw;
  }

  fromRaw(data) {
    const br = bio.read(data, true);

    this.tx = TX.fromReader(br);
    this.index = br.readVarint();

    this.coin = new Output();
    this.coin.value = br.readVarint();
    this.coin.script.fromReader(br);

    this.flags = br.readI32();

    if (this.flags === -1)
      this.flags = null;

    return this;
  }

  static fromRaw(data) {
    return new CheckInputPacket().fromRaw(data);
  }
}

/**
 * CheckInputResultPacket
 */

class CheckInputResultPacket extends CheckResultPacket {
  constructor(error) {
    super(error);
    this.cmd = packetTypes.CHECKINPUTRESULT;
  }

  static fromRaw(data) {
    return new CheckInputResultPacket().fromRaw(data);
  }
}

/**
 * SignInputPacket
 */

class SignInputPacket extends Packet {
  constructor(tx, index, coin, ring, type) {
    super();
    this.cmd = packetTypes.SIGNINPUT;
    this.tx = tx || null;
    this.index = index;
    this.coin = coin || null;
    this.ring = ring || null;
    this.type = type != null ? type : 1;
  }

  getSize() {
    let size = 0;
    size += this.tx.getSize();
    size += encoding.sizeVarint(this.index);
    size += encoding.sizeVarint(this.coin.value);
    size += this.coin.script.getVarSize();
    size += this.ring.getSize();
    size += 1;
    return size;
  }

  toWriter(bw) {
    this.tx.toWriter(bw);
    bw.writeVarint(this.index);
    bw.writeVarint(this.coin.value);
    this.coin.script.toWriter(bw);
    this.ring.toWriter(bw);
    bw.writeU8(this.type);
    return bw;
  }

  fromRaw(data) {
    const br = bio.read(data, true);

    this.tx = MTX.fromReader(br);
    this.index = br.readVarint();

    this.coin = new Output();
    this.coin.value = br.readVarint();
    this.coin.script.fromReader(br);

    this.ring = KeyRing.fromReader(br);
    this.type = br.readU8();

    return this;
  }

  static fromRaw(data) {
    return new SignInputPacket().fromRaw(data);
  }
}

/**
 * SignInputResultPacket
 */

class SignInputResultPacket extends Packet {
  constructor(value, witness, script) {
    super();
    this.cmd = packetTypes.SIGNINPUTRESULT;
    this.value = value || false;
    this.script = script || null;
    this.witness = witness || null;
  }

  fromTX(tx, i, value) {
    const input = tx.inputs[i];

    assert(input);

    this.value = value;
    this.script = input.script;
    this.witness = input.witness;

    return this;
  }

  static fromTX(tx, i, value) {
    return new SignInputResultPacket().fromTX(tx, i, value);
  }

  getSize() {
    return 1 + this.script.getVarSize() + this.witness.getVarSize();
  }

  toWriter(bw) {
    bw.writeU8(this.value ? 1 : 0);
    this.script.toWriter(bw);
    this.witness.toWriter(bw);
    return bw;
  }

  inject(tx, i) {
    const input = tx.inputs[i];
    assert(input);
    input.script = this.script;
    input.witness = this.witness;
  }

  fromRaw(data) {
    const br = bio.read(data, true);
    this.value = br.readU8() === 1;
    this.script = Script.fromReader(br);
    this.witness = Witness.fromReader(br);
    return this;
  }

  static fromRaw(data) {
    return new SignInputResultPacket().fromRaw(data);
  }
}

/**
 * ECVerifyPacket
 */

class ECVerifyPacket extends Packet {
  constructor(msg, sig, key) {
    super();
    this.cmd = packetTypes.ECVERIFY;
    this.msg = msg || null;
    this.sig = sig || null;
    this.key = key || null;
  }

  getSize() {
    let size = 0;
    size += encoding.sizeVarBytes(this.msg);
    size += encoding.sizeVarBytes(this.sig);
    size += encoding.sizeVarBytes(this.key);
    return size;
  }

  toWriter(bw) {
    bw.writeVarBytes(this.msg);
    bw.writeVarBytes(this.sig);
    bw.writeVarBytes(this.key);
    return bw;
  }

  fromRaw(data) {
    const br = bio.read(data, true);
    this.msg = br.readVarBytes();
    this.sig = br.readVarBytes();
    this.key = br.readVarBytes();
    return this;
  }

  static fromRaw(data) {
    return new ECVerifyPacket().fromRaw(data);
  }
}

/**
 * ECVerifyResultPacket
 */

class ECVerifyResultPacket extends Packet {
  constructor(value) {
    super();
    this.cmd = packetTypes.ECVERIFYRESULT;
    this.value = value;
  }

  getSize() {
    return 1;
  }

  toWriter(bw) {
    bw.writeU8(this.value ? 1 : 0);
    return bw;
  }

  fromRaw(data) {
    const br = bio.read(data, true);
    this.value = br.readU8() === 1;
    return this;
  }

  static fromRaw(data) {
    return new ECVerifyResultPacket().fromRaw(data);
  }
}

/**
 * ECSignPacket
 */

class ECSignPacket extends Packet {
  constructor(msg, key) {
    super();
    this.cmd = packetTypes.ECSIGN;
    this.msg = msg || null;
    this.key = key || null;
  }

  getSize() {
    let size = 0;
    size += encoding.sizeVarBytes(this.msg);
    size += encoding.sizeVarBytes(this.key);
    return size;
  }

  toWriter(bw) {
    bw.writeVarBytes(this.msg);
    bw.writeVarBytes(this.key);
    return bw;
  }

  fromRaw(data) {
    const br = bio.read(data, true);
    this.msg = br.readVarBytes();
    this.key = br.readVarBytes();
    return this;
  }

  static fromRaw(data) {
    return new ECSignPacket().fromRaw(data);
  }
}

/**
 * ECSignResultPacket
 */

class ECSignResultPacket extends Packet {
  constructor(sig) {
    super();
    this.cmd = packetTypes.ECSIGNRESULT;
    this.sig = sig;
  }

  getSize() {
    return encoding.sizeVarBytes(this.sig);
  }

  toWriter(bw) {
    bw.writeVarBytes(this.sig);
    return bw;
  }

  fromRaw(data) {
    const br = bio.read(data, true);
    this.sig = br.readVarBytes();
    return this;
  }

  static fromRaw(data) {
    return new ECSignResultPacket().fromRaw(data);
  }
}

/**
 * MinePacket
 */

class MinePacket extends Packet {
  constructor(data, target, min, max) {
    super();
    this.cmd = packetTypes.MINE;
    this.data = data || null;
    this.target = target || null;
    this.min = min != null ? min : -1;
    this.max = max != null ? max : -1;
  }

  getSize() {
    return 120;
  }

  toWriter(bw) {
    bw.writeBytes(this.data);
    bw.writeBytes(this.target);
    bw.writeU32(this.min);
    bw.writeU32(this.max);
    return bw;
  }

  fromRaw(data) {
    const br = bio.read(data, true);
    this.data = br.readBytes(80);
    this.target = br.readBytes(32);
    this.min = br.readU32();
    this.max = br.readU32();
    return this;
  }

  static fromRaw(data) {
    return new MinePacket().fromRaw(data);
  }
}

/**
 * MineResultPacket
 */

class MineResultPacket extends Packet {
  constructor(nonce) {
    super();
    this.cmd = packetTypes.MINERESULT;
    this.nonce = nonce != null ? nonce : -1;
  }

  getSize() {
    return 5;
  }

  toWriter(bw) {
    bw.writeU8(this.nonce !== -1 ? 1 : 0);
    bw.writeU32(this.nonce);
    return bw;
  }

  fromRaw(data) {
    const br = bio.read(data, true);
    this.nonce = -1;
    if (br.readU8() === 1)
      this.nonce = br.readU32();
    return this;
  }

  static fromRaw(data) {
    return new MineResultPacket().fromRaw(data);
  }
}

/**
 * ScryptPacket
 */

class ScryptPacket extends Packet {
  constructor(passwd, salt, N, r, p, len) {
    super();
    this.cmd = packetTypes.SCRYPT;
    this.passwd = passwd || null;
    this.salt = salt || null;
    this.N = N != null ? N : -1;
    this.r = r != null ? r : -1;
    this.p = p != null ? p : -1;
    this.len = len != null ? len : -1;
  }

  getSize() {
    let size = 0;
    size += encoding.sizeVarBytes(this.passwd);
    size += encoding.sizeVarBytes(this.salt);
    size += 16;
    return size;
  }

  toWriter(bw) {
    bw.writeVarBytes(this.passwd);
    bw.writeVarBytes(this.salt);
    bw.writeU32(this.N);
    bw.writeU32(this.r);
    bw.writeU32(this.p);
    bw.writeU32(this.len);
    return bw;
  }

  fromRaw(data) {
    const br = bio.read(data, true);
    this.passwd = br.readVarBytes();
    this.salt = br.readVarBytes();
    this.N = br.readU32();
    this.r = br.readU32();
    this.p = br.readU32();
    this.len = br.readU32();
    return this;
  }

  static fromRaw(data) {
    return new ScryptPacket().fromRaw(data);
  }
}

/**
 * ScryptResultPacket
 */

class ScryptResultPacket extends Packet {
  constructor(key) {
    super();
    this.cmd = packetTypes.SCRYPTRESULT;
    this.key = key || null;
  }

  getSize() {
    return encoding.sizeVarBytes(this.key);
  }

  toWriter(bw) {
    bw.writeVarBytes(this.key);
    return bw;
  }

  fromRaw(data) {
    const br = bio.read(data, true);
    this.key = br.readVarBytes();
    return this;
  }

  static fromRaw(data) {
    return new ScryptResultPacket().fromRaw(data);
  }
}

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
