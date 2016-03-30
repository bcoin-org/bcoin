/**
 * script.js - script interpreter for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var utils = require('./utils');
var assert = utils.assert;
var BufferWriter = require('./writer');
var opcodes = constants.opcodes;
var STACK_TRUE = new Buffer([1]);
var STACK_FALSE = new Buffer([]);
var STACK_NEGATE = new Buffer([0xff]);

function Witness(items) {
  if (items instanceof Witness)
    return items;

  if (!(this instanceof Witness))
    return new Witness(items);

  if (!items)
    items = [];

  if (items.items)
    items = items.items;

  this.items = items || [];

  this.redeem = null;
}

Witness.prototype.inspect = function inspect() {
  return Script.format(this.items);
};

Witness.prototype.clone = function clone() {
  return new Witness(this.items.slice());
};

Witness.prototype.toStack = function toStack() {
  return new Stack(this.items.slice());
};

Witness.prototype.getInputType = function getInputType(prev) {
  return Script.getInputType(this.items, prev, true);
};

Witness.prototype.getInputAddress = function getInputAddress(prev) {
  return Script.getInputAddress(this.items, prev, true);
};

Witness.prototype.getInputHash = function getInputHash(prev) {
  return Script.getInputHash(this.items, prev, true);
};

Witness.prototype.isPubkeyInput = function isPubkeyInput(key) {
  return Script.isPubkeyInput(this.items, key);
};

Witness.prototype.isPubkeyhashInput = function isPubkeyhashInput(hash) {
  return Script.isPubkeyhashInput(this.items, hash);
};

Witness.prototype.isMultisigInput = function isMultisigInput(keys) {
  return Script.isMultisigInput(this.items, keys, true);
};

Witness.prototype.isScripthashInput = function isScripthashInput(redeem) {
  return Script.isScripthashInput(this.items, redeem, true);
};

Witness.prototype.isNonstandardInput = function isNonstandardInput(prev) {
  return Script.isNonstandardInput(this.items, prev, true);
};

Witness.prototype.getRedeem = function getRedeem() {
  if (!this.redeem)
    this.redeem = Script.getRedeem(this.items);

  return this.redeem;
};

Witness.fromString = function fromString(items) {
  var i, op, symbol;

  items = items.trim().split(/\s+/);

  for (i = 0; i < items.length; i++) {
    op = items[i].toLowerCase();

    if (op.indexOf('op_') === 0)
      op = op.slice(3);

    if (op === '-1' || op === '1negate') {
      op = STACK_NEGATE;
    } else if (op === '0' || op === 'false') {
      op = STACK_FALSE;
    } else if (op === 'true') {
      op = STACK_TRUE;
    } else if (+op >= 1 && +op <= 16) {
      op = new Buffer([+op]);
    } else {
      symbol = 'OP_' + op.toUpperCase();
      if (opcodes[symbol] == null) {
        if (op[0] === '[')
          op = op.slice(1, -1);
        if (op.indexOf('0x') === 0)
          op = op.substring(2);
        assert(utils.isHex(op), 'Non-stack item in witness string.');
        op = new Buffer(op, 'hex');
      } else {
        assert(false, 'Non-stack item in witness string.');
      }
    }

    items[i] = op;
  }

  return new Witness(items);
};

Witness.fromSymbolic = function fromSymbolic(items) {
  var code = new Array(items.length);
  var i, op, symbol;

  for (i = 0; i < items.length; i++) {
    op = items[i];

    if (Buffer.isBuffer(op)) {
      code[i] = op;
      continue;
    }

    op = (op + '').toLowerCase();
    if (op.indexOf('op_') === 0)
      op = op.slice(3);

    if (+op === -1)
      op = STACK_NEGATE;
    else if (+op === 0 || op === 'false')
      op = STACK_FALSE;
    else if (+op === 1 || op === 'true')
      op = STACK_TRUE;
    else if (+op >= 1 && +op <= 16)
      op = new Buffer([+op]);
    else
      assert(false, 'Non-stack item in witness string.');

    code[i] = op;
  }

  return new Witness(code);
};

Witness.isWitness = function isWitness(obj) {
  return obj
    && Array.isArray(obj.items)
    && typeof obj.toStack === 'function';
};

function Stack(items) {
  this.items = items || [];
  this.alt = [];
}

Stack.prototype.inspect = function inspect() {
  return Script.format(this.items);
};

Stack.prototype.__defineGetter__('length', function() {
  return this.items.length;
});

Stack.prototype.__defineSetter__('length', function(value) {
  return this.items.length = value;
});

Stack.prototype.getRedeem = function getRedeem(pop) {
  var redeem = Script.getRedeem(this.items);
  if (!redeem)
    return;

  if (pop !== false)
    this.pop();

  return redeem;
};

Stack.prototype.clone = function clone() {
  var stack = new Stack(this.items.slice());
  stack.alt = this.alt.slice();
  return stack;
};

Stack.prototype.getSize = function getSize() {
  return this.items.length + this.alt.length;
};

Stack.prototype.push = function push(item) {
  return this.items.push(item);
};

Stack.prototype.unshift = function unshift(item) {
  return this.items.unshift(item);
};

Stack.prototype.slice = function slice(start, end) {
  return this.items.slice(start, end);
};

Stack.prototype.splice = function splice(i, remove, insert) {
  return this.items.splice(i, remove, insert);
};

Stack.prototype.pop = function pop() {
  return this.items.pop();
};

Stack.prototype.shift = function shift() {
  return this.items.shift();
};

Stack.prototype.get = function get(i) {
  return this.items[i];
};

Stack.prototype.top = function top(i) {
  return this.items[this.items.length + i];
};

Stack.prototype.set = function set(i, value) {
  return this.items[i] = value;
};

Stack.prototype._swap = function _swap(i1, i2) {
  var v1, v2;

  i1 = this.items.length + i1;
  i2 = this.items.length + i2;

  v1 = this.items[i1];
  v2 = this.items[i2];

  this.items[i1] = v2;
  this.items[i2] = v1;
};

Stack.prototype.toalt = function toalt() {
  if (this.length === 0)
    throw new ScriptError('Stack too small.', opcodes.OP_TOALTSTACK);

  this.alt.push(this.pop());
};

Stack.prototype.fromalt = function fromalt() {
  if (this.alt.length === 0)
    throw new ScriptError('Stack too small.', opcodes.OP_FROMALTSTACK);

  this.push(this.alt.pop());
};

Stack.prototype.ifdup = function ifdup() {
  if (this.length === 0)
    throw new ScriptError('Stack too small.', opcodes.OP_IFDUP);

  if (Script.bool(this.top(-1)))
    this.push(Script.array(this.top(-1)));
};

Stack.prototype.depth = function depth() {
  this.push(Script.array(this.length));
};

Stack.prototype.drop = function drop() {
  if (this.length === 0)
    throw new ScriptError('Stack too small.', opcodes.OP_DROP);

  this.pop();
};

Stack.prototype.dup = function dup() {
  if (this.length === 0)
    throw new ScriptError('Stack too small.', opcodes.OP_DUP);

  this.push(this.top(-1));
};

Stack.prototype.nip = function nip() {
  if (this.length < 2)
    throw new ScriptError('Stack too small.', opcodes.OP_NIP);

  this.splice(this.length - 2, 1);
};

Stack.prototype.over = function over() {
  if (this.length < 2)
    throw new ScriptError('Stack too small.', opcodes.OP_OVER);

  this.push(this.top(-2));
};

Stack.prototype.pick = function pick(flags) {
  return this._pickroll(opcodes.OP_PICK, flags);
};

Stack.prototype.roll = function roll(flags) {
  return this._pickroll(opcodes.OP_ROLL, flags);
};

Stack.prototype._pickroll = function pickroll(op, flags) {
  var val, n;

  if (this.length < 2)
    throw new ScriptError('Stack too small.', op);

  val = this.pop();
  n = Script.num(val, flags).toNumber();

  if (n <= 0 || n > this.length)
    throw new ScriptError('Bad value.', op);

  val = this.get(-n - 1);

  if (op === opcodes.OP_ROLL)
    this.splice(this.length - n - 1, 1);

  this.push(val);
};

Stack.prototype.rot = function rot() {
  if (this.length < 3)
    throw new ScriptError('Stack too small.', opcodes.OP_ROT);

  this._swap(-3, -2);
  this._swap(-2, -1);
};

Stack.prototype.swap = function swap() {
  if (this.length < 2)
    throw new ScriptError('Stack too small.', opcodes.OP_SWAP);

  this._swap(-2, -1);
};

Stack.prototype.tuck = function tuck() {
  if (this.length < 2)
    throw new ScriptError('Stack too small.', opcodes.OP_TUCK);

  this.splice(this.length - 2, 0, this.top(-1));
};

Stack.prototype.drop2 = function drop2() {
  if (this.length < 2)
    throw new ScriptError('Stack too small.', opcodes.OP_2DROP);

  this.pop();
  this.pop();
};

Stack.prototype.dup2 = function dup2() {
  var v1, v2;

  if (this.length < 2)
    throw new ScriptError('Stack too small.', opcodes.OP_2DUP);

  v1 = this.top(-2);
  v2 = this.top(-1);

  this.push(v1);
  this.push(v2);
};

Stack.prototype.dup3 = function dup3() {
  var v1, v2, v3;

  if (this.length < 3)
    throw new ScriptError('Stack too small.', opcodes.OP_3DUP);

  v1 = this.top(-3);
  v2 = this.top(-2);
  v3 = this.top(-1);

  this.push(v1);
  this.push(v2);
  this.push(v3);
};

Stack.prototype.over2 = function over2() {
  var v1, v2;

  if (this.length < 4)
    throw new ScriptError('Stack too small.', opcodes.OP_2OVER);

  v1 = this.top(-4);
  v2 = this.top(-3);

  this.push(v1);
  this.push(v2);
};

Stack.prototype.rot2 = function rot2() {
  var v1, v2;

  if (this.length < 6)
    throw new ScriptError('Stack too small.', opcodes.OP_2ROT);

  v1 = this.top(-6);
  v2 = this.top(-5);

  this.splice(this.length - 6, 2);
  this.push(v1);
  this.push(v2);
};

Stack.prototype.swap2 = function swap2() {
  this._swap(-4, -2);
  this._swap(-3, -1);
};

Stack.prototype.size = function size() {
  if (this.length < 1)
    throw new ScriptError('Stack too small.', opcodes.OP_SIZE);

  this.push(Script.array(this.top(-1).length));
};

Stack.isStack = function isStack(obj) {
  return obj && Array.isArray(obj.alt) && typeof obj.swap2 === 'function';
};

/**
 * Script
 */

function Script(code) {
  if (code instanceof Script)
    return code;

  if (!(this instanceof Script))
    return new Script(code);

  if (Buffer.isBuffer(code)) {
    this.raw = code;
    this.code = Script.decode(code);
  } else {
    if (!code)
      code = [];
    if (code.code) {
      this.raw = code.raw || null;
      this.code = code.code;
      if (!this.code)
        this.code = Script.decode(this.raw);
    } else {
      assert(Array.isArray(code));
      this.raw = null;
      this.code = code;
    }
  }

  this.redeem = null;
}

Script.prototype.clone = function clone() {
  return new Script(this.code.slice());
};

Script.prototype.inspect = function inspect() {
  return Script.format(this.code);
};

Script.prototype.encode = function encode() {
  if (!this.raw)
    this.raw = Script.encode(this.code);
  return this.raw;
};

Script.prototype.getSubscript = function getSubscript(lastSep) {
  var res = [];
  var i;

  if (lastSep == null)
    lastSep = -1;

  assert(lastSep <= 0 || this.code[lastSep] === opcodes.OP_CODESEPARATOR);

  for (i = lastSep + 1; i < this.code.length; i++) {
    if (this.code[i] !== opcodes.OP_CODESEPARATOR)
      res.push(this.code[i]);
  }

  // Optimization: avoid re-rendering
  // of the script in 99.9% of cases.
  if (res.length === this.code.length) {
    res = this.clone();
    res.raw = this.raw;
    return res;
  }

  return new Script(res);
};

Script.prototype._next = function _next(to, code, ip) {
  var depth = 0;
  var op;

  while (code[ip]) {
    op = code[ip];

    if (op === opcodes.OP_IF || op === opcodes.OP_NOTIF)
      depth++;
    else if (op === opcodes.OP_ELSE)
      depth--;
    else if (op === opcodes.OP_ENDIF)
      depth--;

    if (depth < 0)
      break;

    if (depth === 0 && op === to)
      return ip;

    if (op === opcodes.OP_ELSE)
      depth++;

    ip++;
  }

  return -1;
};

Script.prototype.execute = function execute(stack, flags, tx, index, version) {
  try {
    return this.interpret(stack, flags, tx, index, version);
  } catch (e) {
    if (e.type === 'ScriptError') {
      utils.debug('Script error: %s.', e.message);
    } else {
      utils.debug('Script interpreter threw:');
      utils.debug(e.stack + '');
    }
    return false;
  }
};

Script.prototype.interpret = function interpret(stack, flags, tx, index, version) {
  var code = this.code.slice();
  var ip = 0;
  var lastSep = -1;
  var op, val;
  var if_, else_, endif;
  var n, n1, n2, n3;
  var res;
  var key, sig, type, subscript, hash;
  var keys, i, j, m;
  var succ;
  var locktime;

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (code.length > constants.script.maxOps)
    throw new ScriptError('Script too large.');

  for (ip = 0; ip < code.length; ip++) {
    op = code[ip];

    if (Buffer.isBuffer(op)) {
      if (op.length > constants.script.maxPush)
        throw new ScriptError('Push data too large.', op, ip);
      if (!Script.checkPush(op, flags))
        throw new ScriptError('Push verification failed.', op, ip);
      stack.push(op);
      continue;
    }

    if (op === opcodes.OP_0) {
      stack.push(STACK_FALSE);
      continue;
    }

    if (op >= opcodes.OP_1 && op <= opcodes.OP_16) {
      stack.push(new Buffer([op - 0x50]));
      continue;
    }

    switch (op) {
      case opcodes.OP_NOP:
      case opcodes.OP_NOP1:
      case opcodes.OP_NOP4:
      case opcodes.OP_NOP5:
      case opcodes.OP_NOP6:
      case opcodes.OP_NOP7:
      case opcodes.OP_NOP8:
      case opcodes.OP_NOP9:
      case opcodes.OP_NOP10: {
        if (flags & constants.flags.VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
          throw new ScriptError('Upgradable NOP used.', op, ip);
        break;
      }
      case opcodes.OP_1NEGATE: {
        stack.push(STACK_NEGATE);
        break;
      }
      case opcodes.OP_IF:
      case opcodes.OP_NOTIF: {
        if (stack.length < 1)
          throw new ScriptError('Stack too small.', op, ip);
        val = Script.bool(stack.pop());
        if (op === opcodes.OP_NOTIF)
          val = !val;
        if_ = ip;
        else_ = this._next(opcodes.OP_ELSE, code, ip);
        endif = this._next(opcodes.OP_ENDIF, code, ip);
        // Splice out the statement blocks we don't need
        if (val) {
          if (endif === -1)
            throw new ScriptError('Missing endif.', op, ip);
          if (else_ === -1) {
            code.splice(endif, 1);
            code.splice(if_, 1);
          } else {
            code.splice(else_, (endif - else_) + 1);
            code.splice(if_, 1);
          }
        } else {
          if (endif === -1)
            throw new ScriptError('Missing endif.', op, ip);
          if (else_ === -1) {
            code.splice(if_, (endif - if_) + 1);
          } else {
            code.splice(endif, 1);
            code.splice(if_, (else_ - if_) + 1);
          }
        }
        // Subtract one since we removed the if/notif opcode
        ip--;
        break;
      }
      case opcodes.OP_ELSE: {
        throw new ScriptError('Unexpected else.', op, ip);
      }
      case opcodes.OP_ENDIF: {
        throw new ScriptError('Unexpected endif.', op, ip);
      }
      case opcodes.OP_VERIFY: {
        if (stack.length === 0)
          throw new ScriptError('Stack too small.', op, ip);
        if (!Script.bool(stack.pop()))
          throw new ScriptError('Verification failed.', op, ip);
        break;
      }
      case opcodes.OP_RETURN: {
        throw new ScriptError('Script returned.', op, ip);
      }
      case opcodes.OP_TOALTSTACK: {
        stack.toalt();
        break;
      }
      case opcodes.OP_FROMALTSTACK: {
        stack.fromalt();
        break;
      }
      case opcodes.OP_IFDUP: {
        stack.ifdup();
        break;
      }
      case opcodes.OP_DEPTH: {
        stack.depth();
        break;
      }
      case opcodes.OP_DROP: {
        stack.drop();
        break;
      }
      case opcodes.OP_DUP: {
        stack.dup();
        break;
      }
      case opcodes.OP_NIP: {
        stack.nip();
        break;
      }
      case opcodes.OP_OVER: {
        stack.over();
        break;
      }
      case opcodes.OP_PICK: {
        stack.pick(flags);
        break;
      }
      case opcodes.OP_ROLL: {
        stack.roll(flags);
        break;
      }
      case opcodes.OP_ROT: {
        stack.rot();
        break;
      }
      case opcodes.OP_SWAP: {
        stack.swap();
        break;
      }
      case opcodes.OP_TUCK: {
        stack.tuck();
        break;
      }
      case opcodes.OP_2DROP: {
        stack.drop2();
        break;
      }
      case opcodes.OP_2DUP: {
        stack.dup2();
        break;
      }
      case opcodes.OP_3DUP: {
        stack.dup3();
        break;
      }
      case opcodes.OP_2OVER: {
        stack.over2();
        break;
      }
      case opcodes.OP_2ROT: {
        stack.rot2();
        break;
      }
      case opcodes.OP_2SWAP: {
        stack.swap2();
        break;
      }
      case opcodes.OP_SIZE: {
        stack.size();
        break;
      }
      case opcodes.OP_1ADD:
      case opcodes.OP_1SUB:
      case opcodes.OP_NEGATE:
      case opcodes.OP_ABS:
      case opcodes.OP_NOT:
      case opcodes.OP_0NOTEQUAL: {
        if (stack.length < 1)
          throw new ScriptError('Stack too small.', op, ip);
        n = Script.num(stack.pop(), flags);
        switch (op) {
          case opcodes.OP_1ADD:
            n.iadd(1);
            break;
          case opcodes.OP_1SUB:
            n.isub(1);
            break;
          case opcodes.OP_NEGATE:
            n = n.neg();
            break;
          case opcodes.OP_ABS:
            if (n.cmpn(0) < 0)
              n.ineg();
            break;
          case opcodes.OP_NOT:
            n = n.cmpn(0) === 0;
            break;
          case opcodes.OP_0NOTEQUAL:
            n = n.cmpn(0) !== 0;
            break;
          default:
            return false;
        }
        if (typeof n === 'boolean')
          n = new bn(n ? 1 : 0, 'le');
        stack.push(Script.array(n));
        break;
      }
      case opcodes.OP_ADD:
      case opcodes.OP_SUB:
      case opcodes.OP_BOOLAND:
      case opcodes.OP_BOOLOR:
      case opcodes.OP_NUMEQUAL:
      case opcodes.OP_NUMEQUALVERIFY:
      case opcodes.OP_NUMNOTEQUAL:
      case opcodes.OP_LESSTHAN:
      case opcodes.OP_GREATERTHAN:
      case opcodes.OP_LESSTHANOREQUAL:
      case opcodes.OP_GREATERTHANOREQUAL:
      case opcodes.OP_MIN:
      case opcodes.OP_MAX: {
        switch (op) {
          case opcodes.OP_ADD:
          case opcodes.OP_SUB:
          case opcodes.OP_BOOLAND:
          case opcodes.OP_BOOLOR:
          case opcodes.OP_NUMEQUAL:
          case opcodes.OP_NUMEQUALVERIFY:
          case opcodes.OP_NUMNOTEQUAL:
          case opcodes.OP_LESSTHAN:
          case opcodes.OP_GREATERTHAN:
          case opcodes.OP_LESSTHANOREQUAL:
          case opcodes.OP_GREATERTHANOREQUAL:
          case opcodes.OP_MIN:
          case opcodes.OP_MAX:
            if (stack.length < 2)
              throw new ScriptError('Stack too small.', op, ip);
            n2 = Script.num(stack.pop(), flags);
            n1 = Script.num(stack.pop(), flags);
            n = new bn(0, 'le');
            switch (op) {
              case opcodes.OP_ADD:
                n = n1.add(n2);
                break;
              case opcodes.OP_SUB:
                n = n1.sub(n2);
                break;
              case opcodes.OP_BOOLAND:
                n = n1.cmpn(0) !== 0 && n2.cmpn(0) !== 0;
                break;
              case opcodes.OP_BOOLOR:
                n = n1.cmpn(0) !== 0 || n2.cmpn(0) !== 0;
                break;
              case opcodes.OP_NUMEQUAL:
                n = n1.cmp(n2) === 0;
                break;
              case opcodes.OP_NUMEQUALVERIFY:
                n = n1.cmp(n2) === 0;
                break;
              case opcodes.OP_NUMNOTEQUAL:
                n = n1.cmp(n2) !== 0;
                break;
              case opcodes.OP_LESSTHAN:
                n = n1.cmp(n2) < 0;
                break;
              case opcodes.OP_GREATERTHAN:
                n = n1.cmp(n2) > 0;
                break;
              case opcodes.OP_LESSTHANOREQUAL:
                n = n1.cmp(n2) <= 0;
                break;
              case opcodes.OP_GREATERTHANOREQUAL:
                n = n1.cmp(n2) >= 0;
                break;
              case opcodes.OP_MIN:
                n = n1.cmp(n2) < 0 ? n1 : n2;
                break;
              case opcodes.OP_MAX:
                n = n1.cmp(n2) > 0 ? n1 : n2;
                break;
              default:
                return false;
            }
            if (typeof n === 'boolean')
              n = new bn(n ? 1 : 0, 'le');
            res = Script.bool(n);
            if (op === opcodes.OP_NUMEQUALVERIFY) {
              if (!res)
                return false;
            } else {
              stack.push(Script.array(n));
            }
            break;
          case opcodes.OP_WITHIN:
            if (stack.length < 3)
              throw new ScriptError('Stack too small.', op, ip);
            n3 = Script.num(stack.pop(), flags);
            n2 = Script.num(stack.pop(), flags);
            n1 = Script.num(stack.pop(), flags);
            val = n2.cmp(n1) <= 0 && n1.cmp(n3) < 0;
            stack.push(val.cmpn(0) !== 0 ? STACK_TRUE : STACK_FALSE);
            break;
        }

        break;
      }
      case opcodes.OP_CODESEPARATOR: {
        lastSep = ip;
        break;
      }
      case opcodes.OP_RIPEMD160: {
        if (stack.length === 0)
          throw new ScriptError('Stack too small.', op, ip);
        stack.push(utils.ripemd160(stack.pop()));
        break;
      }
      case opcodes.OP_SHA1: {
        if (stack.length === 0)
          throw new ScriptError('Stack too small.', op, ip);
        stack.push(utils.sha1(stack.pop()));
        break;
      }
      case opcodes.OP_SHA256: {
        if (stack.length === 0)
          throw new ScriptError('Stack too small.', op, ip);
        stack.push(utils.sha256(stack.pop()));
        break;
      }
      case opcodes.OP_HASH256: {
        if (stack.length === 0)
          throw new ScriptError('Stack too small.', op, ip);
        stack.push(utils.dsha256(stack.pop()));
        break;
      }
      case opcodes.OP_HASH160: {
        if (stack.length === 0)
          throw new ScriptError('Stack too small.', op, ip);
        stack.push(utils.ripesha(stack.pop()));
        break;
      }
      case opcodes.OP_EQUALVERIFY:
      case opcodes.OP_EQUAL: {
        if (stack.length < 2)
          throw new ScriptError('Stack too small.', op, ip);
        res = utils.isEqual(stack.pop(), stack.pop());
        if (op === opcodes.OP_EQUALVERIFY) {
          if (!res)
            throw new ScriptError('Equal verification failed.', op, ip);
        } else {
          stack.push(res ? STACK_TRUE : STACK_FALSE);
        }
        break;
      }
      case opcodes.OP_CHECKSIGVERIFY:
      case opcodes.OP_CHECKSIG: {
        if (!tx)
          throw new ScriptError('No TX passed in.', op, ip);

        if (stack.length < 2)
          throw new ScriptError('Stack too small.', op, ip);

        key = stack.pop();
        sig = stack.pop();

        if (!Script.isValidKey(key, flags))
          throw new ScriptError('Key is not valid.', op, ip);

        if (!Script.isValidSignature(sig, flags))
          throw new ScriptError('Signature is not valid.', op, ip);

        type = sig[sig.length - 1];

        subscript = this.getSubscript(lastSep);
        subscript.removeData(sig);

        hash = tx.signatureHash(index, subscript, type, version);

        res = Script.checksig(hash, sig, key, flags);
        if (op === opcodes.OP_CHECKSIGVERIFY) {
          if (!res)
            throw new ScriptError('Signature verification failed.', op, ip);
        } else {
          stack.push(res ? STACK_TRUE : STACK_FALSE);
        }

        break;
      }
      case opcodes.OP_CHECKMULTISIGVERIFY:
      case opcodes.OP_CHECKMULTISIG: {
        if (!tx)
          throw new ScriptError('No TX passed in.', op, ip);

        if (stack.length < 4)
          throw new ScriptError('Stack too small.', op, ip);

        n = Script.num(stack.pop(), flags).toNumber();

        if (!(n >= 1 && n <= 15))
          throw new ScriptError('`n` is out of bounds.', op, ip);

        if (stack.length < n + 1)
          throw new ScriptError('`n` exceeds stack size.', op, ip);

        keys = [];
        for (i = 0; i < n; i++) {
          key = stack.pop();

          if (!Script.isValidKey(key, flags))
            throw new ScriptError('Key is not valid.', op, ip);

          keys.push(key);
        }

        m = Script.num(stack.pop(), flags).toNumber();

        if (!(m >= 1 && m <= n))
          throw new ScriptError('`m` is out of bounds.', op, ip);

        if (stack.length < m)
          throw new ScriptError('`m` exceeds stack size.', op, ip);

        subscript = this.getSubscript(lastSep);

        for (i = 0; i < m; i++) {
          sig = stack.get(stack.length - 1 - i);
          subscript.removeData(sig);
        }

        succ = 0;
        for (i = 0, j = 0; i < m; i++) {
          sig = stack.pop();

          if (!Script.isValidSignature(sig, flags))
            throw new ScriptError('Signature is not valid.', op, ip);

          type = sig[sig.length - 1];

          hash = tx.signatureHash(index, subscript, type, version);

          res = false;
          for (; !res && j < n; j++)
            res = Script.checksig(hash, sig, keys[j], flags);

          if (res)
            succ++;
        }

        if (stack.length < 1)
          throw new ScriptError('No dummy present.', op, ip);

        val = stack.pop();

        if (flags & constants.flags.VERIFY_NULLDUMMY) {
          if (!Script.isDummy(val))
            throw new ScriptError('Dummy did not verify.', op, ip);
        }

        res = succ >= m;

        if (op === opcodes.OP_CHECKMULTISIGVERIFY) {
          if (!res)
            throw new ScriptError('Signature verification failed.', op, ip);
        } else {
          stack.push(res ? STACK_TRUE : STACK_FALSE);
        }

        break;
      }
      case opcodes.OP_CHECKLOCKTIMEVERIFY: {
        // OP_CHECKLOCKTIMEVERIFY = OP_NOP2
        if (!(flags & constants.flags.VERIFY_CHECKLOCKTIMEVERIFY)) {
          if (flags & constants.flags.VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
            throw new ScriptError('Upgradable NOP used.', op, ip);
          break;
        }

        if (!tx)
          throw new ScriptError('No TX passed in.', op, ip);

        if (stack.length === 0)
          throw new ScriptError('Stack too small.', op, ip);

        // NOTE: Bitcoind accepts 5 byte locktimes.
        // 4 byte locktimes become useless in 2106.
        locktime = Script.num(stack.top(-1), flags, 5).toNumber();

        if (locktime < 0)
          throw new ScriptError('Negative locktime.', op, ip);

        if (!Script.checkLocktime(locktime, tx, index))
          throw new ScriptError('Locktime verification failed.', op, ip);

        break;
      }
      case opcodes.OP_CHECKSEQUENCEVERIFY: {
        // OP_CHECKSEQUENCEVERIFY = OP_NOP3
        if (!(flags & constants.flags.VERIFY_CHECKSEQUENCEVERIFY)) {
          if (flags & constants.flags.VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
            throw new ScriptError('Upgradable NOP used.', op, ip);
          break;
        }

        if (!tx)
          throw new ScriptError('No TX passed in.', op, ip);

        if (stack.length === 0)
          throw new ScriptError('Stack too small.', op, ip);

        // NOTE: Bitcoind accepts 5 byte locktimes.
        // 4 byte locktimes become useless in 2106
        // (will people still be using bcoin then?).
        locktime = Script.num(stack.top(-1), flags, 4).toNumber();

        if (locktime < 0)
          throw new ScriptError('Negative sequence.', op, ip);

        if ((locktime & constants.sequenceLocktimeDisableFlag) !== 0)
          break;

        if (!Script.checkSequence(locktime, tx, index))
          throw new ScriptError('Sequence verification failed.', op, ip);

        break;
      }
      default: {
        throw new ScriptError('Unknown opcode.', op, ip);
      }
    }
  }

  if (stack.getSize() > constants.script.maxStack)
    throw new ScriptError('Stack size too large.', op, ip);

  return true;
};

Script.checkLocktime = function checkLocktime(locktime, tx, i) {
  var threshold = constants.locktimeThreshold;

  if (!(
    (tx.locktime < threshold && locktime < threshold)
    || (tx.locktime >= threshold && locktime >= threshold)
  )) {
    return false;
  }

  if (locktime > tx.locktime)
    return false;

  if (tx.inputs[i].sequence === 0xffffffff)
    return false;

  return true;
};

Script.checkSequence = function checkSequence(sequence, tx, i) {
  var txSequence = tx.inputs[i].sequence;
  var locktimeMask, txSequenceMasked, sequenceMasked;

  if ((tx.version >>> 0) < 2)
    return false;

  if (txSequence & constants.sequenceLocktimeDisableFlag)
    return false;

  locktimeMask = constants.sequenceLocktimeTypeFlag
    | constants.sequenceLocktimeMask;
  txSequenceMasked = txSequence & locktimeMask;
  sequenceMasked = sequence & locktimeMask;

  if (!(
    (txSequenceMasked < constants.sequenceLocktimeTypeFlag
    && sequenceMasked < constants.sequenceLocktimeTypeFlag)
    || (txSequenceMasked >= constants.sequenceLocktimeTypeFlag
    && sequenceMasked >= constants.sequenceLocktimeTypeFlag)
  )) {
    return false;
  }

  if (sequenceMasked > txSequenceMasked)
    return false;

  return true;
};

Script.bool = function bool(value) {
  var i;

  // Should never happen:
  // if (typeof value === 'boolean')
  //   return value;

  // Should never happen:
  // if (utils.isFinite(value))
  //   return value !== 0;

  if (bn.isBN(value))
    return value.cmpn(0) !== 0;

  assert(Buffer.isBuffer(value));

  for (i = 0; i < value.length; i++) {
    if (value[i] !== 0) {
      // Cannot be negative zero
      if (i === value.length - 1 && value[i] === 0x80)
        return false;
      return true;
    }
  }

  return false;
};

Script.num = function num(value, flags, size) {
  assert(Buffer.isBuffer(value));

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (size == null)
    size = 4;

  if (value.length > size)
    throw new ScriptError('Script number overflow.');

  if ((flags & constants.flags.VERIFY_MINIMALDATA) && value.length > 0) {
    // If the low bits on the last byte are unset,
    // fail if the value's second to last byte does
    // not have the high bit set. A number can't
    // justify having the last byte's low bits unset
    // unless they ran out of space for the sign bit
    // in the second to last bit. We also fail on [0]
    // to avoid negative zero (also avoids positive
    // zero).
    if (!(value[value.length - 1] & 0x7f)) {
      if (value.length === 1 || !(value[value.length - 2] & 0x80))
        throw new ScriptError('Non-minimally encoded Script number.');
    }
  }

  // If we are signed, do (~num + 1) to get
  // the positive counterpart and set bn's
  // negative flag.
  if (value[value.length - 1] & 0x80) {
    if (utils.isNegZero(value, 'le')) {
      value = new bn(0, 'le');
    } else {
      value = new bn(value, 'le');
      value = value.notn(value.bitLength()).addn(1).neg();
    }
  } else {
    value = new bn(value, 'le');
  }

  return value;
};

Script.array = function(value) {
  if (Buffer.isBuffer(value))
    return value;

  if (utils.isFinite(value))
    value = new bn(value, 'le');

  assert(bn.isBN(value));

  // Convert the number to the
  // negative byte representation.
  if (value.isNeg()) {
    if (value.cmpn(0) === 0)
      value = new bn(0);
    else
      value = value.neg().notn(value.bitLength()).subn(1);
  }

  if (value.cmpn(0) === 0)
    return STACK_FALSE;

  return value.toBuffer('le');
};

Script.prototype.removeData = function removeData(data) {
  for (var i = this.code.length - 1; i >= 0; i--) {
    if (utils.isEqual(this.code[i], data))
      this.code.splice(i, 1);
  }
};

Script.checkPush = function checkPush(value, flags) {
  var pushdata = value.pushdata;

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (!(flags & constants.flags.VERIFY_MINIMALDATA))
    return true;

  if (!pushdata)
    return true;

  if (value.length === 1 && value[0] === 0)
    return false;

  if (value.length === 1 && value[0] >= 1 && value[0] <= 16)
    return false;

  if (value.length === 1 && value[0] === 0xff)
    return false;

  if (value.length <= 75)
    return pushdata.opcode == null && pushdata.size === value.length;

  if (value.length <= 255)
    return pushdata.opcode === opcodes.OP_PUSHDATA1;

  if (value.length <= 65535)
    return pushdata.opcode === opcodes.OP_PUSHDATA2;

  return true;
};

Script.isCode = function isCode(buf) {
  var i, op, code;

  if (!buf)
    return false;

  if (!Buffer.isBuffer(buf))
    return false;

  code = Script.decode(buf);

  for (i = 0; i < code.length; i++) {
    op = code[i];
    if (Buffer.isBuffer(op))
      continue;
    if (constants.opcodesByVal[op] == null)
      return false;
  }

  return true;
};

Script.prototype.concat = function concat(scripts) {
  scripts.unshift(this);
  return Script.concat(scripts);
};

Script.createPubkey = function createPubkey(key) {
  return new Script([key, opcodes.OP_CHECKSIG]);
};

Script.createPubkeyhash = function createPubkeyhash(hash) {
  return new Script([
    opcodes.OP_DUP,
    opcodes.OP_HASH160,
    hash,
    opcodes.OP_EQUALVERIFY,
    opcodes.OP_CHECKSIG
  ]);
};

Script.createMultisig = function createMultisig(keys, m, n) {
  var code = [];
  var i;

  assert(keys.length === n, '`n` keys are required for multisig.');
  assert(m >= 1 && m <= n);
  assert(n >= 1 && n <= 15);

  keys = utils.sortKeys(keys);

  code.push(m + 0x50);

  for (i = 0; i < keys.length; i++)
    code.push(keys[i]);

  code.push(n + 0x50);
  code.push(opcodes.OP_CHECKMULTISIG);

  return new Script(code);
};

Script.createScripthash = function createScripthash(hash) {
  return new Script([
    opcodes.OP_HASH160,
    hash,
    opcodes.OP_EQUAL
  ]);
};

Script.createNulldata = function createNulldata(flags) {
  return new Script([
    opcodes.OP_RETURN,
    flags
  ]);
};

Script.createWitnessProgram = function createWitnessProgram(version, data) {
  assert(typeof version === 'number' && version >= 0 && version <= 16);
  assert(Buffer.isBuffer(data));
  assert(data.length === 20 || data.length === 32);
  return new Script([version === 0 ? 0 : version + 0x50, data]);
};

Script.prototype.getRedeem = function getRedeem() {
  if (!this.redeem)
    this.redeem = Script.getRedeem(this.code);

  return this.redeem;
};

Script.getRedeem = function getRedeem(code) {
  var redeem = code[code.length - 1];

  if (!Buffer.isBuffer(redeem))
    return;

  return new Script(redeem);
};

Script.prototype.getType = function getType() {
  if (this.isCommitment())
    return 'commitment';

  if (this.isWitnessProgram()) {
    if (this.isWitnessPubkeyhash())
      return 'witnesspubkeyhash';
    if (this.isWitnessScripthash())
      return 'witnessscripthash';
    return 'unknown';
  }

  return (this.isPubkey() && 'pubkey')
    || (this.isPubkeyhash() && 'pubkeyhash')
    || (this.isMultisig() && 'multisig')
    || (this.isScripthash() && 'scripthash')
    || (this.isNulldata() && 'nulldata')
    || 'unknown';
};

Script.prototype.isNonstandard = function isNonstandard() {
  return this.getType() === 'unknown';
};

Script.prototype.isStandard = function isStandard() {
  var type = this.getType();
  var m, n;

  if (type === 'multisig') {
    m = Script.getSmall(this.code[0]);
    n = Script.getSmall(this.code[this.code.length - 2]);

    if (n < 1 || n > 3)
      return false;

    if (m < 1 || m > n)
      return false;
  } else if (type === 'nulldata') {
    if (this.getSize() > constants.script.maxOpReturnBytes)
      return false;
  }

  return type !== 'unknown';
};

Script.prototype.isStandardProgram = function isStandardProgram(witness, flags) {
  var program, witnessScript, i;

  assert((flags & constants.flags.VERIFY_WITNESS) !== 0);
  assert(this.isWitnessProgram());

  program = this.getWitnessProgram();

  if (!program.type)
    return false;

  if (program.version > 0) {
    if (flags & constants.flags.VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
      return false;
    return true;
  }

  if (program.type === 'witnesspubkeyhash') {
    if (witness.items.length !== 2)
      return false;
  } else if (program.type === 'witnessscripthash') {
    if (witness.items.length === 0)
      return false;
  } else {
    assert(false);
  }

  for (i = 0; i < witness.items.length; i++) {
    if (witness.items[i].length > constants.script.maxSize)
      return false;
  }

  return true;
};

Script.prototype.getSize = function getSize() {
  return this.encode().length;
};

Script.prototype.getInputAddress = function getInputAddress(prev) {
  return Script.getInputAddress(this.code, prev, false);
};

Script.getInputAddress = function getInputAddress(code, prev, isWitness) {
  if (prev)
    return prev.getAddress();

  if (Script.isPubkeyInput(code))
    return;

  if (Script.isPubkeyhashInput(code)) {
    return bcoin.address.compileData(code[1],
      isWitness ? 'witnesspubkeyhash' : 'pubkeyhash');
  }

  if (Script.isMultisigInput(code, null, isWitness))
    return;

  if (Script.isScripthashInput(code, null, isWitness)) {
    return bcoin.address.compileData(code[code.length - 1],
      isWitness ? 'witnessscripthash' : 'scripthash');
  }
};

Script.prototype.getAddress = function getAddress() {
  var program;

  if (this.isWitnessProgram()) {
    program = this.getWitnessProgram();
    if (!program.type || program.type === 'unknown')
      return;
    return bcoin.address.compileHash(program.data, program.type);
  }

  // Convert p2pk to p2pkh addresses
  if (this.isPubkey())
    return bcoin.address.compileData(this.code[0], 'pubkeyhash');

  if (this.isPubkeyhash())
    return bcoin.address.compileHash(this.code[2], 'pubkeyhash');

  // Convert bare multisig to scripthash address
  if (this.isMultisig())
    return bcoin.address.compileData(this.encode(), 'scripthash');

  if (this.isScripthash())
    return bcoin.address.compileHash(this.code[1], 'scripthash');
};

Script.prototype.getInputHash = function getInputHash(prev) {
  return Script.getInputHash(this.code, prev, false);
};

Script.getInputHash = function getInputHash(prev, isWitness) {
  if (prev)
    return prev.getHash();

  if (Script.isPubkeyInput(code))
    return;

  if (Script.isPubkeyhashInput(code))
    return utils.ripesha(code[1]);

  if (Script.isMultisigInput(code, null, isWitness))
    return;

  if (Script.isScripthashInput(code, null, isWitness)) {
    return isWitness
      ? utils.sha256(code[code.length - 1])
      : utils.ripesha(code[code.length - 1]);
  }
};

Script.prototype.getHash = function getHash() {
  var program;

  if (this.isWitnessProgram()) {
    program = this.getWitnessProgram();
    if (!program.type || program.type === 'unknown')
      return;
    return program.data;
  }

  if (this.isPubkey())
    return utils.ripesha(this.code[0]);

  if (this.isPubkeyhash())
    return this.code[2];

  if (this.isMultisig())
    return utils.ripesha(this.encode());

  if (this.isScripthash())
    return this.code[1];
};

Script.prototype.isPubkey = function isPubkey(key) {
  var res;

  if (this.code.length !== 2)
    return false;

  res = Script.isKey(this.code[0]) && this.code[1] === opcodes.OP_CHECKSIG;

  if (!res)
    return false;

  if (key) {
    if (!utils.isEqual(this.code[0], key))
      return false;
  }

  return true;
};

Script.prototype.isPubkeyhash = function isPubkeyhash(hash) {
  var res;

  if (this.code.length !== 5)
    return false;

  res = this.code[0] === opcodes.OP_DUP
    && this.code[1] === opcodes.OP_HASH160
    && Script.isHash(this.code[2])
    && this.code[3] === opcodes.OP_EQUALVERIFY
    && this.code[4] === opcodes.OP_CHECKSIG;

  if (!res)
    return false;

  if (hash) {
    if (!utils.isEqual(this.code[2], hash))
      return false;
  }

  return true;
};

Script.prototype.isMultisig = function isMultisig(keys) {
  var m, n, i, j;
  var total = 0;

  if (this.code.length < 4)
    return false;

  if (this.code[this.code.length - 1] !== opcodes.OP_CHECKMULTISIG)
    return false;

  n = Script.getSmall(this.code[this.code.length - 2]);

  if (n == null)
    return false;

  m = Script.getSmall(this.code[0]);

  if (m == null)
    return false;

  if (!(m >= 1 && m <= n))
    return false;

  if (n + 3 !== this.code.length)
    return false;

  for (i = 1; i < n + 1; i++) {
    if (!Script.isKey(this.code[i]))
      return false;
  }

  if (keys) {
    for (i = 1; i < n + 1; i++) {
      for (j = 0; j < keys.length; j++) {
        if (utils.isEqual(this.code[i], keys[j])) {
          total++;
          break;
        }
      }
    }

    if (total !== n)
      return false;
  }

  return true;
};

Script.prototype.isScripthash = function isScripthash(hash) {
  var res;

  if (this.code.length !== 3)
    return false;

  res = this.code[0] === opcodes.OP_HASH160
    && Script.isHash(this.code[1])
    && this.code[2] === opcodes.OP_EQUAL;

  if (!res)
    return false;

  if (hash) {
    if (!utils.isEqual(this.code[1], hash))
      return false;
  }

  return true;
};

Script.prototype.isNulldata = function isNulldata() {
  var res;

  if (this.code.length !== 2)
    return false;

  res = this.code[0] === opcodes.OP_RETURN && Script.isData(this.code[1]);

  if (!res)
    return false;

  return true;
};

Script.prototype.isCommitment = function isCommitment() {
  return this.code.length >= 2
    && this.code[0] === opcodes.OP_RETURN
    && Buffer.isBuffer(this.code[1])
    && this.code[1].length === 36
    && utils.readU32BE(this.code[1], 0) === 0xaa21a9ed;
};

Script.prototype.getCommitmentHash = function getCommitmentHash() {
  if (!this.isCommitment())
    return;

  return this.code[1].slice(4, 36);
};

Script.prototype.isWitnessProgram = function isWitnessProgram() {
  if (this.code.length !== 2)
    return false;

  if (typeof this.code[0] !== 'number')
    return false;

  if (!Buffer.isBuffer(this.code[1]))
    return false;

  return (this.code[0] === opcodes.OP_0
    || (this.code[0] >= opcodes.OP_1 && this.code[0] <= opcodes.OP_16))
    && this.code[1].length >= 2 && this.code[1].length <= 32;
};

Script.prototype.getWitnessProgram = function getWitnessProgram() {
  var version, data, type;

  if (!this.isWitnessProgram())
    return;

  version = Script.getSmall(this.code[0]);
  data = this.code[1];

  if (version > 0) {
    // No interpretation of script (anyone can spend)
    type = 'unknown';
  } else if (version === 0 && data.length === 20) {
    type = 'witnesspubkeyhash';
  } else if (version === 0 && data.length === 32) {
    type = 'witnessscripthash';
  } else {
    // Fail on bad version=0
    type = null;
  }

  return {
    version: version,
    type: type,
    data: data
  };
};

Script.prototype.isWitnessPubkeyhash = function isWitnessPubkeyhash() {
  if (!this.isWitnessProgram())
    return false;

  return this.code[0] === opcodes.OP_0 && this.code[1].length === 20;
};

Script.prototype.isWitnessScripthash = function isWitnessScripthash() {
  if (!this.isWitnessProgram())
    return false;

  return this.code[0] === opcodes.OP_0 && this.code[1].length === 32;
};

Script.prototype.getInputType = function getInputType(prev) {
  return Script.getInputType(this.code, prev);
};

Script.getInputType = function getInputType(code, prev, isWitness) {
  var type;

  if (prev)
    return prev.getType();

  type = (Script.isPubkeyInput(code) && 'pubkey')
    || (Script.isPubkeyhashInput(code) && 'pubkeyhash')
    || (Script.isMultisigInput(code, null, isWitness) && 'multisig')
    || (Script.isScripthashInput(code, null, isWitness) && 'scripthash')
    || 'unknown';

  if (isWitness) {
    if (type === 'pubkeyhash')
      return 'witnesspubkeyhash';
    if (type === 'scripthash')
      return 'witnessscripthash';
    return 'unknown';
  }

  return type;
};

Script.prototype.isNonstandardInput = function isNonstandardInput(prev) {
  return Script.isNonstandardInput(this.code, prev, false);
};

Script.isNonstandardInput = function isNonstandardInput(code, prev, isWitness) {
  return Script.getInputType(code, prev, isWitness) === 'unknown';
};

Script.createOutputScript = function(options) {
  var script, keys, m, n, hash, flags, address, redeem;

  if (!options)
    options = {};

  if (options.keys) {
    keys = options.keys.map(utils.ensureBuffer);

    m = options.m;
    n = options.n || keys.length;

    assert(m >= 1 && m <= n, 'm must be between 1 and n');

    assert(
      n >= 1 && n <= (options.scriptHash ? 15 : 3),
      'n must be between 1 and 15');

    script = Script.createMultisig(keys, m, n);
  } else if (options.address) {
    address = bcoin.address.parse(options.address);

    if (!address)
      throw new Error(options.address + ' is not a valid address.');

    if (address.type === 'pubkeyhash')
      script = Script.createPubkeyhash(address.hash);
    else if (address.type === 'scripthash')
      script = Script.createScripthash(address.hash);
    else if (address.version !== -1)
      script = Script.createWitnessProgram(address.version, address.hash);
    else
      throw new Error('Cannot parse address: ' + options.address);
  } else if (options.key) {
    script = Script.createPubkey(utils.ensureBuffer(options.key));
  } else if (options.flags) {
    flags = options.flags;
    if (typeof flags === 'string')
      flags = new Buffer(flags, 'ascii');
    assert(Buffer.isBuffer(flags));
    assert(flags.length <= constants.script.maxOpReturn);
    script = Script.createNulldata(flags);
  }

  if (options.scriptHash) {
    if (options.locktime != null) {
      script = new Script([
        Script.array(options.locktime),
        opcodes.OP_CHECKLOCKTIMEVERIFY,
        opcodes.OP_DROP
      ].concat(script.code));
    }
    redeem = script;
    hash = utils.ripesha(script.encode());
    script = Script.createScripthash(hash);
    script.redeem = redeem;
  }

  return script;
};

Script.prototype.isPubkeyInput = function isPubkeyInput(key) {
  return Script.isPubkeyInput(this.code, key);
};

Script.isPubkeyInput = function isPubkeyInput(code, key) {
  if (code.length !== 1)
    return false;

  if (!Script.isSignature(code[0]))
    return false;

  assert(!key);

  return true;
};

Script.prototype.isPubkeyhashInput = function isPubkeyhashInput(key) {
  return Script.isPubkeyhashInput(this.code, key);
};

Script.isPubkeyhashInput = function isPubkeyhashInput(code, key) {
  if (code.length !== 2)
    return false;

  if (!Script.isSignature(code[0]))
    return false;

  if (!Script.isKey(code[1]))
    return false;

  if (key) {
    if (!utils.isEqual(code[1], key))
      return false;
  }

  return true;
};

Script.prototype.isMultisigInput = function isMultisigInput(keys) {
  return Script.isMultisigInput(this.code, keys);
};

Script.isMultisigInput = function isMultisigInput(code, keys, isWitness) {
  var i;

  // We need to rule out scripthash because
  // it may look like multisig. This is
  // strange because it's technically a
  // recursive call.
  if (Script.isScripthashInput(code, null, isWitness))
    return false;

  if (code.length < 3)
    return false;

  if (isWitness) {
    if (!Script.isDummy(code[0]))
      return false;
  } else {
    if (code[0] !== opcodes.OP_0)
      return false;
  }

  for (i = 1; i < code.length; i++) {
    if (!Script.isSignature(code[i]))
      return false;
  }

  assert(!keys);

  return true;
};

Script.prototype.isScripthashInput = function isScripthashInput(redeem) {
  return Script.isScripthashInput(this.code, redeem);
};

Script.isScripthashInput = function isScripthashInput(code, redeem, isWitness) {
  var raw;

  // Grab the raw redeem script.
  raw = code[code.length - 1];

  // Need at least one data element with
  // the redeem script. NOTE: NOT THE CASE FOR SEGWIT!
  if (isWitness) {
    if (code.length < 1)
      return false;
  } else {
    if (code.length < 2)
      return false;
  }

  // Last data element should be an array
  // for the redeem script.
  if (!Buffer.isBuffer(raw))
    return false;

  // Check data against last array in case
  // a raw redeem script was passed in.
  if (redeem)
    return utils.isEqual(redeem.encode(), raw);

  // Testing for scripthash inputs requires
  // some evil magic to work. We do it by
  // ruling things _out_. This test will not
  // be correct 100% of the time. We rule
  // out that the last data element is: a
  // null dummy, a valid signature, a valid
  // key, and we ensure that it is at least
  // a script that does not use undefined
  // opcodes.
  if (Script.isDummy(raw))
    return false;

  if (Script.isSignatureEncoding(raw))
    return false;

  if (Script.isKeyEncoding(raw))
    return false;

  if (!Script.isCode(raw))
    return false;

  return true;
};

Script.prototype.getCoinbaseData = function getCoinbaseData() {
  var coinbase, flags;

  coinbase = {
    script: this
  };

  if (Buffer.isBuffer(this.code[0]) && this.code[0].length <= 6)
    coinbase.height = new bn(this.code[0], 'le').toNumber();
  else
    coinbase.height = -1;

  if (Buffer.isBuffer(this.code[1]))
    coinbase.extraNonce = new bn(this.code[1], 'le');
  else
    coinbase.extraNonce = new bn(0, 'le');

  flags = this.code.slice(2).filter(function(chunk) {
    return Buffer.isBuffer(chunk) && chunk.length !== 0;
  });

  coinbase.flags = flags;

  flags = flags.map(function(flag) {
    return flag.toString('utf8');
  });

  coinbase.text = flags.join('').replace(/[\u0000-\u0019\u007f-\u00ff]/g, '');

  return coinbase;
};

// Detect script array types. Note: these functions
// are not mutually exclusive. Only use for
// verification, not detection.

Script.isHash = function isHash(hash) {
  if (!Buffer.isBuffer(hash))
    return false;

  return hash.length === 20;
};

Script.isKey = function isKey(key) {
  if (!Buffer.isBuffer(key))
    return false;

  return key.length >= 33 && key.length <= 65;
};

Script.isSignature = function isSignature(sig) {
  if (!Buffer.isBuffer(sig))
    return false;

  return sig.length >= 9 && sig.length <= 73;
};

Script.isDummy = function isDummy(data) {
  if (!Buffer.isBuffer(data))
    return false;

  return data.length === 0;
};

Script.isZero = function isZero(op) {
  if (op === opcodes.OP_0)
    return true;

  return Script.isDummy(op);
};

Script.isData = function isData(data) {
  if (!Buffer.isBuffer(data))
    return false;

  return data.length <= constants.script.maxOpReturn;
};

Script.isValidKey = function isValidKey(key, flags) {
  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (!Buffer.isBuffer(key))
    return false;

  if (flags & constants.flags.VERIFY_STRICTENC) {
    if (!Script.isKeyEncoding(key)) {
      utils.debug('Script failed key encoding test.');
      return false;
    }
  }

  return true;
};

Script.isKeyEncoding = function isKeyEncoding(key) {
  if (!Buffer.isBuffer(key))
    return false;

  if (key.length < 33)
    return false;

  if (key[0] === 0x04) {
    if (key.length !== 65)
      return false;
  } else if (key[0] === 0x02 || key[0] === 0x03) {
    if (key.length !== 33)
      return false;
  } else {
    return false;
  }

  return true;
};

Script.isValidSignature = function isValidSignature(sig, flags) {
  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (!Buffer.isBuffer(sig))
    return false;

  // Allow empty sigs
  if (sig.length === 0)
    return true;

  if ((flags & constants.flags.VERIFY_DERSIG)
      || (flags & constants.flags.VERIFY_LOW_S)
      || (flags & constants.flags.VERIFY_STRICTENC)) {
    if (!Script.isSignatureEncoding(sig)) {
      utils.debug('Script does not have a proper signature encoding.');
      return false;
    }
  }

  if (flags & constants.flags.VERIFY_LOW_S) {
    if (!Script.isLowDER(sig)) {
      utils.debug('Script does not have a low DER.');
      return false;
    }
  }

  if (flags & constants.flags.VERIFY_STRICTENC) {
    if (!Script.isHashType(sig)) {
      utils.debug('Script does not have a valid hash type.');
      return false;
    }
  }

  return true;
};

// https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
/**
 * A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
 * Where R and S are not negative (their first byte has its highest bit not set), and not
 * excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
 * in which case a single 0 byte is necessary and even required).
 *
 * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
 *
 * This function is consensus-critical since BIP66.
 */
Script.isSignatureEncoding = function isSignatureEncoding(sig) {
  var lenR, lenS;

  if (!Buffer.isBuffer(sig))
    return false;

  // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
  // * total-length: 1-byte length descriptor of everything that follows,
  //   excluding the sighash byte.
  // * R-length: 1-byte length descriptor of the R value that follows.
  // * R: arbitrary-length big-endian encoded R value. It must use the shortest
  //   possible encoding for a positive integers (which means no null bytes at
  //   the start, except a single one when the next byte has its highest bit set).
  // * S-length: 1-byte length descriptor of the S value that follows.
  // * S: arbitrary-length big-endian encoded S value. The same rules apply.
  // * sighash: 1-byte value indicating what data is hashed (not part of the DER
  //   signature)

  // Minimum and maximum size constraints.
  if (sig.length < 9)
    return false;

  if (sig.length > 73)
    return false;

  // A signature is of type 0x30 (compound).
  if (sig[0] !== 0x30)
    return false;

  // Make sure the length covers the entire signature.
  if (sig[1] !== sig.length - 3)
    return false;

  // Extract the length of the R element.
  lenR = sig[3];

  // Make sure the length of the S element is still inside the signature.
  if (5 + lenR >= sig.length)
    return false;

  // Extract the length of the S element.
  lenS = sig[5 + lenR];

  // Verify that the length of the signature matches the sum of the length
  // of the elements.
  if (lenR + lenS + 7 !== sig.length)
    return false;

  // Check whether the R element is an integer.
  if (sig[2] !== 0x02)
    return false;

  // Zero-length integers are not allowed for R.
  if (lenR === 0)
    return false;

  // Negative numbers are not allowed for R.
  if (sig[4] & 0x80)
    return false;

  // Null bytes at the start of R are not allowed, unless R would
  // otherwise be interpreted as a negative number.
  if (lenR > 1 && (sig[4] === 0x00) && !(sig[5] & 0x80))
    return false;

  // Check whether the S element is an integer.
  if (sig[lenR + 4] !== 0x02)
    return false;

  // Zero-length integers are not allowed for S.
  if (lenS === 0)
    return false;

  // Negative numbers are not allowed for S.
  if (sig[lenR + 6] & 0x80)
    return false;

  // Null bytes at the start of S are not allowed, unless S would otherwise be
  // interpreted as a negative number.
  if (lenS > 1 && (sig[lenR + 6] === 0x00) && !(sig[lenR + 7] & 0x80))
    return false;

  return true;
};

Script.isHashType = function isHashType(sig) {
  var type;

  if (!Buffer.isBuffer(sig))
    return false;

  if (sig.length === 0)
    return false;

  type = sig[sig.length - 1] & ~constants.hashType.anyonecanpay;

  if (!constants.hashTypeByVal[type])
    return false;

  return true;
};

Script.isLowDER = function isLowDER(sig) {
  if (!sig.s) {
    if (!Buffer.isBuffer(sig))
      return false;

    if (!Script.isSignatureEncoding(sig))
      return false;

    sig = sig.slice(0, -1);
  }

  return bcoin.ec.isLowS(sig);
};

Script.format = function format(code) {
  var scripts = [];

  if (Array.isArray(code)) {
    scripts.push({ code: code });
  } else if (code instanceof Stack) {
    scripts.push({ code: code.items });
  } else if (code instanceof Witness) {
    scripts.push({ code: code.items });
  } else if (code instanceof Script) {
    scripts.push(code);
  } else if (code instanceof bcoin.input) {
    scripts.push(code.script);
    if (code.witness.length > 0)
      scripts.push({ code: code.witness.items });
    if (code.coin) {
      scripts.push(code.coin.script);
      if (code.coin.script.isScripthash())
        scripts.push(code.coin.script.getRedeem());
    }
  } else if (code instanceof bcoin.output) {
    scripts.push(code.script);
  }

  return Script.concat(scripts).map(function(chunk) {
    if (Buffer.isBuffer(chunk))
      return '[' + utils.toHex(chunk) + ']';

    assert(typeof chunk === 'number');

    if (constants.opcodesByVal[chunk])
      return constants.opcodesByVal[chunk];

    chunk = chunk.toString(16);
    if (chunk.length < 2)
      chunk = '0' + chunk;

    return 'UNKNOWN(' + chunk + ')';
  }).join(' ');
};

Script.prototype.isPushOnly = function isPushOnly() {
  var i, op;
  for (i = 0; i < this.code.length; i++) {
    op = this.code[i];
    if (Buffer.isBuffer(op)
        || op === opcodes.OP_1NEGATE
        || op === opcodes.OP_0
        || (op >= opcodes.OP_1 && op <= opcodes.OP_16)) {
      continue;
    }
    return false;
  }
  return true;
};

Script.prototype.getSigops = function getSigops(accurate) {
  var total = 0;
  var lastOp = -1;
  var i, op;

  for (i = 0; i < this.code.length; i++) {
    op = this.code[i];

    if (Buffer.isBuffer(op))
      continue;

    if (constants.opcodesByVal[op] == null)
      return 0;

    if (op === opcodes.OP_CHECKSIG || op === opcodes.OP_CHECKSIGVERIFY) {
      total++;
    } else if (op === opcodes.OP_CHECKMULTISIG || op === opcodes.OP_CHECKMULTISIGVERIFY) {
      if (accurate && lastOp >= opcodes.OP_1 && lastOp <= opcodes.OP_16)
        total += lastOp;
      else
        total += constants.script.maxPubkeysPerMultisig;
    }

    lastOp = op;
  }

  return total;
};

Script.prototype.getArgs = function getArgs() {
  var keys, m;

  if (this.isPubkey())
    return 1;

  if (this.isPubkeyhash())
    return 2;

  if (this.isMultisig()) {
    keys = this.code.length - 3;
    m = Script.getSmall(this.code[0]);
    if (keys < 1 || m < 1)
      return -1;
    return m + 1;
  }

  if (this.isScripthash())
    return 1;

  if (this.isNulldata())
    return -1;

  if (this.isWitnessScripthash())
    return 1;

  if (this.isWitnessPubkeyhash())
    return 2;

  return -1;
};

Script.fromString = function fromString(code) {
  var i, op, symbol;

  code = code.trim().split(/\s+/);

  for (i = 0; i < code.length; i++) {
    op = code[i];

    if (op === '-1')
      op = '1negate';

    symbol = (op + '').toUpperCase();
    if (symbol.indexOf('OP_') !== 0)
      symbol = 'OP_' + op;

    if (opcodes[symbol] == null) {
      if (op[0] === '[')
        op = op.slice(1, -1);
      if (op.indexOf('0x') === 0)
        op = op.substring(2);
      assert(utils.isHex(op), 'Unknown opcode.');
      op = new Buffer(op, 'hex');
      code[i] = op;
      continue;
    }

    code[i] = opcodes[symbol];
  }

  return new Script(code);
};

Script.prototype.getSmall = function getSmall(i) {
  if (i < 0)
    i = this.code.length + i;

  return Script.getSmall(this.code[i]);
};

Script.getSmall = function getSmall(op) {
  if (typeof op !== 'number')
    return null;

  if (op === opcodes.OP_0)
    return 0;

  if (op >= opcodes.OP_1 && op <= opcodes.OP_16)
    return op - 0x50;

  return null;
};

Script.toSmall = function toSmall(op) {
  assert(op >= 0 && op <= 16);

  if (op === 0)
    return opcodes.OP_0;

  return op + 0x50;
};

Script.fromSymbolic = function fromSymbolic(items) {
  var code = new Array(items.length);
  var i, op;

  for (i = 0; i < items.length; i++) {
    op = items[i];

    if (Buffer.isBuffer(op)) {
      code[i] = op;
      continue;
    }

    if (+op === -1)
      op = '1negate';

    op = (op + '').toUpperCase();
    if (op.indexOf('OP_') !== 0)
      op = 'OP_' + op;

    assert(opcodes[op] != null, 'Unknown opcode.');

    code[i] = opcodes[op];
  }

  return new Script(code);
};

Script.verify = function verify(input, witness, output, tx, i, flags) {
  var copy, res, raw, redeem, hadWitness;
  var stack = new Stack();

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (flags & constants.flags.VERIFY_SIGPUSHONLY) {
    if (!input.isPushOnly())
      return false;
  }

  // Execute the input script
  input.execute(stack, flags, tx, i, 0);

  // Copy the stack for P2SH
  if (flags & constants.flags.VERIFY_P2SH)
    copy = stack.clone();

  // Execute the previous output script
  res = output.execute(stack, flags, tx, i, 0);

  // Verify the script did not fail as well as the stack values
  if (!res || stack.length === 0 || !Script.bool(stack.pop()))
    return false;

  if ((flags & constants.flags.VERIFY_WITNESS) && output.isWitnessProgram()) {
    hadWitness = true;

    // Input script must be empty.
    if (input.code.length !== 0)
      return false;

    // Verify the program in the output script
    if (!Script.verifyProgram(witness, output, flags, tx, i))
      return false;

    // Force a cleanstack
    stack.length = 0;
  }

  // If the script is P2SH, execute the real output script
  if ((flags & constants.flags.VERIFY_P2SH) && output.isScripthash()) {
    // P2SH can only have push ops in the scriptSig
    if (!input.isPushOnly())
      return false;

    // Reset the stack
    stack = copy;

    // Stack should not be empty at this point
    if (stack.length === 0)
      return false;

    // Grab the real redeem script
    raw = stack.pop();

    if (!Buffer.isBuffer(raw))
      return false;

    redeem = new Script(raw);

    // Execute the redeem script
    res = redeem.execute(stack, flags, tx, i, 0);

    // Verify the script did not fail as well as the stack values
    if (!res || stack.length === 0 || !Script.bool(stack.pop()))
      return false;

    if ((flags & constants.flags.VERIFY_WITNESS) && redeem.isWitnessProgram()) {
      hadWitness = true;

      // Input script must be exactly one push of the redeem script.
      if (!(input.code.length === 1 && utils.isEqual(input.code[0], raw)))
        return false;

      // Verify the program in the redeem script
      if (!Script.verifyProgram(witness, redeem, flags, tx, i))
        return false;

      // Force a cleanstack
      stack.length = 0;
    }
  }

  // Ensure there is nothing left on the stack
  if (flags & constants.flags.VERIFY_CLEANSTACK) {
    assert((flags & constants.flags.VERIFY_P2SH) !== 0);
    // assert((flags & constants.flags.VERIFY_WITNESS) !== 0);
    if (stack.length !== 0)
      return false;
  }

  // If we had a witness but no witness program, fail.
  if (flags & constants.flags.VERIFY_WITNESS) {
    assert((flags & constants.flags.VERIFY_P2SH) !== 0);
    if (!hadWitness && witness.length > 0)
      return false;
  }

  return true;
};

Script.verifyProgram = function verifyProgram(witness, output, flags, tx, i) {
  var program, witnessScript, redeem, stack, j, res;

  assert((flags & constants.flags.VERIFY_WITNESS) !== 0);
  assert(output.isWitnessProgram());

  program = output.getWitnessProgram();

  // Failure on version=0 (bad program data length)
  if (!program.type) {
    utils.debug('Malformed witness program.');
    return false;
  }

  if (program.version > 0) {
    utils.debug('Unknown witness program version: %s', program.version);
    // Anyone can spend (we can return true here
    // if we want to always relay these transactions).
    // Otherwise, if we want to act like an "old"
    // implementation and only accept them in blocks,
    // we can use the regalar output script which will
    // succeed in a block, but fail in the mempool
    // due to VERIFY_CLEANSTACK.
    if (flags & constants.flags.VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
      return false;
    return true;
  }

  stack = witness.toStack();

  if (program.type === 'witnesspubkeyhash') {
    if (stack.length !== 2)
      return false;

    redeem = Script.createPubkeyhash(program.data);
  } else if (program.type === 'witnessscripthash') {
    if (stack.length === 0)
      return false;

    witnessScript = stack.pop();

    if (!utils.isEqual(utils.sha256(witnessScript), program.data))
      return false;

    redeem = new Script(witnessScript);
  } else {
    assert(false);
  }

  for (j = 0; j < stack.length; j++) {
    if (stack.get(j).length > constants.script.maxSize)
      return false;
  }

  res = redeem.execute(stack, flags, tx, i, 1);

  // Verify the script did not fail as well as the stack values
  if (!res || stack.length === 0 || !Script.bool(stack.pop()))
    return false;

  // Witnesses always require cleanstack
  if (stack.length !== 0)
    return false;

  return true;
};

Script.concat = function concat(scripts) {
  var code = [];
  var i;

  code = code.concat(scripts[0].code);

  for (i = 1; i < scripts.length; i++) {
    code.push(opcodes.OP_CODESEPARATOR);
    code = code.concat(scripts[i].code);
  }

  return code;
};

Script.checksig = function checksig(msg, sig, key, flags) {
  var historical = false;

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (!Buffer.isBuffer(sig))
    return false;

  if (sig.length === 0)
    return false;

  // Attempt to normalize the signature
  // length before passing to elliptic.
  // Note: We only do this for historical data!
  // https://github.com/indutny/elliptic/issues/78
  if (!((flags & constants.flags.VERIFY_DERSIG)
      || (flags & constants.flags.VERIFY_LOW_S)
      || (flags & constants.flags.VERIFY_STRICTENC))) {
    historical = true;
  }

  return bcoin.ec.verify(msg, sig.slice(0, -1), key, historical);
};

Script.sign = function sign(msg, key, type) {
  var sig = bcoin.ec.sign(msg, key);

  // Add the sighash type as a single byte
  // to the signature.
  sig = Buffer.concat([sig, new Buffer([type])]);

  return sig;
};

Script.decode = function decode(buf) {
  var code = [];
  var off = 0;
  var op, size;

  assert(Buffer.isBuffer(buf));

  // NOTE: We can't use a BufferReader here since
  // script parsing was originally non-strict/ridiculous.
  // Something could do a direct push of 30 bytes with
  // only 20 bytes after it.
  // NOTE 2: We use reference Buffer slices here. Larger
  // buffer slices should _never_ be passed in here.
  while (off < buf.length) {
    op = buf[off++];

    // Direct Push
    // Next `op` bytes should be pushed to stack
    if (op >= 0x01 && op <= 0x4b) {
      code.push(buf.slice(off, off + op));
      off += op;
      if (off > buf.length) {
        utils.hidden(code[code.length - 1], 'pushdata', {
          opcode: null,
          size: op
        });
      }
      continue;
    }

    if (off >= buf.length) {
      code.push(op);
      continue;
    }

    if (op === opcodes.OP_PUSHDATA1) {
      size = buf[off];
      off += 1;
      code.push(buf.slice(off, off + size));
      off += size;
      if (size <= 0x4b || off > buf.length) {
        utils.hidden(code[code.length - 1], 'pushdata', {
          opcode: op,
          size: size
        });
      }
    } else if (op === opcodes.OP_PUSHDATA2) {
      size = utils.readU16(buf, off);
      off += 2;
      code.push(buf.slice(off, off + size));
      off += size;
      if (size <= 0xff || off > buf.length) {
        utils.hidden(code[code.length - 1], 'pushdata', {
          opcode: op,
          size: size
        });
      }
    } else if (op === opcodes.OP_PUSHDATA4) {
      size = utils.readU32(buf, off);
      off += 4;
      code.push(buf.slice(off, off + size));
      off += size;
      if (size <= 0xffff || off > buf.length) {
        utils.hidden(code[code.length - 1], 'pushdata', {
          opcode: op,
          size: size
        });
      }
    } else {
      code.push(op);
    }
  }

  return code;
};

Script.encode = function encode(code) {
  var p = new BufferWriter();
  var i = 0;
  var op;

  assert(Array.isArray(code));

  for (i = 0; i < code.length; i++) {
    op = code[i];

    // Push value to stack
    if (Buffer.isBuffer(op)) {
      // Check for nonstandard pushdatas that
      // may have been decoded from before.
      if (op.pushdata) {
        if (op.pushdata.opcode === null) {
          p.writeU8(op.pushdata.size);
          p.writeBytes(op);
        } else if (op.pushdata.opcode === opcodes.OP_PUSHDATA1) {
          p.writeU8(opcodes.OP_PUSHDATA1);
          p.writeU8(op.pushdata.size);
          p.writeBytes(op);
        } else if (op.pushdata.opcode === opcodes.OP_PUSHDATA2) {
          p.writeU8(opcodes.OP_PUSHDATA2);
          p.writeU16(op.pushdata.size);
          p.writeBytes(op);
        } else if (op.pushdata.opcode === opcodes.OP_PUSHDATA4) {
          p.writeU8(opcodes.OP_PUSHDATA4);
          p.writeU32(op.pushdata.size);
          p.writeBytes(op);
        }
        continue;
      }
      // Standard minimaldata encoding
      if (op.length === 0) {
        p.writeU8(opcodes.OP_0);
      } else if (op.length <= 0x4b) {
        p.writeU8(op.length);
        p.writeBytes(op);
      } else if (op.length <= 0xff) {
        p.writeU8(opcodes.OP_PUSHDATA1);
        p.writeU8(op.length);
        p.writeBytes(op);
      } else if (op.length <= 0xffff) {
        p.writeU8(opcodes.OP_PUSHDATA2);
        p.writeU16(op.length);
        p.writeBytes(op);
      } else {
        p.writeU8(opcodes.OP_PUSHDATA4);
        p.writeU32(op.length);
        p.writeBytes(op);
      }
      continue;
    }

    assert(typeof op === 'number');

    p.writeU8(op);
  }

  return p.render();
};

Script.isScript = function isScript(obj) {
  return obj
    && Array.isArray(obj.code)
    && typeof obj.getSubscript === 'function';
};

/**
 * ScriptError
 */

function ScriptError(msg, op, ip) {
  Error.call(this);
  if (Error.captureStackTrace)
    Error.captureStackTrace(this, ScriptError);
  this.type = 'ScriptError';
  if (Buffer.isBuffer(op))
    op = 'PUSHDATA[' + op.length + ']';
  if (op || ip != null) {
    msg += '(';
    if (op) {
      op = constants.opcodesByVal[op] || op;
      msg += 'op=' + op;
      if (ip != null)
        msg += ', ';
    }
    if (ip != null)
      msg += 'ip=' + ip;
  }
  this.message = msg;
  this.op = op;
  this.ip = ip;
}

utils.inherits(ScriptError, Error);

Script.witness = Witness;
Script.stack = Stack;
Script.error = ScriptError;
module.exports = Script;
