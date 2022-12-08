/*!
 * script.js - script interpreter for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const ripemd160 = require('bcrypto/lib/ripemd160');
const sha1 = require('bcrypto/lib/sha1');
const sha256 = require('bcrypto/lib/sha256');
const hash160 = require('bcrypto/lib/hash160');
const hash256 = require('bcrypto/lib/hash256');
const secp256k1 = require('bcrypto/lib/secp256k1');
const consensus = require('../protocol/consensus');
const policy = require('../protocol/policy');
const Program = require('./program');
const Opcode = require('./opcode');
const Stack = require('./stack');
const ScriptError = require('./scripterror');
const ScriptNum = require('./scriptnum');
const common = require('./common');
const Address = require('../primitives/address');
const opcodes = common.opcodes;
const scriptTypes = common.types;
const {encoding} = bio;
const {inspectSymbol} = require('../utils');

/*
 * Constants
 */

const EMPTY_BUFFER = Buffer.alloc(0);

/**
 * Script
 * Represents a input or output script.
 * @alias module:script.Script
 * @property {Array} code - Parsed script code.
 * @property {Buffer?} raw - Serialized script.
 * @property {Number} length - Number of parsed opcodes.
 */

class Script {
  /**
   * Create a script.
   * @constructor
   * @param {Buffer|Array|Object} options
   */

  constructor(options) {
    this.raw = EMPTY_BUFFER;
    this.code = [];

    if (options)
      this.fromOptions(options);
  }

  /**
   * Get length.
   * @returns {Number}
   */

  get length() {
    return this.code.length;
  }

  /**
   * Set length.
   * @param {Number} value
   */

  set length(value) {
    this.code.length = value;
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    assert(options, 'Script data is required.');

    if (Buffer.isBuffer(options))
      return this.fromRaw(options);

    if (Array.isArray(options))
      return this.fromArray(options);

    if (options.raw) {
      if (!options.code)
        return this.fromRaw(options.raw);
      assert(Buffer.isBuffer(options.raw), 'Raw must be a Buffer.');
      this.raw = options.raw;
    }

    if (options.code) {
      if (!options.raw)
        return this.fromArray(options.code);
      assert(Array.isArray(options.code), 'Code must be an array.');
      this.code = options.code;
    }

    return this;
  }

  /**
   * Insantiate script from options object.
   * @param {Object} options
   * @returns {Script}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Instantiate a value-only iterator.
   * @returns {ScriptIterator}
   */

  values() {
    return this.code.values();
  }

  /**
   * Instantiate a key and value iterator.
   * @returns {ScriptIterator}
   */

  entries() {
    return this.code.entries();
  }

  /**
   * Instantiate a value-only iterator.
   * @returns {ScriptIterator}
   */

  [Symbol.iterator]() {
    return this.code[Symbol.iterator]();
  }

  /**
   * Convert the script to an array of
   * Buffers (pushdatas) and Numbers
   * (opcodes).
   * @returns {Array}
   */

  toArray() {
    return this.code.slice();
  }

  /**
   * Inject properties from an array of
   * of buffers and numbers.
   * @private
   * @param {Array} code
   * @returns {Script}
   */

  fromArray(code) {
    assert(Array.isArray(code));

    this.clear();

    for (const op of code)
      this.push(op);

    return this.compile();
  }

  /**
   * Instantiate script from an array
   * of buffers and numbers.
   * @param {Array} code
   * @returns {Script}
   */

  static fromArray(code) {
    return new this().fromArray(code);
  }

  /**
   * Convert script to stack items.
   * @returns {Buffer[]}
   */

  toItems() {
    const items = [];

    for (const op of this.code) {
      const data = op.toPush();

      if (!data)
        throw new Error('Non-push opcode in script.');

      items.push(data);
    }

    return items;
  }

  /**
   * Inject data from stack items.
   * @private
   * @param {Buffer[]} items
   * @returns {Script}
   */

  fromItems(items) {
    assert(Array.isArray(items));

    this.clear();

    for (const item of items)
      this.pushData(item);

    return this.compile();
  }

  /**
   * Instantiate script from stack items.
   * @param {Buffer[]} items
   * @returns {Script}
   */

  static fromItems(items) {
    return new this().fromItems(items);
  }

  /**
   * Convert script to stack.
   * @returns {Stack}
   */

  toStack() {
    return new Stack(this.toItems());
  }

  /**
   * Inject data from stack.
   * @private
   * @param {Stack} stack
   * @returns {Script}
   */

  fromStack(stack) {
    return this.fromItems(stack.items);
  }

  /**
   * Instantiate script from stack.
   * @param {Stack} stack
   * @returns {Script}
   */

  static fromStack(stack) {
    return new this().fromStack(stack);
  }

  /**
   * Clone the script.
   * @returns {Script} Cloned script.
   */

  clone() {
    return new this.constructor().inject(this);
  }

  /**
   * Inject properties from script.
   * Used for cloning.
   * @private
   * @param {Script} script
   * @returns {Script}
   */

  inject(script) {
    this.raw = script.raw;
    this.code = script.code.slice();
    return this;
  }

  /**
   * Test equality against script.
   * @param {Script} script
   * @returns {Boolean}
   */

  equals(script) {
    assert(Script.isScript(script));
    return this.raw.equals(script.raw);
  }

  /**
   * Compare against another script.
   * @param {Script} script
   * @returns {Number}
   */

  compare(script) {
    assert(Script.isScript(script));
    return this.raw.compare(script.raw);
  }

  /**
   * Clear the script.
   * @returns {Script}
   */

  clear() {
    this.raw = EMPTY_BUFFER;
    this.code.length = 0;
    return this;
  }

  /**
   * Inspect the script.
   * @returns {String} Human-readable script code.
   */

  [inspectSymbol]() {
    return `<Script: ${this.toString()}>`;
  }

  /**
   * Convert the script to a bitcoind test string.
   * @returns {String} Human-readable script code.
   */

  toString() {
    const out = [];

    for (const op of this.code)
      out.push(op.toFormat());

    return out.join(' ');
  }

  /**
   * Format the script as bitcoind asm.
   * @param {Boolean?} decode - Attempt to decode hash types.
   * @returns {String} Human-readable script.
   */

  toASM(decode) {
    if (this.isNulldata())
      decode = false;

    const out = [];

    for (const op of this.code)
      out.push(op.toASM(decode));

    return out.join(' ');
  }

  /**
   * Re-encode the script internally. Useful if you
   * changed something manually in the `code` array.
   * @returns {Script}
   */

  compile() {
    if (this.code.length === 0)
      return this.clear();

    let size = 0;

    for (const op of this.code)
      size += op.getSize();

    const bw = bio.write(size);

    for (const op of this.code)
      op.toWriter(bw);

    this.raw = bw.render();

    return this;
  }

  /**
   * Write the script to a buffer writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeVarBytes(this.raw);
    return bw;
  }

  /**
   * Encode the script to a Buffer. See {@link Script#encode}.
   * @returns {Buffer|String} Serialized script.
   */

  toRaw() {
    return this.raw;
  }

  /**
   * Convert script to a hex string.
   * @returns {String}
   */

  toJSON() {
    return this.toRaw().toString('hex');
  }

  /**
   * Inject properties from json object.
   * @private
   * @param {String} json
   */

  fromJSON(json) {
    assert(typeof json === 'string', 'Code must be a string.');
    return this.fromRaw(Buffer.from(json, 'hex'));
  }

  /**
   * Instantiate script from a hex string.
   * @params {String} json
   * @returns {Script}
   */

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  /**
   * Get the script's "subscript" starting at a separator.
   * @param {Number} index - The last separator to sign/verify beyond.
   * @returns {Script} Subscript.
   */

  getSubscript(index) {
    if (index === 0)
      return this.clone();

    const script = new Script();

    for (let i = index; i < this.code.length; i++) {
      const op = this.code[i];

      if (op.value === -1)
        break;

      script.code.push(op);
    }

    return script.compile();
  }

  /**
   * Get the script's "subscript" starting at a separator.
   * Remove all OP_CODESEPARATORs if present. This bizarre
   * behavior is necessary for signing and verification when
   * code separators are present.
   * @returns {Script} Subscript.
   */

  removeSeparators() {
    let found = false;

    // Optimizing for the common case:
    // Check for any separators first.
    for (const op of this.code) {
      if (op.value === -1)
        break;

      if (op.value === opcodes.OP_CODESEPARATOR) {
        found = true;
        break;
      }
    }

    if (!found)
      return this;

    // Uncommon case: someone actually
    // has a code separator. Go through
    // and remove them all.
    const script = new Script();

    for (const op of this.code) {
      if (op.value === -1)
        break;

      if (op.value !== opcodes.OP_CODESEPARATOR)
        script.code.push(op);
    }

    return script.compile();
  }

  /**
   * Execute and interpret the script.
   * @param {Stack} stack - Script execution stack.
   * @param {Number?} flags - Script standard flags.
   * @param {TX?} tx - Transaction being verified.
   * @param {Number?} index - Index of input being verified.
   * @param {Amount?} value - Previous output value.
   * @param {Number?} version - Signature hash version (0=legacy, 1=segwit).
   * @throws {ScriptError} Will be thrown on VERIFY failures.
   */

  execute(stack, flags, tx, index, value, version) {
    if (flags == null)
      flags = Script.flags.STANDARD_VERIFY_FLAGS;

    if (version == null)
      version = 0;

    if (this.raw.length > consensus.MAX_SCRIPT_SIZE)
      throw new ScriptError('SCRIPT_SIZE');

    const state = [];
    const alt = [];

    let lastSep = 0;
    let opCount = 0;
    let negate = 0;
    let minimal = false;

    if (flags & Script.flags.VERIFY_MINIMALDATA)
      minimal = true;

    for (let ip = 0; ip < this.code.length; ip++) {
      const op = this.code[ip];

      if (op.value === -1)
        throw new ScriptError('BAD_OPCODE', op, ip);

      if (op.data && op.data.length > consensus.MAX_SCRIPT_PUSH)
        throw new ScriptError('PUSH_SIZE', op, ip);

      if (op.value > opcodes.OP_16 && ++opCount > consensus.MAX_SCRIPT_OPS)
        throw new ScriptError('OP_COUNT', op, ip);

      if (op.isDisabled())
        throw new ScriptError('DISABLED_OPCODE', op, ip);

      if (op.value === opcodes.OP_CODESEPARATOR && version === 0 &&
          (flags & Script.flags.VERIFY_CONST_SCRIPTCODE))
        throw new ScriptError('OP_CODESEPARATOR', op, ip);

      if (negate && !op.isBranch()) {
        if (stack.length + alt.length > consensus.MAX_SCRIPT_STACK)
          throw new ScriptError('STACK_SIZE', op, ip);
        continue;
      }

      if (op.data) {
        if (minimal && !op.isMinimal())
          throw new ScriptError('MINIMALDATA', op, ip);

        stack.push(op.data);

        if (stack.length + alt.length > consensus.MAX_SCRIPT_STACK)
          throw new ScriptError('STACK_SIZE', op, ip);

        continue;
      }

      switch (op.value) {
        case opcodes.OP_0: {
          stack.pushInt(0);
          break;
        }
        case opcodes.OP_1NEGATE: {
          stack.pushInt(-1);
          break;
        }
        case opcodes.OP_1:
        case opcodes.OP_2:
        case opcodes.OP_3:
        case opcodes.OP_4:
        case opcodes.OP_5:
        case opcodes.OP_6:
        case opcodes.OP_7:
        case opcodes.OP_8:
        case opcodes.OP_9:
        case opcodes.OP_10:
        case opcodes.OP_11:
        case opcodes.OP_12:
        case opcodes.OP_13:
        case opcodes.OP_14:
        case opcodes.OP_15:
        case opcodes.OP_16: {
          stack.pushInt(op.value - 0x50);
          break;
        }
        case opcodes.OP_NOP: {
          break;
        }
        case opcodes.OP_CHECKLOCKTIMEVERIFY: {
          // OP_CHECKLOCKTIMEVERIFY = OP_NOP2
          if (!(flags & Script.flags.VERIFY_CHECKLOCKTIMEVERIFY))
            break;

          if (!tx)
            throw new ScriptError('UNKNOWN_ERROR', 'No TX passed in.');

          if (stack.length === 0)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          const num = stack.getNum(-1, minimal, 5);

          if (num.isNeg())
            throw new ScriptError('NEGATIVE_LOCKTIME', op, ip);

          const locktime = num.toDouble();

          if (!tx.verifyLocktime(index, locktime))
            throw new ScriptError('UNSATISFIED_LOCKTIME', op, ip);

          break;
        }
        case opcodes.OP_CHECKSEQUENCEVERIFY: {
          // OP_CHECKSEQUENCEVERIFY = OP_NOP3
          if (!(flags & Script.flags.VERIFY_CHECKSEQUENCEVERIFY))
            break;

          if (!tx)
            throw new ScriptError('UNKNOWN_ERROR', 'No TX passed in.');

          if (stack.length === 0)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          const num = stack.getNum(-1, minimal, 5);

          if (num.isNeg())
            throw new ScriptError('NEGATIVE_LOCKTIME', op, ip);

          const locktime = num.toDouble();

          if (!tx.verifySequence(index, locktime))
            throw new ScriptError('UNSATISFIED_LOCKTIME', op, ip);

          break;
        }
        case opcodes.OP_NOP1:
        case opcodes.OP_NOP4:
        case opcodes.OP_NOP5:
        case opcodes.OP_NOP6:
        case opcodes.OP_NOP7:
        case opcodes.OP_NOP8:
        case opcodes.OP_NOP9:
        case opcodes.OP_NOP10: {
          if (flags & Script.flags.VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
            throw new ScriptError('DISCOURAGE_UPGRADABLE_NOPS', op, ip);
          break;
        }
        case opcodes.OP_IF:
        case opcodes.OP_NOTIF: {
          let val = false;

          if (!negate) {
            if (stack.length < 1)
              throw new ScriptError('UNBALANCED_CONDITIONAL', op, ip);

            if (version === 1 && (flags & Script.flags.VERIFY_MINIMALIF)) {
              const item = stack.get(-1);

              if (item.length > 1)
                throw new ScriptError('MINIMALIF');

              if (item.length === 1 && item[0] !== 1)
                throw new ScriptError('MINIMALIF');
            }

            val = stack.getBool(-1);

            if (op.value === opcodes.OP_NOTIF)
              val = !val;

            stack.pop();
          }

          state.push(val);

          if (!val)
            negate += 1;

          break;
        }
        case opcodes.OP_ELSE: {
          if (state.length === 0)
            throw new ScriptError('UNBALANCED_CONDITIONAL', op, ip);

          state[state.length - 1] = !state[state.length - 1];

          if (!state[state.length - 1])
            negate += 1;
          else
            negate -= 1;

          break;
        }
        case opcodes.OP_ENDIF: {
          if (state.length === 0)
            throw new ScriptError('UNBALANCED_CONDITIONAL', op, ip);

          if (!state.pop())
            negate -= 1;

          break;
        }
        case opcodes.OP_VERIFY: {
          if (stack.length === 0)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          if (!stack.getBool(-1))
            throw new ScriptError('VERIFY', op, ip);

          stack.pop();

          break;
        }
        case opcodes.OP_RETURN: {
          throw new ScriptError('OP_RETURN', op, ip);
        }
        case opcodes.OP_TOALTSTACK: {
          if (stack.length === 0)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          alt.push(stack.pop());
          break;
        }
        case opcodes.OP_FROMALTSTACK: {
          if (alt.length === 0)
            throw new ScriptError('INVALID_ALTSTACK_OPERATION', op, ip);

          stack.push(alt.pop());
          break;
        }
        case opcodes.OP_2DROP: {
          if (stack.length < 2)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          stack.pop();
          stack.pop();
          break;
        }
        case opcodes.OP_2DUP: {
          if (stack.length < 2)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          const v1 = stack.get(-2);
          const v2 = stack.get(-1);

          stack.push(v1);
          stack.push(v2);
          break;
        }
        case opcodes.OP_3DUP: {
          if (stack.length < 3)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          const v1 = stack.get(-3);
          const v2 = stack.get(-2);
          const v3 = stack.get(-1);

          stack.push(v1);
          stack.push(v2);
          stack.push(v3);
          break;
        }
        case opcodes.OP_2OVER: {
          if (stack.length < 4)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          const v1 = stack.get(-4);
          const v2 = stack.get(-3);

          stack.push(v1);
          stack.push(v2);
          break;
        }
        case opcodes.OP_2ROT: {
          if (stack.length < 6)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          const v1 = stack.get(-6);
          const v2 = stack.get(-5);

          stack.erase(-6, -4);
          stack.push(v1);
          stack.push(v2);
          break;
        }
        case opcodes.OP_2SWAP: {
          if (stack.length < 4)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          stack.swap(-4, -2);
          stack.swap(-3, -1);
          break;
        }
        case opcodes.OP_IFDUP: {
          if (stack.length === 0)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          if (stack.getBool(-1)) {
            const val = stack.get(-1);
            stack.push(val);
          }

          break;
        }
        case opcodes.OP_DEPTH: {
          stack.pushInt(stack.length);
          break;
        }
        case opcodes.OP_DROP: {
          if (stack.length === 0)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          stack.pop();
          break;
        }
        case opcodes.OP_DUP: {
          if (stack.length === 0)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          stack.push(stack.get(-1));
          break;
        }
        case opcodes.OP_NIP: {
          if (stack.length < 2)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          stack.remove(-2);
          break;
        }
        case opcodes.OP_OVER: {
          if (stack.length < 2)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          stack.push(stack.get(-2));
          break;
        }
        case opcodes.OP_PICK:
        case opcodes.OP_ROLL: {
          if (stack.length < 2)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          const num = stack.getInt(-1, minimal, 4);
          stack.pop();

          if (num < 0 || num >= stack.length)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          const val = stack.get(-num - 1);

          if (op.value === opcodes.OP_ROLL)
            stack.remove(-num - 1);

          stack.push(val);
          break;
        }
        case opcodes.OP_ROT: {
          if (stack.length < 3)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          stack.swap(-3, -2);
          stack.swap(-2, -1);
          break;
        }
        case opcodes.OP_SWAP: {
          if (stack.length < 2)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          stack.swap(-2, -1);
          break;
        }
        case opcodes.OP_TUCK: {
          if (stack.length < 2)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          stack.insert(-2, stack.get(-1));
          break;
        }
        case opcodes.OP_SIZE: {
          if (stack.length < 1)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          stack.pushInt(stack.get(-1).length);
          break;
        }
        case opcodes.OP_EQUAL:
        case opcodes.OP_EQUALVERIFY: {
          if (stack.length < 2)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          const v1 = stack.get(-2);
          const v2 = stack.get(-1);

          const res = v1.equals(v2);

          stack.pop();
          stack.pop();

          stack.pushBool(res);

          if (op.value === opcodes.OP_EQUALVERIFY) {
            if (!res)
              throw new ScriptError('EQUALVERIFY', op, ip);
            stack.pop();
          }

          break;
        }
        case opcodes.OP_1ADD:
        case opcodes.OP_1SUB:
        case opcodes.OP_NEGATE:
        case opcodes.OP_ABS:
        case opcodes.OP_NOT:
        case opcodes.OP_0NOTEQUAL: {
          if (stack.length < 1)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          let num = stack.getNum(-1, minimal, 4);
          let cmp;

          switch (op.value) {
            case opcodes.OP_1ADD:
              num.iaddn(1);
              break;
            case opcodes.OP_1SUB:
              num.isubn(1);
              break;
            case opcodes.OP_NEGATE:
              num.ineg();
              break;
            case opcodes.OP_ABS:
              num.iabs();
              break;
            case opcodes.OP_NOT:
              cmp = num.isZero();
              num = ScriptNum.fromBool(cmp);
              break;
            case opcodes.OP_0NOTEQUAL:
              cmp = !num.isZero();
              num = ScriptNum.fromBool(cmp);
              break;
            default:
              assert(false, 'Fatal script error.');
              break;
          }

          stack.pop();
          stack.pushNum(num);

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
          if (stack.length < 2)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          const n1 = stack.getNum(-2, minimal, 4);
          const n2 = stack.getNum(-1, minimal, 4);
          let num, cmp;

          switch (op.value) {
            case opcodes.OP_ADD:
              num = n1.iadd(n2);
              break;
            case opcodes.OP_SUB:
              num = n1.isub(n2);
              break;
            case opcodes.OP_BOOLAND:
              cmp = n1.toBool() && n2.toBool();
              num = ScriptNum.fromBool(cmp);
              break;
            case opcodes.OP_BOOLOR:
              cmp = n1.toBool() || n2.toBool();
              num = ScriptNum.fromBool(cmp);
              break;
            case opcodes.OP_NUMEQUAL:
              cmp = n1.eq(n2);
              num = ScriptNum.fromBool(cmp);
              break;
            case opcodes.OP_NUMEQUALVERIFY:
              cmp = n1.eq(n2);
              num = ScriptNum.fromBool(cmp);
              break;
            case opcodes.OP_NUMNOTEQUAL:
              cmp = !n1.eq(n2);
              num = ScriptNum.fromBool(cmp);
              break;
            case opcodes.OP_LESSTHAN:
              cmp = n1.lt(n2);
              num = ScriptNum.fromBool(cmp);
              break;
            case opcodes.OP_GREATERTHAN:
              cmp = n1.gt(n2);
              num = ScriptNum.fromBool(cmp);
              break;
            case opcodes.OP_LESSTHANOREQUAL:
              cmp = n1.lte(n2);
              num = ScriptNum.fromBool(cmp);
              break;
            case opcodes.OP_GREATERTHANOREQUAL:
              cmp = n1.gte(n2);
              num = ScriptNum.fromBool(cmp);
              break;
            case opcodes.OP_MIN:
              num = ScriptNum.min(n1, n2);
              break;
            case opcodes.OP_MAX:
              num = ScriptNum.max(n1, n2);
              break;
            default:
              assert(false, 'Fatal script error.');
              break;
          }

          stack.pop();
          stack.pop();
          stack.pushNum(num);

          if (op.value === opcodes.OP_NUMEQUALVERIFY) {
            if (!stack.getBool(-1))
              throw new ScriptError('NUMEQUALVERIFY', op, ip);
            stack.pop();
          }

          break;
        }
        case opcodes.OP_WITHIN: {
          if (stack.length < 3)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          const n1 = stack.getNum(-3, minimal, 4);
          const n2 = stack.getNum(-2, minimal, 4);
          const n3 = stack.getNum(-1, minimal, 4);

          const val = n2.lte(n1) && n1.lt(n3);

          stack.pop();
          stack.pop();
          stack.pop();

          stack.pushBool(val);
          break;
        }
        case opcodes.OP_RIPEMD160: {
          if (stack.length === 0)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          stack.push(ripemd160.digest(stack.pop()));
          break;
        }
        case opcodes.OP_SHA1: {
          if (stack.length === 0)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          stack.push(sha1.digest(stack.pop()));
          break;
        }
        case opcodes.OP_SHA256: {
          if (stack.length === 0)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          stack.push(sha256.digest(stack.pop()));
          break;
        }
        case opcodes.OP_HASH160: {
          if (stack.length === 0)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          stack.push(hash160.digest(stack.pop()));
          break;
        }
        case opcodes.OP_HASH256: {
          if (stack.length === 0)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          stack.push(hash256.digest(stack.pop()));
          break;
        }
        case opcodes.OP_CODESEPARATOR: {
          lastSep = ip + 1;
          break;
        }
        case opcodes.OP_CHECKSIG:
        case opcodes.OP_CHECKSIGVERIFY: {
          if (!tx)
            throw new ScriptError('UNKNOWN_ERROR', 'No TX passed in.');

          if (stack.length < 2)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          const sig = stack.get(-2);
          const key = stack.get(-1);

          const subscript = this.getSubscript(lastSep);

          if (version === 0) {
            const found = subscript.findAndDelete(sig);
            if (found > 0 && (flags & Script.flags.VERIFY_CONST_SCRIPTCODE))
              throw new ScriptError('SIG_FINDANDDELETE', op, ip);
          }

          validateSignature(sig, flags);
          validateKey(key, flags, version);

          let res = false;

          if (sig.length > 0) {
            const type = sig[sig.length - 1];
            const hash = tx.signatureHash(
              index,
              subscript,
              value,
              type,
              version
            );
            res = checksig(hash, sig, key);
          }

          if (!res && (flags & Script.flags.VERIFY_NULLFAIL)) {
            if (sig.length !== 0)
              throw new ScriptError('NULLFAIL', op, ip);
          }

          stack.pop();
          stack.pop();

          stack.pushBool(res);

          if (op.value === opcodes.OP_CHECKSIGVERIFY) {
            if (!res)
              throw new ScriptError('CHECKSIGVERIFY', op, ip);
            stack.pop();
          }

          break;
        }
        case opcodes.OP_CHECKMULTISIG:
        case opcodes.OP_CHECKMULTISIGVERIFY: {
          if (!tx)
            throw new ScriptError('UNKNOWN_ERROR', 'No TX passed in.');

          let i = 1;
          if (stack.length < i)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          let n = stack.getInt(-i, minimal, 4);
          let okey = n + 2;
          let ikey, isig;

          if (n < 0 || n > consensus.MAX_MULTISIG_PUBKEYS)
            throw new ScriptError('PUBKEY_COUNT', op, ip);

          opCount += n;

          if (opCount > consensus.MAX_SCRIPT_OPS)
            throw new ScriptError('OP_COUNT', op, ip);

          i += 1;
          ikey = i;
          i += n;

          if (stack.length < i)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          let m = stack.getInt(-i, minimal, 4);

          if (m < 0 || m > n)
            throw new ScriptError('SIG_COUNT', op, ip);

          i += 1;
          isig = i;
          i += m;

          if (stack.length < i)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          const subscript = this.getSubscript(lastSep);

          for (let j = 0; j < m; j++) {
            const sig = stack.get(-isig - j);
            if (version === 0) {
              const found = subscript.findAndDelete(sig);
              if (found > 0 && (flags & Script.flags.VERIFY_CONST_SCRIPTCODE))
                throw new ScriptError('SIG_FINDANDDELETE', op, ip);
            }
          }

          let res = true;
          while (res && m > 0) {
            const sig = stack.get(-isig);
            const key = stack.get(-ikey);

            validateSignature(sig, flags);
            validateKey(key, flags, version);

            if (sig.length > 0) {
              const type = sig[sig.length - 1];
              const hash = tx.signatureHash(
                index,
                subscript,
                value,
                type,
                version
              );

              if (checksig(hash, sig, key)) {
                isig += 1;
                m -= 1;
              }
            }

            ikey += 1;
            n -= 1;

            if (m > n)
              res = false;
          }

          while (i > 1) {
            if (!res && (flags & Script.flags.VERIFY_NULLFAIL)) {
              if (okey === 0 && stack.get(-1).length !== 0)
                throw new ScriptError('NULLFAIL', op, ip);
            }

            if (okey > 0)
              okey -= 1;

            stack.pop();

            i -= 1;
          }

          if (stack.length < 1)
            throw new ScriptError('INVALID_STACK_OPERATION', op, ip);

          if (flags & Script.flags.VERIFY_NULLDUMMY) {
            if (stack.get(-1).length !== 0)
              throw new ScriptError('SIG_NULLDUMMY', op, ip);
          }

          stack.pop();

          stack.pushBool(res);

          if (op.value === opcodes.OP_CHECKMULTISIGVERIFY) {
            if (!res)
              throw new ScriptError('CHECKMULTISIGVERIFY', op, ip);
            stack.pop();
          }

          break;
        }
        default: {
          throw new ScriptError('BAD_OPCODE', op, ip);
        }
      }

      if (stack.length + alt.length > consensus.MAX_SCRIPT_STACK)
        throw new ScriptError('STACK_SIZE', op, ip);
    }

    if (state.length !== 0)
      throw new ScriptError('UNBALANCED_CONDITIONAL');
  }

  /**
   * Remove all matched data elements from
   * a script's code (used to remove signatures
   * before verification). Note that this
   * compares and removes data on the _byte level_.
   * It also reserializes the data to a single
   * script with minimaldata encoding beforehand.
   * A signature will _not_ be removed if it is
   * not minimaldata.
   * @see https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2014-November/006878.html
   * @see https://test.webbtc.com/tx/19aa42fee0fa57c45d3b16488198b27caaacc4ff5794510d0c17f173f05587ff
   * @param {Buffer} data - Data element to match against.
   * @returns {Number} Total.
   */

  findAndDelete(data) {
    const target = Opcode.fromPush(data);

    if (this.raw.length < target.getSize())
      return 0;

    let found = false;

    for (const op of this.code) {
      if (op.value === -1)
        break;

      if (op.equals(target)) {
        found = true;
        break;
      }
    }

    if (!found)
      return 0;

    const code = [];

    let total = 0;

    for (const op of this.code) {
      if (op.value === -1)
        break;

      if (op.equals(target)) {
        total += 1;
        continue;
      }

      code.push(op);
    }

    this.code = code;
    this.compile();

    return total;
  }

  /**
   * Find a data element in a script.
   * @param {Buffer} data - Data element to match against.
   * @returns {Number} Index (`-1` if not present).
   */

  indexOf(data) {
    for (let i = 0; i < this.code.length; i++) {
      const op = this.code[i];

      if (op.value === -1)
        break;

      if (!op.data)
        continue;

      if (op.data.equals(data))
        return i;
    }

    return -1;
  }

  /**
   * Test a script to see if it is likely
   * to be script code (no weird opcodes).
   * @returns {Boolean}
   */

  isCode() {
    for (const op of this.code) {
      if (op.value === -1)
        return false;

      if (op.isDisabled())
        return false;

      switch (op.value) {
        case opcodes.OP_RESERVED:
        case opcodes.OP_NOP:
        case opcodes.OP_VER:
        case opcodes.OP_VERIF:
        case opcodes.OP_VERNOTIF:
        case opcodes.OP_RESERVED1:
        case opcodes.OP_RESERVED2:
        case opcodes.OP_NOP1:
          return false;
      }

      if (op.value > opcodes.OP_CHECKSEQUENCEVERIFY)
        return false;
    }

    return true;
  }

  /**
   * Inject properties from a pay-to-pubkey script.
   * @private
   * @param {Buffer} key
   */

  fromPubkey(key) {
    assert(Buffer.isBuffer(key) && (key.length === 33 || key.length === 65));

    this.raw = Buffer.allocUnsafe(1 + key.length + 1);
    this.raw[0] = key.length;
    key.copy(this.raw, 1);
    this.raw[1 + key.length] = opcodes.OP_CHECKSIG;

    key = this.raw.slice(1, 1 + key.length);

    this.code.length = 0;
    this.code.push(Opcode.fromPush(key));
    this.code.push(Opcode.fromOp(opcodes.OP_CHECKSIG));

    return this;
  }

  /**
   * Create a pay-to-pubkey script.
   * @param {Buffer} key
   * @returns {Script}
   */

  static fromPubkey(key) {
    return new this().fromPubkey(key);
  }

  /**
   * Inject properties from a pay-to-pubkeyhash script.
   * @private
   * @param {Buffer} hash
   */

  fromPubkeyhash(hash) {
    assert(Buffer.isBuffer(hash) && hash.length === 20);

    this.raw = Buffer.allocUnsafe(25);
    this.raw[0] = opcodes.OP_DUP;
    this.raw[1] = opcodes.OP_HASH160;
    this.raw[2] = 0x14;
    hash.copy(this.raw, 3);
    this.raw[23] = opcodes.OP_EQUALVERIFY;
    this.raw[24] = opcodes.OP_CHECKSIG;

    hash = this.raw.slice(3, 23);

    this.code.length = 0;
    this.code.push(Opcode.fromOp(opcodes.OP_DUP));
    this.code.push(Opcode.fromOp(opcodes.OP_HASH160));
    this.code.push(Opcode.fromPush(hash));
    this.code.push(Opcode.fromOp(opcodes.OP_EQUALVERIFY));
    this.code.push(Opcode.fromOp(opcodes.OP_CHECKSIG));

    return this;
  }

  /**
   * Create a pay-to-pubkeyhash script.
   * @param {Buffer} hash
   * @returns {Script}
   */

  static fromPubkeyhash(hash) {
    return new this().fromPubkeyhash(hash);
  }

  /**
   * Inject properties from pay-to-multisig script.
   * @private
   * @param {Number} m
   * @param {Number} n
   * @param {Buffer[]} keys
   */

  fromMultisig(m, n, keys) {
    assert((m & 0xff) === m && (n & 0xff) === n);
    assert(Array.isArray(keys));
    assert(keys.length === n, '`n` keys are required for multisig.');
    assert(m >= 1 && m <= n);
    assert(n >= 1 && n <= 15);

    this.clear();

    this.pushSmall(m);

    for (const key of sortKeys(keys))
      this.pushData(key);

    this.pushSmall(n);
    this.pushOp(opcodes.OP_CHECKMULTISIG);

    return this.compile();
  }

  /**
   * Create a pay-to-multisig script.
   * @param {Number} m
   * @param {Number} n
   * @param {Buffer[]} keys
   * @returns {Script}
   */

  static fromMultisig(m, n, keys) {
    return new this().fromMultisig(m, n, keys);
  }

  /**
   * Inject properties from a pay-to-scripthash script.
   * @private
   * @param {Buffer} hash
   */

  fromScripthash(hash) {
    assert(Buffer.isBuffer(hash) && hash.length === 20);

    this.raw = Buffer.allocUnsafe(23);
    this.raw[0] = opcodes.OP_HASH160;
    this.raw[1] = 0x14;
    hash.copy(this.raw, 2);
    this.raw[22] = opcodes.OP_EQUAL;

    hash = this.raw.slice(2, 22);

    this.code.length = 0;
    this.code.push(Opcode.fromOp(opcodes.OP_HASH160));
    this.code.push(Opcode.fromPush(hash));
    this.code.push(Opcode.fromOp(opcodes.OP_EQUAL));

    return this;
  }

  /**
   * Create a pay-to-scripthash script.
   * @param {Buffer} hash
   * @returns {Script}
   */

  static fromScripthash(hash) {
    return new this().fromScripthash(hash);
  }

  /**
   * Inject properties from a nulldata/opreturn script.
   * @private
   * @param {Buffer} flags
   */

  fromNulldata(flags) {
    assert(Buffer.isBuffer(flags));
    assert(flags.length <= policy.MAX_OP_RETURN, 'Nulldata too large.');

    this.clear();
    this.pushOp(opcodes.OP_RETURN);
    this.pushData(flags);

    return this.compile();
  }

  /**
   * Create a nulldata/opreturn script.
   * @param {Buffer} flags
   * @returns {Script}
   */

  static fromNulldata(flags) {
    return new this().fromNulldata(flags);
  }

  /**
   * Inject properties from a witness program.
   * @private
   * @param {Number} version
   * @param {Buffer} data
   */

  fromProgram(version, data) {
    assert((version & 0xff) === version && version >= 0 && version <= 16);
    assert(Buffer.isBuffer(data) && data.length >= 2 && data.length <= 40);

    this.raw = Buffer.allocUnsafe(2 + data.length);
    this.raw[0] = version === 0 ? 0 : version + 0x50;
    this.raw[1] = data.length;
    data.copy(this.raw, 2);

    data = this.raw.slice(2, 2 + data.length);

    this.code.length = 0;
    this.code.push(Opcode.fromSmall(version));
    this.code.push(Opcode.fromPush(data));

    return this;
  }

  /**
   * Create a witness program.
   * @param {Number} version
   * @param {Buffer} data
   * @returns {Script}
   */

  static fromProgram(version, data) {
    return new this().fromProgram(version, data);
  }

  /**
   * Inject properties from an address.
   * @private
   * @param {Address|AddressString} address
   */

  fromAddress(address) {
    if (typeof address === 'string')
      address = Address.fromString(address);

    assert(address instanceof Address, 'Not an address.');

    if (address.isPubkeyhash())
      return this.fromPubkeyhash(address.hash);

    if (address.isScripthash())
      return this.fromScripthash(address.hash);

    if (address.isProgram())
      return this.fromProgram(address.version, address.hash);

    throw new Error('Unknown address type.');
  }

  /**
   * Create an output script from an address.
   * @param {Address|AddressString} address
   * @returns {Script}
   */

  static fromAddress(address) {
    return new this().fromAddress(address);
  }

  /**
   * Inject properties from a witness block commitment.
   * @private
   * @param {Buffer} hash
   * @param {String|Buffer} flags
   */

  fromCommitment(hash, flags) {
    const bw = bio.write(36);

    bw.writeU32BE(0xaa21a9ed);
    bw.writeHash(hash);

    this.clear();
    this.pushOp(opcodes.OP_RETURN);
    this.pushData(bw.render());

    if (flags)
      this.pushData(flags);

    return this.compile();
  }

  /**
   * Create a witness block commitment.
   * @param {Buffer} hash
   * @param {String|Buffer} flags
   * @returns {Script}
   */

  static fromCommitment(hash, flags) {
    return new this().fromCommitment(hash, flags);
  }

  /**
   * Grab and deserialize the redeem script.
   * @returns {Script|null} Redeem script.
   */

  getRedeem() {
    let data = null;

    for (const op of this.code) {
      if (op.value === -1)
        return null;

      if (op.value > opcodes.OP_16)
        return null;

      data = op.data;
    }

    if (!data)
      return null;

    return Script.fromRaw(data);
  }

  /**
   * Get the standard script type.
   * @returns {ScriptType}
   */

  getType() {
    if (this.isPubkey())
      return scriptTypes.PUBKEY;

    if (this.isPubkeyhash())
      return scriptTypes.PUBKEYHASH;

    if (this.isScripthash())
      return scriptTypes.SCRIPTHASH;

    if (this.isWitnessPubkeyhash())
      return scriptTypes.WITNESSPUBKEYHASH;

    if (this.isWitnessScripthash())
      return scriptTypes.WITNESSSCRIPTHASH;

    if (this.isMultisig())
      return scriptTypes.MULTISIG;

    if (this.isNulldata())
      return scriptTypes.NULLDATA;

    return scriptTypes.NONSTANDARD;
  }

  /**
   * Test whether a script is of an unknown/non-standard type.
   * @returns {Boolean}
   */

  isUnknown() {
    return this.getType() === scriptTypes.NONSTANDARD;
  }

  /**
   * Test whether the script is standard by policy standards.
   * @returns {Boolean}
   */

  isStandard() {
    const [m, n] = this.getMultisig();

    if (m !== -1) {
      if (n < 1 || n > 3)
        return false;

      if (m < 1 || m > n)
        return false;

      return true;
    }

    if (this.isNulldata())
      return this.raw.length <= policy.MAX_OP_RETURN_BYTES;

    return this.getType() !== scriptTypes.NONSTANDARD;
  }

  /**
   * Calculate the size of the script
   * excluding the varint size bytes.
   * @returns {Number}
   */

  getSize() {
    return this.raw.length;
  }

  /**
   * Calculate the size of the script
   * including the varint size bytes.
   * @returns {Number}
   */

  getVarSize() {
    return encoding.sizeVarBytes(this.raw);
  }

  /**
   * "Guess" the address of the input script.
   * This method is not 100% reliable.
   * @returns {Address|null}
   */

  getInputAddress() {
    return Address.fromInputScript(this);
  }

  /**
   * Get the address of the script if present. Note that
   * pubkey and multisig scripts will be treated as though
   * they are pubkeyhash and scripthashes respectively.
   * @returns {Address|null}
   */

  getAddress() {
    return Address.fromScript(this);
  }

  /**
   * Get the hash160 of the raw script.
   * @param {String?} enc
   * @returns {Hash}
   */

  hash160(enc) {
    let hash = hash160.digest(this.toRaw());
    if (enc === 'hex')
      hash = hash.toString('hex');
    return hash;
  }

  /**
   * Get the sha256 of the raw script.
   * @param {String?} enc
   * @returns {Hash}
   */

  sha256(enc) {
    let hash = sha256.digest(this.toRaw());
    if (enc === 'hex')
      hash = hash.toString('hex');
    return hash;
  }

  /**
   * Test whether the output script is pay-to-pubkey.
   * @param {Boolean} [minimal=false] - Minimaldata only.
   * @returns {Boolean}
   */

  isPubkey(minimal) {
    if (minimal) {
      return this.raw.length >= 35
        && (this.raw[0] === 33 || this.raw[0] === 65)
        && this.raw[0] + 2 === this.raw.length
        && this.raw[this.raw.length - 1] === opcodes.OP_CHECKSIG;
    }

    if (this.code.length !== 2)
      return false;

    const size = this.getLength(0);

    return (size === 33 || size === 65)
      && this.getOp(1) === opcodes.OP_CHECKSIG;
  }

  /**
   * Get P2PK key if present.
   * @param {Boolean} [minimal=false] - Minimaldata only.
   * @returns {Buffer|null}
   */

  getPubkey(minimal) {
    if (!this.isPubkey(minimal))
      return null;

    if (minimal)
      return this.raw.slice(1, 1 + this.raw[0]);

    return this.getData(0);
  }

  /**
   * Test whether the output script is pay-to-pubkeyhash.
   * @param {Boolean} [minimal=false] - Minimaldata only.
   * @returns {Boolean}
   */

  isPubkeyhash(minimal) {
    if (minimal || this.raw.length === 25) {
      return this.raw.length === 25
        && this.raw[0] === opcodes.OP_DUP
        && this.raw[1] === opcodes.OP_HASH160
        && this.raw[2] === 0x14
        && this.raw[23] === opcodes.OP_EQUALVERIFY
        && this.raw[24] === opcodes.OP_CHECKSIG;
    }

    if (this.code.length !== 5)
      return false;

    return this.getOp(0) === opcodes.OP_DUP
      && this.getOp(1) === opcodes.OP_HASH160
      && this.getLength(2) === 20
      && this.getOp(3) === opcodes.OP_EQUALVERIFY
      && this.getOp(4) === opcodes.OP_CHECKSIG;
  }

  /**
   * Get P2PKH hash if present.
   * @param {Boolean} [minimal=false] - Minimaldata only.
   * @returns {Buffer|null}
   */

  getPubkeyhash(minimal) {
    if (!this.isPubkeyhash(minimal))
      return null;

    if (minimal)
      return this.raw.slice(3, 23);

    return this.getData(2);
  }

  /**
   * Test whether the output script is pay-to-multisig.
   * @param {Boolean} [minimal=false] - Minimaldata only.
   * @returns {Boolean}
   */

  isMultisig(minimal) {
    if (this.code.length < 4 || this.code.length > 19)
      return false;

    if (this.getOp(-1) !== opcodes.OP_CHECKMULTISIG)
      return false;

    const m = this.getSmall(0);

    if (m < 1)
      return false;

    const n = this.getSmall(-2);

    if (n < 1 || m > n)
      return false;

    if (this.code.length !== n + 3)
      return false;

    for (let i = 1; i < n + 1; i++) {
      const op = this.code[i];
      const size = op.toLength();

      if (size !== 33 && size !== 65)
        return false;

      if (minimal && !op.isMinimal())
        return false;
    }

    return true;
  }

  /**
   * Get multisig m and n values if present.
   * @param {Boolean} [minimal=false] - Minimaldata only.
   * @returns {Array} [m, n]
   */

  getMultisig(minimal) {
    if (!this.isMultisig(minimal))
      return [-1, -1];

    return [this.getSmall(0), this.getSmall(-2)];
  }

  /**
   * Test whether the output script is pay-to-scripthash. Note that
   * bitcoin itself requires scripthashes to be in strict minimaldata
   * encoding. Using `OP_HASH160 OP_PUSHDATA1 [hash] OP_EQUAL` will
   * _not_ be recognized as a scripthash.
   * @returns {Boolean}
   */

  isScripthash() {
    return this.raw.length === 23
      && this.raw[0] === opcodes.OP_HASH160
      && this.raw[1] === 0x14
      && this.raw[22] === opcodes.OP_EQUAL;
  }

  /**
   * Get P2SH hash if present.
   * @returns {Buffer|null}
   */

  getScripthash() {
    if (!this.isScripthash())
      return null;

    return this.getData(1);
  }

  /**
   * Test whether the output script is nulldata/opreturn.
   * @param {Boolean} [minimal=false] - Minimaldata only.
   * @returns {Boolean}
   */

  isNulldata(minimal) {
    if (this.code.length === 0)
      return false;

    if (this.getOp(0) !== opcodes.OP_RETURN)
      return false;

    if (this.code.length === 1)
      return true;

    if (minimal) {
      if (this.raw.length > policy.MAX_OP_RETURN_BYTES)
        return false;
    }

    for (let i = 1; i < this.code.length; i++) {
      const op = this.code[i];

      if (op.value === -1)
        return false;

      if (op.value > opcodes.OP_16)
        return false;

      if (minimal && !op.isMinimal())
        return false;
    }

    return true;
  }

  /**
   * Get OP_RETURN data if present.
   * @param {Boolean} [minimal=false] - Minimaldata only.
   * @returns {Buffer|null}
   */

  getNulldata(minimal) {
    if (!this.isNulldata(minimal))
      return null;

    for (let i = 1; i < this.code.length; i++) {
      const op = this.code[i];
      const data = op.toPush();
      if (data)
        return data;
    }

    return EMPTY_BUFFER;
  }

  /**
   * Test whether the output script is a segregated witness
   * commitment.
   * @returns {Boolean}
   */

  isCommitment() {
    return this.raw.length >= 38
      && this.raw[0] === opcodes.OP_RETURN
      && this.raw[1] === 0x24
      && this.raw.readUInt32BE(2, true) === 0xaa21a9ed;
  }

  /**
   * Get the commitment hash if present.
   * @returns {Buffer|null}
   */

  getCommitment() {
    if (!this.isCommitment())
      return null;

    return this.raw.slice(6, 38);
  }

  /**
   * Test whether the output script is a witness program.
   * Note that this will return true even for malformed
   * witness v0 programs.
   * @return {Boolean}
   */

  isProgram() {
    if (this.raw.length < 4 || this.raw.length > 42)
      return false;

    if (this.raw[0] !== opcodes.OP_0
        && (this.raw[0] < opcodes.OP_1 || this.raw[0] > opcodes.OP_16)) {
      return false;
    }

    if (this.raw[1] + 2 !== this.raw.length)
      return false;

    return true;
  }

  /**
   * Get the witness program if present.
   * @returns {Program|null}
   */

  getProgram() {
    if (!this.isProgram())
      return null;

    const version = this.getSmall(0);
    const data = this.getData(1);

    return new Program(version, data);
  }

  /**
   * Get the script to the equivalent witness
   * program (mimics bitcoind's scriptForWitness).
   * @returns {Script|null}
   */

  forWitness() {
    if (this.isProgram())
      return this.clone();

    const pk = this.getPubkey();
    if (pk) {
      const hash = hash160.digest(pk);
      return Script.fromProgram(0, hash);
    }

    const pkh = this.getPubkeyhash();
    if (pkh)
      return Script.fromProgram(0, pkh);

    return Script.fromProgram(0, this.sha256());
  }

  /**
   * Test whether the output script is
   * a pay-to-witness-pubkeyhash program.
   * @returns {Boolean}
   */

  isWitnessPubkeyhash() {
    return this.raw.length === 22
      && this.raw[0] === opcodes.OP_0
      && this.raw[1] === 0x14;
  }

  /**
   * Get P2WPKH hash if present.
   * @returns {Buffer|null}
   */

  getWitnessPubkeyhash() {
    if (!this.isWitnessPubkeyhash())
      return null;

    return this.getData(1);
  }

  /**
   * Test whether the output script is
   * a pay-to-witness-scripthash program.
   * @returns {Boolean}
   */

  isWitnessScripthash() {
    return this.raw.length === 34
      && this.raw[0] === opcodes.OP_0
      && this.raw[1] === 0x20;
  }

  /**
   * Get P2WSH hash if present.
   * @returns {Buffer|null}
   */

  getWitnessScripthash() {
    if (!this.isWitnessScripthash())
      return null;

    return this.getData(1);
  }

  /**
   * Test whether the output script is unspendable.
   * @returns {Boolean}
   */

  isUnspendable() {
    if (this.raw.length > consensus.MAX_SCRIPT_SIZE)
      return true;

    return this.raw.length > 0 && this.raw[0] === opcodes.OP_RETURN;
  }

  /**
   * "Guess" the type of the input script.
   * This method is not 100% reliable.
   * @returns {ScriptType}
   */

  getInputType() {
    if (this.isPubkeyInput())
      return scriptTypes.PUBKEY;

    if (this.isPubkeyhashInput())
      return scriptTypes.PUBKEYHASH;

    if (this.isScripthashInput())
      return scriptTypes.SCRIPTHASH;

    if (this.isMultisigInput())
      return scriptTypes.MULTISIG;

    return scriptTypes.NONSTANDARD;
  }

  /**
   * "Guess" whether the input script is an unknown/non-standard type.
   * This method is not 100% reliable.
   * @returns {Boolean}
   */

  isUnknownInput() {
    return this.getInputType() === scriptTypes.NONSTANDARD;
  }

  /**
   * "Guess" whether the input script is pay-to-pubkey.
   * This method is not 100% reliable.
   * @returns {Boolean}
   */

  isPubkeyInput() {
    if (this.code.length !== 1)
      return false;

    const size = this.getLength(0);

    return size >= 9 && size <= 73;
  }

  /**
   * Get P2PK signature if present.
   * @returns {Buffer|null}
   */

  getPubkeyInput() {
    if (!this.isPubkeyInput())
      return null;

    return this.getData(0);
  }

  /**
   * "Guess" whether the input script is pay-to-pubkeyhash.
   * This method is not 100% reliable.
   * @returns {Boolean}
   */

  isPubkeyhashInput() {
    if (this.code.length !== 2)
      return false;

    const sig = this.getLength(0);
    const key = this.getLength(1);

    return sig >= 9 && sig <= 73
      && (key === 33 || key === 65);
  }

  /**
   * Get P2PKH signature and key if present.
   * @returns {Array} [sig, key]
   */

  getPubkeyhashInput() {
    if (!this.isPubkeyhashInput())
      return [null, null];

    return [this.getData(0), this.getData(1)];
  }

  /**
   * "Guess" whether the input script is pay-to-multisig.
   * This method is not 100% reliable.
   * @returns {Boolean}
   */

  isMultisigInput() {
    if (this.code.length < 2)
      return false;

    if (this.getOp(0) !== opcodes.OP_0)
      return false;

    if (this.getOp(1) > opcodes.OP_PUSHDATA4)
      return false;

    // We need to rule out scripthash
    // because it may look like multisig.
    if (this.isScripthashInput())
      return false;

    for (let i = 1; i < this.code.length; i++) {
      const size = this.getLength(i);
      if (size < 9 || size > 73)
        return false;
    }

    return true;
  }

  /**
   * Get multisig signatures if present.
   * @returns {Buffer[]|null}
   */

  getMultisigInput() {
    if (!this.isMultisigInput())
      return null;

    const sigs = [];

    for (let i = 1; i < this.code.length; i++)
      sigs.push(this.getData(i));

    return sigs;
  }

  /**
   * "Guess" whether the input script is pay-to-scripthash.
   * This method is not 100% reliable.
   * @returns {Boolean}
   */

  isScripthashInput() {
    if (this.code.length < 1)
      return false;

    // Grab the raw redeem script.
    const raw = this.getData(-1);

    // Last data element should be an array
    // for the redeem script.
    if (!raw)
      return false;

    // Testing for scripthash inputs requires
    // some evil magic to work. We do it by
    // ruling things _out_. This test will not
    // be correct 100% of the time. We rule
    // out that the last data element is: a
    // null dummy, a valid signature, a valid
    // key, and we ensure that it is at least
    // a script that does not use undefined
    // opcodes.
    if (raw.length === 0)
      return false;

    if (common.isSignatureEncoding(raw))
      return false;

    if (common.isKeyEncoding(raw))
      return false;

    const redeem = Script.fromRaw(raw);

    if (!redeem.isCode())
      return false;

    if (redeem.isUnspendable())
      return false;

    if (!this.isPushOnly())
      return false;

    return true;
  }

  /**
   * Get P2SH redeem script if present.
   * @returns {Buffer|null}
   */

  getScripthashInput() {
    if (!this.isScripthashInput())
      return null;

    return this.getData(-1);
  }

  /**
   * Get coinbase height.
   * @returns {Number} `-1` if not present.
   */

  getCoinbaseHeight() {
    return Script.getCoinbaseHeight(this.raw);
  }

  /**
   * Get coinbase height.
   * @param {Buffer} raw - Raw script.
   * @returns {Number} `-1` if not present.
   */

  static getCoinbaseHeight(raw) {
    if (raw.length === 0)
      return -1;

    if (raw[0] >= opcodes.OP_1 && raw[0] <= opcodes.OP_16)
      return raw[0] - 0x50;

    if (raw[0] > 0x06)
      return -1;

    const op = Opcode.fromRaw(raw);
    const num = op.toNum();

    if (!num)
      return 1;

    if (num.isNeg())
      return -1;

    if (!op.equals(Opcode.fromNum(num)))
      return -1;

    return num.toDouble();
  }

  /**
   * Test the script against a bloom filter.
   * @param {BloomFilter} filter
   * @returns {Boolean}
   */

  test(filter) {
    for (const op of this.code) {
      if (op.value === -1)
        break;

      if (!op.data || op.data.length === 0)
        continue;

      if (filter.test(op.data))
        return true;
    }

    return false;
  }

  /**
   * Test the script to see if it contains only push ops.
   * Push ops are: OP_1NEGATE, OP_0-OP_16 and all PUSHDATAs.
   * @returns {Boolean}
   */

  isPushOnly() {
    for (const op of this.code) {
      if (op.value === -1)
        return false;

      if (op.value > opcodes.OP_16)
        return false;
    }

    return true;
  }

  /**
   * Count the sigops in the script.
   * @param {Boolean} accurate - Whether to enable accurate counting. This will
   * take into account the `n` value for OP_CHECKMULTISIG(VERIFY).
   * @returns {Number} sigop count
   */

  getSigops(accurate) {
    let total = 0;
    let lastOp = -1;

    for (const op of this.code) {
      if (op.value === -1)
        break;

      switch (op.value) {
        case opcodes.OP_CHECKSIG:
        case opcodes.OP_CHECKSIGVERIFY:
          total += 1;
          break;
        case opcodes.OP_CHECKMULTISIG:
        case opcodes.OP_CHECKMULTISIGVERIFY:
          if (accurate && lastOp >= opcodes.OP_1 && lastOp <= opcodes.OP_16)
            total += lastOp - 0x50;
          else
            total += consensus.MAX_MULTISIG_PUBKEYS;
          break;
      }

      lastOp = op.value;
    }

    return total;
  }

  /**
   * Count the sigops in the script, taking into account redeem scripts.
   * @param {Script} input - Input script, needed for access to redeem script.
   * @returns {Number} sigop count
   */

  getScripthashSigops(input) {
    if (!this.isScripthash())
      return this.getSigops(true);

    const redeem = input.getRedeem();

    if (!redeem)
      return 0;

    return redeem.getSigops(true);
  }

  /**
   * Count the sigops in a script, taking into account witness programs.
   * @param {Script} input
   * @param {Witness} witness
   * @returns {Number} sigop count
   */

  getWitnessSigops(input, witness) {
    let program = this.getProgram();

    if (!program) {
      if (this.isScripthash()) {
        const redeem = input.getRedeem();
        if (redeem)
          program = redeem.getProgram();
      }
    }

    if (!program)
      return 0;

    if (program.version === 0) {
      if (program.data.length === 20)
        return 1;

      if (program.data.length === 32 && witness.items.length > 0) {
        const redeem = witness.getRedeem();
        return redeem.getSigops(true);
      }
    }

    return 0;
  }

  /*
   * Mutation
   */

  get(index) {
    if (index < 0)
      index += this.code.length;

    if (index < 0 || index >= this.code.length)
      return null;

    return this.code[index];
  }

  pop() {
    const op = this.code.pop();
    return op || null;
  }

  shift() {
    const op = this.code.shift();
    return op || null;
  }

  remove(index) {
    if (index < 0)
      index += this.code.length;

    if (index < 0 || index >= this.code.length)
      return null;

    const items = this.code.splice(index, 1);

    if (items.length === 0)
      return null;

    return items[0];
  }

  set(index, op) {
    if (index < 0)
      index += this.code.length;

    assert(Opcode.isOpcode(op));
    assert(index >= 0 && index <= this.code.length);

    this.code[index] = op;

    return this;
  }

  push(op) {
    assert(Opcode.isOpcode(op));
    this.code.push(op);
    return this;
  }

  unshift(op) {
    assert(Opcode.isOpcode(op));
    this.code.unshift(op);
    return this;
  }

  insert(index, op) {
    if (index < 0)
      index += this.code.length;

    assert(Opcode.isOpcode(op));
    assert(index >= 0 && index <= this.code.length);

    this.code.splice(index, 0, op);

    return this;
  }

  /*
   * Op
   */

  getOp(index) {
    const op = this.get(index);
    return op ? op.value : -1;
  }

  popOp() {
    const op = this.pop();
    return op ? op.value : -1;
  }

  shiftOp() {
    const op = this.shift();
    return op ? op.value : -1;
  }

  removeOp(index) {
    const op = this.remove(index);
    return op ? op.value : -1;
  }

  setOp(index, value) {
    return this.set(index, Opcode.fromOp(value));
  }

  pushOp(value) {
    return this.push(Opcode.fromOp(value));
  }

  unshiftOp(value) {
    return this.unshift(Opcode.fromOp(value));
  }

  insertOp(index, value) {
    return this.insert(index, Opcode.fromOp(value));
  }

  /*
   * Data
   */

  getData(index) {
    const op = this.get(index);
    return op ? op.data : null;
  }

  popData() {
    const op = this.pop();
    return op ? op.data : null;
  }

  shiftData() {
    const op = this.shift();
    return op ? op.data : null;
  }

  removeData(index) {
    const op = this.remove(index);
    return op ? op.data : null;
  }

  setData(index, data) {
    return this.set(index, Opcode.fromData(data));
  }

  pushData(data) {
    return this.push(Opcode.fromData(data));
  }

  unshiftData(data) {
    return this.unshift(Opcode.fromData(data));
  }

  insertData(index, data) {
    return this.insert(index, Opcode.fromData(data));
  }

  /*
   * Length
   */

  getLength(index) {
    const op = this.get(index);
    return op ? op.toLength() : -1;
  }

  /*
   * Push
   */

  getPush(index) {
    const op = this.get(index);
    return op ? op.toPush() : null;
  }

  popPush() {
    const op = this.pop();
    return op ? op.toPush() : null;
  }

  shiftPush() {
    const op = this.shift();
    return op ? op.toPush() : null;
  }

  removePush(index) {
    const op = this.remove(index);
    return op ? op.toPush() : null;
  }

  setPush(index, data) {
    return this.set(index, Opcode.fromPush(data));
  }

  pushPush(data) {
    return this.push(Opcode.fromPush(data));
  }

  unshiftPush(data) {
    return this.unshift(Opcode.fromPush(data));
  }

  insertPush(index, data) {
    return this.insert(index, Opcode.fromPush(data));
  }

  /*
   * String
   */

  getString(index, enc) {
    const op = this.get(index);
    return op ? op.toString(enc) : null;
  }

  popString(enc) {
    const op = this.pop();
    return op ? op.toString(enc) : null;
  }

  shiftString(enc) {
    const op = this.shift();
    return op ? op.toString(enc) : null;
  }

  removeString(index, enc) {
    const op = this.remove(index);
    return op ? op.toString(enc) : null;
  }

  setString(index, str, enc) {
    return this.set(index, Opcode.fromString(str, enc));
  }

  pushString(str, enc) {
    return this.push(Opcode.fromString(str, enc));
  }

  unshiftString(str, enc) {
    return this.unshift(Opcode.fromString(str, enc));
  }

  insertString(index, str, enc) {
    return this.insert(index, Opcode.fromString(str, enc));
  }

  /*
   * Small
   */

  getSmall(index) {
    const op = this.get(index);
    return op ? op.toSmall() : -1;
  }

  popSmall() {
    const op = this.pop();
    return op ? op.toSmall() : -1;
  }

  shiftSmall() {
    const op = this.shift();
    return op ? op.toSmall() : -1;
  }

  removeSmall(index) {
    const op = this.remove(index);
    return op ? op.toSmall() : -1;
  }

  setSmall(index, num) {
    return this.set(index, Opcode.fromSmall(num));
  }

  pushSmall(num) {
    return this.push(Opcode.fromSmall(num));
  }

  unshiftSmall(num) {
    return this.unshift(Opcode.fromSmall(num));
  }

  insertSmall(index, num) {
    return this.insert(index, Opcode.fromSmall(num));
  }

  /*
   * Num
   */

  getNum(index, minimal, limit) {
    const op = this.get(index);
    return op ? op.toNum(minimal, limit) : null;
  }

  popNum(minimal, limit) {
    const op = this.pop();
    return op ? op.toNum(minimal, limit) : null;
  }

  shiftNum(minimal, limit) {
    const op = this.shift();
    return op ? op.toNum(minimal, limit) : null;
  }

  removeNum(index, minimal, limit) {
    const op = this.remove(index);
    return op ? op.toNum(minimal, limit) : null;
  }

  setNum(index, num) {
    return this.set(index, Opcode.fromNum(num));
  }

  pushNum(num) {
    return this.push(Opcode.fromNum(num));
  }

  unshiftNum(num) {
    return this.unshift(Opcode.fromNum(num));
  }

  insertNum(index, num) {
    return this.insert(index, Opcode.fromNum(num));
  }

  /*
   * Int
   */

  getInt(index, minimal, limit) {
    const op = this.get(index);
    return op ? op.toInt(minimal, limit) : -1;
  }

  popInt(minimal, limit) {
    const op = this.pop();
    return op ? op.toInt(minimal, limit) : -1;
  }

  shiftInt(minimal, limit) {
    const op = this.shift();
    return op ? op.toInt(minimal, limit) : -1;
  }

  removeInt(index, minimal, limit) {
    const op = this.remove(index);
    return op ? op.toInt(minimal, limit) : -1;
  }

  setInt(index, num) {
    return this.set(index, Opcode.fromInt(num));
  }

  pushInt(num) {
    return this.push(Opcode.fromInt(num));
  }

  unshiftInt(num) {
    return this.unshift(Opcode.fromInt(num));
  }

  insertInt(index, num) {
    return this.insert(index, Opcode.fromInt(num));
  }

  /*
   * Bool
   */

  getBool(index) {
    const op = this.get(index);
    return op ? op.toBool() : false;
  }

  popBool() {
    const op = this.pop();
    return op ? op.toBool() : false;
  }

  shiftBool() {
    const op = this.shift();
    return op ? op.toBool() : false;
  }

  removeBool(index) {
    const op = this.remove(index);
    return op ? op.toBool() : false;
  }

  setBool(index, value) {
    return this.set(index, Opcode.fromBool(value));
  }

  pushBool(value) {
    return this.push(Opcode.fromBool(value));
  }

  unshiftBool(value) {
    return this.unshift(Opcode.fromBool(value));
  }

  insertBool(index, value) {
    return this.insert(index, Opcode.fromBool(value));
  }

  /*
   * Symbol
   */

  getSym(index) {
    const op = this.get(index);
    return op ? op.toSymbol() : null;
  }

  popSym() {
    const op = this.pop();
    return op ? op.toSymbol() : null;
  }

  shiftSym() {
    const op = this.shift();
    return op ? op.toSymbol() : null;
  }

  removeSym(index) {
    const op = this.remove(index);
    return op ? op.toSymbol() : null;
  }

  setSym(index, symbol) {
    return this.set(index, Opcode.fromSymbol(symbol));
  }

  pushSym(symbol) {
    return this.push(Opcode.fromSymbol(symbol));
  }

  unshiftSym(symbol) {
    return this.unshift(Opcode.fromSymbol(symbol));
  }

  insertSym(index, symbol) {
    return this.insert(index, Opcode.fromSymbol(symbol));
  }

  /**
   * Inject properties from bitcoind test string.
   * @private
   * @param {String} code - Script string.
   * @throws Parse error.
   */

  fromString(code) {
    assert(typeof code === 'string');

    code = code.trim();

    if (code.length === 0)
      return this;

    const items = code.split(/\s+/);
    const bw = bio.write();

    for (const item of items) {
      let symbol = item;

      if (symbol.charCodeAt(0) & 32)
        symbol = symbol.toUpperCase();

      if (!/^OP_/.test(symbol))
        symbol = `OP_${symbol}`;

      const value = opcodes[symbol];

      if (value == null) {
        if (item[0] === '\'') {
          assert(item[item.length - 1] === '\'', 'Invalid string.');
          const str = item.slice(1, -1);
          const op = Opcode.fromString(str);
          bw.writeBytes(op.toRaw());
          continue;
        }

        if (/^-?\d+$/.test(item)) {
          const num = ScriptNum.fromString(item, 10);
          const op = Opcode.fromNum(num);
          bw.writeBytes(op.toRaw());
          continue;
        }

        assert(item.indexOf('0x') === 0, 'Unknown opcode.');

        const hex = item.substring(2);
        const data = Buffer.from(hex, 'hex');

        assert(data.length === hex.length / 2, 'Invalid hex string.');

        bw.writeBytes(data);

        continue;
      }

      bw.writeU8(value);
    }

    return this.fromRaw(bw.render());
  }

  /**
   * Parse a bitcoind test script
   * string into a script object.
   * @param {String} code - Script string.
   * @returns {Script}
   * @throws Parse error.
   */

  static fromString(code) {
    return new this().fromString(code);
  }

  /**
   * Verify an input and output script, and a witness if present.
   * @param {Script} input
   * @param {Witness} witness
   * @param {Script} output
   * @param {TX} tx
   * @param {Number} index
   * @param {Amount} value
   * @param {VerifyFlags} flags
   * @throws {ScriptError}
   */

  static verify(input, witness, output, tx, index, value, flags) {
    if (flags == null)
      flags = Script.flags.STANDARD_VERIFY_FLAGS;

    if (flags & Script.flags.VERIFY_SIGPUSHONLY) {
      if (!input.isPushOnly())
        throw new ScriptError('SIG_PUSHONLY');
    }

    // Setup a stack.
    let stack = new Stack();

    // Execute the input script
    input.execute(stack, flags, tx, index, value, 0);

    // Copy the stack for P2SH
    let copy;
    if (flags & Script.flags.VERIFY_P2SH)
      copy = stack.clone();

    // Execute the previous output script.
    output.execute(stack, flags, tx, index, value, 0);

    // Verify the stack values.
    if (stack.length === 0 || !stack.getBool(-1))
      throw new ScriptError('EVAL_FALSE');

    let hadWitness = false;

    if ((flags & Script.flags.VERIFY_WITNESS) && output.isProgram()) {
      hadWitness = true;

      // Input script must be empty.
      if (input.raw.length !== 0)
        throw new ScriptError('WITNESS_MALLEATED');

      // Verify the program in the output script.
      Script.verifyProgram(witness, output, flags, tx, index, value);

      // Force a cleanstack
      stack.length = 1;
    }

    // If the script is P2SH, execute the real output script
    if ((flags & Script.flags.VERIFY_P2SH) && output.isScripthash()) {
      // P2SH can only have push ops in the scriptSig
      if (!input.isPushOnly())
        throw new ScriptError('SIG_PUSHONLY');

      // Reset the stack
      stack = copy;

      // Stack should not be empty at this point
      if (stack.length === 0)
        throw new ScriptError('EVAL_FALSE');

      // Grab the real redeem script
      const raw = stack.pop();
      const redeem = Script.fromRaw(raw);

      // Execute the redeem script.
      redeem.execute(stack, flags, tx, index, value, 0);

      // Verify the the stack values.
      if (stack.length === 0 || !stack.getBool(-1))
        throw new ScriptError('EVAL_FALSE');

      if ((flags & Script.flags.VERIFY_WITNESS) && redeem.isProgram()) {
        hadWitness = true;

        // Input script must be exactly one push of the redeem script.
        if (!input.raw.equals(Opcode.fromPush(raw).toRaw()))
          throw new ScriptError('WITNESS_MALLEATED_P2SH');

        // Verify the program in the redeem script.
        Script.verifyProgram(witness, redeem, flags, tx, index, value);

        // Force a cleanstack.
        stack.length = 1;
      }
    }

    // Ensure there is nothing left on the stack.
    if (flags & Script.flags.VERIFY_CLEANSTACK) {
      assert((flags & Script.flags.VERIFY_P2SH) !== 0);
      if (stack.length !== 1)
        throw new ScriptError('CLEANSTACK');
    }

    // If we had a witness but no witness program, fail.
    if (flags & Script.flags.VERIFY_WITNESS) {
      assert((flags & Script.flags.VERIFY_P2SH) !== 0);
      if (!hadWitness && witness.items.length > 0)
        throw new ScriptError('WITNESS_UNEXPECTED');
    }
  }

  /**
   * Verify a witness program. This runs after regular script
   * execution if a witness program is present. It will convert
   * the witness to a stack and execute the program.
   * @param {Witness} witness
   * @param {Script} output
   * @param {VerifyFlags} flags
   * @param {TX} tx
   * @param {Number} index
   * @param {Amount} value
   * @throws {ScriptError}
   */

  static verifyProgram(witness, output, flags, tx, index, value) {
    const program = output.getProgram();

    assert(program, 'verifyProgram called on non-witness-program.');
    assert((flags & Script.flags.VERIFY_WITNESS) !== 0);

    const stack = witness.toStack();
    let redeem;

    if (program.version === 0) {
      if (program.data.length === 32) {
        if (stack.length === 0)
          throw new ScriptError('WITNESS_PROGRAM_WITNESS_EMPTY');

        const witnessScript = stack.pop();

        if (!sha256.digest(witnessScript).equals(program.data))
          throw new ScriptError('WITNESS_PROGRAM_MISMATCH');

        redeem = Script.fromRaw(witnessScript);
      } else if (program.data.length === 20) {
        if (stack.length !== 2)
          throw new ScriptError('WITNESS_PROGRAM_MISMATCH');

        redeem = Script.fromPubkeyhash(program.data);
      } else {
        // Failure on version=0 (bad program data length).
        throw new ScriptError('WITNESS_PROGRAM_WRONG_LENGTH');
      }
    } else {
      // Anyone can spend (we can return true here
      // if we want to always relay these transactions).
      // Otherwise, if we want to act like an "old"
      // implementation and only accept them in blocks,
      // we can use the regular output script which will
      // succeed in a block, but fail in the mempool
      // due to VERIFY_CLEANSTACK.
      if (flags & Script.flags.VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
        throw new ScriptError('DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM');
      return;
    }

    // Witnesses still have push limits.
    for (let j = 0; j < stack.length; j++) {
      if (stack.get(j).length > consensus.MAX_SCRIPT_PUSH)
        throw new ScriptError('PUSH_SIZE');
    }

    // Verify the redeem script.
    redeem.execute(stack, flags, tx, index, value, 1);

    // Verify the stack values.
    if (stack.length !== 1)
      throw new ScriptError('CLEANSTACK');

    if (!stack.getBool(-1))
      throw new ScriptError('EVAL_FALSE');
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    return this.fromRaw(br.readVarBytes());
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    const br = bio.read(data);

    this.raw = data;

    while (br.left())
      this.code.push(Opcode.fromReader(br));

    return this;
  }

  /**
   * Create a script from buffer reader.
   * @param {BufferReader} br
   * @returns {Script}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Create a script from a serialized buffer.
   * @param {Buffer|String} data - Serialized script.
   * @param {String?} enc - Either `"hex"` or `null`.
   * @returns {Script}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }

  /**
   * Test whether an object a Script.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isScript(obj) {
    return obj instanceof Script;
  }
}

/**
 * Script opcodes.
 * @enum {Number}
 * @default
 */

Script.opcodes = common.opcodes;

/**
 * Opcodes by value.
 * @const {RevMap}
 */

Script.opcodesByVal = common.opcodesByVal;

/**
 * Script and locktime flags. See {@link VerifyFlags}.
 * @enum {Number}
 */

Script.flags = common.flags;

/**
 * Sighash Types.
 * @enum {SighashType}
 * @default
 */

Script.hashType = common.hashType;

/**
 * Sighash types by value.
 * @const {RevMap}
 */

Script.hashTypeByVal = common.hashTypeByVal;

/**
 * Output script types.
 * @enum {Number}
 */

Script.types = common.types;

/**
 * Output script types by value.
 * @const {RevMap}
 */

Script.typesByVal = common.typesByVal;

/*
 * Helpers
 */

function sortKeys(keys) {
  return keys.slice().sort((a, b) => {
    return a.compare(b);
  });
}

/**
 * Test whether the data element is a valid key if VERIFY_STRICTENC is enabled.
 * @param {Buffer} key
 * @param {VerifyFlags?} flags
 * @param {Number} version
 * @returns {Boolean}
 * @throws {ScriptError}
 */

function validateKey(key, flags, version) {
  assert(Buffer.isBuffer(key));
  assert(typeof flags === 'number');
  assert(typeof version === 'number');

  if (flags & Script.flags.VERIFY_STRICTENC) {
    if (!common.isKeyEncoding(key))
      throw new ScriptError('PUBKEYTYPE');
  }

  if (version === 1) {
    if (flags & Script.flags.VERIFY_WITNESS_PUBKEYTYPE) {
      if (!common.isCompressedEncoding(key))
        throw new ScriptError('WITNESS_PUBKEYTYPE');
    }
  }

  return true;
}

/**
 * Test whether the data element is a valid signature based
 * on the encoding, S value, and sighash type. Requires
 * VERIFY_DERSIG|VERIFY_LOW_S|VERIFY_STRICTENC, VERIFY_LOW_S
 * and VERIFY_STRING_ENC to be enabled respectively. Note that
 * this will allow zero-length signatures.
 * @param {Buffer} sig
 * @param {VerifyFlags?} flags
 * @returns {Boolean}
 * @throws {ScriptError}
 */

function validateSignature(sig, flags) {
  assert(Buffer.isBuffer(sig));
  assert(typeof flags === 'number');

  // Allow empty sigs
  if (sig.length === 0)
    return true;

  if ((flags & Script.flags.VERIFY_DERSIG)
      || (flags & Script.flags.VERIFY_LOW_S)
      || (flags & Script.flags.VERIFY_STRICTENC)) {
    if (!common.isSignatureEncoding(sig))
      throw new ScriptError('SIG_DER');
  }

  if (flags & Script.flags.VERIFY_LOW_S) {
    if (!common.isLowDER(sig))
      throw new ScriptError('SIG_HIGH_S');
  }

  if (flags & Script.flags.VERIFY_STRICTENC) {
    if (!common.isHashType(sig))
      throw new ScriptError('SIG_HASHTYPE');
  }

  return true;
}

/**
 * Verify a signature, taking into account sighash type.
 * @param {Buffer} msg - Signature hash.
 * @param {Buffer} sig
 * @param {Buffer} key
 * @returns {Boolean}
 */

function checksig(msg, sig, key) {
  return secp256k1.verifyDER(msg, sig.slice(0, -1), key);
}

/*
 * Expose
 */

module.exports = Script;
