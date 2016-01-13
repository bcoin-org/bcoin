/**
 * script.js - script interpreter for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var utils = bcoin.utils;
var assert = bcoin.utils.assert;
var script = exports;

/**
 * Script
 */

script.decode = function decode(s) {
  if (!s)
    return [];

  var opcodes = [];
  var i = 0;
  var b, opcode, len;

  while (i < s.length) {
    b = s[i++];

    // Next `b` bytes should be pushed to stack
    if (b >= 0x01 && b <= 0x4b) {
      opcodes.push(s.slice(i, i + b));
      i += b;
      utils.hidden(opcodes[opcodes.length - 1], 'pushdata', {
        opcode: null,
        len: b
      });
      continue;
    }

    // Zero
    if (b === 0) {
      opcodes.push([]);
      continue;
    }

    // Raw number (-1 and 1-16)
    if (b === 0x4f || (b >= 0x51 && b <= 0x60)) {
      opcodes.push(b - 0x50);
      continue;
    }

    opcode = constants.opcodesByVal[b];

    if (i >= s.length) {
      opcodes.push(opcode || b);
      continue;
    }

    if (opcode === 'pushdata1') {
      len = s[i];
      i += 1;
      opcodes.push(s.slice(i, i + len));
      i += len;
      utils.hidden(opcodes[opcodes.length - 1], 'pushdata', {
        opcode: opcode,
        len: len
      });
    } else if (opcode === 'pushdata2') {
      len = utils.readU16(s, i);
      i += 2;
      opcodes.push(s.slice(i, i + len));
      i += len;
      utils.hidden(opcodes[opcodes.length - 1], 'pushdata', {
        opcode: opcode,
        len: len
      });
    } else if (opcode === 'pushdata4') {
      len = utils.readU32(s, i);
      i += 4;
      opcodes.push(s.slice(i, i + len));
      i += len;
      utils.hidden(opcodes[opcodes.length - 1], 'pushdata', {
        opcode: opcode,
        len: len
      });
    } else {
      opcodes.push(opcode || b);
    }
  }

  utils.hidden(opcodes, '_raw', s);

  return opcodes;
};

script.encode = function encode(s) {
  if (!s)
    return [];

  var opcodes = constants.opcodes;
  var res = [];
  var i = 0;
  var instr;

  for (i = 0; i < s.length; i++) {
    instr = s[i];

    // Push value to stack
    if (Array.isArray(instr)) {
      // Check for nonstandard pushdatas that
      // may have been decoded from before.
      if (instr.pushdata) {
        if (instr.pushdata.opcode === null) {
          res = res.concat(instr.pushdata.len, instr);
        } else if (instr.pushdata.opcode === 'pushdata1') {
          res = res.concat(opcodes.pushdata1, instr.pushdata.len, instr);
        } else if (instr.pushdata.opcode === 'pushdata2') {
          res.push(opcodes.pushdata2);
          utils.writeU16(res, instr.pushdata.len, res.length);
          res = res.concat(instr);
        } else if (instr.pushdata.opcode === 'pushdata4') {
          res.push(opcodes.pushdata4);
          utils.writeU32(res, instr.pushdata.len, res.length);
          res = res.concat(instr);
        }
        continue;
      }
      if (instr.length === 0) {
        // OP_FALSE
        res.push(0);
      } else if (1 <= instr.length && instr.length <= 0x4b) {
        res = res.concat(instr.length, instr);
      } else if (instr.length <= 0xff) {
        res = res.concat(opcodes.pushdata1, instr.length, instr);
      } else if (instr.length <= 0xffff) {
        res.push(opcodes.pushdata2);
        utils.writeU16(res, instr.length, res.length);
        res = res.concat(instr);
      } else {
        res.push(opcodes.pushdata4);
        utils.writeU32(res, instr.length, res.length);
        res = res.concat(instr);
      }
      continue;
    }

    res.push(opcodes[instr] || instr);
  }

  return res;
};

script.verify = function verify(input, output, tx, i, flags) {
  var copy, res, redeem;
  var stack = [];

  if (!flags)
    flags = {};

  // Execute the input script
  script.execute(input, stack, tx, i, flags);

  // Copy the stack for P2SH
  if (flags.verifyp2sh !== false)
    copy = stack.slice();

  // Execute the previous output script
  res = script.execute(output, stack, tx, i, flags);

  // Verify the script did not fail as well as the stack values
  if (!res || stack.length === 0 || new bn(stack.pop()).cmpn(0) === 0)
    return false;

  // If the script is P2SH, execute the real output script
  if (flags.verifyp2sh !== false && script.isScripthash(output)) {
    // P2SH can only have push ops in the scriptSig
    if (!script.pushOnly(input))
      return false;

    // Reset the stack
    stack = copy;

    // Stack should _never_ be empty at this point
    assert(stack.length !== 0);

    // Grab the real redeem script
    redeem = stack.pop();

    if (!Array.isArray(redeem))
      return false;

    redeem = script.decode(redeem);

    // Execute the redeem script
    res = script.execute(redeem, stack, tx, i, flags);

    // Verify the script did not fail as well as the stack values
    if (!res || stack.length === 0 || new bn(stack.pop()).cmpn(0) === 0)
      return false;
  }

  // Ensure there is nothing left on the stack
  if (flags.cleanstack !== false) {
    if (stack.length !== 0)
      return false;
  }

  return true;
};

script.subscript = function subscript(s, lastSep) {
  var i, res;

  if (!s)
    return [];

  if (lastSep == null) {
    lastSep = -1;
    for (i = 0; i < s.length; i++) {
      if (s[i] === 'checksig'
        || s[i] === 'checksigverify'
        || s[i] === 'checkmultisig'
        || s[i] === 'checkmultisigverify') {
        break;
      }
      if (s[i] === 'codesep')
        lastSep = i;
    }
  }

  res = [];
  for (i = lastSep + 1; i < s.length; i++) {
    if (s[i] !== 'codesep')
      res.push(s[i]);
  }

  return res;
};

script.checksig = function checksig(msg, sig, pub) {
  var k;

  if (pub.getPublic)
    pub = pub.getPublic();

  try {
    k = bcoin.ecdsa.keyPair({ pub: pub });
  } catch (e) {
    return false;
  }

  // Points at Infinity make verify() throw.
  // This specifically throws on wallet-test.js
  // where [1] is concatted to the pubkey.
  if (k.getPublic().isInfinity())
    return false;

  // Use a try catch in case there are
  // any uncaught errors for bad inputs in verify().
  try {
    return bcoin.ecdsa.verify(msg, sig, pub);
  } catch (e) {
    return false;
  }
};

script._next = function _next(to, s, pc) {
  var depth = 0;
  var o;

  while (s[pc]) {
    o = s[pc];

    if (o === 'if_' || o === 'notif')
      depth++;
    else if (o === 'else_')
      depth--;
    else if (o === 'endif')
      depth--;

    if (depth < 0)
      break;

    if (depth === 0 && o === to)
      return pc;

    if (o === 'else_')
      depth++;

    pc++;
  }

  return -1;
};

script.execute = function execute(s, stack, tx, index, flags, recurse) {
  s = s.slice();

  if (!flags)
    flags = {};

  if (s.length > constants.script.maxOps)
    return false;

  var lastSep = -1;
  var pc = 0;
  var o, val;
  var if_, else_, endif;
  var v, v1, v2, v3, v4;
  var n, n1, n2, n3;
  var res;
  var key, sig, type, subscript, hash;
  var keys, i, j, m;
  var succ;
  var lock, threshold;
  var evalScript;

  stack.alt = stack.alt || [];

  for (pc = 0; pc < s.length; pc++) {
    o = s[pc];

    if (Array.isArray(o)) {
      if (o.length > constants.script.maxPush)
        return false;
      stack.push(o);
      continue;
    }

    if (o === -1 || (o >= 1 && o <= 16)) {
      stack.push([o]);
      continue;
    }

    switch (o) {
      case 'nop':
      case 'nop3':
      case 'nop4':
      case 'nop5':
      case 'nop6':
      case 'nop7':
      case 'nop8':
      case 'nop9':
      case 'nop10': {
        break;
      }
      case 'if_':
      case 'notif': {
        val = false;
        if (stack.length < 1)
          return false;
        v = stack.pop();
        val = new bn(v).cmpn(0) !== 0;
        if (o === 'notif')
          val = !val;
        if_ = pc;
        else_ = script._next('else_', s, pc);
        endif = script._next('endif', s, pc);
        // Splice out the statement blocks we don't need
        if (val) {
          if (endif === -1)
            return false;
          if (else_ === -1) {
            s.splice(endif, 1);
            s.splice(if_, 1);
          } else {
            s.splice(else_, (endif - else_) + 1);
            s.splice(if_, 1);
          }
        } else {
          if (endif === -1)
            return false;
          if (else_ === -1) {
            s.splice(if_, (endif - if_) + 1);
          } else {
            s.splice(endif, 1);
            s.splice(if_, (else_ - if_) + 1);
          }
        }
        // Subtract one since we removed the if/notif opcode
        pc--;
        break;
      }
      case 'else_': {
        return false;
      }
      case 'endif': {
        return false;
      }
      case 'verify': {
        if (stack.length === 0)
          return false;
        if (new bn(stack.pop()).cmpn(0) === 0)
          return false;
        break;
      }
      case 'ret': {
        return false;
      }
      case 'toaltstack': {
        if (stack.length === 0)
          return false;
        stack.alt.push(stack.pop());
        break;
      }
      case 'fromaltstack': {
        if (stack.alt.length === 0)
          return false;
        stack.push(stack.alt.pop());
        break;
      }
      case 'ifdup': {
        if (stack.length === 0)
          return false;
        if (new bn(stack[stack.length - 1]).cmpn(0) !== 0)
          stack.push(new bn(stack[stack.length - 1]).toArray());
        break;
      }
      case 'depth': {
        stack.push(new bn(stack.length).toArray());
        break;
      }
      case 'drop': {
        if (stack.length === 0)
          return false;
        stack.pop();
        break;
      }
      case 'dup': {
        if (stack.length === 0)
          return false;
        stack.push(stack[stack.length - 1]);
        break;
      }
      case 'nip': {
        if (stack.length < 2)
          return false;
        stack.splice(stack.length - 2, 1);
        break;
      }
      case 'over': {
        if (stack.length < 2)
          return false;
        stack.push(stack[stack.length - 2]);
        break;
      }
      case 'pick':
      case 'roll': {
        if (stack.length < 2)
          return false;
        v = stack.pop();
        if (v.length > 6)
          return false;
        n = new bn(v).toNumber();
        if (n < 0 || n >= stack.length)
          return false;
        v = stack[-n - 1];
        if (o === 'roll')
          stack.splice(stack.length - n - 1, 1);
        stack.push(v);
        break;
      }
      case 'rot': {
        if (stack.length < 3)
          return false;
        v3 = stack[stack.length - 3];
        v2 = stack[stack.length - 2];
        v1 = stack[stack.length - 1];
        stack[stack.length - 3] = v2;
        stack[stack.length - 2] = v3;
        v2 = stack[stack.length - 2];
        stack[stack.length - 2] = v1;
        stack[stack.length - 1] = v2;
        break;
      }
      case 'swap': {
        if (stack.length < 2)
          return false;
        v2 = stack[stack.length - 2];
        v1 = stack[stack.length - 1];
        stack[stack.length - 2] = v1;
        stack[stack.length - 1] = v2;
        break;
      }
      case 'tuck': {
        if (stack.length < 2)
          return false;
        stack.splice(stack.length - 2, 0, stack[stack.length - 1]);
        break;
      }
      case 'drop2': {
        if (stack.length < 2)
          return false;
        stack.pop();
        stack.pop();
        break;
      }
      case 'dup2': {
        if (stack.length < 2)
          return false;
        v1 = stack[stack.length - 1];
        v2 = stack[stack.length - 2];
        stack.push(v1);
        stack.push(v2);
        break;
      }
      case 'dup3': {
        if (stack.length < 3)
          return false;
        v1 = stack[stack.length - 1];
        v2 = stack[stack.length - 2];
        v3 = stack[stack.length - 3];
        stack.push(v1);
        stack.push(v2);
        stack.push(v3);
        break;
      }
      case 'over2': {
        if (stack.length < 4)
          return false;
        v1 = stack[stack.length - 4];
        v2 = stack[stack.length - 3];
        stack.push(v1);
        stack.push(v2);
        break;
      }
      case 'rot2': {
        if (stack.length < 6)
          return false;
        v1 = stack[stack.length - 6];
        v2 = stack[stack.length - 5];
        stack.splice(stack.length - 6, 2);
        stack.push(v1);
        stack.push(v2);
        break;
      }
      case 'swap2': {
        if (stack.length < 4)
          return false;
        v4 = stack[stack.length - 4];
        v3 = stack[stack.length - 3];
        v2 = stack[stack.length - 2];
        v1 = stack[stack.length - 1];
        stack[stack.length - 4] = v2;
        stack[stack.length - 2] = v4;
        stack[stack.length - 3] = v1;
        stack[stack.length - 1] = v3;
        break;
      }
      case 'size': {
        if (stack.length < 1)
          return false;
        stack.push(new bn(stack[stack.length - 1].length || 0).toArray());
        break;
      }
      case 'add1':
      case 'sub1':
      case 'negate':
      case 'abs':
      case 'not':
      case 'noteq0': {
        if (stack.length < 1)
          return false;
        n = new bn(stack.pop());
        switch (o) {
          case 'add1':
            n.iadd(1);
            break;
          case 'sub1':
            n.isub(1);
            break;
          case 'negate':
            n = n.neg();
            break;
          case 'abs':
            if (n.cmpn(0) < 0)
              n = n.neg();
            break;
          case 'not':
            n = n.cmpn(0) === 0;
            break;
          case 'noteq0':
            n = n.cmpn(0) !== 0;
            break;
          default:
            return false;
        }
        if (typeof n === 'boolean')
          n = new bn(+n);
        stack.push(n.toArray());
        break;
      }
      case 'add':
      case 'sub':
      case 'booland':
      case 'boolor':
      case 'numeq':
      case 'numeqverify':
      case 'numneq':
      case 'lt':
      case 'gt':
      case 'lte':
      case 'gte':
      case 'min':
      case 'max': {
        switch (o) {
          case 'add':
          case 'sub':
          case 'booland':
          case 'boolor':
          case 'numeq':
          case 'numeqverify':
          case 'numneq':
          case 'lt':
          case 'gt':
          case 'lte':
          case 'gte':
          case 'min':
          case 'max':
            if (stack.length < 2)
              return false;
            n2 = new bn(stack.pop());
            n1 = new bn(stack.pop());
            n = new bn(0);
            switch (o) {
              case 'add':
                n = n1.add(n2);
                break;
              case 'sub':
                n = n1.sub(n2);
                break;
              case 'booland':
                n = n1.cmpn(0) !== 0 && n2.cmpn(0) !== 0;
                break;
              case 'boolor':
                n = n1.cmpn(0) !== 0 || n2.cmpn(0) !== 0;
                break;
              case 'numeq':
                n = n1.cmp(n2) === 0;
                break;
              case 'numeqverify':
                n = n1.cmp(n2) === 0;
                break;
              case 'numneq':
                n = n1.cmp(n2) !== 0;
                break;
              case 'lt':
                n = n1.cmp(n2) < 0;
                break;
              case 'gt':
                n = n1.cmp(n2) > 0;
                break;
              case 'lte':
                n = n1.cmp(n2) <= 0;
                break;
              case 'gte':
                n = n1.cmp(n2) >= 0;
                break;
              case 'min':
                n = n1.cmp(n2) < 0 ? n1 : n2;
                break;
              case 'max':
                n = n1.cmp(n2) > 0 ? n1 : n2;
                break;
              default:
                return false;
            }
            if (typeof n === 'boolean')
              n = new bn(+n);
            res = n.cmpn(0) !== 0;
            if (o === 'numeqverify') {
              if (!res)
                return false;
            } else {
              stack.push(n.toArray());
            }
            break;
          case 'within':
            if (stack.length < 3)
              return false;
            n3 = new bn(stack.pop());
            n2 = new bn(stack.pop());
            n1 = new bn(stack.pop());
            val = n2.cmp(n1) <= 0 && n1.cmp(n3) < 0;
            stack.push(val.cmpn(0) !== 0 ? [ 1 ] : []);
            break;
        }

        break;
      }
      case 'codesep': {
        lastSep = pc;
        break;
      }
      case 'ripemd160': {
        if (stack.length === 0)
          return false;
        stack.push(utils.ripemd160(stack.pop()));
        break;
      }
      case 'sha1': {
        if (stack.length === 0)
          return false;
        stack.push(utils.sha1(stack.pop()));
        break;
      }
      case 'sha256': {
        if (stack.length === 0)
          return false;
        stack.push(utils.sha256(stack.pop()));
        break;
      }
      case 'hash256': {
        if (stack.length === 0)
          return false;
        stack.push(utils.dsha256(stack.pop()));
        break;
      }
      case 'hash160': {
        if (stack.length === 0)
          return false;
        stack.push(utils.ripesha(stack.pop()));
        break;
      }
      case 'eqverify':
      case 'eq': {
        if (stack.length < 2)
          return false;
        res = utils.isEqual(stack.pop(), stack.pop());
        if (o === 'eqverify') {
          if (!res)
            return false;
        } else {
          stack.push(res ? [ 1 ] : []);
        }
        break;
      }
      case 'checksigverify':
      case 'checksig': {
        if (!tx || stack.length < 2)
          return false;

        key = stack.pop();
        sig = stack.pop();

        if (!script.isKey(key))
          return false;

        if (!script.isSignature(sig))
          return false;

        if (flags.strictder !== false) {
          if (!script.isValidSignature(sig))
            return false;
        }

        type = sig[sig.length - 1];

        if (!constants.hashTypeByVal[type & 0x1f])
          return false;

        subscript = script.subscript(s, lastSep);
        hash = tx.signatureHash(index, subscript, type);

        res = script.checksig(hash, sig.slice(0, -1), key);
        if (o === 'checksigverify') {
          if (!res)
            return false;
        } else {
          stack.push(res ? [ 1 ] : []);
        }

        break;
      }
      case 'checkmultisigverify':
      case 'checkmultisig': {
        if (!tx || stack.length < 3)
          return false;

        n = stack.pop();

        if (!Array.isArray(n))
          return false;

        if (n.length !== 1 || !(n[0] >= 1 && n[0] <= 15))
          return false;

        n = n[0];

        if (stack.length < n + 1)
          return false;

        keys = [];
        for (i = 0; i < n; i++) {
          key = stack.pop();
          if (!script.isKey(key))
            return false;

          keys.push(key);
        }

        m = stack.pop();

        if (!Array.isArray(m))
          return false;

        if (m.length !== 1 || !(m[0] >= 1 && m[0] <= n))
          return false;

        m = m[0];

        if (stack.length < m + 1)
          return false;

        subscript = script.subscript(s, lastSep);

        succ = 0;
        for (i = 0, j = 0; i < m && j < n; i++) {
          sig = stack.pop();

          if (!script.isSignature(sig))
            return false;

          if (flags.strictder !== false) {
            if (!script.isValidSignature(sig))
              return false;
          }

          type = sig[sig.length - 1];

          if (!constants.hashTypeByVal[type & 0x1f])
            return false;

          hash = tx.signatureHash(index, subscript, type);

          res = false;
          for (; !res && j < n; j++)
            res = script.checksig(hash, sig.slice(0, -1), keys[j]);

          if (res)
            succ++;
        }

        if (stack.length < 1)
          return false;

        val = stack.pop();

        if (flags.verifynulldummy !== false) {
          if (!Array.isArray(val) || val.length > 0)
            return false;
        }

        res = succ >= m;
        if (o === 'checkmultisigverify') {
          if (!res)
            return false;
        } else {
          stack.push(res ? [ 1 ] : []);
        }

        break;
      }
      case 'checklocktimeverify': {
        // OP_CHECKLOCKTIMEVERIFY = OP_NOP2
        if (flags.cltv === false)
          break;

        if (!tx || stack.length === 0)
          return false;

        lock = stack[stack.length - 1];

        if (!Array.isArray(lock))
          return false;

        if (lock.length > 6)
          return false;

        lock = new bn(lock).toNumber();

        if (lock < 0)
          return false;

        threshold = constants.locktimeThreshold;
        if (!(
          (tx.lock < threshold && lock < threshold)
          || (tx.lock >= threshold && lock >= threshold)
        )) {
          return false;
        }

        if (lock > tx.lock)
          return false;

        if (!tx.inputs[index] || tx.inputs[index].seq === 0xffffffff)
          return false;

        break;
      }
      case 'eval_': {
        // OP_EVAL = OP_NOP1
        if (!flags.allowEval)
          break;

        recurse = recurse || 0;

        if (recurse++ > 2)
          return false;

        evalScript = stack.pop();

        if (!Array.isArray(evalScript))
          return false;

        evalScript = script.decode(evalScript);

        res = evalScript.some(function(op) {
          return op === 'codesep';
        });

        if (res)
          return false;

        res = script.execute(evalScript, stack, tx, index, flags, recurse);
        if (!res)
          return false;

        break;
      }
      default: {
        // Unknown operation
        return false;
      }
    }
  }

  if (stack.length + stack.alt.length > constants.script.maxStack)
    return false;

  return true;
};

script.redeem = function redeem(keys, m, n) {
  if (keys.length !== n)
    throw new Error(n + ' keys are required to generate redeem script');

  assert(m >= 1 && m <= n);
  assert(n >= 1 && n <= 15);

  while (keys.length < n)
    keys.push([]);

  keys = utils.sortKeys(keys);

  return [m].concat(
    keys,
    [n, 'checkmultisig']
  );
};

script.standard = function standard(s) {
  return (script.isPubkey(s) && 'pubkey')
    || (script.isPubkeyhash(s) && 'pubkeyhash')
    || (script.isMultisig(s) && 'multisig')
    || (script.isScripthash(s) && 'scripthash')
    || (script.isNulldata(s) && 'nulldata')
    || null;
};

script.isStandard = function isStandard(s) {
  var type = script.standard(s);
  var m, n;

  if (type === 'multisig') {
    m = new bn(s[0]).toNumber();
    n = new bn(s[s.length - 2]).toNumber();
    if (n < 1 || n > 3)
      return false;
    if (m < 1 || m > n)
      return false;
  } else if (type === 'nulldata') {
    if (script.size(s) > constants.script.maxOpReturnBytes)
      return false;
  }

  return type != null;
};

script.size = function size(s) {
  if (s._raw)
    return s._raw.length;
  return bcoin.script.encode(s).length;
};

script.isEncoded = function isEncoded(s) {
  return utils.isBytes(s);
};

script.normalize = function normalize(s) {
  if (script.isEncoded(s))
    s = script.decode(s);

  s = script.subscript(s);

  if (script.lockTime(s))
    s = s.slice(3);

  return s;
};

script.lockTime = function lockTime(s) {
  var lock = s[0];
  var res = s.length > 3
    && Array.isArray(s[0])
    && s[1] === 'checklocktimeverify'
    && s[2] === 'drop';

  if (!res)
    return false;

  // Number can only store 6 & 5/8 bytes
  if (lock.length > 6)
    lock = lock.slice(0, 6);

  return new bn(lock);
};

script.spendable = function spendable(s, lockTime) {
  if (!script.standard(s))
    return false;

  var lock = script.lockTime(s);
  if (lock && lock.toNumber() > lockTime)
    return false;

  return true;
};

script.isPubkey = function isPubkey(s, key) {
  var res;

  s = script.subscript(s);

  if (script.lockTime(s))
    s = s.slice(3);

  if (s.length !== 2)
    return false;

  res = Array.isArray(s[0]) && s[1] === 'checksig';

  if (!res)
    return false;

  if (key)
    return utils.isEqual(s[0], key);

  return true;
};

script.isPubkeyhash = function isPubkeyhash(s, hash) {
  var res;

  s = script.subscript(s);

  if (script.lockTime(s))
    s = s.slice(3);

  if (s.length !== 5)
    return false;

  res = s[0] === 'dup'
    && s[1] === 'hash160'
    && Array.isArray(s[2])
    && s[3] === 'eqverify'
    && s[4] === 'checksig';

  if (!res)
    return false;

  if (hash)
    return utils.isEqual(s[2], hash);

  return true;
};

script.isMultisig = function isMultisig(s, keys) {
  var m, n, i, j;
  var total = 0;

  s = script.subscript(s);

  if (script.lockTime(s))
    s = s.slice(3);

  if (s.length < 4)
    return false;

  if (s[s.length - 1] !== 'checkmultisig')
    return false;

  n = s[s.length - 2];

  if (Array.isArray(n)) {
    if (n.length !== 1)
      return false;
    n = n[0];
  }

  if (!(n >= 1 && n <= 15))
    return false;

  m = s[0];

  if (Array.isArray(m)) {
    if (m.length !== 1)
      return false;
    m = m[0];
  }

  if (!(m >= 1 && m <= n))
    return false;

  if (n + 3 !== s.length)
    return false;

  for (i = 1; i < n + 1; i++) {
    if (!Array.isArray(s[i]))
      return false;
  }

  if (!keys)
    return true;

  keys = utils.sortKeys(keys);

  for (i = 1; i < n + 1; i++) {
    for (j = 0; j < keys.length; j++) {
      if (utils.isEqual(s[i], keys[j])) {
        total++;
        break;
      }
    }
  }

  return total === n;
};

script.isScripthash = function isScripthash(s, hash) {
  var res;

  s = script.subscript(s);

  if (script.lockTime(s))
    s = s.slice(3);

  if (s.length !== 3)
    return false;

  res = s[0] === 'hash160'
    && Array.isArray(s[1])
    && s[1].length === 20
    && s[2] === 'eq';

  if (!res)
    return false;

  if (hash)
    return utils.isEqual(s[1], hash);

  return true;
};

script.isNulldata = function isNulldata(s) {
  s = script.subscript(s);

  if (s.length !== 2)
    return false;

  return s[0] === 'ret'
    && Array.isArray(s[1])
    && s[1].length <= constants.script.maxOpReturn;
};

script.nulldata = function nulldata(s) {
  if (!script.isNulldata(s))
    return false;

  return script.subscript(s)[1];
};

script.standardInput = function standardInput(s) {
  return (script.isPubkeyInput(s) && 'pubkey')
    || (script.isPubkeyhashInput(s) && 'pubkeyhash')
    || (script.isMultisigInput(s) && 'multisig')
    || (script.isScripthashInput(s) && 'scripthash')
    || null;
};

script.isPubkeyInput = function isPubkeyInput(s, key, tx, i) {
  s = script.subscript(s);

  if (s.length !== 1 || !Array.isArray(s[0]))
    return false;

  if (!script.isSignature(s[0]))
    return false;

  // Execute the script against our key's
  // checksig script to see if this is our input.
  // This will only work if the script verifies.
  if (key) {
    assert(tx);
    assert(i != null);
    return script.verify(s, [key, 'checksig'], tx, i);
  }

  return true;
};

script.isPubkeyhashInput = function isPubkeyhashInput(s, key) {
  s = script.subscript(s);

  if (s.length !== 2 || !Array.isArray(s[0]) || !Array.isArray(s[1]))
    return false;

  if (!script.isSignature(s[0]))
    return false;

  if (!script.isKey(s[1]))
    return false;

  if (key)
    return utils.isEqual(s[1], key);

  return true;
};

script.isMultisigInput = function isMultisigInput(s, keys, tx, i) {
  var i, o;

  // We need to rule out scripthash
  // because it may look like multisig
  if (script.isScripthashInput(s))
    return false;

  s = script.subscript(s);

  if (s.length < 3)
    return false;

  if (!Array.isArray(s[0]) || s[0].length !== 0)
    return false;

  for (i = 1; i < s.length; i++) {
    if (!script.isSignature(s[i]))
      return false;
  }

  // Execute the script against our pubkeys'
  // redeem script to see if this is our input.
  // This will only work if the script verifies.
  if (keys) {
    assert(keys.length >= 2);
    assert(tx);
    assert(i != null);
    o = script.redeem(keys, s.length - 1, keys.length);
    return script.verify(s, o, tx, i);
  }

  // We also also try to recover the keys from the signatures.
  // var recovered = [];
  // for (i = 1; i < s.length; i++) {
  //   var sig = s[i];
  //   var prev = script.redeem(keys, s.length - 1, keys.length);
  //   var msg = tx.signatureHash(i, prev, s[s.length - 1]);
  //   var key = bcoin.ecdsa.recoverPubKey(msg, sig.slice(0, -1), 0).toArray();
  //   recovered.push(key);
  // }

  return true;
};

script.isScripthashInput = function isScripthashInput(s, data) {
  var raw, redeem;

  s = script.subscript(s);

  // Grab the raw redeem script.
  raw = s[s.length - 1];

  // Need at least one data element with
  // the redeem script.
  if (s.length < 2)
    return false;

  // Last data element should be an array
  // for the redeem script.
  if (!Array.isArray(raw))
    return false;

  // P2SH redeem scripts can be nonstandard: make
  // it easier for other functions to parse this.
  redeem = script.normalize(raw);

  // Get the "real" scriptSig
  s = s.slice(0, -1);

  // Do some sanity checking on the inputs
  if (!script.isPubkeyInput(s)
    && !script.isPubkeyhashInput(s)
    && !script.isMultisigInput(s)) {
    return false;
  }

  // Check data against last array in case
  // a raw redeem script was passed in.
  if (data && utils.isEqual(data, raw))
    return true;

  // Test against all other script types
  return script.isPubkey(redeem, data)
    || script.isPubkeyhash(redeem, data)
    || script.isMultisig(redeem, data);
};

script.coinbaseBits = function coinbaseBits(s, block) {
  var value;

  s = s.filter(function(chunk) {
    return Array.isArray(chunk) && chunk.length !== 0;
  });

  if (!Array.isArray(s[0]))
    return { type: 'value', value: s[0] };

  // Number can only store up to 53 bits (6 & 5/8 bytes)
  if (s[0].length > 6)
    return { type: 'value', value: s[0] };

  value = new bn(s[0].slice().reverse()).toNumber();

  // Test for bits and ts
  if (block && block.version < 2) {
    if (value === block.bits)
      return { type: 'bits', value: value };

    if (value === block.ts)
      return { type: 'ts', value: value };
  }

  // Test for height
  if (block) {
    if (block.version < 2)
      return { type: 'value', value: value };
  } else {
    if (value <= 227835)
      return { type: 'value', value: value };
  }

  if (s[0].length < 3)
    return { type: 'value', value: value };

  return { type: 'height', value: value };
};

script.coinbaseHeight = function coinbaseHeight(s, block) {
  var data = script.coinbaseBits(s, block);
  if (data.type !== 'height')
    return -1;
  return data.value;
};

script.coinbase = function coinbase(s, block) {
  var coinbase, data, extraNonce, flags;

  s = s.filter(function(chunk) {
    return Array.isArray(chunk) && chunk.length !== 0;
  });

  coinbase = {
    script: s
  };

  data = script.coinbaseBits(s, block);

  if (Array.isArray(s[1]))
    extraNonce = new bn(s[1]);

  flags = s.slice(2);

  coinbase[data.type] = data.value;
  coinbase.extraNonce = extraNonce;
  coinbase.flags = flags;
  coinbase.text =
    flags.map(utils.array2utf8).join('')
    .replace(/[\u0000-\u0019\u007f-\u00ff]/g, '');

  return coinbase;
};

script.isCoinbase = function isCoinbase(s, block, strict) {
  var coinbase = script.coinbase(s, block);
  var size = script.size(s);

  if (size < 2 || size > 100)
    return false;

  if (strict) {
    if (s.length < 2)
      return false;

    if (coinbase.value != null)
      return false;

    if (coinbase.extraNonce == null)
      return false;

    if (block) {
      // The early bitcoind miner (which used the bits
      // as the first stack push) had no flags after it.
      if (coinbase.bits != null && coinbase.flags.length)
        return false;
    }
  }

  return coinbase;
};

script.isKey = function isKey(key) {
  if (!utils.isBuffer(key))
    return false;

  return key.length >= 33 && key.length <= 65;
};

script.isSignature = function isSignature(sig, allowZero) {
  if (!utils.isBuffer(sig))
    return false;

  if (allowZero && sig.length === 0)
    return true;

  return sig.length >= 9 && sig.length <= 73;
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
script.isValidSignature = function isValidSignature(sig, allowZero) {
  var lenR, lenS;

  if (!utils.isBuffer(sig))
    return false;

  // Empty signature. Not strictly DER encoded, but allowed to provide a
  // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
  if (allowZero && sig.length === 0)
    return true;

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

script.isLowDER = function isLowDER(sig, type) {
  var half = bcoin.ecdsa.n.ushrn(1);

  if (!sig.s) {
    assert(utils.isBuffer(sig));

    if (sig[sig.length - 1] === type)
      sig = sig.slice(0, -1);

    try {
      sig = new bcoin.signature(sig);
    } catch (e) {
      return false;
    }
  }

  // Technically a negative S value is low,
  // but we don't want to ever use negative
  // S values in bitcoin.
  if (sig.s.cmpn(0) <= 0)
    return false;

  // If S is greater than half the order,
  // it's too high.
  if (sig.s.cmp(half) > 0)
    return false;

  return true;
};

script.sign = function sign(msg, key) {
  var half = bcoin.ecdsa.n.ushrn(1);
  var sig = bcoin.ecdsa.sign(msg, key.priv);

  // Elliptic shouldn't be generating
  // negative S values.
  assert(sig.s.cmpn(0) > 0);

  // S value is already low.
  if (sig.s.cmp(half) <= 0)
    return sig.toDER();

  // Subtract from the `n` order to make it smaller.
  sig.s = bcoin.ecdsa.n.sub(sig.s);

  return sig.toDER();
};

script.format = function format(input, output) {
  var scripts = [];
  var prev, redeem;

  if (Array.isArray(input)) {
    scripts.push(input);
  } else if (Array.isArray(output)) {
    scripts.push(output);
  } else if (input) {
    scripts.push(input.script);
    if (input.out.tx && input.out.tx.outputs[input.out.index]) {
      prev = input.out.tx.outputs[input.out.index].script;
      scripts.push(prev);
      if (script.isScripthash(prev)) {
        redeem = script.decode(input.script[input.script.length - 1]);
        scripts.push(redeem);
      }
    }
  } else if (output) {
    scripts.push(output.script);
  }

  scripts = scripts.map(function(script) {
    return script.map(function(chunk) {
      if (Array.isArray(chunk)) {
        if (chunk.length === 0)
          return 0 + '';
        return '[' + utils.toHex(chunk) + ']';
      }
      if (typeof chunk === 'number')
        return chunk + '';
      return chunk;
    }).join(' ');
  });

  return scripts;
};

script.pushOnly = function pushOnly(s) {
  var i, op;
  for (i = 0; i < s.length; i++) {
    op = s[i];
    if (Array.isArray(op) || (op >= 1 && op <= 16))
      continue;
    if (constants.opcodes[op] == null)
      return false;
    return false;
  }
  return true;
};

script.sigops = function sigops(s, accurate) {
  var i, op;
  var n = 0;
  var lastOp = -1;

  for (i = 0; i < s.length; i++) {
    op = s[i];
    if (Array.isArray(op))
      continue;
    if (constants.opcodes[op] == null)
      return 0;
    if (op === 'checksig' || op === 'checksigverify') {
      n++;
    } else if (op === 'checkmultisig' || op === 'checkmultisigverify') {
      if (accurate && lastOp >= 1 && lastOp <= 16) {
        n += lastOp;
      } else {
        n += constants.script.maxPubkeysPerMultisig;
      }
    }
    lastOp = op;
  }

  return n;
};

script.sigopsScripthash = function sigopsScripthash(s) {
  if (!script.isScripthashInput(s))
    return 0;

  if (!script.pushOnly(s))
    return 0;

  s = script.decode(s[s.length - 1]);

  return script.sigops(s, true);
};

script.args = function args(s) {
  var type, keys, m;

  s = bcoin.script.subscript(s);

  if (script.lockTime(s))
    s = s.slice(3);

  type = script.standard(s);

  if (type === 'pubkey')
    return 1;

  if (type === 'pubkeyhash')
    return 2;

  if (type === 'multisig') {
    keys = bcoin.script.isMultisig(s);
    if (!pub)
      return -1;
    m = new bn(s[0]).toNumber();
    if (keys.length < 1 || m < 1)
      return -1;
    return m + 1;
  }

  if (type === 'scripthash')
    return 1;

  if (type === 'nulldata')
    return -1;

  return -1;
};
