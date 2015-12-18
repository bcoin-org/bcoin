var bcoin = require('../bcoin');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var utils = bcoin.utils;
var assert = bcoin.utils.assert;
var script = exports;

script.decode = function decode(s) {
  if (!s)
    return [];
  var opcodes = [];
  for (var i = 0; i < s.length;) {
    var b = s[i++];

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

    var opcode = constants.opcodesByVal[b];
    if (opcode === 'pushdata1') {
      // NOTE: pushdata1 could be substituted with 0x01-0x4b
      // later if less than or equal to 0x4b.
      // bad when passed back into encode().
      var len = s[i];
      i += 1;
      opcodes.push(s.slice(i, i + len));
      i += len;
      utils.hidden(opcodes[opcodes.length - 1], 'pushdata', {
        opcode: opcode,
        len: len
      });
    } else if (opcode === 'pushdata2') {
      // NOTE: len could theoretically be less than 0xffff
      // here. bad when passed back into encode().
      var len = utils.readU16(s, i);
      i += 2;
      opcodes.push(s.slice(i, i + len));
      i += len;
      utils.hidden(opcodes[opcodes.length - 1], 'pushdata', {
        opcode: opcode,
        len: len
      });
    } else if (opcode === 'pushdata4') {
      // NOTE: len could theoretically be less than 0xffffffff
      // here. bad when passed back into encode().
      var len = utils.readU32(s, i);
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

  return opcodes;
};

script.encode = function encode(s) {
  if (!s)
    return [];

  var opcodes = constants.opcodes;
  var res = [];
  for (var i = 0; i < s.length; i++) {
    var instr = s[i];

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

script.subscript = function subscript(s, lastSep) {
  if (!s)
    return [];

  if (lastSep == null) {
    lastSep = -1;
    for (var i = 0; i < s.length; i++) {
      if (s[i] === 'codesep')
        lastSep = i;
      else if (s[i] === 'checksig' ||
               s[i] === 'checksigverify' ||
               s[i] === 'checkmultisig' ||
               s[i] === 'checkmultisigverify') {
        break;
      }
    }
  }

  var res = [];
  for (var i = lastSep + 1; i < s.length; i++)
    if (s[i] !== 'codesep')
      res.push(s[i]);

  return res;
};

script.verify = function verify(hash, sig, pub) {
  var k = bcoin.ecdsa.keyFromPublic(pub);

  // Points at Infinity make verify() throw.
  // This specifically throws on wallet-test.js
  // where [1] is concatted to the pubkey.
  if (k.getPublic().isInfinity())
    return false;

  // Use a try catch in case there are
  // any uncaught errors for bad inputs in verify().
  try {
    return bcoin.ecdsa.verify(hash, sig, pub);
  } catch (e) {
    return false;
  }
};

script._next = function(to, s, pc) {
  var depth = 0;
  while (s[pc]) {
    var o = s[pc];
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

script.execute = function execute(s, stack, tx, index) {
  s = s.slice();

  if (s.length > constants.script.maxOps)
    return false;

  var lastSep = -1;

  stack.alt = stack.alt || [];

  for (var pc = 0; pc < s.length; pc++) {
    var o = s[pc];

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
      case 'nop1':
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
        var val = false;
        if (stack.length < 1)
          return false;
        var v = stack.pop();
        val = new bn(v).cmpn(0) !== 0;
        if (o === 'notif')
          val = !val;
        var if_ = pc;
        var else_ = script._next('else_', s, pc);
        var endif = script._next('endif', s, pc);
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
        if (new bn(stack[stack.length - 1]).cmpn(0) === 0)
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
        var n = new bn(stack.pop()).toNumber();
        if (n < 0 || n >= stack.length)
          return false;
        var v = stack[-n - 1];
        if (o === 'roll')
          stack.splice(stack.length - n - 1, 1);
        stack.push(v);
        break;
      }
      case 'rot': {
        if (stack.length < 3)
          return false;
        var v3 = stack[stack.length - 3];
        var v2 = stack[stack.length - 2];
        var v1 = stack[stack.length - 1];
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
        var v2 = stack[stack.length - 2];
        var v1 = stack[stack.length - 1];
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
        var v1 = stack[stack.length - 1];
        var v2 = stack[stack.length - 2];
        stack.push(v1);
        stack.push(v2);
        break;
      }
      case 'dup3': {
        if (stack.length < 3)
          return false;
        var v1 = stack[stack.length - 1];
        var v2 = stack[stack.length - 2];
        var v3 = stack[stack.length - 3];
        stack.push(v1);
        stack.push(v2);
        stack.push(v3);
        break;
      }
      case 'over2': {
        if (stack.length < 4)
          return false;
        var v1 = stack[stack.length - 4];
        var v2 = stack[stack.length - 3];
        stack.push(v1);
        stack.push(v2);
        break;
      }
      case 'rot2': {
        if (stack.length < 6)
          return false;
        var v1 = stack[stack.length - 6];
        var v2 = stack[stack.length - 5];
        stack.splice(stack.length - 6, 2);
        stack.push(v1);
        stack.push(v2);
        break;
      }
      case 'swap2': {
        if (stack.length < 4)
          return false;
        var v4 = stack[stack.length - 4];
        var v3 = stack[stack.length - 3];
        var v2 = stack[stack.length - 2];
        var v1 = stack[stack.length - 1];
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
        var n = new bn(stack.pop());
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
            var n2 = new bn(stack.pop());
            var n1 = new bn(stack.pop());
            var n = new bn(0);
            switch (o) {
              case 'add':
                n = n1.add(b2);
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
            var res = n.cmpn(0) !== 0;
            if (o === 'numeqverify') {
              if (!res)
                return false;
            } else {
              stack.push(n.toArray());
              // stack.push(res ? [ 1 ] : []);
            }
            break;
          case 'within':
            if (stack.length < 3)
              return false;
            var n3 = new bn(stack.pop());
            var n2 = new bn(stack.pop());
            var n1 = new bn(stack.pop());
            var val = n2.cmp(n1) <= 0 && n1.cmp(n3) < 0;
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
        var res = utils.isEqual(stack.pop(), stack.pop());
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

        var pub = stack.pop();
        var sig = stack.pop();
        var type = sig[sig.length - 1];
        if (!constants.rhashType[type & 0x1f])
          return false;

        if (!script.isValidSig(sig))
          return false;

        var subscript = script.subscript(s, lastSep);
        var hash = tx.subscriptHash(index, subscript, type);

        var res = script.verify(hash, sig.slice(0, -1), pub);
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

        var n = stack.pop();
        if (n.length !== 1 || !(1 <= n[0] && n[0] <= 15))
          return false;
        n = n[0] || 0;

        if (stack.length < n + 1)
          return false;

        var keys = [];
        for (var i = 0; i < n; i++) {
          var key = stack.pop();
          if (!(33 <= key.length && key.length <= 65))
            return false;

          keys.push(key);
        }

        var m = stack.pop();
        if (m.length !== 1 || !(1 <= m[0] && m[0] <= n))
          return false;
        m = m[0] || 0;

        if (stack.length < m + 1)
          return false;

        var subscript = script.subscript(s, lastSep);

        // Get signatures
        var succ = 0;
        for (var i = 0; i < m; i++) {
          var sig = stack.pop();
          var type = sig[sig.length - 1];
          if (!constants.rhashType[type & 0x1f])
            return false;

          if (!script.isValidSig(sig))
            return false;

          var hash = tx.subscriptHash(index, subscript, type);

          // Strict order:
          var res = script.verify(hash, sig.slice(0, -1), keys.pop());
          if (res)
            succ++;
        }

        // Extra value
        stack.pop();

        var res = succ >= m;
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
        // input: [[], sig1, sig2, 1]
        // prev_out: [[lock], 'checklocktimeverify', 'drop',
        //            'dup', 'hash160', pubkey, 'equalverify', 'checksig']
        if (!tx || stack.length === 0)
          return false;

        var lock = new bn(stack[stack.length - 1]).toNumber();

        if (lock < 0)
          return false;

        var threshold = constants.locktimeThreshold;
        if (!(
          (tx.lock <  threshold && lock <  threshold) ||
          (tx.lock >= threshold && lock >= threshold)
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
        // var evalScript = script.decode(stack.pop());
        // if (!Array.isArray(evalScript))
        //   return false;
        // var res = script.execute(evalScript, stack, tx, index);
        // if (!res)
        //   return false;
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

script.exec = function(input, output, tx, i) {
  var stack = [];
  script.execute(input, stack, tx, i);
  var res = script.execute(output, stack, tx, i);
  if (!res || stack.length === 0 || !utils.isEqual(stack.pop(), [ 1 ]))
    return false;
  return true;
};

script.multisig = function(keys, m, n) {
  if (keys.length < m)
    throw new Error('Wrong amount of pubkeys for multisig script');

  assert(m >= 1 && m <= n);
  assert(n >= 1 && n <= 15);

  while (keys.length < n)
    keys.push([]);

  // Keys need to be in a predictable order.
  keys = keys.sort(function(a, b) {
    return new bn(a).cmp(new bn(b)) > 0;
  });

  return [ m ].concat(
    keys,
    [ n, 'checkmultisig' ]
  );
};

script.standard = function standard(s) {
  return (script.isPubkey(s) && 'pubkey')
    || (script.isPubkeyhash(s) && 'pubkeyhash')
    || (script.isMultisig(s) && 'multisig')
    || (script.isScripthash(s) && 'scripthash')
    || (script.isColored(s) && 'colored')
    || null;
};

script.lockTime = function lockTime(s) {
  return s.length > 3
    && Array.isArray(s[0])
    && s[1] === 'checklocktimeverify'
    && s[2] === 'drop'
    && new bn(s[0]);
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
  if (script.lockTime(s))
    s = s.slice(3);

  if (s.length !== 2)
    return false;

  var match = Array.isArray(s[0]) && s[1] === 'checksig';
  if (!match)
    return false;

  if (key)
    return utils.isEqual(s[0], key);
  else
    return s[0];
};

script.isPubkeyhash = function isPubkeyhash(s, hash) {
  if (script.lockTime(s))
    s = s.slice(3);

  if (s.length !== 5)
    return false;

  var match = s[0] === 'dup' &&
              s[1] === 'hash160' &&
              Array.isArray(s[2]) &&
              s[3] === 'eqverify' &&
              s[4] === 'checksig';
  if (!match)
    return false;

  if (hash)
    return utils.isEqual(s[2], hash);
  else
    return s[2];
};

script.isMultisig = function isMultisig(s, pubs) {
  if (script.lockTime(s))
    s = s.slice(3);

  if (s.length < 4)
    return false;

  if (pubs && !Array.isArray(pubs[0]))
    pubs = [pubs];

  var m = s[0];
  if (typeof m === 'number' && m >= 1 && m <= 15)
    m = [m];
  if (!Array.isArray(m) || m.length !== 1)
    return false;
  m = m[0] || 0;

  if (s[s.length - 1] !== 'checkmultisig')
    return false;

  var n = s[s.length - 2];
  if (typeof n === 'number' && n >= 1 && n <= 15)
    n = [n];
  if (!Array.isArray(n) || n.length !== 1)
    return false;
  n = n[0] || 0;

  if (n + 3 !== s.length)
    return false;

  var keys = s.slice(1, 1 + n);
  var isArray = keys.every(function(k) {
    return Array.isArray(k);
  });
  if (!isArray)
    return false;

  if (!pubs)
    return keys;

  var total = keys.filter(function(k) {
    return pubs.some(function(pub) {
      return utils.isEqual(k, pub);
    });
  }).length;

  return total >= m;
};

script.isScripthash = function isScripthash(s, hash) {
  if (script.lockTime(s))
    s = s.slice(3);

  if (s.length !== 3)
    return false;

  var res = s[0] === 'hash160' &&
            Array.isArray(s[1]) &&
            s[1].length === 20 &&
            s[2] === 'eq';

  if (!res)
    return false;

  if (hash)
    return utils.isEqual(s[1], hash);

  return true;
};

script.isColored = function isColored(s) {
  if (s.length !== 2)
    return false;

  return s[0] === 'ret' &&
         Array.isArray(s[1]) &&
         s[1].length <= 40;
};

script.colored = function colored(s) {
  if (!script.isColored(s))
    return false;

  return s[1];
};

script.standardInput = function standardInput(s) {
  return (script.isPubkeyInput(s) && 'pubkey')
    || (script.isPubkeyhashInput(s) && 'pubkeyhash')
    || (script.isScripthashInput(s) && 'scripthash')
    || (script.isMultisigInput(s) && 'multisig')
    || null;
};

script.isPubkeyInput = function isPubkeyInput(s, key, tx, i) {
  if (s.length !== 1 || !Array.isArray(s[0]))
    return false;

  // var res = script.isValidSig(s[0]);
  var res = 9 <= s[0].length && s[0].length <= 73;
  if (!res)
    return false;

  if (key)
    return script.exec(s, [key, 'checksig'], tx, i);

  return true;
};

script.isPubkeyhashInput = function isPubkeyhashInput(s, key) {
  if (s.length !== 2 || !Array.isArray(s[0]) || !Array.isArray(s[1]))
    return false;

  // var res = script.isValidSig(s[0]) &&
  //           33 <= s[1].length && s[1].length <= 65;

  var res = 9 <= s[0].length && s[0].length <= 73 &&
            33 <= s[1].length && s[1].length <= 65;

  if (!res)
    return false;

  if (key)
    return utils.isEqual(s[1], key);

  return true;
};

script.isMultisigInput = function isMultisigInput(s, pubs, tx, i) {
  if (s.length < 3)
    return false;

  if (!Array.isArray(s[0]) || s[0].length !== 0)
    return false;

  for (var i = 1; i < s.length; i++) {
    // var res = Array.isArray(s[i]) && script.isValidSig(s[i]);
    var res = Array.isArray(s[i]) && 9 <= s[i].length && s[i].length <= 73;
    if (!res)
      return false;
  }

  if (pubs && pubs.length >= 2) {
    var o = script.multisig(pubs, 2, pubs.length);
    return script.exec(s, o, tx, i);
  }

  return true;
};

script.isScripthashInput = function isScripthashInput(s, redeem) {
  if (s.length < 4)
    return false;

  if (!Array.isArray(s[0]) || s[0].length !== 0)
    return false;

  for (var i = 1; i < s.length - 1; i++) {
    // var res = Array.isArray(s[i]) && script.isValidSig(s[i]);
    var res = Array.isArray(s[i]) && 9 <= s[i].length && s[i].length <= 73;
    if (!res)
      return false;
  }

  var r = Array.isArray(s[s.length - 1]) && s[s.length - 1];
  if (r[r.length - 1] !== constants.opcodes.checkmultisig)
    return false;

  if (redeem)
    return utils.isEqual(redeem, r);

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
script.isValidSig = function(sig) {
  // Empty signature. Not strictly DER encoded, but allowed to provide a
  // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
  if (sig.length === 0)
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
  var lenR = sig[3];

  // Make sure the length of the S element is still inside the signature.
  if (5 + lenR >= sig.length)
    return false;

  // Extract the length of the S element.
  var lenS = sig[5 + lenR];

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

script.format = function(input, output) {
  var scripts = [];

  if (input) {
    var script = input.script;
    scripts.push(script);
    if (input.out.tx && input.out.tx.outputs[input.out.index]) {
      var prev = input.out.tx.outputs[input.out.index].script;
      scripts.push(prev);
      if (script.isScripthash(prev)) {
        var redeem = script.decode(input.script[input.script.length - 1]);
        scripts.push(redeem);
      }
    }
  } else if (output) {
    scripts.push(output);
  }

  scripts = scripts.map(function(script) {
    return script.map(function(chunk) {
      if (Array.isArray(chunk)) {
        if (chunk.length === 0)
          return 0 + '';
        return utils.toHex(chunk);
      }
      if (typeof chunk === 'number')
        return chunk + '';
      return chunk;
    }).join(' ');
  });

  return scripts;
};
