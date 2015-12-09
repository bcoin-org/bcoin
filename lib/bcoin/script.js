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
      continue;
    }

    // Zero
    if (b === 0) {
      opcodes.push([]);
      continue;
    }

    // Raw number
    if (b >= 0x51 && b <= 0x60) {
      opcodes.push(b - 0x50);
      continue;
    }

    var opcode = constants.opcodesByVal[b];
    if (opcode === 'pushdata1') {
      var len = s[i++];
      opcodes.push(s.slice(i, i + len));
      i += 2 + len;
    } else if (opcode === 'pushdata2') {
      var len = utils.readU16(s, i);
      i += 2;
      opcodes.push(s.slice(i, i + len));
      i += len;
    } else if (opcode === 'pushdata4') {
      var len = utils.readU32(s, i);
      i += 4;
      opcodes.push(s.slice(i, i + len));
      i += len;
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

script.subscript = function subscript(s) {
  if (!s)
    return [];

  var lastSep = -1;
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
    else if (o === 'else')
      depth--;
    else if (o === 'endif')
      depth--;
    if (depth < 0)
      break;
    if (depth === 0 && o === to)
      return pc;
    if (o === 'else')
      depth++;
    pc++;
  }
  return -1;
};

script.execute = function execute(s, stack, tx, index) {
  s = s.slice();

  if (s.length > 10000)
    return false;

  var input = tx.inputs[index];
  var lastSep = -1;

  stack.alt = stack.alt || [];

  for (var pc = 0; pc < s.length; pc++) {
    var o = s[pc];

    if (Array.isArray(o)) {
      stack.push(o);
      continue;
    }

    if (typeof o === 'number' && o >= 1 && o <= 16) {
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
        val = new bn(v).cmp(0) !== 0;
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
          if (else_ === -1)
            s.splice(if_, (endif - if_) + 1);
          else
            s.splice(if_, (else_ - if_) + 1);
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
        if (new bn(stack[stack.length - 1]).cmp(0) === 0)
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
        if (new bn(stack[stack.length - 1]).cmp(0) !== 0)
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
            if (n.cmp(0) < 0)
              n = n.neg();
            break;
          case 'not':
            n = n.cmp(0) === 0;
            break;
          case 'noteq0':
            n = n.cmp(0) !== 0;
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
                n = n1.cmp(0) !== 0 && n2.cmp(0) !== 0;
                break;
              case 'boolor':
                n = n1.cmp(0) !== 0 || n2.cmp(0) !== 0;
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
            var res = n.cmp(0) !== 0;
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
            stack.push(val.cmp(0) !== 0 ? [ 1 ] : []);
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
        if (!constants.rhashType[type & 0x7f])
          return false;

        if (!script.isValidSig(sig))
          return false;

        var subscript = s.slice(lastSep + 1);
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
        if (n.length !== 1 || !(1 <= n[0] && n[0] <= 3))
          return false;
        n = n[0];

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
        m = m[0];

        if (stack.length < m + 1)
          return false;

        // Get signatures
        var succ = 0;
        for (var i = 0; i < m; i++) {
          var sig = stack.pop();
          var type = sig[sig.length - 1];
          if (!constants.rhashType[type & 0x7f])
            return false;

          var subscript = s.slice(lastSep + 1);
          var hash = tx.subscriptHash(index, subscript, type);

          if (!script.isValidSig(sig))
            return false;

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
        if (stack.length === 0)
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

        if (input.seq === 0xffffffff)
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
        // break;
        return false;
      }
      default: {
        // Unknown operation
        return false;
      }
    }
  }

  if (stack.length + stack.alt.length > 1000)
    return false;

  return true;
};

script.multisig = function(keys, m, n) {
  if (keys.length < m)
    throw new Error('wrong amount of pubkeys for multisig script');

  assert(m >= 1 && m <= n);
  assert(n >= 1 && n <= 7);

  // Format:
  // op_[m] [pubkey1-len] [pubkey1] ... op_[n] op_checkmultisig

  // Using pushdata ops for m and n:
  // return [ [ m ] ].concat(
  //   keys,
  //   [ [ n ], 'checkmultisig' ]
  // );

  // Keys need to be in a predictable order.
  keys = keys.sort(function(a, b) {
    return new bn(a).cmp(new bn(b)) > 0;
  });

  // Using OP_1-16 for m and n:
  return [ m ].concat(
    keys,
    [ n, 'checkmultisig' ]
  );
};

script.isPubkeyhash = function isPubkeyhash(s, hash) {
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

script.isSimplePubkeyhash = function isSimplePubkeyhash(s, hash) {
  if (s.length !== 2)
    return false;

  var match = Array.isArray(s[0]) && s[1] === 'checksig';
  if (!match)
    return false;

  if (hash)
    return utils.isEqual(s[0], hash);
  else
    return s[0];
};

script.isMultisig = function isMultisig(s, key) {
  if (s.length < 4)
    return false;

  var m = s[0];
  if (typeof m === 'number' && m >= 1 && m <= 16)
    m = [m];
  if (!Array.isArray(m) || m.length !== 1)
    return false;
  m = m[0];

  if (s[s.length - 1] !== 'checkmultisig')
    return false;

  var n = s[s.length - 2];
  if (typeof n === 'number' && n >= 1 && n <= 16)
    n = [n];
  if (!Array.isArray(n) || n.length !== 1)
    return false;
  n = n[0];

  if (n + 3 !== s.length)
    return false;

  var keys = s.slice(1, 1 + n);
  var isArray = keys.every(function(k) {
    return Array.isArray(k);
  });
  if (!isArray)
    return false;

  if (!key)
    return keys;

  return m === keys.filter(function(k) {
    return utils.isEqual(k, key);
  }).length;
};

script.isPubkeyhashInput = function isPubkeyhashInput(s) {
  if (s.length !== 2)
    return false;

  return 9 <= s[0].length && s[0].length <= 73 &&
         33 <= s[1].length && s[1].length <= 65;
};

script.isScripthash = function isScripthash(s, hash) {
  if (s.length !== 3)
    return false;

  var ret = s[0] === 'hash160' &&
            Array.isArray(s[1]) &&
            s[1].length === 20 &&
            s[2] === 'eq';

  if (!ret)
    return false;

  if (hash)
    return utils.isEqual(s[1], hash);

  return true;
};

script.isNullData = function isNullData(s) {
  if (s.length !== 2)
    return false;

  return s[0] === 'ret' &&
         Array.isArray(s[1]) &&
         s[1].length <= 40;
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
