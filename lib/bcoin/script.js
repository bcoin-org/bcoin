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

script.execute = function execute(s, stack, tx, index) {
  if (s.length > 10000)
    return false;

  var input = tx.inputs[index];

  for (var pc = 0; pc < s.length; pc++) {
    var o = s[pc];
    if (Array.isArray(o)) {
      stack.push(o);
    } else if (typeof o === 'number' && o >= 1 && o <= 16) {
      stack.push([o]);
    } else if (o === 'dup') {
      if (stack.length === 0)
        return false;

      stack.push(stack[stack.length - 1]);
    } else if (o === 'drop') {
      stack.pop();
    } else if (o === 'hash160') {
      if (stack.length === 0)
        return false;

      stack.push(utils.ripesha(stack.pop()));
    } else if (o === 'eqverify' || o === 'eq') {
      if (stack.length < 2)
        return false;

      var res = utils.isEqual(stack.pop(), stack.pop());
      if (o === 'eqverify') {
        if (!res)
          return false;
      } else {
        stack.push(res ? [ 1 ] : []);
      }

    } else if (o === 'checksigverify' || o === 'checksig') {
      if (!tx || stack.length < 2)
        return false;

      var pub = stack.pop();
      var sig = stack.pop();
      var type = sig[sig.length - 1];
      if (!constants.rhashType[type & 0x7f])
        return false;

      if (!script.isValidSig(sig))
        return false;

      var subscript = input.out.tx.getSubscript(input.out.index);
      var hash = tx.subscriptHash(index, subscript, type);

      var res = script.verify(hash, sig.slice(0, -1), pub);
      if (o === 'checksigverify') {
        if (!res)
          return false;
      } else {
        stack.push(res ? [ 1 ] : []);
      }
    } else if (o === 'checkmultisigverify' || o === 'checkmultisig') {
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
      for (var i = 0, j = 0; i < m && j < n; i++) {
        var sig = stack.pop();
        var type = sig[sig.length - 1];
        if (!constants.rhashType[type & 0x7f])
          return false;

        var subscript = input.out.tx.getSubscript(input.out.index);
        var hash = tx.subscriptHash(index, subscript, type);

        if (!script.isValidSig(sig))
          return false;

        var res = false;
        for (; !res && j < n; j++)
          res = script.verify(hash, sig.slice(0, -1), keys[j]);
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
    } else if (o === 'checklocktimeverify') {
      // input: [[], sig1, sig2, 1]
      // prev_out: [[lock], 'checklocktimeverify', 'drop',
      //            'dup', 'hash160', pubkey, 'equalverify', 'checksig']
      if (stack.length === 0)
        return false;

      var lock = stack[stack.length - 1];
      if (lock.length !== 1)
        return false;

      lock = lock[0];

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
    } else {
      // Unknown operation
      return false;
    }
  }

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
