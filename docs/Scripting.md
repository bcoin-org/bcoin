Scripts are array-like objects with some helper functions.

``` js
var bcoin = require('bcoin');
var assert = require('assert');
var BN = bcoin.bn;
var opcodes = bcoin.script.opcodes;

var output = new bcoin.script();
output.push(opcodes.OP_DROP);
output.push(opcodes.OP_ADD);
output.push(new BN(7));
output.push(opcodes.OP_NUMEQUAL);
// Compile the script to its binary representation
// (you must do this if you change something!).
output.compile();
assert(output.getSmall(2) === 7); // compiled as OP_7

var input = new bcoin.script();
input.set(0, 'hello world'); // add some metadata
input.push(new BN(2));
input.push(new BN(5));
input.push(input.shift());
assert(input.getString(2) === 'hello world');
input.compile();

// A stack is another array-like object which contains
// only Buffers (whereas scripts contain Opcode objects).
var stack = new bcoin.stack();
input.execute(stack);
output.execute(stack);
// Verify the script was successful in its execution:
assert(stack.length === 1);
assert(bcoin.script.bool(stack.pop()) === true);
```

Using a witness would be similar, but witnesses do not get executed, they
simply _become_ the stack. The witness object itself is very similar to the
Stack object (an array-like object containing Buffers).

``` js
var witness = new bcoin.witness();
witness.push(new BN(2));
witness.push(new BN(5));
witness.push('hello world');

var stack = witness.toStack();
output.execute(stack);
```