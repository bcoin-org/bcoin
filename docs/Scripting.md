Scripts are array-like objects with some helper functions.

``` js
const bcoin = require('bcoin');
const assert = require('assert');
const Script = bcoin.script;
const Witness = bcoin.witness;
const Stack = bcoin.stack;

const output = new Script();
output.pushSym('OP_DROP');
output.pushSym('OP_ADD');
output.pushInt(7);
output.pushSym('OP_NUMEQUAL');
// Compile the script to its binary representation
// (you must do this if you change something!).
assert(output.getSmall(2) === 7); // compiled as OP_7
output.compile();

const input = new Script();
input.setString(0, 'hello world'); // add some metadata
input.pushInt(2);
input.pushInt(5);
input.push(input.shift());
assert(input.getString(2) === 'hello world');
input.compile();

// A stack is another array-like object which contains
// only Buffers (whereas scripts contain Opcode objects).
const stack = new Stack();
input.execute(stack);
output.execute(stack);
// Verify the script was successful in its execution:
assert(stack.length === 1);
assert(stack.getBool(-1) === true);
```

Using a witness would be similar, but witnesses do not get executed, they
simply _become_ the stack. The witness object itself is very similar to the
Stack object (an array-like object containing Buffers).

``` js
const witness = new Witness();
witness.pushInt(2);
witness.pushInt(5);
witness.pushString('hello world');

const stack = witness.toStack();
output.execute(stack);
```
