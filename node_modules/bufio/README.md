# bufio

Buffer and serialization utilities for javascript.

## Usage

``` js
const assert = require('assert');
const bio = require('bufio');

const bw = bio.write();
bw.writeU64(100);
bw.writeString('foo');
const data = bw.render();

const br = bio.read(data);
assert(br.readU64() === 100);
assert(br.readString(3) === 'foo');
```

## Struct Usage

``` js
const bio = require('bufio');

class MyStruct extends bio.Struct {
  constructor() {
    super();
    this.str = 'hello';
    this.value = 0;
  }

  write(bw) {
    bw.writeVarString(this.str, 'ascii');
    bw.writeU64(this.value);
    return this;
  }

  read(br) {
    this.str = br.readVarString('ascii');
    this.value = br.readU64();
    return this;
  }
}

const obj = new MyStruct();

console.log('Buffer:');
console.log(obj.encode());

console.log('Decoded:');
console.log(MyStruct.decode(obj.encode()));

console.log('Hex:');
console.log(obj.toHex());

console.log('Decoded:');
console.log(MyStruct.fromHex(obj.toHex()));

console.log('Base64:');
console.log(obj.toBase64());
```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2017, Christopher Jeffrey (MIT License).

See LICENSE for more info.
