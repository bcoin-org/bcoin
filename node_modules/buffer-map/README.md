# buffer-map

Buffer-keyed map for javascript.

## Usage

``` js
const assert = require('assert');
const {BufferMap} = require('buffer-map');
const key1 = Buffer.alloc(32, 0xab);
const key2 = Buffer.alloc(32, 0xab);

const map = new BufferMap();
map.set(key1, 'foo');
assert(map.get(key2) === 'foo');
```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2018, Christopher Jeffrey (MIT License).

See LICENSE for more info.
