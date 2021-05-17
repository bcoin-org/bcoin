# loady

Dynamic loader for node.js. Similar to [node-bindings].

## Usage

Scripts:

``` js
const addon = require('loady')('addon.node', __dirname);
```

Modules:

``` js
import loady from 'loady';

const addon = loady('addon.node', import.meta.url);
```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2019-2020, Christopher Jeffrey (MIT License).

See LICENSE for more info.

[node-bindings]: https://github.com/TooTallNate/node-bindings
