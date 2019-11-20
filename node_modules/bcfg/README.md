# bcfg

Config parser (used for bcoin).

## Usage

``` js
const Config = require('bcfg');

// Will consider ~/.my-module the prefix directory.
const config = new Config('my-module', {
  alias: {
    'n': 'network'
  }
});

// Inject some custom options first.
config.inject({
  some: 'user',
  options: 'here'
});

config.load({
  // Parse URL hash
  hash: true,
  // Parse querystring
  query: true,
  // Parse environment
  env: true,
  // Parse args
  argv: true
});

// Will parse ~/.my-module/my-config.conf (throws on FS error).
config.open('my-config.conf');

// These will cast types and throw on incorrect type.
console.log(config.str('username'));
console.log(config.str('password'));
console.log(config.uint('userid'));
console.log(config.float('percent'));
console.log(config.bool('initialize'));
```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2017, Christopher Jeffrey (MIT License).

See LICENSE for more info.
