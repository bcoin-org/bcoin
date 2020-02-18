# bmutex

Mutex locks for javascript.

## Usage

``` js
const {Lock} = require('bmutex');
const lock = Lock.create();

async function doSomething() {
  const unlock = await lock();
  try {
    await _doSomething();
  } finally {
    unlock();
  }
}

async function _doSomething() {
  // actually do something async
}
```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2017, Christopher Jeffrey (MIT License).

See LICENSE for more info.
