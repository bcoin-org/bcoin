'use strict';

function getter(obj, prop, get) {
  Object.defineProperty(obj, prop, { get });
}

function thrower(obj, prop, get) {
  getter(obj, prop, () => {
    throw new Error(prop);
  });
}

// I think any one of these will crash Mocha.
describe('Evil Error Test', () => {
  it('should not crash', (cb) => {
    cb({
      name: 'Error',
      get message() {
        throw new Error('haha');
      },
      stack: 'foobar'
    });
  });

  it('should not crash', (cb) => {
    cb({
      get name() {
        throw new Error('haha');
      },
      message: 'foobar',
      stack: 'foobar'
    });
  });

  it('should not crash', (cb) => {
    cb({
      name: 'Error',
      message: 'foobar',
      get stack() {
        throw new Error('haha');
      }
    });
  });

  it('should not crash', (cb) => {
    const err = new Error('foobar');
    err.stack;
    thrower(err, 'name');
    cb(err);
  });

  it('should not crash', (cb) => {
    const err = new Error('foobar');
    err.stack;
    thrower(err, 'message');
    cb(err);
  });

  it('should not crash', (cb) => {
    const err = new Error('foobar');
    err.stack;
    thrower(err, 'stack');
    cb(err);
  });

  it('should not crash', (cb) => {
    const err = new Error('foobar');
    thrower(err, 'name');
    cb(err);
  });

  it('should not crash', (cb) => {
    const err = new Error('foobar');
    thrower(err, 'message');
    cb(err);
  });

  it('should not crash', (cb) => {
    const err = new Error('foobar');
    thrower(err, 'stack');
    cb(err);
  });

  it('should not crash', (cb) => {
    cb(Object.create(null));
  });

  it('should not crash', (cb) => {
    const err = new Error('foobar');
    err.stack;
    err.name = Object.create(null);
    cb(err);
  });

  it('should not crash', (cb) => {
    const err = new Error('foobar');
    err.stack;
    err.message = Object.create(null);
    cb(err);
  });

  it('should not crash', (cb) => {
    const err = new Error('foobar');
    err.stack;
    err.stack = Object.create(null);
    cb(err);
  });

  it('should not crash', (cb) => {
    const err = new Error('foobar');
    err.name = Object.create(null);
    cb(err);
  });

  it('should not crash', (cb) => {
    const err = new Error('foobar');
    err.message = Object.create(null);
    cb(err);
  });

  it('should not crash', (cb) => {
    const err = new Error('foobar');
    err.stack = Object.create(null);
    cb(err);
  });

  it('should not crash', (cb) => {
    const err = new Error('foobar');
    err.name = Object.create(null);
    err.message = Object.create(null);
    cb(err);
  });

  it('should not crash', (cb) => {
    const err = new Error('foobar');
    thrower(err, 'name');
    thrower(err, 'message');
    cb(err);
  });

  it('should not crash', () => {
    return {
      get then() {
        throw new Error('haha');
      }
    };
  });

  it('should not crash on fake promise', () => {
    let i = 0;
    return {
      get then() {
        i ^= 1;
        if (i === 1)
          return () => {};
        throw new Error('haha');
      }
    };
  });

  it('should not crash', () => {
    return {
      then() {
        throw new Error('haha');
      }
    };
  });

  it('should not crash', (cb) => {
    cb(new Proxy(new Error('haha'), {
      getPrototypeOf() {
        throw new Error('haha');
      }
    }));
  });

  it('should not crash', (cb) => {
    // The most evil object there is...
    cb(new Proxy(new Error('haha'), {
      has() {
        throw new Error('haha');
      },
      get() {
        throw new Error('haha');
      },
      set() {
        throw new Error('haha');
      },
      ownKeys() {
        throw new Error('haha');
      },
      getOwnPropertyDescriptor() {
        throw new Error('haha');
      },
      defineProperty() {
        throw new Error('haha');
      }
    }));
  });

  it('should not crash', (cb) => {
    // I take it back, _this_ is the most evil object there is...
    const proxy = new Proxy(new Error('haha'), {
      has() {
        throw new Error('haha');
      },
      get() {
        throw new Error('haha');
      },
      set() {
        throw new Error('haha');
      },
      ownKeys() {
        throw new Error('haha');
      },
      getOwnPropertyDescriptor() {
        throw new Error('haha');
      },
      defineProperty() {
        throw new Error('haha');
      }
    });

    cb(new Proxy(new Error('haha'), {
      has(_, key) {
        return true;
      },
      get(_, key) {
        return proxy;
      },
      set() {
        throw new Error('haha');
      },
      ownKeys() {
        return [];
      },
      getOwnPropertyDescriptor() {
        return {
          value: proxy
        };
      },
      defineProperty() {
        throw new Error('haha');
      }
    }));
  });
});
