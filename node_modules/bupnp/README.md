# bupnp

UPNP for node.js.

## Usage

``` js
const UPNP = require('bupnp');
```

## API

```javascript
// Set a timeout
UPNP.RESPONSE_TIMEOUT = 1000

// Discovering internet gateway (upnp)
let wan = await UPNP.discover()

// Find external IP (upnp)
let host = await wan.getExternalIP()

// Add port mapping (remoteHost, externalPort, internalPort)
await wan.addPortMapping(host, src, dest)

// Remove port mapping
await wan.removePortMapping(host, port)
```


## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2017, Christopher Jeffrey (MIT License).

See LICENSE for more info.
