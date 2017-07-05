all:
	@npm run webpack
	@cp -f lib/workers/worker-browser.js browser/bcoin-worker.js

browser:
	@npm run webpack-browser
	@cp -f lib/workers/worker-browser.js browser/bcoin-worker.js

compat:
	@npm run webpack-compat
	@cp -f lib/workers/worker-browser.js browser/bcoin-worker.js

node:
	@npm run webpack-node
	@cp -f lib/workers/worker.js ./bcoin-worker.js

clean:
	@npm run clean

docs:
	@npm run docs

lint:
	@npm run lint

test:
	@npm test

.PHONY: all browser compat node clean docs lint test
