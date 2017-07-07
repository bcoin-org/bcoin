all:
	@npm run webpack

browser:
	@npm run webpack-browser

compat:
	@npm run webpack-compat

node:
	@npm run webpack-node

clean:
	@npm run clean

docs:
	@npm run docs

lint:
	@npm run lint

test:
	@npm test

.PHONY: all browser compat node clean docs lint test
