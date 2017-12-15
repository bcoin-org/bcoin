all:
	@npm run webpack

app:
	@npm run webpack-app

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

.PHONY: all app browser compat node clean docs lint test
