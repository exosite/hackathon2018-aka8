.PHONY: test

test:
	rm -f luacov.* && \
	luacheck . && \
	busted --lpath='./modules/?.lua' && \
	luacov-console && \
	luacov-console -s
