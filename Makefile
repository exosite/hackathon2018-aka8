test-pre:
	luacheck .

test: test-pre test-impl test-post

test-impl:
	rm -f luacov.*
	busted tests > busted.xml

test-post:
	luacov-console
	luacov-console -s

deploy:
	murano syncup
