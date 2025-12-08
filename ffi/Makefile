hs-test:
	cargo build --release --locked

	cd bindings/haskell && \
	# link Rust libs we just built \
	# required because cabal does not support relative paths outside its root dir :/ \
	ln -fs ../../../target . && \
	cabal test --test-show-details=always --test-option=--color
