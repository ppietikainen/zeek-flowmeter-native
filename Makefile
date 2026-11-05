all:
	@test -d build || ./configure
	$(MAKE) -C build
clean:
	rm -rf build
