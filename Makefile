all: release

clean:
	@echo Cleaning...
	-rm -r ./build
	-rm -r ./dist

remove_symlinks:
	@echo Removing symlinks for build...
	-rm ./RNS

create_symlinks:
	@echo Creating symlinks...
	-ln -s ../Reticulum/RNS ./

build_wheel:
	python3 setup.py sdist bdist_wheel

release: remove_symlinks build_wheel create_symlinks

upload:
	@echo Uploading to PyPi...
	twine upload dist/*
