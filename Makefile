all: release

clean:
	@echo Cleaning...
	-rm -r ./build
	-rm -r ./dist

remove_symlinks:
	@echo Removing symlinks for build...
	-rm ./RNS
	-rm ./LXMF/Utilities/LXMF

create_symlinks:
	@echo Creating symlinks...
	-ln -s ../Reticulum/RNS ./
	-ln -s ../../LXMF ./LXMF/Utilities/LXMF

build_wheel:
	python3 setup.py bdist_wheel

build_sdist:
	python3 setup.py sdist

build_spkg: remove_symlinks build_sdist create_symlinks

release: remove_symlinks build_wheel build_spkg create_symlinks

upload:
	@echo Ready to publish release over Reticulum
	@read VOID
	rngit release rns://7649a50d84610232d1416b41d2896aff/reticulum/lxmf create $$(python setup.py --getversion):dist --name lxmf

upload-pip:
	@echo Uploading to PyPi...
	twine upload dist/*.whl dist/*.tar.gz
