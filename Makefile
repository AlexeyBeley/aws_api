
SHELL := /bin/bash

SRC_DIR= /Users/alexeybe/private
BUILD_DIR= ${SRC_DIR}/_build
VENV_DIR= ${BUILD_DIR}/_venv
ZIP_FILE= ${BUILD_DIR}/function.zip

REQUIREMENTS=~/private/IP

ALL_FILES := $(wildcard *)
EXCLUSIONS := Makefile _build
SRC_FILES := $(filter-out $(EXCLUSIONS), $(ALL_FILES))

venv_dir:
	mkdir -p ${BUILD_DIR}
	python3 -m venv ${VENV_DIR} && \
	pip3 install wheel

package_source_requirements: venv_dir
	for VARIABLE in ${REQUIREMENTS}; do \
	cd $$VARIABLE; \
	rm -rf $$VARIABLE\dist; \
	python3 setup.py sdist bdist_wheel; \
	done

install_source_requirements: package_source_requirements
	source ${VENV_DIR}/bin/activate && \
	for VARIABLE in ${REQUIREMENTS}; do \
	cd $$VARIABLE; \
	pip3 install dist/*.whl; \
	done

clear_zip:
	rm -rf ${SRC_DIR}/function.zip

zip_src: install_source_requirements clear_zip
	cd ${VENV_DIR}/lib/python3.7/site-packages &&\
	zip -r9 ${ZIP_FILE} . &&\
	cd ${SRC_DIR} && \
	for SRC_FILE in ${SRC_FILES}; do \
	zip -g ${ZIP_FILE} $$SRC_FILE; \
	done

invoke: install_source_requirements
	source ${VENV_DIR}/bin/activate &&\
	python3 invoke_me.py

raw_invoke:
	source ${VENV_DIR}/bin/activate &&\
	python3 invoke_me.py

clear:
	rm -rf ${VENV_DIR}

pylint:
	source ${VENV_DIR}/bin/activate &&\
	pip3 install pylint &&\
	pylint lambda_event.py
	#pylint ${SRC_FILES}

