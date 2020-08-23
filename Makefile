# AWS
AWS_ACCESS_KEY_ID?=AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY?=AWS_SECRET_ACCESS_KEY
AWS_REGION?=AWS_REGION

# run 'make deps-dev' prior to running any other targets

# run as a module
run-module: format lint test	
	python -m s3encrypt --log-level INFO --directories testfiles/testzip testfiles/testzip2 --s3_bucket tdk-bd-keep.io --password 12345 --force 

run-module-watch: format lint test	
	python -m s3encrypt --log-level INFO --mode watch --directories testfiles/testzip testfiles/testzipsdsd2 --s3_bucket tdk-bd-keep.io --password 12345 --force 

run-profile:	
	python -m cProfile -s time -o profile.cprof runner.py
	#pyprof2calltree -k -i profile.cprof

run-profile-memory:	
	python -m memory_profiler runner.py

# output a text formatted profile information
run-profile-text:	
	python -m cProfile -s time runner.py > profile.txt

# requirements.txt is needed for snyk integration
create-requirementstxt:
	pipenv lock -r > requirements.txt

debug-test:
	python -m pytest -sv
	# using more processes makes it slower for a small number of tests
	# --numprocesses=auto
	
test: lint
	coverage run --source s3encrypt --omit */test*,e2e.py -m pytest
	coverage report -m 
	coverage html

# run as a script
test-e2e:	
	python e2e.py

format:
	black s3encrypt 

lint: format
	flake8 s3encrypt
	mypy s3encrypt --strict

tox:
	pyenv local 3.7.0 3.8.0 && tox

clean-all: clean
	rm -r .venv/ || true	

clean: clean-docs clean-pyc
	rm -r __pycache__/ || true
	rm -r .mypy_cache/ || true
	rm -r .pytest_cache/ || true
	rm -r .tox/ || true
	rm -r s3encrypt.egg* || true
	rm -r htmlcov/ || true
	rm *.log || true
	rm -r build/ || true
	rm -r dist/ || true
	rm df.csv || true
	rm -rf ~/stock_data || true
	
clean-pyc: 
	find . -name '*.pyc' -exec rm -f {} + || true
	find . -name '*.pyo' -exec rm -f {} + || true
	find . -name '*~' -exec rm -f {} + || true
	find . -name '__pycache__' -exec rm -fr {} + || true

clean-docs:
	rm -f docs/s3encrypt.rst || true
	rm -f docs/modules.rst || true
	rm -fr docs/_build || true

docs-html: clean-docs
	sphinx-apidoc -o docs/ s3encrypt
	$(MAKE) -C docs clean
	$(MAKE) -C docs html

bumpversion-patch:
	bump2version patch

bumpversion-minor:
	bump2version minor

bumpversion-major:
	bump2version major

deps-dev:
	pipenv install --dev
	pipenv shell

lock-deps:
	pipenv lock

deps-prd:
	pipenv install --ignore-pipfile

build-wheel: clean
	python setup.py bdist_wheel

install-wheel:
	pip install dist/s3encrypt-version_0.0.1_-py3-none-any.whl

uninstall-wheel:
	pip uninstall -y s3encrypt

run-wheel: # must be done after installing the wheel
	# run directly from the wheel file
	# python dist/s3encrypt-version_0.0.1_-py3-none-any.whl/s3encrypt
	# or use the module
	cd ~ && python -m s3encrypt --log-level INFO --directories /workspaces/s3encrypt/testfiles/testzip /workspaces/s3encrypt/testfiles/testzip2 --s3_bucket tdk-bd-keep.io --key 12345 --salt testsalt --force 

run-entry-point: 
	.venv/bin/s3encrypt --log-level INFO --directories testfiles/testzip testfiles/testzip2 --s3_bucket tdk-bd-keep.io --key 12345 --salt testsalt --force 

build-sdist: clean
	python setup.py sdist

distribute:
	#python setup.py register s3encrypt
	#python setup.py sdist upload -r testpypi
	# OR #
	#python setup.py bdist_wheel upload -r testpypi

install-setup:
	python setup.py install 

uninstall-setup:
	rm .venv/lib/python3.8/site-packages/s3encrypt-version_0.0.1_-py3.8.egg || true
	rm .venv/bin/s3encrypt || true
