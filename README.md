s3encrypt
-----------

![Test](https://github.com/tkeech1/s3encrypt/workflows/Test/badge.svg)
[![codecov](https://codecov.io/gh/tkeech1/s3encrypt/branch/master/graph/badge.svg)](https://codecov.io/gh/tkeech1/s3encrypt)
[![Known Vulnerabilities](https://snyk.io/test/github/tkeech1/s3encrypt/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/tkeech1/s3encrypt?targetFile=requirements.txt)


A python program to compress and encrypt the contents of a directory and store in S3.

Features
--------

s3encrypt store LOCAL_DIRECTORY(S) S3_BUCKETNAME S3_FILENAME ENCRYPTION_KEY
	- zips contents of directory
		- https://www.geeksforgeeks.org/working-zip-files-python/
	- encrypts the zip with aws client library
		- https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/python-example-code.html#python-example-streams
	- saves to S3 bucket with distinct filename

TODO
----

* Logging to file
* Integration with KMS
* Unit tests
* e2e tests
* Docs 
* Github actions