s3encrypt
-----------

![Test](https://github.com/tkeech1/s3encrypt/workflows/Test/badge.svg)
[![codecov](https://codecov.io/gh/tkeech1/s3encrypt/branch/master/graph/badge.svg)](https://codecov.io/gh/tkeech1/s3encrypt)
[![Known Vulnerabilities](https://snyk.io/test/github/tkeech1/s3encrypt/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/tkeech1/s3encrypt?targetFile=requirements.txt)

A python program to compress and encrypt the contents of a directory and store in S3.

Features
--------

s3encrypt store LOCAL_DIRECTORY(S) S3_BUCKETNAME S3_FILENAME ENCRYPTION_KEY

TODO
----

* Logging to file
* Integration with KMS and AWS Encryption SDK
* Unit tests
* Docs
* packaging
* boto3 exception handling