s3encrypt
-----------

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

* File watch and automatic upload
* Logging to file
* Integration with KMS
* Fix salt
* Unit tests
* e2e tests
* Docs
* update pipfile