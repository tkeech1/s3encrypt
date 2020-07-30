s3encrypt
-----------

![Build](https://github.com/tkeech1/s3encrypt/workflows/Test/badge.svg)
[![codecov](https://codecov.io/gh/tkeech1/s3encrypt/branch/master/graph/badge.svg)](https://codecov.io/gh/tkeech1/s3encrypt)

A command line tool to compress and encrypt the contents of a directory and store in S3.

Usage
--------
```
s3encrypt --log-level INFO --directories testfiles/ testfiles2/ --s3_bucket tdk-bd-keep.io --password 12345
```

TODO
----

* Docs
* packaging
* boto3 exception handling