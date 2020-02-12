# AwsSignature

Amazon PHP SDK Version 4 for general use. 
This SDK involves services the project does not need and can create unnecessary load. 
For this reason, it is PHP SDK Version 4 is minimized.

Aws-signature library sends requests that are compatible with Amazon’s Restful structure.

  * You can transfer files from local to S3 or from S3 to local.
  * You can create a temporary access link to a file in S3.

## Tests

* mv tests/template-env.in tests/env.ini
* kendi inilerini yaz 
* vendor/bin/phpunit tests git log
