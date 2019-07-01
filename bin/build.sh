#!/bin/bash

if [ -d ~/git/a2cmgmt/html/css ]; then
  aws --profile nejllreports s3 cp --acl public-read ~/git/a2cmgmt/html/css/* s3://a2c-html-530317771161/admin/css/
fi

if [ -d ~/git/a2cmgmt/html/javascript ]; then
  aws --profile nejllreports s3 cp --acl public-read ~/git/a2cmgmt/html/javascript/* s3://a2c-html-530317771161/admin/javascript/
fi
