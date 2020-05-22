#!/bin/bash

# fail in case of error
set -e

# set the same Go environment for dealing with modules
export GO111MODULE=on
export GOPROXY=https://goproxy.io
export GOPRIVATE=$GOPRIVATE,github.com/Infoblox-CTO

# get Infoblox-CTO packages
go get github.com/Infoblox-CTO/janus-common/log
go get github.com/Infoblox-CTO/ngp.app.common/log

# create the tarballs on vpp package level
pushd $(go env GOPATH)/pkg/mod/github.com
tar -cvzf ibpkg-mod.tgz ./\!infoblox-\!c\!t\!o
cd ../cache/download/github.com
tar -cvzf ibpkg-mod-cache.tgz ./\!infoblox-\!c\!t\!o
popd
mv $(go env GOPATH)/pkg/mod/github.com/ibpkg-mod.tgz .
mv $(go env GOPATH)/pkg/mod/cache/download/github.com/ibpkg-mod-cache.tgz .
