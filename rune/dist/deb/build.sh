#!/bin/bash

PROJECT_DIR=$(cd ../../..; pwd)
DEBBUILD_DIR=$(mktemp -u /tmp/debbuild.XXXX)
SCRIPT_DIR=$(pwd)
PACKAGE=rune
PROJECT=inclavare-containers
VERSION=$(cd ../..; cat ./VERSION)
RELEASE_TARBALL=$DEBBUILD_DIR/v$VERSION.tar.gz
RELEASE_TARBALL_URL=https://github.com/alibaba/inclavare-containers/archive/v$VERSION.tar.gz
TARBALL_NAME=$PACKAGE\_$VERSION.orig.tar.gz
DEB_BUILD_FOLDER=$DEBBUILD_DIR/$PACKAGE-$VERSION

# create and rename the tarball
mkdir -p $DEBBUILD_DIR
if [ ! -f "$RELEASE_TARBALL" ]; then
  wget -P $DEBBUILD_DIR $RELEASE_TARBALL_URL
fi
tar zxfP $DEBBUILD_DIR/v$VERSION.tar.gz -C $DEBBUILD_DIR
mv $DEBBUILD_DIR/$PROJECT-$VERSION $DEBBUILD_DIR/$PACKAGE-$VERSION
cd $DEBBUILD_DIR && tar zcfP $TARBALL_NAME $PACKAGE-$VERSION

# check the go version
if ! [ -x "$(command -v go)" ]; then
  echo 'Error: go is not installed. Please install Go 1.14 and above'
  exit 1
fi

NEED_GO_VERSION=14
CURRENT_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//g' | sed 's/\./ /g' | awk '{print $2}')
if [ $CURRENT_GO_VERSION -lt $NEED_GO_VERSION  ]; then
  echo 'Error: go version is less than 1.14.0. Please install Go 1.14 and above'
  exit
fi

# build_deb_package
cp -rf  $SCRIPT_DIR/debian $DEB_BUILD_FOLDER
cd $DEB_BUILD_FOLDER
dpkg-buildpackage -us -uc
cp $DEBBUILD_DIR/*.*deb $PROJECT_DIR
rm -rf $DEBBUILD_DIR
