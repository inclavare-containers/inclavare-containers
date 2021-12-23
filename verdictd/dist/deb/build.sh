#!/bin/bash

PROJECT_DIR=$(cd ../../..; pwd)
DEBBUILD_DIR=$(mktemp -u /tmp/debbuild.XXXX)
SCRIPT_DIR=$(pwd)
PACKAGE=verdictd
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

# check the Rust
if ! [ -x "$(command -v rustc)" ]; then
  echo 'Error: Rust is not installed. Please type the "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; source $HOME/.cargo/env" command to install Rust firstly'
  exit 1
fi

if ! [ -x "$(command -v cargo)" ]; then
   echo 'Error: Cargo is not installed. Please type the "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; source $HOME/.cargo/env" command to install Cargo firstly'
   exit 1
fi

# build_deb_package
cp -rf  $SCRIPT_DIR/debian $DEB_BUILD_FOLDER
cd $DEB_BUILD_FOLDER
DEB_CFLAGS_SET="-std=gnu11 -fPIC" DEB_CXXFLAGS_SET="-std=c++11 -fPIC" DEB_LDFLAGS_SET="-fPIC -L/usr/lib/x86_64-linux-gnu" dpkg-buildpackage -us -uc
cp $DEBBUILD_DIR/*.*deb $PROJECT_DIR
rm -rf $DEBBUILD_DIR
