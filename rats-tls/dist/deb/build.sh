#!/bin/bash

PROJECT_DIR=$(cd ../../..; pwd)
DEBBUILD_DIR=$(mktemp -u /tmp/debbuild.XXXX)
SCRIPT_DIR=$(pwd)
PACKAGE=rats-tls
PROJECT=inclavare-containers
VERSION=$(cd ../..; cat ./VERSION)
RELEASE_TARBALL=$DEBBUILD_DIR/v$VERSION.tar.gz
RELEASE_TARBALL_URL=https://github.com/alibaba/inclavare-containers/archive/v$VERSION.tar.gz
TARBALL_NAME=$PACKAGE\_$VERSION.orig.tar.gz
DEB_BUILD_FOLDER=$DEBBUILD_DIR/$PACKAGE-$VERSION

BUILD_MODE[0]=host
BUILD_MODE[1]=occlum
BUILD_MODE[2]=tdx
BUILD_MODE_SPECIAL[0]=sgx

# create and rename the tarball
mkdir -p $DEBBUILD_DIR
if [ ! -f "$RELEASE_TARBALL" ]; then
  wget -P $DEBBUILD_DIR $RELEASE_TARBALL_URL
fi
tar zxfP $DEBBUILD_DIR/v$VERSION.tar.gz -C $DEBBUILD_DIR
mv $DEBBUILD_DIR/$PROJECT-$VERSION $DEBBUILD_DIR/$PACKAGE-$VERSION
cd $DEBBUILD_DIR && tar zcfP $TARBALL_NAME $PACKAGE-$VERSION

if [ -z "$SGX_SDK" ]; then
        SGX_SDK="/opt/intel/sgxsdk"
fi

# If the SGX SDK is not prepared well in build environment, stop the build
if [ ! -d "$SGX_SDK" ]; then
        echo 'Error: The SGX_SDK environment variable value is not correct'
        exit 1
fi

# build deb package for host/occlum/tdx build mode
for BUILD_MODE in "${BUILD_MODE[@]}"; do
	cd $SCRIPT_DIR
	sed 's/Package: rats-tls/Package: rats-tls-'$BUILD_MODE'/g' debian/control.in > debian/control && \
	sed 's/cmake -H. -Bbuild/cmake -DRATS_TLS_BUILD_MODE='$BUILD_MODE' -DBUILD_SAMPLES=on -H. -Bbuild/g' debian/rules.in > debian/rules;
	cp -rf  $SCRIPT_DIR/debian $DEB_BUILD_FOLDER
	cd $DEB_BUILD_FOLDER
	DEB_CFLAGS_SET="-std=gnu11 -fPIC" DEB_CXXFLAGS_SET="-std=c++11 -fPIC" DEB_LDFLAGS_SET="-fPIC" dpkg-buildpackage -us -uc
	cp $DEBBUILD_DIR/*.*deb $PROJECT_DIR
	rm -rf $DEBBUILD_DIR/$PACKAGE-$VERSION/$PACKAGE/build
	rm -rf $DEB_BUILD_FOLDER/debian
done
# build deb package for sgx build mode
for BUILD_MODE in "${BUILD_MODE_SPECIAL[@]}"; do
	cd $SCRIPT_DIR
	sed 's/Package: rats-tls/Package: rats-tls-'$BUILD_MODE'/g' debian/control.in > debian/control && \
	sed 's/cmake -H. -Bbuild/cmake -DRATS_TLS_BUILD_MODE='$BUILD_MODE' -DBUILD_SAMPLES=on -H. -Bbuild/g' debian/rules.in > debian/rules && \
	sed -i "/rats-tls-server/d" debian/rules && \
	sed -i "/override_dh_strip/adh_strip --exclude=rats-tls-server --exclude=rats-tls-client --exclude=sgx_stub_enclave.signed.so --exclude=librats_tls.a --exclude=librats_tls_u.a --exclude=librtls_edl_t.a --exclude=libtls_wrapper*.a --exclude=libcrypto_wrapper*.a --exclude=libattester*.a --exclude=libverifier*.a" debian/rules && \
	sed -i 's/dh_strip --exclude/\tdh_strip --exclude/g' debian/rules;
	cp -rf  $SCRIPT_DIR/debian $DEB_BUILD_FOLDER
	cd $DEB_BUILD_FOLDER
	DEB_CFLAGS_SET="-std=gnu11 -fPIC" DEB_CXXFLAGS_SET="-std=c++11 -fPIC" DEB_LDFLAGS_SET="-fPIC" dpkg-buildpackage -us -uc
	cp $DEBBUILD_DIR/*.*deb $PROJECT_DIR
	rm -rf $DEBBUILD_DIR/$PACKAGE-$VERSION/$PACKAGE/build
	rm -rf $DEB_BUILD_FOLDER/debian
done
rm -rf $DEBBUILD_DIR
