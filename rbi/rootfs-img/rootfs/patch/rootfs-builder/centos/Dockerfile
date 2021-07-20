FROM registry.centos.org/centos:7

LABEL maintainer="Ding Ma <ding.ma@linux.alibaba.com>"

RUN yum -y update && yum install -y \
    autoconf-2.69-11.el7.noarch \
    automake-1.13.4-3.el7.noarch \
    binutils-2.27-44.base.el7.x86_64 \
    chrony-3.4-1.el7.x86_64 \
    coreutils-8.22-24.el7_9.2.x86_64 \
    curl-7.29.0-59.el7_9.1.x86_64 \
    gcc-4.8.5-44.el7.x86_64 \
    gcc-c++-4.8.5-44.el7.x86_64 \
    git-1.8.3.1-23.el7_8.x86_64 \
    glibc-common-2.17-324.el7_9.x86_64 \
    glibc-devel-2.17-324.el7_9.x86_64 \
    glibc-headers-2.17-324.el7_9.x86_64 \
    glibc-static-2.17-324.el7_9.x86_64 \
    glibc-utils-2.17-324.el7_9.x86_64 \
    libseccomp-2.3.1-4.el7.x86_64 \
    libseccomp-devel-2.3.1-4.el7.x86_64 \
    libstdc++-devel-4.8.5-44.el7.x86_64 \
    libstdc++-static-4.8.5-44.el7.x86_64 \
    m4-1.4.16-10.el7.x86_64 \
    1:make-3.82-24.el7.x86_64 \
    sed-4.2.2-7.el7.x86_64 \
    2:tar-1.26-35.el7.x86_64 \
    2:vim-enhanced-7.4.629-8.el7_9.x86_64 \
    which-2.20-7.el7.x86_64 

# musl
RUN pushd /root;     curl -sLO https://www.musl-libc.org/releases/musl-1.1.23.tar.gz; tar -zxf musl-1.1.23.tar.gz; 	cd musl-1.1.23; 	sed -i "s/^ARCH = .*/ARCH = x86_64/g" dist/config.mak; 	./configure > /dev/null 2>&1; 	make > /dev/null 2>&1; 	make install > /dev/null 2>&1; 	echo "/usr/local/musl/lib" > /etc/ld-musl-x86_64.path; 	popd
ENV PATH=$PATH:/usr/local/musl/bin

# go
RUN cd /tmp ; curl -OL https://storage.googleapis.com/golang/go1.14.4.linux-amd64.tar.gz
RUN tar -C /usr/ -xzf /tmp/go1.14.4.linux-amd64.tar.gz
ENV GOROOT=/usr/go
ENV PATH=$PATH:$GOROOT/bin:$GOPATH/bin

# rust
RUN curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSLf --output /tmp/rust-init;     chmod a+x /tmp/rust-init; 	export http_proxy=; 	export https_proxy=; 	/tmp/rust-init -y --default-toolchain 1.47.0
RUN . /root/.cargo/env;     export http_proxy=; 	export https_proxy=; 	cargo install cargo-when; 	rustup target install x86_64-unknown-linux-musl
RUN ln -sf /usr/bin/g++ /bin/musl-g++