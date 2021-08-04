FROM centos:8.3.2011

LABEL maintainer="Ding Ma <ding.ma@linux.alibaba.com>"

ENV GCC_VERSION     8.4.1
ENV BISON_VERSION   3.0.4
ENV FLEX_VERSION    2.6.1
ENV ELFUTILS_LIBELF_DEVEL_VERSION   0.182
ENV BC_VERSION      1.07.1
ENV DIFFUTILS_VERSION   3.6

RUN [ -n "$http_proxy" ] && sed -i '$ a proxy='$http_proxy /etc/dnf/dnf.conf ; true
RUN dnf install -y make \
                gcc-$GCC_VERSION \
                bison-$BISON_VERSION \
                flex-$FLEX_VERSION \
                elfutils-libelf-devel-$ELFUTILS_LIBELF_DEVEL_VERSION \
                bc-$BC_VERSION \
                git \
                diffutils-$DIFFUTILS_VERSION

RUN curl -O https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz && \
    tar -zxvf go1.14.2.linux-amd64.tar.gz -C /usr/lib && \
    rm -f go1.14.2.linux-amd64.tar.gz

ENV GOROOT=/usr/lib/go
ENV GOPATH=/root/gopath
ENV PATH=$PATH:$GOROOT/bin:$GOPATH/bin
WORKDIR /root
COPY scripts/* /root

CMD ["bash", "start.sh"]