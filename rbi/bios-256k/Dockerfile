FROM centos:8.3.2011

LABEL maintainer="Ding Ma <ding.ma@linux.alibaba.com>"

ENV MAKE_VERSION    1:4.2.1
ENV GCC_VERSION     8.4.1

RUN [ -n "$http_proxy" ] && sed -i '$ a proxy='$http_proxy /etc/dnf/dnf.conf ; true
RUN dnf install -y make-$MAKE_VERSION \
                gcc-$GCC_VERSION \
                git \
                python2 \
                && alternatives --set python /usr/bin/python2

WORKDIR /root
COPY scripts/* /root

CMD ["bash", "start.sh"]