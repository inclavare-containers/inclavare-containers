FROM centos:8.3.2011

LABEL maintainer="Ding Ma <ding.ma@linux.alibaba.com>"

RUN [ -n "$http_proxy" ] && sed -i '$ a proxy='$http_proxy /etc/dnf/dnf.conf ; true
RUN dnf install -y make \
                gcc-8.4.1-1.el8.x86_64 \
                bison-3.0.4-10.el8.x86_64 \
                flex-2.6.1-9.el8.x86_64 \
                elfutils-libelf-devel-0.182-3.el8.x86_64 \
                bc-1.07.1-5.el8.x86_64

COPY scripts/start.sh /root

WORKDIR /root
CMD ["bash", "start.sh"]