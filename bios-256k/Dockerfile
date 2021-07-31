FROM centos:8.3.2011

LABEL maintainer="Ding Ma <ding.ma@linux.alibaba.com>"

RUN [ -n "$http_proxy" ] && sed -i '$ a proxy='$http_proxy /etc/dnf/dnf.conf ; true
RUN dnf install -y make-1:4.2.1-10.el8.x86_64 \
                gcc-8.4.1-1.el8.x86_64 \
                git \
                python2
RUN ln /usr/bin/python2 /usr/bin/python

WORKDIR /root
COPY scripts/* /root

CMD ["bash", "start.sh"]