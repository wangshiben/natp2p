FROM centos:centos7

COPY nodeserver caserver billingqueue-inspect billing-adversary-node tunserver tunclient httpfileserver /opt/bnfs/
COPY busybox /usr/local/bin/busybox

RUN chmod 0755 /opt/bnfs/* /usr/local/bin/busybox \
    && ln -s busybox /usr/local/bin/nc \
    && ln -s busybox /usr/local/bin/ip \
    && ln -s busybox /usr/local/bin/netstat

ENTRYPOINT []
CMD ["sleep", "infinity"]
