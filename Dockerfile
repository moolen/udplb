FROM zlim/bcc

ADD ./udplb /usr/bin/udplb

ENTRYPOINT [ "/usr/bin/udplb" ]
