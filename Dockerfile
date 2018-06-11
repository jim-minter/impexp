FROM scratch
COPY import .
ENTRYPOINT [ "/import" ]
