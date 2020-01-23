FROM scratch

COPY fail2ban_exporter /

EXPOSE 9539
ENTRYPOINT ["/fail2ban_exporter"]
