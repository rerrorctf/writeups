FROM ubuntu:22.04 AS app
RUN dpkg --add-architecture i386
RUN apt update && apt install -y libc6:i386
FROM pwn.red/jail

COPY --from=app / /srv
COPY ./gambling /srv/app/run
COPY ./flag.txt /srv/app/flag.txt

RUN chmod +x /srv/app/run

ENV JAIL_PORT=1447 JAIL_MEM=16M JAIL_ENV_NUM=5 JAIL_PID=20 JAIL_TIME=600
