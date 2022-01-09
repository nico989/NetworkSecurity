# syntax = edrevo/dockerfile-plus

INCLUDE+ shared/Dockerfile.term

#
# ARGs
#
ARG BACKGROUND_IMAGE=hosts/server/background.png

#
# Install tools
#
RUN apt-get -y install \
        xinetd \
        telnetd

# Copy telnet config file
COPY hosts/server/telnet /etc/xinetd.d/telnet

# Copy banky executable
COPY  hosts/server/banky /usr/local/bin/banky
RUN chmod +x /usr/local/bin/banky
