FROM --platform=linux/arm64/v8 ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y haproxy tor netcat ruby wget curl zlib1g-dev libyaml-dev build-essential unzip golang
RUN wget https://github.com/jech/polipo/archive/master.zip -O polipo.zip -Y off \
    && unzip polipo.zip \
    && cd polipo-master \
    && make \
    && install polipo /usr/local/bin/ \
    && cd .. \
    && rm -rf polipo.zip polipo-master \
    && mkdir -p /usr/share/polipo/www /var/cache/polipo

RUN update-rc.d -f tor remove
RUN update-rc.d -f polipo remove

RUN gem install excon

ADD start.rb /usr/local/bin/start.rb
RUN chmod +x /usr/local/bin/start.rb

ADD newnym.sh /usr/local/bin/newnym.sh
RUN chmod +x /usr/local/bin/newnym.sh

ADD haproxy.cfg.erb /usr/local/etc/haproxy.cfg.erb
ADD uncachable /etc/polipo/uncachable

COPY healtcheck.go /usr/src
RUN go build /usr/src/healtcheck.go && mv healtcheck /usr/local/bin/healtcheck && rm /usr/src/healtcheck.go

EXPOSE 5566 4444

CMD /usr/local/bin/start.rb
