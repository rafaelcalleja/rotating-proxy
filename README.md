docker-rotating-proxy
=====================

# Updates on Health Checks

We've introduced an update that will improve the reliability of our load balancing handled by HAProxy.

To ensure a robust and fault-tolerant system, we've now implemented a dynamic health check system for our backend servers. Before this update, HAProxy would send traffic to all configured backends, regardless of their status. However, our system now comes with more intelligence by checking the health of individual backends before deciding where to route the incoming traffic.

So, what's new exactly? We've created a HealthCheck service that is built around a Go application. This service will regularly ping a predefined target URL through the Tor network, acting as a sentinel for each backend. Its primary job is to ensure the Tor circuit for each backend is functioning well and is ready to take on incoming traffic. 

What this means for our HAProxy setup: instead of blindly distributing incoming network load amongst all configured backends, HAProxy would now only balance between healthy connections. It would perform these checks against the server using `option httpchk GET /` at an interval of 10sec. This update ensures that traffic is only sent to the backends that are confirmed as active and healthy, resulting in reduced error rates and improved user experience.

In short, this update is all about improving reliability and fault tolerance by ensuring only healthy backend servers receive traffic and take part in load balancing. Therefore, you can rest cool knowing that your load balancing needs are now handled more intelligently and efficiently than ever before.


[![Docker Pulls](https://img.shields.io/docker/pulls/mattes/rotating-proxy.svg)](https://hub.docker.com/r/mattes/rotating-proxy/)

```
               Docker Container
               -------------------------------------
                        <-> Polipo 1 <-> Tor Proxy 1
Client <---->  HAproxy  <-> Polipo 2 <-> Tor Proxy 2
                        <-> Polipo n <-> Tor Proxy n
```

__Why:__ Lots of IP addresses. One single endpoint for your client.
Load-balancing by HAproxy.

Usage
-----

```bash
# build docker container
docker build -t mattes/rotating-proxy:latest .

# ... or pull docker container
docker pull mattes/rotating-proxy:latest

# start docker container
docker run -d -p 5566:5566 -p 4444:4444 --env tors=25 mattes/rotating-proxy

# test with ...
curl --proxy 127.0.0.1:5566 https://api.my-ip.io/ip

# monitor
http://127.0.0.1:4444/haproxy?stats
```


Further Readings
----------------

 * [Tor Manual](https://www.torproject.org/docs/tor-manual.html.en)
 * [Tor Control](https://www.thesprawl.org/research/tor-control-protocol/)
 * [HAProxy Manual](http://cbonte.github.io/haproxy-dconv/configuration-1.5.html)
 * [Polipo](http://www.pps.univ-paris-diderot.fr/~jch/software/polipo/)

--------------

Please note: Tor offers a SOCKS Proxy only. In order to allow communication
from HAproxy to Tor, Polipo is used to translate from HTTP proxy to SOCKS proxy.
HAproxy is able to talk to HTTP proxies only.

