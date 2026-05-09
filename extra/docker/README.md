# NFDump Docker image

> These commands assume the current working directory is the root of the nfdump repository

To build and run the `nfcapd` target (runs `nfcapd` by default):

```bash
docker build -t nfcapd --target nfcapd -f extra/docker/Dockerfile .
# Create a docker volume so as not to run into permissions issues with non-root user
docker volume create flows
docker run -it --rm --name=nfcapd -p 9995:9995/udp -v flows:/data nfcapd
```

Desired `nfcapd` arguments can be appended to the `docker run` command above.

To build the `nfdump` target (drops you into an interactive shell by default):

```bash
docker build -t nfdump --target nfdump -f extra/docker/Dockerfile .
# Create a docker volume so as not to run into permissions issues with non-root user
docker volume create flows
docker run -it --rm --name=nfdump -v flows:/data nfdump
```

Desired `nfdump` arguments can be appended to the `docker run` command above.

For reference, there is also an Ubuntu Dockerfile at _extra/docker/Dockerfile.ubuntu_ with similar `nfcapd` and `nfdump` targets.

## Attribution

Contributed by [heywoodlh](https://github.com/heywoodlh).
