# docker-gamma-auth

Docker registry token issuer that authenticated against [Gamma](https://github.com/cthit/gamma).

## todo

* Create a Dockerfile
* Refractor and clean some things up
* Make more configurable (from env vars etc.)
* Actually auth against gamma
* Store and validate refresh tokens, using persistent or semi-persistent storage (e.g. postgres, redis)
