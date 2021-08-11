# docker-gamma-auth

Docker registry token issuer that authenticated against [Gamma](https://github.com/cthit/gamma).

## todo

* [x] Create a Dockerfile
* [ ] Refactor and clean some things up
* [x] Make more configurable (from env vars etc.)
* [x] Actually auth against gamma
* [x] Store and validate refresh tokens, using persistent or semi-persistent storage (e.g. postgres, redis)
