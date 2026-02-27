# HttplibApp

Extension for `cpp-httplib` focused on web services, adding route-based dispatching and middleware support.

## Goal

This project extends [`yhirose/cpp-httplib`](https://github.com/yhirose/cpp-httplib) by adding:

- A **routing** system for web services.
- Per-route and global **middlewares**.
- Keep it as simple as possible, with a focus on performance and ease of use.

## Current status

### ✅ Implemented

#### Trie-based router

- Route registration by HTTP method.
- Route matching priority:
  1. Literal segment.
  2. Typed parameter.
  3. Generic parameter.
- Support for nested routes.
- Basic path normalization (`/users` and `/users/`).

#### Supported HTTP methods

- `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `HEAD`.
- Wildcard method `ANY` with fallback behavior.
- String conversion via `Router::fromMethodString`.

#### Route parameters

- Generic: `<id>`.
- Typed:
  - `<id:int>`
  - `<id:base64id>` (UUID represented as Base64URL, with or without `==` padding)
  - `<name:string>`
  - `<id:uuid>`
  - `<amount:float>`
- Parameter extraction through `ICtx::setParam`.

#### Middlewares

- API to attach middlewares to a route (`RouteInfo`).
- Middleware storage per route in `RouteInfo`.

#### Quality

- Unit test suite using GoogleTest covering:
  - basic routes,
  - typed parameters,
  - matching priorities,
  - `ANY` method behavior,
  - edge cases.

### 🚧 Not implemented yet

- Full end-to-end integration with `cpp-httplib` server pipeline (documented runtime flow).
- Automatic middleware + handler execution chain inside the router.
- Ultra-basic JWT support using **Botan**.
- Custom in-house JSON library.
- Trait-based pluggable backends for:
  - JSON,
  - cryptography.
- Complete server usage documentation with practical examples.

## Roadmap

1. Integrate router + middlewares into the `cpp-httplib` request/response lifecycle.
2. Add minimal JWT support with Botan (no OpenSSL).
3. Add an internal JSON library.
4. Design trait/policy-based interchangeable backends (JSON/crypto).
5. Publish reference examples and adoption guides.

## Contributing

Contributions are welcome. If you want to contribute:

1. Fork the repository.
2. Create a branch (`git checkout -b feature/new-feature`).
3. Commit your changes (`git commit -m "Add new feature"`).
4. Open a pull request.

## License

This project is released under **The Unlicense**.

See: <https://unlicense.org>