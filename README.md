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

- Middleware contract based on `IMiddlewareNext`:
  - `Middleware = std::function<void(ICtx&, IMiddlewareNext&)>`
  - Each middleware decides whether to continue the chain with `next.next()`.
- Two middleware scopes:
  - Global middlewares (`Router::addMiddleware(Middleware middleware)`).
  - Route middlewares (`Router::addMiddleware(RouteInfo&, Middleware middleware)`).
- Execution pipeline order:
  1. Global middlewares,
  2. Route middlewares,
  3. Route handler.
- Onion-style execution is supported (before/after behavior around `next.next()`).
- Interruption is supported (if a middleware does not call `next.next()`, execution stops).

#### Quality

- Unit test suite using GoogleTest covering:
  - Basic routes,
  - Typed parameters,
  - Matching priorities,
  - `ANY` method behavior,
  - Edge cases,
  - Middleware chain execution,
  - Middleware interruption,
  - Logger-like before/after flow,
  - Protection against invalid multiple `next.next()` calls.

### 🚧 Not implemented yet

- Full end-to-end integration with `cpp-httplib` server pipeline (documented runtime flow).
- Automatic middleware + handler execution chain inside the router.
- Ultra-basic JWT support using **Botan**.
- Custom in-house JSON library.
- Trait-based pluggable backends for:
  - JSON,		
  - Cryptography.
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