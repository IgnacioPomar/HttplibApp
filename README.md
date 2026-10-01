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

- Unit test suite using [Catch2](https://github.com/catchorg/Catch2) covering:
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
- JWT (`HttplibApp/Jwt.h`): the API and the token workflow are implemented, but there are only fake providers (in the tests). Pending real backends:
  - Cryptography with **Botan**.
  - JSON with **glaze**.
- Trait-based pluggable backends for:
  - JSON,		
  - Cryptography.
- Complete server usage documentation with practical examples.

## Roadmap

1. Integrate router + middlewares into the `cpp-httplib` request/response lifecycle.
2. Add minimal JWT support with Botan (no OpenSSL).
3. JSON provider with glaze.
4. Design trait/policy-based interchangeable backends (JSON/crypto).
5. Publish reference examples and adoption guides.

## Build

Requirements: CMake >= 3.23, a C++20 compiler and Conan 2.

```bash
conan install . --build=missing -s compiler.cppstd=20 -o build_tests=True
cmake --preset conan-release
cmake --build --preset conan-release
ctest --preset conan-release
```

Dependencies:

- [`cpp-httplib`](https://github.com/yhirose/cpp-httplib) `0.56.0`. TLS (HTTPS) is optional, with the Conan option `tls`:
  - `none` (default): plain HTTP, no TLS library.
  - `wolfssl`: `CPPHTTPLIB_WOLFSSL_SUPPORT`. The recipe also sets `wolfssl/*:opensslextra=True` and `wolfssl/*:opensslall=True`, required by `cpp-httplib`. Note: wolfSSL is GPL or commercial.
  - `openssl`: `CPPHTTPLIB_OPENSSL_SUPPORT`.
- [Botan](https://botan.randombit.net) `3`: crypto for JWT. It is always required, even without TLS.
- Tests: [Catch2](https://github.com/catchorg/Catch2) `3`.

```bash
conan install . --build=missing -s compiler.cppstd=20 -o tls=wolfssl
```

Without Conan, it can be added to a CMake project with `add_subdirectory` (the tests are off by default). The parent project must provide `find_package(httplib)` (with the TLS backend it wants) and `find_package(botan)`:

```cmake
add_subdirectory(HttplibApp)
target_link_libraries(myTarget PRIVATE HttplibApp::HttplibApp)
```

## Conan package

```bash
conan create . --build=missing -s compiler.cppstd=20
```

The package is a shared library by default (`libHttplibApp.so`); use `-o "httplibapp/*:shared=False"` for the static one. `conan create` also builds and runs `test_package/`.

The recipe (with the sources) is published in the Conan registry of Forgejo. No binaries are published: the library is built from source by each consumer, with its own compiler and settings (`build_policy = "missing"`, so `--build` is not needed):

```bash
conan remote add forgejo https://<forgejo>/api/packages/Commons/conan
conan remote login forgejo <user> -p <token>    # Token with the read:package scope
```

Usage from another project:

```python
self.requires("httplibapp/[~0.1]")    # >=0.1.0 <0.2.0
```

```cmake
find_package(HttplibApp REQUIRED)
target_link_libraries(myTarget PRIVATE HttplibApp::HttplibApp)
```

```cpp
#include "HttplibApp/Route.h"
#include "HttplibApp/Jwt.h"
```

The TLS backend is chosen with `-o httplibapp/*:tls=wolfssl` (or `openssl`). If the consumer also requires `cpp-httplib` or `wolfssl` directly, it must set the same options on them.

`HttplibApp/httplib_app_exportcfg.h` (`HAPP_API`) is generated by CMake (`generate_export_header`) in the build folder, and installed with the other headers. The shared library is built with hidden visibility: it only exports the symbols marked with `HAPP_API`.

`docs/httplib_app_api_draft.cpp` is the draft (not compiled) of the pending integration with `httplib::Server`.

## Version information

The version is only written in the `VERSION` file. The name, description and version are available:

- **Compile time**: `HttplibApp/HttplibAppVersion.h` (generated by CMake) defines `HTTPLIBAPP_NAME`, `HTTPLIBAPP_DESCRIPTION`, `HTTPLIBAPP_VERSION` and `HTTPLIBAPP_VERSION_MAJOR` / `_MINOR` / `_PATCH`.
- **Run time**: `ipb::http::getLibraryInfo()` (`HttplibApp/LibraryInfo.h`) returns the same data of the loaded library, plus its build date (`buildDate`).

## CI and releases

- `.forgejo/workflows/ci.yml`: on every push and pull request, runs the unit tests and `conan create`.
- `.forgejo/workflows/release.yml`: started by hand from Forgejo, asks which part of the version to increase (patch, minor or major), commits the new `VERSION` with its `vX.Y.Z` tag, and publishes the recipe (with the sources) in the Forgejo Conan registry.

See [docs/ci-and-releases.md](docs/ci-and-releases.md) for what each workflow does, the version numbering rules and how to create a release.

## Contributing

Contributions are welcome. If you want to contribute:

1. Fork the repository.
2. Create a branch (`git checkout -b feature/new-feature`).
3. Commit your changes (`git commit -m "Add new feature"`).
4. Open a pull request.

## License

This project is released under **The Unlicense**.

See: <https://unlicense.org>