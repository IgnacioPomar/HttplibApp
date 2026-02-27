/*********************************************************************************************
 *  Description : Router class - Trie-based HTTP router with typed parameters
 *  License     : The unlicense (https://unlicense.org)
 *	Copyright	(C) 2026  Ignacio Pomar Ballestero
 ********************************************************************************************/

#pragma once
#ifndef _ROUTE_H_
#	define _ROUTE_H_

#	include <functional>
#	include <map>
#	include <optional>
#	include <string>
#	include <string_view>
#	include <vector>
#	include <memory>

#	include "httplib_app_exportcfg.h"

namespace ipb::http
{
	class ICtx
	{
		public:
			virtual void setParam (std::string_view name, std::string_view value) = 0;
	};

	// Forward declarations
	using Next         = std::function<void()>;
	using Middleware   = std::function<void (ICtx &, Next)>;
	using RouteHandler = std::function<void (ICtx &)>;
	// class TrieNode;

	struct TypedParam;

	// HTTP Method Enum
	enum class HttpMethod : uint8_t
	{
		GET     = 0,
		POST    = 1,
		PUT     = 2,
		PATCH   = 3,
		DELETE_ = 4,
		OPTIONS = 5,
		HEAD    = 6,
		ANY     = 255    // Wildcard: any method
	};

	// Route Info (stored at the end of the Trie)
	struct RouteInfo
	{
			std::string pattern;                    // Original pattern: "/users/<id:int>"
			HttpMethod method;                      // GET, POST, etc.
			RouteHandler handler;                   // Route handler
			std::vector<Middleware> middlewares;    // Route-specific middlewares
	};

	// ============================================================================
	// Router - Manages the routes Trie tree
	// ============================================================================
	class Router
	{
		public:
			HAPP_API Router ();
			HAPP_API ~Router();

			// Non-copyable but movable (like httplib::Server)
			Router (const Router &)            = delete;
			Router &operator= (const Router &) = delete;
			HAPP_API Router (Router &&) noexcept;
			HAPP_API Router &operator= (Router &&) noexcept;

			/**
			 * Add new route
			 */
			HAPP_API RouteInfo &add (HttpMethod method, std::string_view pattern, RouteHandler handler);

			/**
			 * Add middleware to an existing route (there are also global middlewares, so this is an "exception")
			 */
			HAPP_API bool addMiddleware (RouteInfo &routeInfo, Middleware middleware);

			/**
			 * Match route and extract parameters
			 */
			HAPP_API std::optional<const RouteInfo *> match (HttpMethod method, std::string_view path,
			                                                 ICtx &context) const;

			/**
			 * Convert HTTP method string to enum
			 */
			HAPP_API static HttpMethod fromMethodString (std::string_view method);

		private:
			// The data is contained in a PIMPL (Pointer to Implementation)
			class Impl;
			std::unique_ptr<Impl> impl_;
	};

}    // namespace ipb::http

#endif
