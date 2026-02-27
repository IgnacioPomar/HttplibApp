/*********************************************************************************************
 *  Description : Router class implementation
 *  License     : The unlicense (https://unlicense.org)
 *	Copyright	(C) 2026  Ignacio Pomar Ballestero
 ********************************************************************************************/

#include "Route.h"
#include <algorithm>
#include <unordered_map>

namespace ipb::http
{
	// ============================================================================
	// Internal types (hidden from header)
	// ============================================================================

	// Parameter Types
	enum class ParamType : uint8_t
	{
		INT      = 0,     // <param:int>
		BASE64ID = 1,     // <param:base64id> (UUID encoded as Base64URL)
		STRING   = 2,     // <param:string>
		UUID     = 3,     // <param:uuid>
		FLOAT    = 4,     // <param:float>
		GENERIC  = 255    // <param> typeless
	};

	/**
	 * @brief Validate an integer parameter.
	 * @param value The parameter value as a string.
	 * @return True if the value is a valid integer, false otherwise.
	 */
	static bool validateIntParam (std::string_view value)
	{
		if (value.empty())
		{
			return false;
		}

		size_t start = 0;
		if (value [0] == '-' || value [0] == '+')
		{
			start = 1;
		}

		if (start >= value.size())
		{
			return false;
		}

		for (size_t i = start; i < value.size(); ++i)
		{
			if (!std::isdigit (static_cast<unsigned char> (value [i])))
			{
				return false;
			}
		}

		return true;
	}

	/**
	 * @brief Validate a Base64URL UUID parameter.
	 * @param value The parameter value as a string.
	 * @return True if the value is a valid Base64URL UUID, false otherwise.
	 */
	static bool validateBase64IdParam (std::string_view value)
	{
		// Base64URL UUID format:
		// - unpadded: 22 chars
		// - padded:   24 chars ending with "=="
		if (value.size() != 22 && value.size() != 24)
		{
			return false;
		}

		size_t payload_len = value.size();

		if (value.size() == 24)
		{
			if (value [22] != '=' || value [23] != '=')
			{
				return false;
			}
			payload_len = 22;
		}

		for (size_t i = 0; i < payload_len; ++i)
		{
			const unsigned char c = static_cast<unsigned char> (value [i]);
			const bool is_alnum   = std::isalnum (c) != 0;
			const bool is_urlsafe = (c == '-') || (c == '_');

			if (!is_alnum && !is_urlsafe)
			{
				return false;
			}
		}

		return true;
	}

	/**
	 * @brief Validate a UUID parameter.
	 * @param value The parameter value as a string.
	 * @return True if the value is a valid UUID, false otherwise.
	 */
	static bool validateUuidParam (std::string_view value)
	{
		// UUID format: 8-4-4-4-12 hexadecimal characters separated by hyphens.
		if (value.size() != 36)
		{
			return false;
		}

		for (size_t i = 0; i < value.size(); ++i)
		{
			const char c = value [i];
			if (i == 8 || i == 13 || i == 18 || i == 23)
			{
				if (c != '-')
				{
					return false;
				}
			}
			else if (!std::isxdigit (static_cast<unsigned char> (c)))
			{
				return false;
			}
		}

		return true;
	}

	/**
	 * @brief Validate a float parameter.
	 * @param value The parameter value as a string.
	 * @return True if the value is a valid float, false otherwise.
	 */
	static bool validateFloatParam (std::string_view value)
	{
		// Float format: optional sign, digits, optional decimal point, more digits.
		if (value.empty())
		{
			return false;
		}

		size_t i = 0;
		if (value [i] == '-' || value [i] == '+')
		{
			++i;
		}

		if (i >= value.size())
		{
			return false;
		}

		bool has_digit = false;
		bool has_dot   = false;

		for (; i < value.size(); ++i)
		{
			const char c = value [i];
			if (std::isdigit (static_cast<unsigned char> (c)))
			{
				has_digit = true;
			}
			else if (c == '.' && !has_dot)
			{
				has_dot = true;
			}
			else
			{
				return false;
			}
		}

		return has_digit;
	}

	// Forward declaration
	struct TypedParam;

	// TrieNode - Trie tree node
	class TrieNode
	{
		public:
			std::map<std::string, TrieNode> literals;
			std::vector<TypedParam> typed_params;    // Sorted by specificity
			std::map<HttpMethod, RouteInfo> handlers;

			bool hasAnyHandler () const noexcept;
			std::optional<const RouteInfo *> getHandler (HttpMethod method) const;
	};

	// TypedParam - Typed parameter in the Trie
	struct TypedParam
	{
			std::string name;
			ParamType type;
			TrieNode next;

			bool validate (std::string_view value) const;
	};

	// ParsedSegment - Result of parsing a segment
	struct ParsedSegment
	{
			bool is_param = false;
			std::string name;
			ParamType type = ParamType::GENERIC;
	};

	// ============================================================================
	// Router::Impl - Pimpl implementation
	// ============================================================================

	class Router::Impl
	{
		public:
			TrieNode root_;

			// Public API implementation
			RouteInfo &add (HttpMethod method, std::string_view pattern, RouteHandler handler);
			bool addMiddleware (HttpMethod method, std::string_view pattern, Middleware middleware);
			std::optional<const RouteInfo *> match (HttpMethod method, std::string_view path, ICtx &context) const;

		private:
			// Helper methods
			static std::vector<std::string_view> splitPath (std::string_view path);
			static ParsedSegment parseSegment (std::string_view segment);
			TrieNode &getOrCreateNode (TrieNode *current, std::string_view segment);
			std::optional<RouteInfo *> findRoute (HttpMethod method, std::string_view pattern);
	};

	// ============================================================================
	// TrieNode implementation
	// ============================================================================

	bool TrieNode::hasAnyHandler () const noexcept
	{
		return !handlers.empty();
	}

	std::optional<const RouteInfo *> TrieNode::getHandler (HttpMethod method) const
	{
		// 1. Specific method
		if (auto it = handlers.find (method); it != handlers.end())
		{
			return &it->second;
		}
		// 2. Fallback to ANY
		if (auto it = handlers.find (HttpMethod::ANY); it != handlers.end())
		{
			return &it->second;
		}
		return std::nullopt;
	}

	// ============================================================================
	// TypedParam implementation
	// ============================================================================

	bool TypedParam::validate (std::string_view value) const
	{
		switch (type)
		{
		case ParamType::INT: return validateIntParam (value);

		case ParamType::BASE64ID: return validateBase64IdParam (value);

		case ParamType::UUID: return validateUuidParam (value);

		case ParamType::FLOAT: return validateFloatParam (value);

		case ParamType::STRING:
			// String accepts any non-empty value.
			return !value.empty();

		case ParamType::GENERIC:
		default:
			// Generic accepts everything.
			return true;
		}
	}

	// ============================================================================
	// Router::Impl implementation
	// ============================================================================

	RouteInfo &Router::Impl::add (HttpMethod method, std::string_view pattern, RouteHandler handler)
	{
		auto segments = splitPath (pattern);
		auto *current = &root_;

		// Traverse/create the tree based on segments
		for (const auto &segment : segments)
		{
			current = &getOrCreateNode (current, segment);
		}

		// Store the handler in the final node
		RouteInfo route_info {
		    .pattern = std::string (pattern), .method = method, .handler = std::move (handler), .middlewares = {}};

		current->handlers [method] = std::move (route_info);
		return current->handlers [method];
	}

	bool Router::Impl::addMiddleware (HttpMethod method, std::string_view pattern, Middleware middleware)
	{
		if (auto route = findRoute (method, pattern))
		{
			route.value()->middlewares.push_back (std::move (middleware));
			return true;
		}
		return false;
	}

	std::optional<const RouteInfo *> Router::Impl::match (HttpMethod method, std::string_view path, ICtx &context) const
	{
		auto segments           = splitPath (path);
		const TrieNode *current = &root_;    // Changed to const TrieNode *

		// Traverse the Trie
		for (const auto &segment : segments)
		{
			if (!current)
			{
				return std::nullopt;
			}

			// 1. Try exact literal first (highest priority)
			if (auto it = current->literals.find (std::string (segment)); it != current->literals.end())
			{
				current = &it->second;
				continue;
			}

			// 2. Try typed parameters (sorted by specificity)
			bool matched = false;
			for (const auto &typed_param : current->typed_params)
			{
				if (typed_param.validate (segment))
				{
					context.setParam (typed_param.name, segment);
					current = &typed_param.next;
					matched = true;
					break;    // First match wins
				}
			}

			if (matched)
			{
				continue;
			}

			// No match found
			return std::nullopt;
		}

		// Check whether the final node has a handler for the method
		if (!current)
		{
			return std::nullopt;
		}

		return current->getHandler (method);
	}

	std::vector<std::string_view> Router::Impl::splitPath (std::string_view path)
	{
		std::vector<std::string_view> segments;

		// Remove trailing slash
		if (path.ends_with ('/') && path.size() > 1)
		{
			path.remove_suffix (1);
		}

		// Remove leading slash
		if (path.starts_with ('/'))
		{
			path.remove_prefix (1);
		}

		// Root path
		if (path.empty())
		{
			return segments;
		}

		// Split by '/'
		size_t start = 0;
		while (start < path.size())
		{
			size_t end = path.find ('/', start);
			if (end == std::string_view::npos)
			{
				segments.emplace_back (path.substr (start));
				break;
			}
			else
			{
				segments.emplace_back (path.substr (start, end - start));
				start = end + 1;
			}
		}

		return segments;
	}

	ParsedSegment Router::Impl::parseSegment (std::string_view segment)
	{
		ParsedSegment result;

		// Is it a parameter? <name> or <name:type>
		if (segment.starts_with ('<') && segment.ends_with ('>'))
		{
			result.is_param = true;
			segment.remove_prefix (1);
			segment.remove_suffix (1);

			// Does it have a type? <name:type>
			if (auto colon_pos = segment.find (':'); colon_pos != std::string_view::npos)
			{
				result.name   = segment.substr (0, colon_pos);
				auto type_str = segment.substr (colon_pos + 1);

				if (type_str == "int")
				{
					result.type = ParamType::INT;
				}
				else if (type_str == "base64id")
				{
					result.type = ParamType::BASE64ID;
				}
				else if (type_str == "string")
				{
					result.type = ParamType::STRING;
				}
				else if (type_str == "uuid")
				{
					result.type = ParamType::UUID;
				}
				else if (type_str == "float")
				{
					result.type = ParamType::FLOAT;
				}
				else
				{
					result.type = ParamType::GENERIC;
				}
			}
			else
			{
				result.name = std::string (segment);
				result.type = ParamType::GENERIC;
			}
		}
		else
		{
			// Literal
			result.is_param = false;
			result.name     = std::string (segment);
		}

		return result;
	}

	TrieNode &Router::Impl::getOrCreateNode (TrieNode *current, std::string_view segment)
	{
		auto parsed = parseSegment (segment);

		if (!parsed.is_param)
		{
			// Literal - map creates it automatically if it does not exist
			return current->literals [parsed.name];
		}

		// Find where the type should be placed (binary search in sorted vector)
		auto compare = [] (const TypedParam &a, const TypedParam &b)
		{
			return static_cast<uint8_t> (a.type) < static_cast<uint8_t> (b.type);
		};

		TypedParam search_key {.name = "", .type = parsed.type, .next = TrieNode {}};
		auto it = std::lower_bound (current->typed_params.begin(), current->typed_params.end(), search_key, compare);

		// If an element exists there with same type, reuse it
		if (it != current->typed_params.end() && it->type == parsed.type)
		{
			return it->next;
		}

		// Not found: create and insert at the correct position (from lower_bound)
		TypedParam new_param {.name = parsed.name, .type = parsed.type, .next = TrieNode {}};

		auto inserted_it = current->typed_params.insert (it, std::move (new_param));

		return inserted_it->next;
	}

	std::optional<RouteInfo *> Router::Impl::findRoute (HttpMethod method, std::string_view pattern)
	{
		auto segments = splitPath (pattern);
		auto *current = &root_;

		for (const auto &segment : segments)
		{
			if (auto it = current->literals.find (std::string (segment)); it != current->literals.end())
			{
				current = &it->second;
				continue;
			}

			bool found  = false;
			auto parsed = parseSegment (segment);
			if (parsed.is_param)
			{
				for (auto &tp : current->typed_params)
				{
					if (tp.name == parsed.name && tp.type == parsed.type)
					{
						current = &tp.next;
						found   = true;
						break;
					}
				}
			}

			if (!found)
			{
				return std::nullopt;
			}
		}

		if (!current)
		{
			return std::nullopt;
		}

		if (auto it = current->handlers.find (method); it != current->handlers.end())
		{
			return &it->second;
		}

		return std::nullopt;
	}

	// ============================================================================
	// Router public API (delegates to Impl)
	// ============================================================================

	Router::Router ()
	    : impl_ (std::make_unique<Impl>())
	{
	}

	Router::~Router () = default;

	Router::Router (Router &&) noexcept = default;

	Router &Router::operator= (Router &&) noexcept = default;

	RouteInfo &Router::add (HttpMethod method, std::string_view pattern, RouteHandler handler)
	{
		return impl_->add (method, pattern, std::move (handler));
	}

	bool Router::addMiddleware (RouteInfo &routeInfo, Middleware middleware)
	{
		routeInfo.middlewares.push_back (std::move (middleware));

		return true;
	}

	std::optional<const RouteInfo *> Router::match (HttpMethod method, std::string_view path, ICtx &context) const
	{
		return impl_->match (method, path, context);
	}

	HttpMethod Router::fromMethodString (std::string_view method)
	{
		static const std::unordered_map<std::string_view, HttpMethod> method_map = {
		    {"GET",     HttpMethod::GET    },
            {"POST",    HttpMethod::POST   },
            {"PUT",     HttpMethod::PUT    },
		    {"PATCH",   HttpMethod::PATCH  },
            {"DELETE",  HttpMethod::DELETE_},
            {"OPTIONS", HttpMethod::OPTIONS},
		    {"HEAD",    HttpMethod::HEAD   }
        };

		if (auto it = method_map.find (method); it != method_map.end())
		{
			return it->second;
		}

		return HttpMethod::GET;    // Default fallback
	}

}    // namespace ipb::http
