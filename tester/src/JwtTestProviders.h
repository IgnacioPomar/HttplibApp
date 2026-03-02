#pragma once

#include "Jwt.h"

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_set>

namespace ipb::http::jwt
{
	class FakeCryptoProvider final : public ICryptoProvider
	{
		public:
			int loadPrivateCalls = 0;
			int loadPublicCalls  = 0;
			int savePrivateCalls = 0;
			int savePublicCalls  = 0;
			int generateCalls    = 0;
			std::string lastPrivatePath;
			std::string lastPublicPath;

			void resetCounters ()
			{
				loadPrivateCalls = 0;
				loadPublicCalls  = 0;
				savePrivateCalls = 0;
				savePublicCalls  = 0;
				generateCalls    = 0;
				lastPrivatePath.clear();
				lastPublicPath.clear();
			}

			Error loadPrivateKeyFromPemFile (std::string_view kid, std::string_view pemPath) override
			{
				++loadPrivateCalls;
				lastPrivatePath = std::string (pemPath);
				if (pemPath.empty() || !std::filesystem::exists (std::filesystem::path (pemPath)))
				{
					return {.code = ErrorCode::IOError, .message = "private key path missing"};
				}
				keys_.insert (std::string (kid));
				return {.code = ErrorCode::Ok, .message = {}};
			}

			Error loadPublicKeyFromPemFile (std::string_view kid, std::string_view pemPath, JwtUse) override
			{
				++loadPublicCalls;
				lastPublicPath = std::string (pemPath);
				if (pemPath.empty() || !std::filesystem::exists (std::filesystem::path (pemPath)))
				{
					return {.code = ErrorCode::IOError, .message = "public key path missing"};
				}
				keys_.insert (std::string (kid));
				return {.code = ErrorCode::Ok, .message = {}};
			}

			Error loadCertificateFromPemFile (std::string_view kid, std::string_view pemPath) override
			{
				if (pemPath.empty())
				{
					return {.code = ErrorCode::CertificateNotFound, .message = "certificate path empty"};
				}
				keys_.insert (std::string (kid));
				return {.code = ErrorCode::Ok, .message = {}};
			}

			Error savePrivateKeyToPemFile (std::string_view kid, std::string_view pemPath) override
			{
				++savePrivateCalls;
				lastPrivatePath = std::string (pemPath);
				if (pemPath.empty() || keys_.find (std::string (kid)) == keys_.end())
				{
					return {.code = ErrorCode::KeyNotFound, .message = "key not found"};
				}
				std::ofstream out (std::filesystem::path (pemPath), std::ios::binary | std::ios::trunc);
				if (!out)
				{
					return {.code = ErrorCode::IOError, .message = "cannot write private key"};
				}
				out << "private-key";
				return {.code = ErrorCode::Ok, .message = {}};
			}

			Error savePublicKeyToPemFile (std::string_view kid, std::string_view pemPath, JwtUse) override
			{
				++savePublicCalls;
				lastPublicPath = std::string (pemPath);
				if (pemPath.empty() || keys_.find (std::string (kid)) == keys_.end())
				{
					return {.code = ErrorCode::KeyNotFound, .message = "key not found"};
				}
				std::ofstream out (std::filesystem::path (pemPath), std::ios::binary | std::ios::trunc);
				if (!out)
				{
					return {.code = ErrorCode::IOError, .message = "cannot write public key"};
				}
				out << "public-key";
				return {.code = ErrorCode::Ok, .message = {}};
			}

			Error generateKeyPair (std::string_view kid, JwtAlg, std::string_view) override
			{
				++generateCalls;
				keys_.insert (std::string (kid));
				return {.code = ErrorCode::Ok, .message = {}};
			}

			Error removeKey (std::string_view kid) override
			{
				keys_.erase (std::string (kid));
				return {.code = ErrorCode::Ok, .message = {}};
			}

			Error sign (JwtAlg alg, std::string_view kid, std::span<const uint8_t> data,
			            ByteBuffer &outSignature) const override
			{
				if (keys_.find (std::string (kid)) == keys_.end())
				{
					return {.code = ErrorCode::KeyNotFound, .message = "missing kid"};
				}

				const std::string sig_text = std::to_string (static_cast<int> (alg)) + "|" + std::string (kid) + "|"
				                             + std::string (reinterpret_cast<const char *> (data.data()), data.size());
				outSignature.assign (sig_text.begin(), sig_text.end());
				return {.code = ErrorCode::Ok, .message = {}};
			}

			Error verify (JwtAlg alg, std::string_view kid, std::span<const uint8_t> data,
			              std::span<const uint8_t> signature) const override
			{
				if (keys_.find (std::string (kid)) == keys_.end())
				{
					return {.code = ErrorCode::KeyNotFound, .message = "missing kid"};
				}

				ByteBuffer expected;
				auto sign_error = sign (alg, kid, data, expected);
				if (sign_error.code != ErrorCode::Ok)
				{
					return sign_error;
				}

				if (expected.size() != signature.size()
				    || !std::equal (expected.begin(), expected.end(), signature.begin(), signature.end()))
				{
					return {.code = ErrorCode::SignatureMismatch, .message = "signature mismatch"};
				}

				return {.code = ErrorCode::Ok, .message = {}};
			}

			Error base64UrlEncode (std::span<const uint8_t> data, std::string &outText) const override
			{
				static constexpr char hex [] = "0123456789ABCDEF";
				outText.clear();
				outText.reserve (data.size() * 2);
				for (auto b : data)
				{
					outText.push_back (hex [(b >> 4) & 0x0F]);
					outText.push_back (hex [b & 0x0F]);
				}
				return {.code = ErrorCode::Ok, .message = {}};
			}

			Error base64UrlDecode (std::string_view text, ByteBuffer &outData) const override
			{
				if ((text.size() % 2) != 0)
				{
					return {.code = ErrorCode::InvalidBase64Url, .message = "invalid hex length"};
				}

				auto decode_nibble = [] (char c) -> int
				{
					if (c >= '0' && c <= '9')
					{
						return c - '0';
					}
					if (c >= 'A' && c <= 'F')
					{
						return 10 + (c - 'A');
					}
					if (c >= 'a' && c <= 'f')
					{
						return 10 + (c - 'a');
					}
					return -1;
				};

				outData.clear();
				outData.reserve (text.size() / 2);
				for (size_t i = 0; i < text.size(); i += 2)
				{
					const int hi = decode_nibble (text [i]);
					const int lo = decode_nibble (text [i + 1]);
					if (hi < 0 || lo < 0)
					{
						return {.code = ErrorCode::InvalidBase64Url, .message = "invalid hex char"};
					}
					outData.push_back (static_cast<uint8_t> ((hi << 4) | lo));
				}

				return {.code = ErrorCode::Ok, .message = {}};
			}

		private:
			mutable std::unordered_set<std::string> keys_;
	};

	class FakeJsonProvider final : public IJsonProvider
	{
		public:
			Error parseHeader (std::string_view text, HeaderMap &outHeader) const override
			{
				return parseMap (text, outHeader);
			}

			Error parseClaims (std::string_view text, ClaimMap &outClaims) const override
			{
				return parseMap (text, outClaims);
			}

			Error toJson (const ClaimMap &claims, std::string &outJson) const override
			{
				return writeMap (claims, outJson);
			}

		private:
			template <typename TMap> static Error writeMap (const TMap &map, std::string &out)
			{
				std::ostringstream oss;
				bool first = true;
				for (const auto &[key, value] : map)
				{
					if (!first)
					{
						oss << ';';
					}
					first = false;

					oss << key << '|';
					if (std::holds_alternative<std::nullptr_t> (value))
					{
						oss << 'n' << '|';
					}
					else if (auto v = std::get_if<bool> (&value))
					{
						oss << 'b' << '|' << (*v ? '1' : '0');
					}
					else if (auto v = std::get_if<int64_t> (&value))
					{
						oss << 'i' << '|' << *v;
					}
					else if (auto v = std::get_if<double> (&value))
					{
						oss << 'd' << '|' << *v;
					}
					else if (auto v = std::get_if<std::string> (&value))
					{
						oss << 's' << '|' << *v;
					}
				}

				out = oss.str();
				return {.code = ErrorCode::Ok, .message = {}};
			}

			template <typename TMap> static Error parseMap (std::string_view text, TMap &out)
			{
				out.clear();
				if (text.empty())
				{
					return {.code = ErrorCode::Ok, .message = {}};
				}

				size_t start = 0;
				while (start < text.size())
				{
					size_t end = text.find (';', start);
					if (end == std::string_view::npos)
					{
						end = text.size();
					}

					const std::string_view item = text.substr (start, end - start);
					const size_t p1             = item.find ('|');
					const size_t p2 = (p1 == std::string_view::npos) ? std::string_view::npos : item.find ('|', p1 + 1);
					if (p1 == std::string_view::npos || p2 == std::string_view::npos)
					{
						return {.code = ErrorCode::InvalidJson, .message = "invalid item"};
					}

					const std::string key        = std::string (item.substr (0, p1));
					const char type              = item [p1 + 1];
					const std::string_view value = item.substr (p2 + 1);

					switch (type)
					{
					case 'n': out [key] = nullptr; break;
					case 'b': out [key] = (value == "1"); break;
					case 'i':
						{
							int64_t parsed = 0;
							auto r         = std::from_chars (value.data(), value.data() + value.size(), parsed);
							if (r.ec != std::errc())
							{
								return {.code = ErrorCode::InvalidJson, .message = "invalid int"};
							}
							out [key] = parsed;
							break;
						}
					case 'd':
						{
							std::string tmp (value);
							try
							{
								out [key] = std::stod (tmp);
							}
							catch (...)
							{
								return {.code = ErrorCode::InvalidJson, .message = "invalid double"};
							}
							break;
						}
					case 's': out [key] = std::string (value); break;
					default: return {.code = ErrorCode::InvalidJson, .message = "invalid type"};
					}

					start = end + 1;
				}

				return {.code = ErrorCode::Ok, .message = {}};
			}
	};
}    // namespace ipb::http::jwt
