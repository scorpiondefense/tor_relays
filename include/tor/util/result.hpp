#pragma once

#include <expected>
#include <format>
#include <source_location>
#include <string>
#include <variant>

namespace tor::util {

// Generic error type with context
class Error {
public:
    enum class Code {
        // General errors
        Unknown = 0,
        InvalidArgument,
        InvalidState,
        NotFound,
        AlreadyExists,
        Timeout,
        Cancelled,

        // I/O errors
        IoError,
        ConnectionFailed,
        ConnectionClosed,
        ReadError,
        WriteError,

        // Protocol errors
        ProtocolError,
        ParseError,
        SerializeError,
        VersionMismatch,

        // Crypto errors
        CryptoError,
        KeyError,
        SignatureError,
        VerificationFailed,

        // Resource errors
        ResourceExhausted,
        QuotaExceeded,
        RateLimited,

        // Configuration errors
        ConfigError,
        MissingConfig,
        InvalidConfig,

        // Circuit errors
        CircuitError,
        CircuitClosed,
        StreamError,
    };

    Error() = default;

    Error(Code code, std::string message,
          std::source_location loc = std::source_location::current())
        : code_(code), message_(std::move(message)),
          file_(loc.file_name()), line_(loc.line()) {}

    [[nodiscard]] Code code() const { return code_; }
    [[nodiscard]] const std::string& message() const { return message_; }
    [[nodiscard]] const char* file() const { return file_; }
    [[nodiscard]] uint32_t line() const { return line_; }

    [[nodiscard]] std::string to_string() const {
        return std::format("{}:{}: [{}] {}",
                          file_, line_, static_cast<int>(code_), message_);
    }

    // Convenience constructors
    [[nodiscard]] static Error invalid_argument(
        std::string msg,
        std::source_location loc = std::source_location::current()) {
        return Error(Code::InvalidArgument, std::move(msg), loc);
    }

    [[nodiscard]] static Error not_found(
        std::string msg,
        std::source_location loc = std::source_location::current()) {
        return Error(Code::NotFound, std::move(msg), loc);
    }

    [[nodiscard]] static Error io_error(
        std::string msg,
        std::source_location loc = std::source_location::current()) {
        return Error(Code::IoError, std::move(msg), loc);
    }

    [[nodiscard]] static Error protocol_error(
        std::string msg,
        std::source_location loc = std::source_location::current()) {
        return Error(Code::ProtocolError, std::move(msg), loc);
    }

    [[nodiscard]] static Error crypto_error(
        std::string msg,
        std::source_location loc = std::source_location::current()) {
        return Error(Code::CryptoError, std::move(msg), loc);
    }

    [[nodiscard]] static Error config_error(
        std::string msg,
        std::source_location loc = std::source_location::current()) {
        return Error(Code::ConfigError, std::move(msg), loc);
    }

private:
    Code code_{Code::Unknown};
    std::string message_;
    const char* file_{"unknown"};
    uint32_t line_{0};
};

// Result type alias
template <typename T>
using Result = std::expected<T, Error>;

// Unit type for void results
struct Unit {};
inline constexpr Unit unit{};

using VoidResult = Result<Unit>;

// Helper macros for error propagation
#define TOR_TRY(expr)                              \
    ({                                             \
        auto&& _result = (expr);                   \
        if (!_result) {                            \
            return std::unexpected(_result.error()); \
        }                                          \
        std::move(*_result);                       \
    })

#define TOR_TRY_VOID(expr)                         \
    do {                                           \
        auto&& _result = (expr);                   \
        if (!_result) {                            \
            return std::unexpected(_result.error()); \
        }                                          \
    } while (0)

// Error code to string
[[nodiscard]] constexpr const char* error_code_name(Error::Code code) {
    switch (code) {
        case Error::Code::Unknown: return "Unknown";
        case Error::Code::InvalidArgument: return "InvalidArgument";
        case Error::Code::InvalidState: return "InvalidState";
        case Error::Code::NotFound: return "NotFound";
        case Error::Code::AlreadyExists: return "AlreadyExists";
        case Error::Code::Timeout: return "Timeout";
        case Error::Code::Cancelled: return "Cancelled";
        case Error::Code::IoError: return "IoError";
        case Error::Code::ConnectionFailed: return "ConnectionFailed";
        case Error::Code::ConnectionClosed: return "ConnectionClosed";
        case Error::Code::ReadError: return "ReadError";
        case Error::Code::WriteError: return "WriteError";
        case Error::Code::ProtocolError: return "ProtocolError";
        case Error::Code::ParseError: return "ParseError";
        case Error::Code::SerializeError: return "SerializeError";
        case Error::Code::VersionMismatch: return "VersionMismatch";
        case Error::Code::CryptoError: return "CryptoError";
        case Error::Code::KeyError: return "KeyError";
        case Error::Code::SignatureError: return "SignatureError";
        case Error::Code::VerificationFailed: return "VerificationFailed";
        case Error::Code::ResourceExhausted: return "ResourceExhausted";
        case Error::Code::QuotaExceeded: return "QuotaExceeded";
        case Error::Code::RateLimited: return "RateLimited";
        case Error::Code::ConfigError: return "ConfigError";
        case Error::Code::MissingConfig: return "MissingConfig";
        case Error::Code::InvalidConfig: return "InvalidConfig";
        case Error::Code::CircuitError: return "CircuitError";
        case Error::Code::CircuitClosed: return "CircuitClosed";
        case Error::Code::StreamError: return "StreamError";
        default: return "Unknown";
    }
}

}  // namespace tor::util
