#pragma once

#include <chrono>
#include <cstdint>
#include <format>
#include <functional>
#include <memory>
#include <mutex>
#include <source_location>
#include <string>
#include <string_view>

namespace tor::util {

// Log levels
enum class LogLevel : uint8_t {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Fatal = 5,
    Off = 6,
};

// Log level names
[[nodiscard]] constexpr const char* log_level_name(LogLevel level) {
    switch (level) {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO";
        case LogLevel::Warn: return "WARN";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Fatal: return "FATAL";
        case LogLevel::Off: return "OFF";
        default: return "UNKNOWN";
    }
}

// Parse log level from string
[[nodiscard]] LogLevel parse_log_level(std::string_view str);

// Log record
struct LogRecord {
    LogLevel level;
    std::string message;
    std::string_view file;
    uint32_t line;
    std::string_view function;
    std::chrono::system_clock::time_point timestamp;
    std::string_view category;  // Optional category/module

    [[nodiscard]] std::string format() const;
};

// Log sink interface
class LogSink {
public:
    virtual ~LogSink() = default;
    virtual void write(const LogRecord& record) = 0;
    virtual void flush() = 0;
};

// Console sink
class ConsoleSink : public LogSink {
public:
    ConsoleSink() = default;
    explicit ConsoleSink(bool colorize);

    void write(const LogRecord& record) override;
    void flush() override;

    void set_colorize(bool colorize) { colorize_ = colorize; }

private:
    bool colorize_{true};
    std::mutex mutex_;
};

// File sink
class FileSink : public LogSink {
public:
    explicit FileSink(const std::string& path);
    ~FileSink() override;

    void write(const LogRecord& record) override;
    void flush() override;

    [[nodiscard]] bool is_open() const { return file_ != nullptr; }
    [[nodiscard]] const std::string& path() const { return path_; }

    // Rotate log file
    void rotate();

private:
    std::string path_;
    std::FILE* file_{nullptr};
    std::mutex mutex_;
};

// Rotating file sink
class RotatingFileSink : public LogSink {
public:
    RotatingFileSink(
        const std::string& base_path,
        size_t max_size_bytes,
        size_t max_files
    );
    ~RotatingFileSink() override;

    void write(const LogRecord& record) override;
    void flush() override;

private:
    std::string base_path_;
    size_t max_size_;
    [[maybe_unused]] size_t max_files_;
    size_t current_size_{0};
    std::unique_ptr<FileSink> current_file_;
    std::mutex mutex_;

    void rotate_if_needed();
};

// Logger instance
class Logger {
public:
    Logger();
    explicit Logger(std::string_view category);

    // Set minimum log level
    void set_level(LogLevel level) { min_level_ = level; }
    [[nodiscard]] LogLevel level() const { return min_level_; }

    // Add sink
    void add_sink(std::shared_ptr<LogSink> sink);

    // Remove all sinks
    void clear_sinks();

    // Check if level is enabled
    [[nodiscard]] bool is_enabled(LogLevel level) const {
        return level >= min_level_;
    }

    // Log methods
    template <typename... Args>
    void log(LogLevel level,
             std::format_string<Args...> fmt,
             Args&&... args) {
        if (is_enabled(level)) {
            do_log(level, std::format(fmt, std::forward<Args>(args)...),
                   std::source_location::current());
        }
    }

    template <typename... Args>
    void trace(std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Trace, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void debug(std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Debug, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void info(std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Info, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void warn(std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Warn, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void error(std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Error, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void fatal(std::format_string<Args...> fmt, Args&&... args) {
        log(LogLevel::Fatal, fmt, std::forward<Args>(args)...);
    }

    // Flush all sinks
    void flush();

private:
    void do_log(LogLevel level, std::string message, std::source_location loc);

    std::string_view category_;
    LogLevel min_level_{LogLevel::Info};
    std::vector<std::shared_ptr<LogSink>> sinks_;
    std::mutex mutex_;
};

// Global logger access
Logger& global_logger();

// Configure global logger
void configure_logging(LogLevel level, bool to_console = true, const std::string& log_file = "");

// Convenience macros using global logger
#define LOG_TRACE(...) ::tor::util::global_logger().trace(__VA_ARGS__)
#define LOG_DEBUG(...) ::tor::util::global_logger().debug(__VA_ARGS__)
#define LOG_INFO(...) ::tor::util::global_logger().info(__VA_ARGS__)
#define LOG_WARN(...) ::tor::util::global_logger().warn(__VA_ARGS__)
#define LOG_ERROR(...) ::tor::util::global_logger().error(__VA_ARGS__)
#define LOG_FATAL(...) ::tor::util::global_logger().fatal(__VA_ARGS__)

// Scoped log context (for request tracing)
class LogContext {
public:
    explicit LogContext(std::string context);
    ~LogContext();

    [[nodiscard]] static std::string_view current();

private:
    std::string context_;
    std::string previous_;
};

}  // namespace tor::util
