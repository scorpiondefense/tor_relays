// Implementation - util/logging.cpp
#include "tor/util/logging.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>

namespace tor::util {

// Global logger singleton
static Logger& get_global_logger() {
    static Logger instance;
    return instance;
}

Logger& global_logger() {
    return get_global_logger();
}

void configure_logging(LogLevel level, bool to_console, const std::string& log_file) {
    auto& logger = global_logger();
    logger.set_level(level);
    logger.clear_sinks();
    if (to_console) {
        logger.add_sink(std::make_shared<ConsoleSink>());
    }
    if (!log_file.empty()) {
        logger.add_sink(std::make_shared<FileSink>(log_file));
    }
}

LogLevel parse_log_level(std::string_view str) {
    if (str == "trace" || str == "TRACE") return LogLevel::Trace;
    if (str == "debug" || str == "DEBUG") return LogLevel::Debug;
    if (str == "info" || str == "INFO") return LogLevel::Info;
    if (str == "warn" || str == "WARN" || str == "warning" || str == "WARNING") return LogLevel::Warn;
    if (str == "error" || str == "ERROR") return LogLevel::Error;
    if (str == "fatal" || str == "FATAL") return LogLevel::Fatal;
    return LogLevel::Info;
}

std::string LogRecord::format() const {
    auto time_t = std::chrono::system_clock::to_time_t(timestamp);
    std::tm tm_buf{};
    localtime_r(&time_t, &tm_buf);
    
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
        << " [" << log_level_name(level) << "] ";
    if (!category.empty()) {
        oss << "[" << category << "] ";
    }
    oss << message;
    return oss.str();
}

// ConsoleSink implementation
ConsoleSink::ConsoleSink(bool colorize) : colorize_(colorize) {}

void ConsoleSink::write(const LogRecord& record) {
    std::lock_guard lock(mutex_);
    std::cerr << record.format() << "\n";
}

void ConsoleSink::flush() {
    std::lock_guard lock(mutex_);
    std::cerr.flush();
}

// FileSink implementation
FileSink::FileSink(const std::string& path) : path_(path) {
    file_ = std::fopen(path.c_str(), "a");
}

FileSink::~FileSink() {
    if (file_) {
        std::fclose(file_);
    }
}

void FileSink::write(const LogRecord& record) {
    if (!file_) return;
    std::lock_guard lock(mutex_);
    std::fprintf(file_, "%s\n", record.format().c_str());
}

void FileSink::flush() {
    if (!file_) return;
    std::lock_guard lock(mutex_);
    std::fflush(file_);
}

void FileSink::rotate() {
    std::lock_guard lock(mutex_);
    if (file_) {
        std::fclose(file_);
    }
    file_ = std::fopen(path_.c_str(), "a");
}

// RotatingFileSink implementation
RotatingFileSink::RotatingFileSink(
    const std::string& base_path,
    size_t max_size_bytes,
    size_t max_files)
    : base_path_(base_path), max_size_(max_size_bytes), max_files_(max_files) {
    current_file_ = std::make_unique<FileSink>(base_path);
}

RotatingFileSink::~RotatingFileSink() = default;

void RotatingFileSink::write(const LogRecord& record) {
    std::lock_guard lock(mutex_);
    if (current_file_) {
        current_file_->write(record);
        current_size_ += record.message.size() + 50; // approximate
        rotate_if_needed();
    }
}

void RotatingFileSink::flush() {
    std::lock_guard lock(mutex_);
    if (current_file_) {
        current_file_->flush();
    }
}

void RotatingFileSink::rotate_if_needed() {
    if (current_size_ >= max_size_) {
        current_file_->rotate();
        current_size_ = 0;
    }
}

// Logger implementation
Logger::Logger() = default;

Logger::Logger(std::string_view category) : category_(category) {}

void Logger::add_sink(std::shared_ptr<LogSink> sink) {
    std::lock_guard lock(mutex_);
    sinks_.push_back(std::move(sink));
}

void Logger::clear_sinks() {
    std::lock_guard lock(mutex_);
    sinks_.clear();
}

void Logger::do_log(LogLevel level, std::string message, std::source_location loc) {
    LogRecord record{
        .level = level,
        .message = std::move(message),
        .file = loc.file_name(),
        .line = loc.line(),
        .function = loc.function_name(),
        .timestamp = std::chrono::system_clock::now(),
        .category = category_
    };

    std::lock_guard lock(mutex_);
    for (auto& sink : sinks_) {
        sink->write(record);
    }
}

void Logger::flush() {
    std::lock_guard lock(mutex_);
    for (auto& sink : sinks_) {
        sink->flush();
    }
}

// LogContext implementation
thread_local std::string current_context;

LogContext::LogContext(std::string context)
    : context_(std::move(context)), previous_(current_context) {
    current_context = context_;
}

LogContext::~LogContext() {
    current_context = previous_;
}

std::string_view LogContext::current() {
    return current_context;
}

}  // namespace tor::util
