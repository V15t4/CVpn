#pragma once

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <ctime>

namespace vpn {

enum class LogLevel { Debug = 0, Info = 1, Warn = 2, Error = 3 };

inline LogLevel& log_level() {
  static LogLevel level = LogLevel::Info;
  return level;
}

inline void set_verbose(bool verbose) {
  log_level() = verbose ? LogLevel::Debug : LogLevel::Info;
}

namespace detail {

inline const char* level_tag(LogLevel level) {
  switch (level) {
    case LogLevel::Debug:
      return "DEBUG";
    case LogLevel::Info:
      return "INFO";
    case LogLevel::Warn:
      return "WARN";
    case LogLevel::Error:
      return "ERROR";
  }
  return "?";
}

__attribute__((format(printf, 2, 3))) inline void log_message(LogLevel level, const char* fmt, ...) {
  if (level < log_level()) {
    return;
  }

  const auto now = std::chrono::system_clock::now();
  const std::time_t seconds = std::chrono::system_clock::to_time_t(now);
  std::tm local{};
  localtime_r(&seconds, &local);

  char timestamp[16] = {};
  std::strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &local);

  std::fprintf(stderr, "[%s] %-5s ", timestamp, level_tag(level));

  va_list args;
  va_start(args, fmt);
  std::vfprintf(stderr, fmt, args);
  va_end(args);
  std::fputc('\n', stderr);
}

}  // namespace detail

__attribute__((format(printf, 1, 2))) inline void log_debug(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  char buffer[1024];
  std::vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);
  detail::log_message(LogLevel::Debug, "%s", buffer);
}

__attribute__((format(printf, 1, 2))) inline void log_info(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  char buffer[1024];
  std::vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);
  detail::log_message(LogLevel::Info, "%s", buffer);
}

__attribute__((format(printf, 1, 2))) inline void log_warn(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  char buffer[1024];
  std::vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);
  detail::log_message(LogLevel::Warn, "%s", buffer);
}

__attribute__((format(printf, 1, 2))) inline void log_error(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  char buffer[1024];
  std::vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);
  detail::log_message(LogLevel::Error, "%s", buffer);
}

}  // namespace vpn
