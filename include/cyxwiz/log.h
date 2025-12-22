/*
 * CyxWiz Protocol - Logging
 *
 * Simple logging with levels and optional file output.
 * Privacy-conscious: can be disabled entirely for production.
 */

#ifndef CYXWIZ_LOG_H
#define CYXWIZ_LOG_H

#include "types.h"

typedef enum {
    CYXWIZ_LOG_TRACE = 0,
    CYXWIZ_LOG_DEBUG = 1,
    CYXWIZ_LOG_INFO = 2,
    CYXWIZ_LOG_WARN = 3,
    CYXWIZ_LOG_ERROR = 4,
    CYXWIZ_LOG_NONE = 5   /* Disable all logging */
} cyxwiz_log_level_t;

/* Initialize logging (call once at startup) */
void cyxwiz_log_init(cyxwiz_log_level_t level);

/* Set minimum log level */
void cyxwiz_log_set_level(cyxwiz_log_level_t level);

/* Get current log level */
cyxwiz_log_level_t cyxwiz_log_get_level(void);

/* Log a message */
void cyxwiz_log(cyxwiz_log_level_t level, const char *fmt, ...);

/* Convenience macros */
#define CYXWIZ_TRACE(...) cyxwiz_log(CYXWIZ_LOG_TRACE, __VA_ARGS__)
#define CYXWIZ_DEBUG(...) cyxwiz_log(CYXWIZ_LOG_DEBUG, __VA_ARGS__)
#define CYXWIZ_INFO(...)  cyxwiz_log(CYXWIZ_LOG_INFO, __VA_ARGS__)
#define CYXWIZ_WARN(...)  cyxwiz_log(CYXWIZ_LOG_WARN, __VA_ARGS__)
#define CYXWIZ_ERROR(...) cyxwiz_log(CYXWIZ_LOG_ERROR, __VA_ARGS__)

#endif /* CYXWIZ_LOG_H */
