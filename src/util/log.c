/*
 * CyxWiz Protocol - Logging Implementation
 */

#include "cyxwiz/log.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

static cyxwiz_log_level_t g_log_level = CYXWIZ_LOG_INFO;

static const char *level_names[] = {
    "TRACE",
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR"
};

void cyxwiz_log_init(cyxwiz_log_level_t level)
{
    g_log_level = level;
}

void cyxwiz_log_set_level(cyxwiz_log_level_t level)
{
    g_log_level = level;
}

cyxwiz_log_level_t cyxwiz_log_get_level(void)
{
    return g_log_level;
}

void cyxwiz_log(cyxwiz_log_level_t level, const char *fmt, ...)
{
    if (level < g_log_level) {
        return;
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    char time_buf[20];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(stderr, "[%s] [%s] ", time_buf, level_names[level]);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
    fflush(stderr);
}
