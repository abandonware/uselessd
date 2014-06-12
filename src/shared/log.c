/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>

#include "printf.h" // glibc-specific, provided as a third-party header for other libcs
#include "log.h"
#include "util.h"
#include "missing.h"
#include "macro.h"
#include "socket-util.h"

#define SNDBUF_SIZE (8*1024*1024)

static LogTarget log_target = LOG_TARGET_CONSOLE;
static int log_max_level = LOG_INFO;
static int log_facility = LOG_DAEMON;

static int console_fd = STDERR_FILENO;
static int syslog_fd = -1;
static int kmsg_fd = -1;

static bool syslog_is_stream = false;

static bool show_color = false;
static bool show_location = false;

/* Akin to glibc's __abort_msg; which is private and we hence cannot
 * use here. */
static char *log_abort_msg = NULL;

void log_close_console(void) {

        if (console_fd < 0)
                return;

        if (getpid() == 1) {
                if (console_fd >= 3)
                        close_nointr_nofail(console_fd);

                console_fd = -1;
        }
}

static int log_open_console(void) {

        if (console_fd >= 0)
                return 0;

        if (getpid() == 1) {
                console_fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
                if (console_fd < 0)
                        return console_fd;
        } else
                console_fd = STDERR_FILENO;

        return 0;
}

void log_close_kmsg(void) {

        if (kmsg_fd < 0)
                return;

        close_nointr_nofail(kmsg_fd);
        kmsg_fd = -1;
}

static int log_open_kmsg(void) {

        if (kmsg_fd >= 0)
                return 0;

        kmsg_fd = open("/dev/kmsg", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (kmsg_fd < 0)
                return -errno;

        return 0;
}

void log_close_syslog(void) {

        if (syslog_fd < 0)
                return;

        close_nointr_nofail(syslog_fd);
        syslog_fd = -1;
}

static int create_log_socket(int type) {
        int fd;
        struct timeval tv;

        fd = socket(AF_UNIX, type|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        fd_inc_sndbuf(fd, SNDBUF_SIZE);

        /* We need a blocking fd here since we'd otherwise lose
        messages way too early. However, let's not hang forever in the
        unlikely case of a deadlock. */
        timeval_store(&tv, 1*USEC_PER_MINUTE);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        return fd;
}

static int log_open_syslog(void) {
        int r;
        union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/dev/log",
        };

        if (syslog_fd >= 0)
                return 0;

        syslog_fd = create_log_socket(SOCK_DGRAM);
        if (syslog_fd < 0) {
                r = syslog_fd;
                goto fail;
        }

        if (connect(syslog_fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path)) < 0) {
                close_nointr_nofail(syslog_fd);

                /* Some legacy syslog systems still use stream
                 * sockets. They really shouldn't. But what can we
                 * do... */
                syslog_fd = create_log_socket(SOCK_STREAM);
                if (syslog_fd < 0) {
                        r = syslog_fd;
                        goto fail;
                }

                if (connect(syslog_fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path)) < 0) {
                        r = -errno;
                        goto fail;
                }

                syslog_is_stream = true;
        } else
                syslog_is_stream = false;

        return 0;

fail:
        log_close_syslog();
        return r;
}

int log_open(void) {
        int r;

        /* If we don't use the console we close it here, to not get
         * killed by SAK. If we don't use syslog we close it here so
         * that we are not confused by somebody deleting the socket in
         * the fs. If we don't use /dev/kmsg we still keep it open,
         * because there is no reason to close it. */

        if (log_target == LOG_TARGET_NULL) {
                log_close_syslog();
                log_close_console();
                return 0;
        }

                if (log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                    log_target == LOG_TARGET_SYSLOG) {
                        r = log_open_syslog();
                        if (r >= 0) {
                                log_close_console();
                                return r;
                        }
                }

                if (log_target == LOG_TARGET_SAFE ||
                    log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                    log_target == LOG_TARGET_KMSG) {
                        r = log_open_kmsg();
                        if (r >= 0) {
                                log_close_syslog();
                                log_close_console();
                                return r;
                        }
                }
        }
        
        log_close_syslog();

        /* Get the real /dev/console if we are PID=1, hence reopen */
        log_close_console();
        return log_open_console();
}

void log_set_target(LogTarget target) {
        assert(target >= 0);
        assert(target < _LOG_TARGET_MAX);

        log_target = target;
}

void log_close(void) {
        log_close_syslog();
        log_close_kmsg();
        log_close_console();
}

void log_forget_fds(void) {
        console_fd = kmsg_fd = syslog_fd = -1;
}

void log_set_max_level(int level) {
        assert((level & LOG_PRIMASK) == level);

        log_max_level = level;
}

void log_set_facility(int facility) {
        log_facility = facility;
}

static int write_to_console(
                int level,
                const char*file,
                int line,
                const char *func,
                const char *object_name,
                const char *object,
                const char *buffer) {

        char location[64];
        struct iovec iovec[5] = {};
        unsigned n = 0;
        bool highlight;

        if (console_fd < 0)
                return 0;

        highlight = LOG_PRI(level) <= LOG_ERR && show_color;

        if (show_location) {
                snprintf(location, sizeof(location), "(%s:%u) ", file, line);
                char_array_0(location);
                IOVEC_SET_STRING(iovec[n++], location);
        }

        if (highlight)
                IOVEC_SET_STRING(iovec[n++], ANSI_HIGHLIGHT_RED_ON);
        IOVEC_SET_STRING(iovec[n++], buffer);
        if (highlight)
                IOVEC_SET_STRING(iovec[n++], ANSI_HIGHLIGHT_OFF);
        IOVEC_SET_STRING(iovec[n++], "\n");

        if (writev(console_fd, iovec, n) < 0)
                return -errno;

        return 1;
}

static int write_to_syslog(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *object_name,
        const char *object,
        const char *buffer) {

        char header_priority[16], header_time[64], header_pid[16];
        struct iovec iovec[5] = {};
        struct msghdr msghdr = {
                .msg_iov = iovec,
                .msg_iovlen = ELEMENTSOF(iovec),
        };
        time_t t;
        struct tm *tm;

        if (syslog_fd < 0)
                return 0;

        snprintf(header_priority, sizeof(header_priority), "<%i>", level);
        char_array_0(header_priority);

        t = (time_t) (now(CLOCK_REALTIME) / USEC_PER_SEC);
        tm = localtime(&t);
        if (!tm)
                return -EINVAL;

        if (strftime(header_time, sizeof(header_time), "%h %e %T ", tm) <= 0)
                return -EINVAL;

        snprintf(header_pid, sizeof(header_pid), "[%lu]: ", (unsigned long) getpid());
        char_array_0(header_pid);

        IOVEC_SET_STRING(iovec[0], header_priority);
        IOVEC_SET_STRING(iovec[1], header_time);
        IOVEC_SET_STRING(iovec[2], program_invocation_short_name);
        IOVEC_SET_STRING(iovec[3], header_pid);
        IOVEC_SET_STRING(iovec[4], buffer);

        /* When using syslog via SOCK_STREAM separate the messages by NUL chars */
        if (syslog_is_stream)
                iovec[4].iov_len++;

        for (;;) {
                ssize_t n;

                n = sendmsg(syslog_fd, &msghdr, MSG_NOSIGNAL);
                if (n < 0)
                        return -errno;

                if (!syslog_is_stream ||
                    (size_t) n >= IOVEC_TOTAL_SIZE(iovec, ELEMENTSOF(iovec)))
                        break;

                IOVEC_INCREMENT(iovec, ELEMENTSOF(iovec), n);
        }

        return 1;
}

static int write_to_kmsg(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *object_name,
        const char *object,
        const char *buffer) {

        char header_priority[16], header_pid[16];
        struct iovec iovec[5] = {};

        if (kmsg_fd < 0)
                return 0;

        snprintf(header_priority, sizeof(header_priority), "<%i>", level);
        char_array_0(header_priority);

        snprintf(header_pid, sizeof(header_pid), "[%lu]: ", (unsigned long) getpid());
        char_array_0(header_pid);

        IOVEC_SET_STRING(iovec[0], header_priority);
        IOVEC_SET_STRING(iovec[1], program_invocation_short_name);
        IOVEC_SET_STRING(iovec[2], header_pid);
        IOVEC_SET_STRING(iovec[3], buffer);
        IOVEC_SET_STRING(iovec[4], "\n");

        if (writev(kmsg_fd, iovec, ELEMENTSOF(iovec)) < 0)
                return -errno;

        return 1;
}

static int log_do_header(char *header, size_t size,
                         int level,
                         const char *file, int line, const char *func,
                         const char *object_name, const char *object) {
        snprintf(header, size,
                 "PRIORITY=%i\n"
                 "SYSLOG_FACILITY=%i\n"
                 "%s%.*s%s"
                 "%s%.*i%s"
                 "%s%.*s%s"
                 "%s%.*s%s"
                 "SYSLOG_IDENTIFIER=%s\n",
                 LOG_PRI(level),
                 LOG_FAC(level),
                 file ? "CODE_FILE=" : "",
                 file ? LINE_MAX : 0, file, /* %.0s means no output */
                 file ? "\n" : "",
                 line ? "CODE_LINE=" : "",
                 line ? 1 : 0, line, /* %.0d means no output too, special case for 0 */
                 line ? "\n" : "",
                 func ? "CODE_FUNCTION=" : "",
                 func ? LINE_MAX : 0, func,
                 func ? "\n" : "",
                 object ? object_name : "",
                 object ? LINE_MAX : 0, object, /* %.0s means no output */
                 object ? "\n" : "",
                 program_invocation_short_name);
        header[size - 1] = '\0';
        return 0;
}

static int log_dispatch(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *object_name,
        const char *object,
        char *buffer) {

        int r = 0;

        if (log_target == LOG_TARGET_NULL)
                return 0;

        /* Patch in LOG_DAEMON facility if necessary */
        if ((level & LOG_FACMASK) == 0)
                level = log_facility | LOG_PRI(level);

        do {
                char *e;
                int k = 0;

                buffer += strspn(buffer, NEWLINE);

                if (buffer[0] == 0)
                        break;

                if ((e = strpbrk(buffer, NEWLINE)))
                        *(e++) = 0;

                if (log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                    log_target == LOG_TARGET_SYSLOG) {

                        k = write_to_syslog(level, file, line, func,
                                            object_name, object, buffer);
                        if (k < 0) {
                                if (k != -EAGAIN)
                                        log_close_syslog();
                                log_open_kmsg();
                        } else if (k > 0)
                                r++;
                }

                if (k <= 0 &&
                    (log_target == LOG_TARGET_SAFE ||
                     log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                     log_target == LOG_TARGET_KMSG)) {

                        k = write_to_kmsg(level, file, line, func,
                                          object_name, object, buffer);
                        if (k < 0) {
                                log_close_kmsg();
                                log_open_console();
                        } else if (k > 0)
                                r++;
                }

                if (k <= 0) {
                        k = write_to_console(level, file, line, func,
                                             object_name, object, buffer);
                        if (k < 0)
                                return k;
                }

                buffer = e;
        } while (buffer);

        return r;
}

int log_dump_internal(
        int level,
        const char*file,
        int line,
        const char *func,
        char *buffer) {

        PROTECT_ERRNO;

        /* This modifies the buffer... */

        if (_likely_(LOG_PRI(level) > log_max_level))
                return 0;

        return log_dispatch(level, file, line, func, NULL, NULL, buffer);
}

int log_metav(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *format,
        va_list ap) {

        PROTECT_ERRNO;
        char buffer[LINE_MAX];

        if (_likely_(LOG_PRI(level) > log_max_level))
                return 0;

        vsnprintf(buffer, sizeof(buffer), format, ap);
        char_array_0(buffer);

        return log_dispatch(level, file, line, func, NULL, NULL, buffer);
}

int log_meta(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *format, ...) {

        int r;
        va_list ap;

        va_start(ap, format);
        r = log_metav(level, file, line, func, format, ap);
        va_end(ap);

        return r;
}

int log_metav_object(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *object_name,
        const char *object,
        const char *format,
        va_list ap) {

        PROTECT_ERRNO;
        char buffer[LINE_MAX];

        if (_likely_(LOG_PRI(level) > log_max_level))
                return 0;

        vsnprintf(buffer, sizeof(buffer), format, ap);
        char_array_0(buffer);

        return log_dispatch(level, file, line, func,
                            object_name, object, buffer);
}

int log_meta_object(
        int level,
        const char*file,
        int line,
        const char *func,
        const char *object_name,
        const char *object,
        const char *format, ...) {

        int r;
        va_list ap;

        va_start(ap, format);
        r = log_metav_object(level, file, line, func,
                             object_name, object, format, ap);
        va_end(ap);

        return r;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
_noreturn_ static void log_assert(const char *text, const char *file, int line, const char *func, const char *format) {
        static char buffer[LINE_MAX];

        snprintf(buffer, sizeof(buffer), format, text, file, line, func);

        char_array_0(buffer);
        log_abort_msg = buffer;

        log_dispatch(LOG_CRIT, file, line, func, NULL, NULL, buffer);
        abort();
}
#pragma GCC diagnostic pop

_noreturn_ void log_assert_failed(const char *text, const char *file, int line, const char *func) {
        log_assert(text, file, line, func, "Assertion '%s' failed at %s:%u, function %s(). Aborting.");
}

_noreturn_ void log_assert_failed_unreachable(const char *text, const char *file, int line, const char *func) {
        log_assert(text, file, line, func, "Code should not be reached '%s' at %s:%u, function %s(). Aborting.");
}

int log_oom_internal(const char *file, int line, const char *func) {
        log_meta(LOG_ERR, file, line, func, "Out of memory.");
        return -ENOMEM;
}

/* This is a hacky solution to a post-vasprintf() va_arg() call-induced segfault,
 * which led to the integration of VA_FORMAT_ADVANCE, a macro dependent
 * on parse_printf_format(), thus nastily locking log.c to glibc-specific printf() dynamics
 * See here: https://bugs.freedesktop.org/show_bug.cgi?id=55213
 */
const char *next_format(
                 const char *format,
                 va_list *ap) {

         char lm, *cs, *fc, *format_copy, *format_ptr;

         if ((fc = strchr(format, '%')) ) {
                 format_copy = strndup(fc, LINE_MAX);

                 // remove any non-format spec % chars
                 while ((fc = strstr(format_copy, "%%")) )
                         *(fc+1) = *fc = ' ';
                 cs = strtok_r(format_copy, "%", &format_ptr);
                 // no need to worry about 'h' or 'hh' length modifiers as these will promoted to ints
                 do {
                         lm = 0;
                         while (*cs) {
                                 switch(*cs++) {
                                    case 'l':
                                            lm = (lm == 'l') ? 'L' : 'l';
                                            break;
                                    case 'L':
                                            lm = 'l';
                                            break;
                                    case 's':
                                            va_arg(*ap, char *);
                                            *cs = 0;
                                            break;
                                    case 'u': case 'd': case 'i': case 'x': case 'X': case 'c': case 'o':
                                            if (!lm)
                                                    va_arg(*ap, int);
                                            else if (lm == 'l')
                                                    va_arg(*ap, long);
                                            else if (lm == 'L')
                                                    va_arg(*ap, long long);
                                            else
                                                    va_arg(*ap, int);
                                            *cs = 0;
                                            break;
                                    case 'e': case 'f': case 'g': case 'E': case 'F': case 'G':
                                            if (lm != 'l')
                                                    va_arg(*ap, double);
                                            else
                                                    va_arg(*ap, long double);
                                            *cs = 0;
                                            break;
                                    case 'p':
                                            va_arg(*ap, void *);
                                            *cs = 0;
                                             break;
                                 }
                         }
                 } while((cs = strtok_r(NULL, "%", &format_ptr)));

                 free(format_copy);
         }
         return va_arg(*ap, char *);
}

int log_struct_internal(
                int level,
                const char *file,
                int line,
                const char *func,
                const char *format, ...) {

        PROTECT_ERRNO;
        va_list ap, app;
        int r;

        if (_likely_(LOG_PRI(level) > log_max_level))
                return 0;

        if (log_target == LOG_TARGET_NULL)
                return 0;

        if ((level & LOG_FACMASK) == 0)
                level = log_facility | LOG_PRI(level);
                
         char buf[LINE_MAX];
                bool found = false;

                /* Fallback if journal logging is not available */

                va_start(ap, format);
                while (format) {

                        va_copy(app, ap);
                        vsnprintf(buf, sizeof(buf), format, app);
                        char_array_0(buf);

                        if (startswith(buf, "MESSAGE=")) {
                                found = true;
                                break;
                        }

                        format = next_format(format, &ap);
                }
                va_end(ap);

                if (found) {
                        r = log_dispatch(level, file, line, func,
                                         NULL, NULL, buf + 8);
                } else {
                        r = -EINVAL;
        }

        return r;
}

int log_set_target_from_string(const char *e) {
        LogTarget t;

        t = log_target_from_string(e);
        if (t < 0)
                return -EINVAL;

        log_set_target(t);
        return 0;
}

int log_set_max_level_from_string(const char *e) {
        int t;

        t = log_level_from_string(e);
        if (t < 0)
                return t;

        log_set_max_level(t);
        return 0;
}

void log_parse_environment(void) {
        const char *e;

        e = getenv("SYSTEMD_LOG_TARGET");
        if (e && log_set_target_from_string(e) < 0)
                log_warning("Failed to parse log target %s. Ignoring.", e);

        e = getenv("SYSTEMD_LOG_LEVEL");
        if (e && log_set_max_level_from_string(e) < 0)
                log_warning("Failed to parse log level %s. Ignoring.", e);

        e = getenv("SYSTEMD_LOG_COLOR");
        if (e && log_show_color_from_string(e) < 0)
                log_warning("Failed to parse bool %s. Ignoring.", e);

        e = getenv("SYSTEMD_LOG_LOCATION");
        if (e && log_show_location_from_string(e) < 0)
                log_warning("Failed to parse bool %s. Ignoring.", e);
}

LogTarget log_get_target(void) {
        return log_target;
}

int log_get_max_level(void) {
        return log_max_level;
}

void log_show_color(bool b) {
        show_color = b;
}

void log_show_location(bool b) {
        show_location = b;
}

int log_show_color_from_string(const char *e) {
        int t;

        t = parse_boolean(e);
        if (t < 0)
                return t;

        log_show_color(t);
        return 0;
}

int log_show_location_from_string(const char *e) {
        int t;

        t = parse_boolean(e);
        if (t < 0)
                return t;

        log_show_location(t);
        return 0;
}

bool log_on_console(void) {
        if (log_target == LOG_TARGET_CONSOLE)
                return true;

        return syslog_fd < 0 && kmsg_fd < 0;
}

static const char *const log_target_table[] = {
        [LOG_TARGET_CONSOLE] = "console",
        [LOG_TARGET_KMSG] = "kmsg",
        [LOG_TARGET_SYSLOG] = "syslog",
        [LOG_TARGET_SYSLOG_OR_KMSG] = "syslog-or-kmsg",
        [LOG_TARGET_SAFE] = "safe",
        [LOG_TARGET_NULL] = "null"
};

DEFINE_STRING_TABLE_LOOKUP(log_target, LogTarget);
