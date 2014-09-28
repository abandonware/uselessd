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

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "macro.h"
#include "util.h"
#include "log.h"
#include "fileio.h"

int hostname_setup(void);

static int read_and_strip_hostname(const char *path, char **hn) {
        char *s;
        int r;

        assert(path);
        assert(hn);

        r = read_one_line_file(path, &s);
        if (r < 0)
                return r;

        hostname_cleanup(s, false);

        if (isempty(s)) {
                free(s);
                return -ENOENT;
        }

        *hn = s;
        return 0;
}

int hostname_setup(void) {
        int r;
        _cleanup_free_ char *b = NULL;
        const char *hn;
        bool enoent = false;

        r = read_and_strip_hostname("/etc/hostname", &b);
        if (r < 0) {
                if (r == -ENOENT)
                        enoent = true;
                else
                        log_warning("Failed to read configured hostname: %s", strerror(-r));

                hn = NULL;
        } else
                hn = b;

        if (isempty(hn)) {
                /* Don't override the hostname if it is already set
                 * and not explicitly configured */
                if (hostname_is_set())
                        return 0;

                if (enoent)
                        log_info("No hostname configured.");

                hn = "localhost";
        }

        if (sethostname(hn, strlen(hn)) < 0) {
                log_warning("Failed to set hostname to <%s>: %m", hn);
                return -errno;
        }

        log_info("Set hostname to <%s>.", hn);
        return 0;
}

static int help(void) {

        printf("%s [OPTIONS...]\n\n"
               "Initialize and set /etc/hostname.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { NULL,        0,                 NULL, 0             }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hqcv", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (optind < argc) {
                help();
                return -EINVAL;
        }

        return 1;
}

int main(void) {
	   int r;

	   log_parse_environment();
	   log_open();

	   r = parse_argv(argc, argv);
       if (r <= 0)
               return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

	   return hostname_setup() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
