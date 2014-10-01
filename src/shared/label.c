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

#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "label.h"
#include "strv.h"
#include "util.h"
#include "path-util.h"

/* The vast majority of these are NOPs, as we do not
 * honor any particular ACL/MAC  and stick to a more generic
 * goal. Nonetheless, we retain them for compatibility.
 */

int label_init(const char *prefix) {
        int r = 0;
        return r;
}

int label_fix(const char *path, bool ignore_enoent, bool ignore_erofs) {
        int r = 0;
        return r;
}

void label_finish(void) {
}

int label_get_create_label_from_exe(const char *exe, char **label) {
        int r = 0;
        return r;
}

int label_context_set(const char *path, mode_t mode) {
        int r = 0;
        return r;
}

int label_socket_set(const char *label) {
        return 0;
}

void label_context_clear(void) {
}

void label_socket_clear(void) {
}

void label_free(const char *label) {
}

int label_mkdir(const char *path, mode_t mode) {
        /* Creates a directory and labels it according to the SELinux policy.
         * Not present here. */
        return mkdir(path, mode) < 0 ? -errno : 0;
}

int label_bind(int fd, const struct sockaddr *addr, socklen_t addrlen) {
        /* Binds a socket and label its file system object according to the SELinux policy.
         * Not present here. */
        return bind(fd, addr, addrlen) < 0 ? -errno : 0;
}
