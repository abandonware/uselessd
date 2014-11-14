/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 ProFUSION embedded systems

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

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/swap.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <linux/loop.h>
#include <linux/dm-ioctl.h>

#include "list.h"
#include "mount-setup.h"
#include "umount.h"
#include "path-util.h"
#include "util.h"
#include "virt.h"

typedef struct MountPoint {
        char *path;
        dev_t devnum;
        LIST_FIELDS (struct MountPoint, mount_point);
} MountPoint;

static void mount_point_free(MountPoint **head, MountPoint *m) {
        assert(head);
        assert(m);

        LIST_REMOVE(MountPoint, mount_point, *head, m);

        free(m->path);
        free(m);
}

static void mount_points_list_free(MountPoint **head) {
        assert(head);

        while (*head)
                mount_point_free(head, *head);
}

static int mount_points_list_get(MountPoint **head) {
        FILE *proc_self_mountinfo;
        char *path, *p;
        unsigned int i;
        int r;

        assert(head);

        if (!(proc_self_mountinfo = fopen("/proc/self/mountinfo", "re")))
                return -errno;

        for (i = 1;; i++) {
                int k;
                MountPoint *m;

                path = p = NULL;

                if ((k = fscanf(proc_self_mountinfo,
                                "%*s "       /* (1) mount id */
                                "%*s "       /* (2) parent id */
                                "%*s "       /* (3) major:minor */
                                "%*s "       /* (4) root */
                                "%ms "       /* (5) mount point */
                                "%*s"        /* (6) mount options */
                                "%*[^-]"     /* (7) optional fields */
                                "- "         /* (8) separator */
                                "%*s "       /* (9) file system type */
                                "%*s"        /* (10) mount source */
                                "%*s"        /* (11) mount options 2 */
                                "%*[^\n]",   /* some rubbish at the end */
                                &path)) != 1) {
                        if (k == EOF)
                                break;

                        log_warning("Failed to parse /proc/self/mountinfo:%u.", i);

                        free(path);
                        continue;
                }

                p = cunescape(path);
                free(path);

                if (!p) {
                        r = -ENOMEM;
                        goto finish;
                }

                /* Ignore mount points we can't unmount because they
                 * are API or because we are keeping them open (like
                 * /dev/console) */
                if (mount_point_is_api(p) ||
                    mount_point_ignore(p) ||
                    path_equal(p, "/dev/console")) {
                        free(p);
                        continue;
                }

                if (!(m = new0(MountPoint, 1))) {
                        free(p);
                        r = -ENOMEM;
                        goto finish;
                }

                m->path = p;
                LIST_PREPEND(MountPoint, mount_point, *head, m);
        }

        r = 0;

finish:
        fclose(proc_self_mountinfo);

        return r;
}

static int swap_list_get(MountPoint **head) {
        FILE *proc_swaps;
        unsigned int i;
        int r;

        assert(head);

        if (!(proc_swaps = fopen("/proc/swaps", "re")))
                return (errno == ENOENT) ? 0 : -errno;

        (void) fscanf(proc_swaps, "%*s %*s %*s %*s %*s\n");

        for (i = 2;; i++) {
                MountPoint *swap;
                char *dev = NULL, *d;
                int k;

                if ((k = fscanf(proc_swaps,
                                "%ms " /* device/file */
                                "%*s " /* type of swap */
                                "%*s " /* swap size */
                                "%*s " /* used */
                                "%*s\n", /* priority */
                                &dev)) != 1) {

                        if (k == EOF)
                                break;

                        log_warning("Failed to parse /proc/swaps:%u.", i);

                        free(dev);
                        continue;
                }

                if (endswith(dev, "(deleted)")) {
                        free(dev);
                        continue;
                }

                d = cunescape(dev);
                free(dev);

                if (!d) {
                        r = -ENOMEM;
                        goto finish;
                }

                if (!(swap = new0(MountPoint, 1))) {
                        free(d);
                        r = -ENOMEM;
                        goto finish;
                }

                swap->path = d;
                LIST_PREPEND(MountPoint, mount_point, *head, swap);
        }

        r = 0;

finish:
        fclose(proc_swaps);

        return r;
}

static int mount_points_list_umount(MountPoint **head, bool *changed, bool log_error) {
        MountPoint *m, *n;
        int n_failed = 0;

        assert(head);

        LIST_FOREACH_SAFE(mount_point, m, n, *head) {

                /* If we are in a container, don't attempt to
                   read-only mount anything as that brings no real
                   benefits, but might confuse the host, as we remount
                   the superblock here, not the bind mound. */
                if (detect_container(NULL) <= 0)  {
                        /* We always try to remount directories
                         * read-only first, before we go on and umount
                         * them.
                         *
                         * Mount points can be stacked. If a mount
                         * point is stacked below / or /usr, we
                         * cannot umount or remount it directly,
                         * since there is no way to refer to the
                         * underlying mount. There's nothing we can do
                         * about it for the general case, but we can
                         * do something about it if it is aliased
                         * somehwere else via a bind mount. If we
                         * explicitly remount the super block of that
                         * alias read-only we hence should be
                         * relatively safe regarding keeping the fs we
                         * can otherwise not see dirty. */
                        mount(NULL, m->path, NULL, MS_REMOUNT|MS_RDONLY, NULL);
                }

                /* Skip / and /usr since we cannot unmount that
                 * anyway, since we are running from it. They have
                 * already been remounted ro. */
                if (path_equal(m->path, "/")
#ifndef HAVE_SPLIT_USR
                    || path_equal(m->path, "/usr")
#endif
                )
                        continue;

                /* Trying to umount. We don't force here since we rely
                 * on busy NFS and FUSE file systems to return EBUSY
                 * until we closed everything on top of them. */
                log_info("Unmounting %s.", m->path);
                if (umount2(m->path, 0) == 0) {
                        if (changed)
                                *changed = true;

                        mount_point_free(head, m);
                } else if (log_error) {
                        log_warning("Could not unmount %s: %m", m->path);
                        n_failed++;
                }
        }

        return n_failed;
}

static int swap_points_list_off(MountPoint **head, bool *changed) {
        MountPoint *m, *n;
        int n_failed = 0;

        assert(head);

        LIST_FOREACH_SAFE(mount_point, m, n, *head) {
                log_info("Deactivating swap %s.", m->path);
                if (swapoff(m->path) == 0) {
                        if (changed)
                                *changed = true;

                        mount_point_free(head, m);
                } else {
                        log_warning("Could not deactivate swap %s: %m", m->path);
                        n_failed++;
                }
        }

        return n_failed;
}

int umount_all(bool *changed) {
        int r;
        bool umount_changed;
        LIST_HEAD(MountPoint, mp_list_head);

        LIST_HEAD_INIT(MountPoint, mp_list_head);
        r = mount_points_list_get(&mp_list_head);
        if (r < 0)
                goto end;

        /* retry umount, until nothing can be umounted anymore */
        do {
                umount_changed = false;

                mount_points_list_umount(&mp_list_head, &umount_changed, false);
                if (umount_changed)
                        *changed = true;

        } while (umount_changed);

        /* umount one more time with logging enabled */
        r = mount_points_list_umount(&mp_list_head, &umount_changed, true);
        if (r <= 0)
                goto end;

end:
        mount_points_list_free(&mp_list_head);

        return r;
}

int swapoff_all(bool *changed) {
        int r;
        LIST_HEAD(MountPoint, swap_list_head);

        LIST_HEAD_INIT(MountPoint, swap_list_head);

        r = swap_list_get(&swap_list_head);
        if (r < 0)
                goto end;

        r = swap_points_list_off(&swap_list_head, changed);

  end:
        mount_points_list_free(&swap_list_head);

        return r;
}

/* Calls losetup(8) from util-linux directly.
 * Used to originally employ libudev. */
int loopback_detach_all(void) {
           int r;
           int s;
           sigset_t mask;
           sigfillset(&mask);

           s = sigprocmask(SIG_SETMASK, &mask, NULL);
           if (s < 0)
                 log_error("Setting blocking signal mask failed.");
	   
	       r = system("/sbin/losetup -D");
	       if (r < 0)
	             log_error("Detaching loopback devices with losetup(8) failed.");
	         
	   return r;
}

/* Call dmsetup(8) directly. Originally called libudev. */
int dm_detach_all(void) {
           int r;
           int s;
           sigset_t mask;
           sigfillset(&mask);

           s = sigprocmask(SIG_SETMASK, &mask, NULL);
           if (s < 0)
                 log_error("Setting blocking signal mask failed.");

           r = system("/sbin/dmsetup remove_all");
           if (r < 0)
                  log_error("Detaching DM devices with dmsetup(8) failed.");

           return r;
}
