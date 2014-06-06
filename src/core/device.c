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

#include <errno.h>
#include <sys/epoll.h>

#include "unit.h"
#include "device.h"
#include "strv.h"
#include "log.h"
#include "unit-name.h"
#include "dbus-device.h"
#include "def.h"
#include "path-util.h"

static const UnitActiveState state_translation_table[_DEVICE_STATE_MAX] = {
        [DEVICE_DEAD] = UNIT_INACTIVE,
        [DEVICE_PLUGGED] = UNIT_ACTIVE
};

static void device_unset_sysfs(Device *d) {
        Device *first;

        assert(d);

        if (!d->sysfs)
                return;

        /* Remove this unit from the chain of devices which share the
         * same sysfs path. */
        first = hashmap_get(UNIT(d)->manager->devices_by_sysfs, d->sysfs);
        LIST_REMOVE(Device, same_sysfs, first, d);

        if (first)
                hashmap_remove_and_replace(UNIT(d)->manager->devices_by_sysfs, d->sysfs, first->sysfs, first);
        else
                hashmap_remove(UNIT(d)->manager->devices_by_sysfs, d->sysfs);

        free(d->sysfs);
        d->sysfs = NULL;
}

static void device_init(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);
        assert(UNIT(d)->load_state == UNIT_STUB);

        /* In contrast to all other unit types we timeout jobs waiting
         * for devices by default. This is because they otherwise wait
         * indefinitely for plugged in devices, something which cannot
         * happen for the other units since their operations time out
         * anyway. */
        UNIT(d)->job_timeout = DEFAULT_TIMEOUT_USEC;

        UNIT(d)->ignore_on_isolate = true;
        UNIT(d)->ignore_on_snapshot = true;
}

static void device_done(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);

        device_unset_sysfs(d);
}

static void device_set_state(Device *d, DeviceState state) {
        DeviceState old_state;
        assert(d);

        old_state = d->state;
        d->state = state;

        if (state != old_state)
                log_debug_unit(UNIT(d)->id,
                               "%s changed %s -> %s", UNIT(d)->id,
                               device_state_to_string(old_state),
                               device_state_to_string(state));

        unit_notify(UNIT(d), state_translation_table[old_state], state_translation_table[state], true);
}

static int device_coldplug(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);
        assert(d->state == DEVICE_DEAD);

        if (d->sysfs)
                device_set_state(d, DEVICE_PLUGGED);

        return 0;
}

static void device_dump(Unit *u, FILE *f, const char *prefix) {
        Device *d = DEVICE(u);

        assert(d);

        fprintf(f,
                "%sDevice State: %s\n"
                "%sSysfs Path: %s\n",
                prefix, device_state_to_string(d->state),
                prefix, strna(d->sysfs));
}

_pure_ static UnitActiveState device_active_state(Unit *u) {
        assert(u);

        return state_translation_table[DEVICE(u)->state];
}

_pure_ static const char *device_sub_state_to_string(Unit *u) {
        assert(u);

        return device_state_to_string(DEVICE(u)->state);
}

static int device_add_escaped_name(Unit *u, const char *dn) {
        char *e;
        int r;

        assert(u);
        assert(dn);
        assert(dn[0] == '/');

        e = unit_name_from_path(dn, ".device");
        if (!e)
                return -ENOMEM;

        r = unit_add_name(u, e);
        free(e);

        if (r < 0 && r != -EEXIST)
                return r;

        return 0;
}

static int device_find_escape_name(Manager *m, const char *dn, Unit **_u) {
        char *e;
        Unit *u;

        assert(m);
        assert(dn);
        assert(dn[0] == '/');
        assert(_u);

        e = unit_name_from_path(dn, ".device");
        if (!e)
                return -ENOMEM;

        u = manager_get_unit(m, e);
        free(e);

        if (u) {
                *_u = u;
                return 1;
        }

        return 0;
}

static Unit *device_following(Unit *u) {
        Device *d = DEVICE(u);
        Device *other, *first = NULL;

        assert(d);

        if (startswith(u->id, "sys-"))
                return NULL;

        /* Make everybody follow the unit that's named after the sysfs path */
        for (other = d->same_sysfs_next; other; other = other->same_sysfs_next)
                if (startswith(UNIT(other)->id, "sys-"))
                        return UNIT(other);

        for (other = d->same_sysfs_prev; other; other = other->same_sysfs_prev) {
                if (startswith(UNIT(other)->id, "sys-"))
                        return UNIT(other);

                first = other;
        }

        return UNIT(first);
}

static int device_following_set(Unit *u, Set **_s) {
        Device *d = DEVICE(u);
        Device *other;
        Set *s;
        int r;

        assert(d);
        assert(_s);

        if (!d->same_sysfs_prev && !d->same_sysfs_next) {
                *_s = NULL;
                return 0;
        }

        if (!(s = set_new(NULL, NULL)))
                return -ENOMEM;

        for (other = d->same_sysfs_next; other; other = other->same_sysfs_next)
                if ((r = set_put(s, other)) < 0)
                        goto fail;

        for (other = d->same_sysfs_prev; other; other = other->same_sysfs_prev)
                if ((r = set_put(s, other)) < 0)
                        goto fail;

        *_s = s;
        return 1;

fail:
        set_free(s);
        return r;
}

static const char* const device_state_table[_DEVICE_STATE_MAX] = {
        [DEVICE_DEAD] = "dead",
        [DEVICE_PLUGGED] = "plugged"
};

DEFINE_STRING_TABLE_LOOKUP(device_state, DeviceState);

const UnitVTable device_vtable = {
        .object_size = sizeof(Device),
        .sections =
                "Unit\0"
                "Device\0"
                "Install\0",

        .no_instances = true,

        .init = device_init,

        .load = unit_load_fragment_and_dropin_optional,
        .done = device_done,
        .coldplug = device_coldplug,

        .dump = device_dump,

        .active_state = device_active_state,
        .sub_state_to_string = device_sub_state_to_string,

        .bus_interface = "org.freedesktop.systemd1.Device",
        .bus_message_handler = bus_device_message_handler,
        .bus_invalidating_properties =  bus_device_invalidating_properties,

        .following = device_following,
        .following_set = device_following_set,

        .status_message_formats = {
                .starting_stopping = {
                        [0] = "Expecting device %s...",
                },
                .finished_start_job = {
                        [JOB_DONE]       = "Found device %s.",
                        [JOB_TIMEOUT]    = "Timed out waiting for device %s.",
                },
        },
};
