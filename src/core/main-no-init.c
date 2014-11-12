/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2014 The Initfinder General

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

#include <dbus/dbus.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/mount.h>

#include "manager.h"
#include "log.h"
#include "load-fragment.h"
#include "fdset.h"
#include "special.h"
#include "conf-parser.h"
#include "dbus-common.h"
#include "missing.h"
#include "mkdir.h"
#include "label.h"
#include "build.h"
#include "strv.h"
#include "def.h"
#include "virt.h"
#include "path-util.h"
#include "capability.h"
#include "killall.h"
#include "env-util.h"
#include "hwclock.h"
#include "sd-daemon.h"
#include "sd-messages.h"

#include "mount-setup.h"
#ifdef HAVE_KMOD
#include "kmod-setup.h"
#endif
#include "fileio.h"

static enum {
        ACTION_RUN,
        ACTION_HELP,
        ACTION_VERSION,
        ACTION_TEST,
        ACTION_DUMP_CONFIGURATION_ITEMS,
        ACTION_DONE
} arg_action = ACTION_RUN;

static char *arg_default_unit = NULL;
static SystemdRunningAs arg_running_as = SYSTEMD_SYSTEM;

static bool arg_dump_core = false;
static bool arg_confirm_spawn = false;
static bool arg_show_status = true;
static char ***arg_join_controllers = NULL;
static ExecOutput arg_default_std_output = EXEC_OUTPUT_SYSLOG;
static ExecOutput arg_default_std_error = EXEC_OUTPUT_INHERIT;
static char **arg_default_environment = NULL;
static struct rlimit *arg_default_rlimit[RLIMIT_NLIMITS] = {};
static uint64_t arg_capability_bounding_set_drop = 0;
static nsec_t arg_timer_slack_nsec = (nsec_t) -1;

static FILE* serialization = NULL;

static int set_default_unit(const char *u) {
        char *c;

        assert(u);

        c = strdup(u);
        if (!c)
                return -ENOMEM;

        free(arg_default_unit);
        arg_default_unit = c;

        return 0;
}

#define DEFINE_SETTER(name, func, descr)                              \
        static int name(const char *unit,                             \
                        const char *filename,                         \
                        unsigned line,                                \
                        const char *section,                          \
                        const char *lvalue,                           \
                        int ltype,                                    \
                        const char *rvalue,                           \
                        void *data,                                   \
                        void *userdata) {                             \
                                                                      \
                int r;                                                \
                                                                      \
                assert(filename);                                     \
                assert(lvalue);                                       \
                assert(rvalue);                                       \
                                                                      \
                r = func(rvalue);                                     \
                if (r < 0)                                            \
                        log_syntax(unit, LOG_ERR, filename, line, -r, \
                                   "Invalid " descr "'%s': %s",       \
                                   rvalue, strerror(-r));             \
                                                                      \
                return 0;                                             \
        }

DEFINE_SETTER(config_parse_level2, log_set_max_level_from_string, "log level")
DEFINE_SETTER(config_parse_target, log_set_target_from_string, "target")
DEFINE_SETTER(config_parse_color, log_show_color_from_string, "color" )
DEFINE_SETTER(config_parse_location, log_show_location_from_string, "location")

static int config_parse_cpu_affinity2(const char *unit,
                                      const char *filename,
                                      unsigned line,
                                      const char *section,
                                      const char *lvalue,
                                      int ltype,
                                      const char *rvalue,
                                      void *data,
                                      void *userdata) {

        char *w;
        size_t l;
        char *state;
        cpu_set_t *c = NULL;
        unsigned ncpus = 0;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        FOREACH_WORD_QUOTED(w, l, rvalue, state) {
                char *t;
                int r;
                unsigned cpu;

                if (!(t = strndup(w, l)))
                        return log_oom();

                r = safe_atou(t, &cpu);
                free(t);

                if (!c)
                        if (!(c = cpu_set_malloc(&ncpus)))
                                return log_oom();

                if (r < 0 || cpu >= ncpus) {
                        log_syntax(unit, LOG_ERR, filename, line, -r,
                                   "Failed to parse CPU affinity '%s'", rvalue);
                        CPU_FREE(c);
                        return -EBADMSG;
                }

                CPU_SET_S(cpu, CPU_ALLOC_SIZE(ncpus), c);
        }

        if (c) {
                if (sched_setaffinity(0, CPU_ALLOC_SIZE(ncpus), c) < 0)
                        log_warning_unit(unit, "Failed to set CPU affinity: %m");

                CPU_FREE(c);
        }

        return 0;
}

static void strv_free_free(char ***l) {
        char ***i;

        if (!l)
                return;

        for (i = l; *i; i++)
                strv_free(*i);

        free(l);
}

static void free_join_controllers(void) {
        strv_free_free(arg_join_controllers);
        arg_join_controllers = NULL;
}

static int config_parse_join_controllers(const char *unit,
                                         const char *filename,
                                         unsigned line,
                                         const char *section,
                                         const char *lvalue,
                                         int ltype,
                                         const char *rvalue,
                                         void *data,
                                         void *userdata) {

        unsigned n = 0;
        char *state, *w;
        size_t length;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        free_join_controllers();

        FOREACH_WORD_QUOTED(w, length, rvalue, state) {
                char *s, **l;

                s = strndup(w, length);
                if (!s)
                        return log_oom();

                l = strv_split(s, ",");
                free(s);

                strv_uniq(l);

                if (strv_length(l) <= 1) {
                        strv_free(l);
                        continue;
                }

                if (!arg_join_controllers) {
                        arg_join_controllers = new(char**, 2);
                        if (!arg_join_controllers) {
                                strv_free(l);
                                return log_oom();
                        }

                        arg_join_controllers[0] = l;
                        arg_join_controllers[1] = NULL;

                        n = 1;
                } else {
                        char ***a;
                        char ***t;

                        t = new0(char**, n+2);
                        if (!t) {
                                strv_free(l);
                                return log_oom();
                        }

                        n = 0;

                        for (a = arg_join_controllers; *a; a++) {

                                if (strv_overlap(*a, l)) {
                                        char **c;

                                        c = strv_merge(*a, l);
                                        if (!c) {
                                                strv_free(l);
                                                strv_free_free(t);
                                                return log_oom();
                                        }

                                        strv_free(l);
                                        l = c;
                                } else {
                                        char **c;

                                        c = strv_copy(*a);
                                        if (!c) {
                                                strv_free(l);
                                                strv_free_free(t);
                                                return log_oom();
                                        }

                                        t[n++] = c;
                                }
                        }

                        t[n++] = strv_uniq(l);

                        strv_free_free(arg_join_controllers);
                        arg_join_controllers = t;
                }
        }

        return 0;
}

static int parse_config_file(void) {

        const ConfigTableItem items[] = {
                { "Manager", "LogLevel",              config_parse_level2,       0, NULL                     },
                { "Manager", "LogTarget",             config_parse_target,       0, NULL                     },
                { "Manager", "LogColor",              config_parse_color,        0, NULL                     },
                { "Manager", "LogLocation",           config_parse_location,     0, NULL                     },
                { "Manager", "DumpCore",              config_parse_bool,         0, &arg_dump_core           },
                { "Manager", "ShowStatus",            config_parse_bool,         0, &arg_show_status         },
                { "Manager", "CPUAffinity",           config_parse_cpu_affinity2, 0, NULL                    },
                { "Manager", "DefaultStandardOutput", config_parse_output,       0, &arg_default_std_output  },
                { "Manager", "DefaultStandardError",  config_parse_output,       0, &arg_default_std_error   },
                { "Manager", "JoinControllers",       config_parse_join_controllers, 0, &arg_join_controllers },
                { "Manager", "CapabilityBoundingSet", config_parse_bounding_set, 0, &arg_capability_bounding_set_drop },
                { "Manager", "TimerSlackNSec",        config_parse_nsec,         0, &arg_timer_slack_nsec    },
                { "Manager", "DefaultEnvironment",    config_parse_environ,      0, &arg_default_environment },
                { "Manager", "DefaultLimitCPU",       config_parse_limit,        0, &arg_default_rlimit[RLIMIT_CPU]},
                { "Manager", "DefaultLimitFSIZE",     config_parse_limit,        0, &arg_default_rlimit[RLIMIT_FSIZE]},
                { "Manager", "DefaultLimitDATA",      config_parse_limit,        0, &arg_default_rlimit[RLIMIT_DATA]},
                { "Manager", "DefaultLimitSTACK",     config_parse_limit,        0, &arg_default_rlimit[RLIMIT_STACK]},
                { "Manager", "DefaultLimitCORE",      config_parse_limit,        0, &arg_default_rlimit[RLIMIT_CORE]},
                { "Manager", "DefaultLimitRSS",       config_parse_limit,        0, &arg_default_rlimit[RLIMIT_RSS]},
                { "Manager", "DefaultLimitNOFILE",    config_parse_limit,        0, &arg_default_rlimit[RLIMIT_NOFILE]},
                { "Manager", "DefaultLimitAS",        config_parse_limit,        0, &arg_default_rlimit[RLIMIT_AS]},
                { "Manager", "DefaultLimitNPROC",     config_parse_limit,        0, &arg_default_rlimit[RLIMIT_NPROC]},
                { "Manager", "DefaultLimitMEMLOCK",   config_parse_limit,        0, &arg_default_rlimit[RLIMIT_MEMLOCK]},
                { "Manager", "DefaultLimitLOCKS",     config_parse_limit,        0, &arg_default_rlimit[RLIMIT_LOCKS]},
                { "Manager", "DefaultLimitSIGPENDING",config_parse_limit,        0, &arg_default_rlimit[RLIMIT_SIGPENDING]},
                { "Manager", "DefaultLimitMSGQUEUE",  config_parse_limit,        0, &arg_default_rlimit[RLIMIT_MSGQUEUE]},
                { "Manager", "DefaultLimitNICE",      config_parse_limit,        0, &arg_default_rlimit[RLIMIT_NICE]},
                { "Manager", "DefaultLimitRTPRIO",    config_parse_limit,        0, &arg_default_rlimit[RLIMIT_RTPRIO]},
                { "Manager", "DefaultLimitRTTIME",    config_parse_limit,        0, &arg_default_rlimit[RLIMIT_RTTIME]},
                { NULL, NULL, NULL, 0, NULL }
        };

        _cleanup_fclose_ FILE *f;
        const char *fn;
        int r;

        fn = arg_running_as == SYSTEMD_SYSTEM ? PKGSYSCONFDIR "/system.conf" : PKGSYSCONFDIR "/user.conf";
        f = fopen(fn, "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                log_warning("Failed to open configuration file '%s': %m", fn);
                return 0;
        }

        r = config_parse(NULL, fn, f, "Manager\0", config_item_table_lookup, (void*) items, false, false, NULL);
        if (r < 0)
                log_warning("Failed to parse configuration file: %s", strerror(-r));

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_LOG_LEVEL = 0x100,
                ARG_LOG_TARGET,
                ARG_LOG_COLOR,
                ARG_LOG_LOCATION,
                ARG_UNIT,
                ARG_SYSTEM,
                ARG_TEST,
                ARG_VERSION,
                ARG_DUMP_CONFIGURATION_ITEMS,
                ARG_DUMP_CORE,
                ARG_CONFIRM_SPAWN,
                ARG_SHOW_STATUS,
                ARG_DESERIALIZE,
                ARG_INTROSPECT,
                ARG_DEFAULT_STD_OUTPUT,
                ARG_DEFAULT_STD_ERROR
        };

        static const struct option options[] = {
                { "log-level",                required_argument, NULL, ARG_LOG_LEVEL                },
                { "log-target",               required_argument, NULL, ARG_LOG_TARGET               },
                { "log-color",                optional_argument, NULL, ARG_LOG_COLOR                },
                { "log-location",             optional_argument, NULL, ARG_LOG_LOCATION             },
                { "unit",                     required_argument, NULL, ARG_UNIT                     },
                { "system",                   no_argument,       NULL, ARG_SYSTEM                   },
                { "test",                     no_argument,       NULL, ARG_TEST                     },
                { "help",                     no_argument,       NULL, 'h'                          },
                { "version",                  no_argument,       NULL, ARG_VERSION                  },
                { "dump-configuration-items", no_argument,       NULL, ARG_DUMP_CONFIGURATION_ITEMS },
                { "dump-core",                optional_argument, NULL, ARG_DUMP_CORE                },
                { "confirm-spawn",            optional_argument, NULL, ARG_CONFIRM_SPAWN            },
                { "show-status",              optional_argument, NULL, ARG_SHOW_STATUS              },
                { "deserialize",              required_argument, NULL, ARG_DESERIALIZE              },
                { "introspect",               optional_argument, NULL, ARG_INTROSPECT               },
                { "default-standard-output",  required_argument, NULL, ARG_DEFAULT_STD_OUTPUT,      },
                { "default-standard-error",   required_argument, NULL, ARG_DEFAULT_STD_ERROR,       },
                { NULL,                       0,                 NULL, 0                            }
        };

        int c, r;

        assert(argc >= 1);
        assert(argv);

        if (getpid() == 1)
                opterr = 0;

        while ((c = getopt_long(argc, argv, "hDbsz:", options, NULL)) >= 0)

                switch (c) {

                case ARG_LOG_LEVEL:
                        if ((r = log_set_max_level_from_string(optarg)) < 0) {
                                log_error("Failed to parse log level %s.", optarg);
                                return r;
                        }

                        break;

                case ARG_LOG_TARGET:

                        if ((r = log_set_target_from_string(optarg)) < 0) {
                                log_error("Failed to parse log target %s.", optarg);
                                return r;
                        }

                        break;

                case ARG_LOG_COLOR:

                        if (optarg) {
                                if ((r = log_show_color_from_string(optarg)) < 0) {
                                        log_error("Failed to parse log color setting %s.", optarg);
                                        return r;
                                }
                        } else
                                log_show_color(true);

                        break;

                case ARG_LOG_LOCATION:

                        if (optarg) {
                                if ((r = log_show_location_from_string(optarg)) < 0) {
                                        log_error("Failed to parse log location setting %s.", optarg);
                                        return r;
                                }
                        } else
                                log_show_location(true);

                        break;

                case ARG_DEFAULT_STD_OUTPUT:

                        if ((r = exec_output_from_string(optarg)) < 0) {
                                log_error("Failed to parse default standard output setting %s.", optarg);
                                return r;
                        } else
                                arg_default_std_output = r;
                        break;

                case ARG_DEFAULT_STD_ERROR:

                        if ((r = exec_output_from_string(optarg)) < 0) {
                                log_error("Failed to parse default standard error output setting %s.", optarg);
                                return r;
                        } else
                                arg_default_std_error = r;
                        break;

                case ARG_UNIT:

                        if ((r = set_default_unit(optarg)) < 0) {
                                log_error("Failed to set default unit %s: %s", optarg, strerror(-r));
                                return r;
                        }

                        break;

                case ARG_SYSTEM:
                        arg_running_as = SYSTEMD_SYSTEM;
                        break;

                case ARG_TEST:
                        arg_action = ACTION_TEST;
                        break;

                case ARG_VERSION:
                        arg_action = ACTION_VERSION;
                        break;

                case ARG_DUMP_CONFIGURATION_ITEMS:
                        arg_action = ACTION_DUMP_CONFIGURATION_ITEMS;
                        break;

                case ARG_DUMP_CORE:
                        r = optarg ? parse_boolean(optarg) : 1;
                        if (r < 0) {
                                log_error("Failed to parse dump core boolean %s.", optarg);
                                return r;
                        }
                        arg_dump_core = r;
                        break;

                case ARG_CONFIRM_SPAWN:
                        r = optarg ? parse_boolean(optarg) : 1;
                        if (r < 0) {
                                log_error("Failed to parse confirm spawn boolean %s.", optarg);
                                return r;
                        }
                        arg_confirm_spawn = r;
                        break;

                case ARG_SHOW_STATUS:
                        r = optarg ? parse_boolean(optarg) : 1;
                        if (r < 0) {
                                log_error("Failed to parse show status boolean %s.", optarg);
                                return r;
                        }
                        arg_show_status = r;
                        break;

                case ARG_DESERIALIZE: {
                        int fd;
                        FILE *f;

                        r = safe_atoi(optarg, &fd);
                        if (r < 0 || fd < 0) {
                                log_error("Failed to parse deserialize option %s.", optarg);
                                return r < 0 ? r : -EINVAL;
                        }

                        fd_cloexec(fd, true);

                        f = fdopen(fd, "r");
                        if (!f) {
                                log_error("Failed to open serialization fd: %m");
                                return -errno;
                        }

                        if (serialization)
                                fclose(serialization);

                        serialization = f;

                        break;
                }

                case ARG_INTROSPECT: {
                        const char * const * i = NULL;

                        for (i = bus_interface_table; *i; i += 2)
                                if (!optarg || streq(i[0], optarg)) {
                                        fputs(DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
                                              "<node>\n", stdout);
                                        fputs(i[1], stdout);
                                        fputs("</node>\n", stdout);

                                        if (optarg)
                                                break;
                                }

                        if (!i[0] && optarg)
                                log_error("Unknown interface %s.", optarg);

                        arg_action = ACTION_DONE;
                        break;
                }

                case 'h':
                        arg_action = ACTION_HELP;
                        break;

                case 'D':
                        log_set_max_level(LOG_DEBUG);
                        break;

                case 'b':
                case 's':
                case 'z':
                        /* Just to eat away the sysvinit kernel
                         * cmdline args without getopt() error
                         * messages that we'll parse in
                         * parse_proc_cmdline_word() or ignore. */

                case '?':
                default:
                        if (getpid() != 1) {
                                log_error("Unknown option code %c", c);
                                return -EINVAL;
                        }

                        break;
                }

        if (optind < argc && getpid() != 1) {
                /* Hmm, when we aren't run as init system
                 * let's complain about excess arguments */

                log_error("Excess arguments.");
                return -EINVAL;
        }

        return 0;
}

static int help(void) {

        printf("uselessd [OPTIONS...]\n\n"
               "Starts up and maintains the system or user services.\n\n"
               "  -h --help                      Show this help\n"
               "     --test                      Determine startup sequence, dump it and exit\n"
               "     --dump-configuration-items  Dump understood unit configuration items\n"
               "     --introspect[=INTERFACE]    Extract D-Bus interface data\n"
               "     --unit=UNIT                 Set default unit\n"
               "     --system                    Run a system instance (default and only)\n"
               "     --dump-core[=0|1]           Dump core on crash\n"
               "     --confirm-spawn[=0|1]       Ask for confirmation when spawning processes\n"
               "     --show-status[=0|1]         Show status updates on the console during bootup\n"
               "     --log-target=TARGET         Set log target (console, syslog, kmsg, syslog-or-kmsg, null)\n"
               "     --log-level=LEVEL           Set log level (debug, info, notice, warning, err, crit, alert, emerg)\n"
               "     --log-color[=0|1]           Highlight important log messages\n"
               "     --log-location[=0|1]        Include code location in log messages\n"
               "     --default-standard-output=  Set default standard output for services\n"
               "     --default-standard-error=   Set default standard error output for services\n");

        return 0;
}

static int version(void) {
        puts(PACKAGE_STRING);
        puts(SYSTEMD_FEATURES);

        return 0;
}

static int prepare_reexecute(Manager *m, FILE **_f, FDSet **_fds, bool switching_root) {
        FILE *f = NULL;
        FDSet *fds = NULL;
        int r;

        assert(m);
        assert(_f);
        assert(_fds);

        r = manager_open_serialization(m, &f);
        if (r < 0) {
                log_error("Failed to create serialization file: %s", strerror(-r));
                goto fail;
        }

        /* Make sure nothing is really destructed when we shut down */
        m->n_reloading ++;
        bus_broadcast_reloading(m, true);

        fds = fdset_new();
        if (!fds) {
                r = -ENOMEM;
                log_error("Failed to allocate fd set: %s", strerror(-r));
                goto fail;
        }

        r = manager_serialize(m, f, fds, switching_root);
        if (r < 0) {
                log_error("Failed to serialize state: %s", strerror(-r));
                goto fail;
        }

        if (fseeko(f, 0, SEEK_SET) < 0) {
                log_error("Failed to rewind serialization fd: %m");
                goto fail;
        }

        r = fd_cloexec(fileno(f), false);
        if (r < 0) {
                log_error("Failed to disable O_CLOEXEC for serialization: %s", strerror(-r));
                goto fail;
        }

        r = fdset_cloexec(fds, false);
        if (r < 0) {
                log_error("Failed to disable O_CLOEXEC for serialization fds: %s", strerror(-r));
                goto fail;
        }

        *_f = f;
        *_fds = fds;

        return 0;

fail:
        fdset_free(fds);

        if (f)
                fclose(f);

        return r;
}

static int bump_rlimit_nofile(struct rlimit *saved_rlimit) {
        struct rlimit nl;
        int r;

        assert(saved_rlimit);

        /* Save the original RLIMIT_NOFILE so that we can reset it
         * later when transitioning from the initrd to the main
         * systemd or suchlike. */
        if (getrlimit(RLIMIT_NOFILE, saved_rlimit) < 0) {
                log_error("Reading RLIMIT_NOFILE failed: %m");
                return -errno;
        }

        /* Make sure forked processes get the default kernel setting */
        if (!arg_default_rlimit[RLIMIT_NOFILE]) {
                struct rlimit *rl;

                rl = newdup(struct rlimit, saved_rlimit, 1);
                if (!rl)
                        return log_oom();

                arg_default_rlimit[RLIMIT_NOFILE] = rl;
        }

        /* Bump up the resource limit for ourselves substantially */
        nl.rlim_cur = nl.rlim_max = 64*1024;
        r = setrlimit_closest(RLIMIT_NOFILE, &nl);
        if (r < 0) {
                log_error("Setting RLIMIT_NOFILE failed: %s", strerror(-r));
                return r;
        }

        return 0;
}

static void test_mtab(void) {
        char *p;

        /* Check that /etc/mtab is a symlink */

        if (readlink_malloc("/etc/mtab", &p) >= 0) {
                bool b;

                b = streq(p, "/proc/self/mounts") || streq(p, "/proc/mounts");
                free(p);

                if (b)
                        return;
        }

        log_warning("/etc/mtab is not a symlink or not pointing to /proc/self/mounts. "
                    "This is not supported anymore. "
                    "Please make sure to replace this file by a symlink to avoid incorrect or misleading mount(8) output.");
}

static void test_usr(void) {

        /* Check that /usr is not a separate fs */

        if (dir_is_empty("/usr") <= 0)
                return;

        log_warning("/usr appears to be on its own filesytem and is not already mounted. This is not a supported setup. "
                    "Some things will probably break (sometimes even silently) in mysterious ways. "
                    "Consult http://freedesktop.org/wiki/Software/systemd/separate-usr-is-broken for more information.");
}

static void test_cgroups(void) {

        if (access("/proc/cgroups", F_OK) >= 0)
                return;

        log_warning("CONFIG_CGROUPS was not set when your kernel was compiled. "
                    "Systems without control groups are not supported. "
                    "We will now sleep for 10s, and then continue boot-up. "
                    "Expect breakage and please do not file bugs. "
                    "Instead fix your kernel and enable CONFIG_CGROUPS. "
                    "Consult http://0pointer.de/blog/projects/cgroups-vs-cgroups.html for more information.");

        sleep(10);
}

static int initialize_join_controllers(void) {
        /* By default, mount "cpu" + "cpuacct" together, and "net_cls"
         * + "net_prio". We'd like to add "cpuset" to the mix, but
         * "cpuset" does't really work for groups with no initialized
         * attributes. */

        arg_join_controllers = new(char**, 3);
        if (!arg_join_controllers)
                return -ENOMEM;

        arg_join_controllers[0] = strv_new("cpu", "cpuacct", NULL);
        arg_join_controllers[1] = strv_new("net_cls", "net_prio", NULL);
        arg_join_controllers[2] = NULL;

        if (!arg_join_controllers[0] || !arg_join_controllers[1]) {
                free_join_controllers();
                return -ENOMEM;
        }

        return 0;
}

int main(int argc, char *argv[]) {
        Manager *m = NULL;
        int r, retval = EXIT_FAILURE;
        usec_t before_startup, after_startup;
        char timespan[FORMAT_TIMESPAN_MAX];
        FDSet *fds = NULL;
        bool reexecute = false;
        dual_timestamp initrd_timestamp = { 0ULL, 0ULL };
        dual_timestamp userspace_timestamp = { 0ULL, 0ULL };
        dual_timestamp kernel_timestamp = { 0ULL, 0ULL };
        static char uselessd[] = "uselessd";
        bool skip_setup = false;
        int j;
        bool queue_default_job = false;
        static struct rlimit saved_rlimit_nofile = { 0, 0 };

#ifdef HAVE_SYSV_COMPAT
        if (getpid() != 1 && strstr(program_invocation_short_name, "init")) {
                /* This is compatibility support for SysV, where
                 * calling init as a user is identical to telinit. */

                errno = -ENOENT;
                execv(SYSTEMCTL_BINARY_PATH, argv);
                log_error("Failed to exec " SYSTEMCTL_BINARY_PATH ": %m");
                return 1;
        }
#endif

        log_set_target(LOG_TARGET_CONSOLE);
        log_parse_environment();
        log_open();

        dual_timestamp_from_monotonic(&kernel_timestamp, 0);
        dual_timestamp_get(&userspace_timestamp);

        /* Determine if this is a reexecution or normal bootup. We do
         * the full command line parsing much later, so let's just
         * have a quick peek here. */
        if (strv_find(argv+1, "--deserialize"))
                skip_setup = true;

        /* If we have switched root, do all the special setup
         * things */
        if (strv_find(argv+1, "--switched-root"))
                skip_setup = false;

        /* If we get started via the /sbin/init symlink then we are
           called 'init'. After a subsequent reexecution we are then
           called 'uselessd'. That is confusing, hence let's call us
           uselessd right-away. */
        program_invocation_short_name = uselessd;
        prctl(PR_SET_NAME, uselessd);

        saved_argv = argv;
        saved_argc = argc;

        log_show_color(isatty(STDERR_FILENO) > 0);

        /* Initialize default unit */
        r = set_default_unit(SPECIAL_DEFAULT_TARGET);
        if (r < 0) {
                log_error("Failed to set default unit %s: %s", SPECIAL_DEFAULT_TARGET, strerror(-r));
                goto finish;
        }

        r = initialize_join_controllers();
        if (r < 0)
                goto finish;

        mkdir_label("/run/systemd", 0755);
        mkdir_label("/run/systemd/system", 0755);
        mkdir_label("/run/systemd/inaccessible", 0000);

        if (parse_config_file() < 0)
                goto finish;

        if (parse_argv(argc, argv) < 0)
                goto finish;

        if (arg_running_as == SYSTEMD_SYSTEM &&
            arg_action == ACTION_RUN &&
            running_in_chroot() > 0) {
                log_error("Cannot be run in a chroot() environment.");
                goto finish;
        }

        if (arg_action == ACTION_HELP) {
                retval = help();
                goto finish;
        } else if (arg_action == ACTION_VERSION) {
                retval = version();
                goto finish;
        } else if (arg_action == ACTION_DUMP_CONFIGURATION_ITEMS) {
                unit_dump_config_items(stdout);
                retval = EXIT_SUCCESS;
                goto finish;
        } else if (arg_action == ACTION_DONE) {
                retval = EXIT_SUCCESS;
                goto finish;
        }

        assert_se(arg_action == ACTION_RUN || arg_action == ACTION_TEST);

        /* Remember open file descriptors for later deserialization */
        r = fdset_new_fill(&fds);
        if (r < 0) {
                log_error("Failed to allocate fd set: %s", strerror(-r));
                goto finish;
        } else
                fdset_cloexec(fds, true);

        if (serialization)
                assert_se(fdset_remove(fds, fileno(serialization)) >= 0);

        if (arg_running_as == SYSTEMD_SYSTEM)
                /* Become a session leader if we aren't one yet. */
                setsid();

        /* Move out of the way, so that we won't block unmounts */
        assert_se(chdir("/")  == 0);

        /* Make sure D-Bus doesn't fiddle with the SIGPIPE handlers */
        dbus_connection_set_change_sigpipe(FALSE);

        if (arg_running_as == SYSTEMD_SYSTEM) {
                const char *virtualization = NULL;

                log_info(PACKAGE_STRING " running in system mode. (" SYSTEMD_FEATURES ")");

                detect_virtualization(&virtualization);
                if (virtualization)
                        log_info("Detected virtualization '%s'.", virtualization);

                if (in_initrd())
                        log_info("Running in initial RAM disk.");

        } else
                log_debug(PACKAGE_STRING " running in user mode. (" SYSTEMD_FEATURES ")");

        if (arg_running_as == SYSTEMD_SYSTEM && !skip_setup) {
                if (arg_show_status)
                        status_welcome();

                test_mtab();
                test_usr();
                test_cgroups();
        }

        if (arg_timer_slack_nsec != (nsec_t) -1)
                if (prctl(PR_SET_TIMERSLACK, arg_timer_slack_nsec) < 0)
                        log_error("Failed to adjust timer slack: %m");

        if (arg_capability_bounding_set_drop) {
                r = capability_bounding_set_drop_usermode(arg_capability_bounding_set_drop);
                if (r < 0) {
                        log_error("Failed to drop capability bounding set of usermode helpers: %s", strerror(-r));
                        goto finish;
                }
                r = capability_bounding_set_drop(arg_capability_bounding_set_drop, true);
                if (r < 0) {
                        log_error("Failed to drop capability bounding set: %s", strerror(-r));
                        goto finish;
                }
        }

        if (arg_running_as == SYSTEMD_SYSTEM)
                bump_rlimit_nofile(&saved_rlimit_nofile);

        r = manager_new(arg_running_as, !!serialization, &m);
        if (r < 0) {
                log_error("Failed to allocate manager object: %s", strerror(-r));
                goto finish;
        }

        m->confirm_spawn = arg_confirm_spawn;
        m->default_std_output = arg_default_std_output;
        m->default_std_error = arg_default_std_error;
        m->userspace_timestamp = userspace_timestamp;
        m->kernel_timestamp = kernel_timestamp;
        m->initrd_timestamp = initrd_timestamp;

        manager_set_default_rlimits(m, arg_default_rlimit);

        if (arg_default_environment)
                manager_environment_add(m, arg_default_environment);

        manager_set_show_status(m, arg_show_status);

        /* Remember whether we should queue the default job */
        queue_default_job = !serialization;

        before_startup = now(CLOCK_MONOTONIC);

        r = manager_startup(m, serialization, fds);
        if (r < 0)
                log_error("Failed to fully start up daemon: %s", strerror(-r));

        /* This will close all file descriptors that were opened, but
         * not claimed by any unit. */
        fdset_free(fds);
        fds = NULL;

        if (serialization) {
                fclose(serialization);
                serialization = NULL;
        }

        if (queue_default_job) {
                DBusError error;
                Unit *target = NULL;
                Job *default_unit_job;

                dbus_error_init(&error);

                log_debug("Activating default unit: %s", arg_default_unit);

                r = manager_load_unit(m, arg_default_unit, NULL, &error, &target);
                if (r < 0) {
                        log_error("Failed to load default target: %s", bus_error(&error, r));
                        dbus_error_free(&error);
                } else if (target->load_state == UNIT_ERROR || target->load_state == UNIT_NOT_FOUND)
                        log_error("Failed to load default target: %s", strerror(-target->load_error));
                else if (target->load_state == UNIT_MASKED)
                        log_error("Default target masked.");

                if (!target || target->load_state != UNIT_LOADED) {
                        log_info("Trying to load rescue target...");

                        r = manager_load_unit(m, SPECIAL_RESCUE_TARGET, NULL, &error, &target);
                        if (r < 0) {
                                log_error("Failed to load rescue target: %s", bus_error(&error, r));
                                dbus_error_free(&error);
                                goto finish;
                        } else if (target->load_state == UNIT_ERROR || target->load_state == UNIT_NOT_FOUND) {
                                log_error("Failed to load rescue target: %s", strerror(-target->load_error));
                                goto finish;
                        } else if (target->load_state == UNIT_MASKED) {
                                log_error("Rescue target masked.");
                                goto finish;
                        }
                }

                assert(target->load_state == UNIT_LOADED);

                if (arg_action == ACTION_TEST) {
                        printf("-> By units:\n");
                        manager_dump_units(m, stdout, "\t");
                }

                r = manager_add_job(m, JOB_START, target, JOB_ISOLATE, false, &error, &default_unit_job);
                if (r == -EPERM) {
                        log_debug("Default target could not be isolated, starting instead: %s", bus_error(&error, r));
                        dbus_error_free(&error);

                        r = manager_add_job(m, JOB_START, target, JOB_REPLACE, false, &error, &default_unit_job);
                        if (r < 0) {
                                log_error("Failed to start default target: %s", bus_error(&error, r));
                                dbus_error_free(&error);
                                goto finish;
                        }
                } else if (r < 0) {
                        log_error("Failed to isolate default target: %s", bus_error(&error, r));
                        dbus_error_free(&error);
                        goto finish;
                }

                m->default_unit_job_id = default_unit_job->id;

                after_startup = now(CLOCK_MONOTONIC);
                log_full(arg_action == ACTION_TEST ? LOG_INFO : LOG_DEBUG,
                         "Loaded units and determined initial transaction in %s.",
                         format_timespan(timespan, sizeof(timespan), after_startup - before_startup, 0));

                if (arg_action == ACTION_TEST) {
                        printf("-> By jobs:\n");
                        manager_dump_jobs(m, stdout, "\t");
                        retval = EXIT_SUCCESS;
                        goto finish;
                }
        }

        for (;;) {
                r = manager_loop(m);
                if (r < 0) {
                        log_error("Failed to run mainloop: %s", strerror(-r));
                        goto finish;
                }

                switch (m->exit_code) {

                case MANAGER_EXIT:
                        retval = EXIT_SUCCESS;
                        log_debug("Exit.");
                        goto finish;

                case MANAGER_RELOAD:
                        log_info("Reloading.");
                        r = manager_reload(m);
                        if (r < 0)
                                log_error("Failed to reload: %s", strerror(-r));
                        break;

                case MANAGER_REEXECUTE:

                        if (prepare_reexecute(m, &serialization, &fds, false) < 0)
                                goto finish;

                        reexecute = true;
                        log_notice("Remove uselessd from the premises.");
                        goto finish;

                case MANAGER_SWITCH_ROOT:
                        log_error("Switching root on a no-init instance unsupported. Exiting.");
                        goto finish;

                case MANAGER_REBOOT:
                case MANAGER_POWEROFF:
                case MANAGER_HALT:
                case MANAGER_KEXEC: {
                       log_error("Running stage 3 system command from a no-init instance. Exiting.");
                       goto finish;

                default:
                        assert_not_reached("Unknown exit code.");
                }
        }
	}

finish:
        if (m)
                manager_free(m);

        for (j = 0; j < RLIMIT_NLIMITS; j++)
                free(arg_default_rlimit[j]);

        free(arg_default_unit);
        free_join_controllers();

        dbus_shutdown();
        label_finish();

        if (serialization)
                fclose(serialization);

        if (fds)
                fdset_free(fds);

        return retval;
}
