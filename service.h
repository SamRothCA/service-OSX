//
//  service.h
//  service
//
//  Created by Sam Rothenberg on 6/29/14.
//
//

#ifndef service_service_h
#define service_service_h

#include "config.h"
#include "launch_priv.h"
#include "vproc_priv.h"
#include "vproc_internal.h"
#include "launch_internal.h"

#include <CoreFoundation/CoreFoundation.h>
#include <CoreFoundation/CFPriv.h>
#include <IOKit/IOKitLib.h>
#include <NSSystemDirectories.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>
#include <dirent.h>
#include <libinfo.h>
#include <glob.h>
#include <readline/readline.h>
#include <utmpx.h>
#include <sysexits.h>
#include <util.h>
#include <fnmatch.h>
#include <os/assumes.h>
#include <dlfcn.h>
#if HAVE_SYSTEMSTATS
#include <systemstats/systemstats.h>
#endif

#if HAVE_LIBAUDITD
#include <bsm/auditd_lib.h>
#ifndef	AUDITD_PLIST_FILE
#define	AUDITD_PLIST_FILE "/System/Library/LaunchDaemons/com.apple.auditd.plist"
#endif
#endif

#define LAUNCH_SECDIR _PATH_TMP "launch-XXXXXX"
#define LAUNCH_ENV_KEEPCONTEXT	"LaunchKeepContext"
#define LAUNCH_ENV_BOOTSTRAPPINGSYSTEM "LaunchBootstrappingSystem"

#define CFTypeCheck(cf, type) (CFGetTypeID(cf) == type ## GetTypeID())

#if TARGET_OS_EMBEDDED
#include <sys/kern_memorystatus.h>

#define XPC_PLIST_CACHE "/System/Library/Caches/com.apple.xpcd/xpcd_cache.dylib"
#define XPC_PLIST_CACHE_KEY "LaunchDaemons"

#if JETSAM_PRIORITY_REVISION
#define READ_JETSAM_DEFAULTS 1
#define JETSAM_PROP_DIR "/System/Library/LaunchDaemons"
#define JETSAM_PROP_DIR_LENGTH (sizeof(JETSAM_PROP_DIR) - 1)
#define JETSAM_PROP_PREFIX "com.apple.jetsamproperties."
#define JETSAM_PROP_PREFIX_LENGTH (sizeof(JETSAM_PROP_PREFIX) - 1)
#define JETSAM_PROP_SUFFIX ".plist"
#define JETSAM_PROP_SUFFIX_LENGTH (sizeof(JETSAM_PROP_SUFFIX) - 1)
#endif
#endif

struct load_unload_state {
	launch_data_t pass1;
	char *session_type;
	bool editondisk:1, load:1, forceload:1;
};

void launchctl_log(int level, const char *fmt, ...);
void launchctl_log_CFString(int level, CFStringRef string);
void myCFDictionaryApplyFunction(const void *key, const void *value, void *context);
CFTypeRef CFTypeCreateFromLaunchData(launch_data_t obj);
CFArrayRef CFArrayCreateFromLaunchArray(launch_data_t arr);
CFDictionaryRef CFDictionaryCreateFromLaunchDictionary(launch_data_t dict);
bool launch_data_array_append(launch_data_t a, launch_data_t o);
void insert_event(launch_data_t, const char *, const char *, launch_data_t);
void distill_jobs(launch_data_t);
void distill_config_file(launch_data_t);
void distill_fsevents(launch_data_t);
void sock_dict_cb(launch_data_t what, const char *key, void *context);
void sock_dict_edit_entry(launch_data_t tmp, const char *key, launch_data_t fdarray, launch_data_t thejob);
launch_data_t CF2launch_data(CFTypeRef);
launch_data_t read_plist_file(const char *file, bool editondisk, bool load);
#if TARGET_OS_EMBEDDED
CFPropertyListRef GetPropertyListFromCache(void);
CFPropertyListRef CreateMyPropertyListFromCachedFile(const char *posixfile);
bool require_jobs_from_cache(void);
#endif
CFPropertyListRef CreateMyPropertyListFromFile(const char *);
CFPropertyListRef CFPropertyListCreateFromFile(CFURLRef plistURL);
void WriteMyPropertyListToFile(CFPropertyListRef, const char *);
bool path_goodness_check(const char *path, bool forceload);
void readpath(const char *, struct load_unload_state *);
void readfile(const char *, struct load_unload_state *);
int _fd(int);
int demux_cmd(int argc, char *const argv[]);
void submit_job_pass(launch_data_t jobs);
void do_mgroup_join(int fd, int family, int socktype, int protocol, const char *mgroup);
mach_port_t str2bsport(const char *s);
void print_jobs(launch_data_t j, const char *key, void *context);
void print_obj(launch_data_t obj, const char *key, void *context);
bool str2lim(const char *buf, rlim_t *res);
const char *lim2str(rlim_t val, char *buf);
const char *num2name(int n);
ssize_t name2num(const char *n);
void unloadjob(launch_data_t job);
void print_key_value(launch_data_t obj, const char *key, void *context);
void print_launchd_env(launch_data_t obj, const char *key, void *context);
void loopback_setup_ipv4(void);
void loopback_setup_ipv6(void);
pid_t fwexec(const char *const *argv, int *wstatus);
void do_potential_fsck(void);
bool path_check(const char *path);
bool is_safeboot(void);
bool is_netboot(void);
void apply_sysctls_from_file(const char *thefile);
void empty_dir(const char *thedir, struct stat *psb);
int touch_file(const char *path, mode_t m);
void do_sysversion_sysctl(void);
void do_application_firewall_magic(int sfd, launch_data_t thejob);
void preheat_page_cache_hack(void);
void do_bootroot_magic(void);
void do_single_user_mode(bool);
bool do_single_user_mode2(void);
void do_crash_debug_mode(void);
bool do_crash_debug_mode2(void);
void read_launchd_conf(void);
bool job_disabled_logic(launch_data_t obj);
void fix_bogus_file_metadata(void);
void do_file_init(void) __attribute__((constructor));
void setup_system_context(void);
void handle_system_bootstrapper_crashes_separately(void);
void system_specific_bootstrap(bool sflag);
void fatal_signal_handler(int sig, siginfo_t *si, void *uap);

typedef enum {
	BOOTCACHE_START = 1,
	BOOTCACHE_TAG,
	BOOTCACHE_STOP,
} BootCache_action_t;

void do_BootCache_magic(BootCache_action_t what);

int bootstrap_cmd(int argc, char *const argv[]);
int load_and_unload_cmd(int argc, char *const argv[]);
//static int reload_cmd(int argc, char *const argv[]);
int start_stop_remove_cmd(int argc, char *const argv[]);
int submit_cmd(int argc, char *const argv[]);
int list_cmd(int argc, char *const argv[]);

int setenv_cmd(int argc, char *const argv[]);
int unsetenv_cmd(int argc, char *const argv[]);
int getenv_and_export_cmd(int argc, char *const argv[]);
int wait4debugger_cmd(int argc, char *const argv[]);

int limit_cmd(int argc, char *const argv[]);
int stdio_cmd(int argc, char *const argv[]);
int fyi_cmd(int argc, char *const argv[]);
int logupdate_cmd(int argc, char *const argv[]);
int umask_cmd(int argc, char *const argv[]);
int getrusage_cmd(int argc, char *const argv[]);
int bsexec_cmd(int argc, char *const argv[]);
int _bslist_cmd(mach_port_t bport, unsigned int depth, bool show_job, bool local_only);
int bslist_cmd(int argc, char *const argv[]);
int _bstree_cmd(mach_port_t bsport, unsigned int depth, bool show_jobs);
int bstree_cmd(int argc __attribute__((unused)), char * const argv[] __attribute__((unused)));
int managerpid_cmd(int argc __attribute__((unused)), char * const argv[] __attribute__((unused)));
int manageruid_cmd(int argc __attribute__((unused)), char * const argv[] __attribute__((unused)));
int managername_cmd(int argc __attribute__((unused)), char * const argv[] __attribute__((unused)));
int asuser_cmd(int argc, char * const argv[]);
int exit_cmd(int argc, char *const argv[]) __attribute__((noreturn));
int help_cmd(int argc, char *const argv[]);

#define CMD_COUNT 31
struct cmd_s {
	const char *name;
	int (*func)(int argc, char *const argv[]);
	const char *desc;
} cmds[CMD_COUNT];

bool _launchctl_istty;
bool _launchctl_verbose;
bool _launchctl_is_managed;
bool _launchctl_apple_internal;
bool _launchctl_system_context;
bool _launchctl_uid0_context;
bool _launchctl_system_bootstrap;
bool _launchctl_peruser_bootstrap;
bool _launchctl_verbose_boot;
bool _launchctl_startup_debugging;

bool _launchctl_overrides_db_changed;
CFMutableDictionaryRef _launchctl_overrides_db;

char *_launchctl_job_overrides_db_path;
char *_launchctl_managername;

#if READ_JETSAM_DEFAULTS
CFDictionaryRef _launchctl_jetsam_defaults;
CFDictionaryRef _launchctl_jetsam_defaults_cached;
#endif

#define LIMLOOKUP_COUNT 9
const struct limlookup_s {
	const char *name;
	int lim;
} limlookup[LIMLOOKUP_COUNT];

#endif
