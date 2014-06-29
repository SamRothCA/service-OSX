//
//  commands.c
//  service
//
//  Created by Sam Rothenberg on 6/29/14.
//
//

#include "service.h"

struct cmd_s cmds[CMD_COUNT] = {
	{ "load",			load_and_unload_cmd,	"Load configuration files and/or directories" },
	{ "unload",			load_and_unload_cmd,	"Unload configuration files and/or directories" },
//	{ "reload",			reload_cmd,				"Reload configuration files and/or directories" },
	{ "start",			start_stop_remove_cmd,	"Start specified job" },
	{ "stop",			start_stop_remove_cmd,	"Stop specified job" },
	{ "submit",			submit_cmd,				"Submit a job from the command line" },
	{ "remove",			start_stop_remove_cmd,	"Remove specified job" },
	{ "bootstrap",		bootstrap_cmd,			"Bootstrap launchd" },
	{ "list",			list_cmd,				"List jobs and information about jobs" },
	{ "setenv",			setenv_cmd,				"Set an environmental variable in launchd" },
	{ "unsetenv",		unsetenv_cmd,			"Unset an environmental variable in launchd" },
	{ "getenv",			getenv_and_export_cmd,	"Get an environmental variable from launchd" },
	{ "export",			getenv_and_export_cmd,	"Export shell settings from launchd" },
	{ "debug",			wait4debugger_cmd,		"Set the WaitForDebugger flag for the target job to true." },
	{ "limit",			limit_cmd,				"View and adjust launchd resource limits" },
	{ "stdout",			stdio_cmd,				"Redirect launchd's standard out to the given path" },
	{ "stderr",			stdio_cmd,				"Redirect launchd's standard error to the given path" },
	{ "shutdown",		fyi_cmd,				"Prepare for system shutdown" },
	{ "singleuser",		fyi_cmd,				"Switch to single-user mode" },
	{ "getrusage",		getrusage_cmd,			"Get resource usage statistics from launchd" },
	{ "log",			logupdate_cmd,			"Adjust the logging level or mask of launchd" },
	{ "umask",			umask_cmd,				"Change launchd's umask" },
	{ "bsexec",			bsexec_cmd,				"Execute a process within a different Mach bootstrap subset" },
	{ "bslist",			bslist_cmd,				"List Mach bootstrap services and optional servers" },
	{ "bstree",			bstree_cmd,				"Show the entire Mach bootstrap tree. Requires root privileges." },
	{ "managerpid",		managerpid_cmd,			"Print the PID of the launchd managing this Mach bootstrap." },
	{ "manageruid",		manageruid_cmd,			"Print the UID of the launchd managing this Mach bootstrap." },
	{ "managername",	managername_cmd,		"Print the name of this Mach bootstrap." },
	{ "asuser",			asuser_cmd,				"Execute a subcommand in the given user's context." },
	{ "exit",			exit_cmd,				"Exit the interactive invocation of launchctl" },
	{ "quit",			exit_cmd,				"Quit the interactive invocation of launchctl" },
	{ "help",			help_cmd,				"This help output" },
};

int
unsetenv_cmd(int argc, char *const argv[])
{
	launch_data_t resp, tmp, msg;

	if (argc != 2) {
		launchctl_log(LOG_ERR, "%s usage: unsetenv <key>", getprogname());
		return 1;
	}

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	tmp = launch_data_new_string(argv[1]);
	launch_data_dict_insert(msg, tmp, LAUNCH_KEY_UNSETUSERENVIRONMENT);

	resp = launch_msg(msg);

	launch_data_free(msg);

	if (resp) {
		launch_data_free(resp);
	} else {
		launchctl_log(LOG_ERR, "launch_msg(\"%s\"): %s", LAUNCH_KEY_UNSETUSERENVIRONMENT, strerror(errno));
	}

	return 0;
}

int
setenv_cmd(int argc, char *const argv[])
{
	launch_data_t resp, tmp, tmpv, msg;

	if (argc != 3) {
		launchctl_log(LOG_ERR, "%s usage: setenv <key> <value>", getprogname());
		return 1;
	}

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	tmp = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	tmpv = launch_data_new_string(argv[2]);
	launch_data_dict_insert(tmp, tmpv, argv[1]);
	launch_data_dict_insert(msg, tmp, LAUNCH_KEY_SETUSERENVIRONMENT);

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp) {
		launch_data_free(resp);
	} else {
		launchctl_log(LOG_ERR, "launch_msg(\"%s\"): %s", LAUNCH_KEY_SETUSERENVIRONMENT, strerror(errno));
	}

	return 0;
}

int
getenv_and_export_cmd(int argc, char *const argv[])
{
	launch_data_t resp;
	bool is_csh = false;
	char *k;

	if (!strcmp(argv[0], "export")) {
		char *s = getenv("SHELL");
		if (s) {
			is_csh = strstr(s, "csh") ? true : false;
		}
	} else if (argc != 2) {
		launchctl_log(LOG_ERR, "%s usage: getenv <key>", getprogname());
		return 1;
	}

	k = argv[1];

	if (vproc_swap_complex(NULL, VPROC_GSK_ENVIRONMENT, NULL, &resp) == NULL) {
		if (!strcmp(argv[0], "export")) {
			launch_data_dict_iterate(resp, print_launchd_env, &is_csh);
		} else {
			launch_data_dict_iterate(resp, print_key_value, k);
		}
		launch_data_free(resp);
		return 0;
	} else {
		return 1;
	}

	return 0;
}

int
wait4debugger_cmd(int argc, char * const argv[])
{
	if (argc != 3) {
		launchctl_log(LOG_ERR, "%s usage: debug <label> <value>", argv[0]);
		return 1;
	}

	int result = 1;
	int64_t inval = 0;
	if (strncmp(argv[2], "true", sizeof("true")) == 0) {
		inval = 1;
	} else if (strncmp(argv[2], "false", sizeof("false")) != 0) {
		inval = atoi(argv[2]);
		inval &= 1;
	}

	vproc_t vp = vprocmgr_lookup_vproc(argv[1]);
	if (vp) {
		vproc_err_t verr = vproc_swap_integer(vp, VPROC_GSK_WAITFORDEBUGGER, &inval, NULL);
		if (verr) {
			launchctl_log(LOG_ERR, "Failed to set WaitForDebugger flag on %s.", argv[1]);
		} else {
			result = 0;
		}
		vproc_release(vp);
	}

	return result;
}

int
help_cmd(int argc, char *const argv[])
{
	size_t i, l, cmdwidth = 0;

	int level = LOG_NOTICE;
	if (argc == 0 || argv == NULL) {
		level = LOG_ERR;
	}

	launchctl_log(level, "usage: %s <subcommand>", getprogname());

	for (i = 0; i < (CMD_COUNT); i++) {
		l = strlen(cmds[i].name);
		if (l > cmdwidth) {
			cmdwidth = l;
		}
	}

	for (i = 0; i < (CMD_COUNT); i++) {
		launchctl_log(level, "\t%-*s\t%s", (int)cmdwidth, cmds[i].name, cmds[i].desc);
	}

	return 0;
}

int
exit_cmd(int argc __attribute__((unused)), char *const argv[] __attribute__((unused)))
{
	exit(0);
}

int
bootstrap_cmd(int argc, char *const argv[])
{
	char *session = NULL;
	bool sflag = false;
	int ch;

	while ((ch = getopt(argc, argv, "sS:")) != -1) {
		switch (ch) {
		case 's':
			sflag = true;
			break;
		case 'S':
			session = optarg;
			break;
		case '?':
		default:
			break;
		}
	}

	optind = 1;
	optreset = 1;

	if (!session) {
		launchctl_log(LOG_ERR, "usage: %s bootstrap [-s] -S <session-type>", getprogname());
		return 1;
	}

	if (strcasecmp(session, "System") == 0) {
		_launchctl_system_bootstrap = true;
		system_specific_bootstrap(sflag);
	} else {
		char *load_launchd_items[] = {
			"load", 
			"-S",
			session,
			"-D",
			"all",
			NULL,
			NULL,
			NULL,
		};
		size_t the_argc = 5;

		bool bootstrap_login_items = false;
		if (strcasecmp(session, VPROCMGR_SESSION_AQUA) == 0) {
			bootstrap_login_items = true;
		} else if (strcasecmp(session, VPROCMGR_SESSION_BACKGROUND) == 0
				   || strcasecmp(session, VPROCMGR_SESSION_LOGINWINDOW) == 0) {
			/* If we're bootstrapping either the LoginWindow or Background
			 * sessions, then we only load items from /System and /Library. We
			 * do not attempt to load anything from a user's home directory, as
			 * it might not be available at this time.
			 */
			load_launchd_items[4] = "system";
			if (!is_safeboot()) {
				load_launchd_items[5] = "-D";
				load_launchd_items[6] = "local";
				the_argc += 2;
			}

			if (strcasecmp(session, VPROCMGR_SESSION_BACKGROUND) == 0) {
				/* This is to force a bootstrapped job to inherit its security
				 * session from the launchd that it resides in.
				 */
				_launchctl_peruser_bootstrap = true;
				read_launchd_conf();
			}
		}

		if (is_safeboot()) {
			load_launchd_items[4] = "system";
		}

		int result = load_and_unload_cmd(the_argc, load_launchd_items);
		if (result) {
			syslog(LOG_ERR, "Could not bootstrap session: %s", session);
			return 1;
		}

		/* This will tell launchd to start listening on MachServices again. When
		 * bootstrapping, launchd ignores requests from everyone but the
		 * bootstrapper (us), so this unsets the "weird bootstrap" mode.
		 */
		int64_t junk = 0;
		vproc_err_t verr = vproc_swap_integer(NULL, VPROC_GSK_WEIRD_BOOTSTRAP, &junk, NULL);
		if (!verr) {
#if !TARGET_OS_EMBEDDED
			if (bootstrap_login_items) {
				void *smf = dlopen("/System/Library/Frameworks/ServiceManagement.framework/Versions/A/ServiceManagement", 0);
				if (smf) {
					void (*_SMLoginItemBootstrapItemsFunc)(void) = dlsym(smf, "_SMLoginItemBootstrapItems");
					if (_SMLoginItemBootstrapItemsFunc) {
						_SMLoginItemBootstrapItemsFunc();
					} else {
						launchctl_log(LOG_ERR, "Could not find login item bootstrap function. LoginItems will be unavailable.");
					}
				} else {
					launchctl_log(LOG_ERR, "Failed to open ServiceManagement framework. LoginItems will be unavailable.");
				}
			}
#endif
		} else if (bootstrap_login_items) {
			launchctl_log(LOG_ERR, "Failed to unset weird bootstrap. LoginItems will be unavailable.");
		}
	}

	return 0;
}

int
load_and_unload_cmd(int argc, char *const argv[])
{
	NSSearchPathEnumerationState es = 0;
	char nspath[PATH_MAX * 2]; /* safe side, we need to append */
	bool badopts = false;
	struct load_unload_state lus;
	size_t i;
	int ch;

	memset(&lus, 0, sizeof(lus));

	if (strcmp(argv[0], "load") == 0) {
		lus.load = true;
	}

	while ((ch = getopt(argc, argv, "wFS:D:")) != -1) {
		switch (ch) {
		case 'w':
			lus.editondisk = true;
			break;
		case 'F':
			lus.forceload = true;
			break;
		case 'S':
			lus.session_type = optarg;
			break;
		case 'D':
			if (strcasecmp(optarg, "all") == 0) {
				es |= NSAllDomainsMask;
			} else if (strcasecmp(optarg, "user") == 0) {
				es |= NSUserDomainMask;
			} else if (strcasecmp(optarg, "local") == 0) {
				es |= NSLocalDomainMask;
			} else if (strcasecmp(optarg, "network") == 0) {
				es |= NSNetworkDomainMask;
			} else if (strcasecmp(optarg, "system") == 0) {
				es |= NSSystemDomainMask;
			} else {
				badopts = true;
			}
			break;
		case '?':
		default:
			badopts = true;
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (lus.session_type == NULL) {
		es &= ~NSUserDomainMask;
	}

	if (argc == 0 && es == 0) {
		badopts = true;
	}

	if (badopts) {
		launchctl_log(LOG_ERR, "usage: %s load [-wF] [-D <user|local|network|system|all>] paths...", getprogname());
		return 1;
	}

	int dbfd = -1;
	vproc_err_t verr = vproc_swap_string(NULL, VPROC_GSK_JOB_OVERRIDES_DB, NULL, &_launchctl_job_overrides_db_path);
	if (verr) {
		if (bootstrap_port) {
			launchctl_log(LOG_ERR, "Could not get location of job overrides database: ppid/bootstrap: %d/0x%x", getppid(), bootstrap_port);
		}
	} else {
		dbfd = open(_launchctl_job_overrides_db_path, O_RDONLY | O_EXLOCK | O_CREAT, S_IRUSR | S_IWUSR);
		if (dbfd != -1) {
			_launchctl_overrides_db = (CFMutableDictionaryRef)CreateMyPropertyListFromFile(_launchctl_job_overrides_db_path);
			if (!_launchctl_overrides_db) {
				_launchctl_overrides_db = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
			}
		} else if (errno != EROFS) {
			launchctl_log(LOG_ERR, "Could not open job overrides database at: %s: %d: %s", _launchctl_job_overrides_db_path, errno, strerror(errno));
		}
	}

#if READ_JETSAM_DEFAULTS
	if (!read_jetsam_defaults()) {
		launchctl_log(LOG_NOTICE, "Failed to read jetsam defaults; no process limits applied");	    
	}
#endif  

	/* Only one pass! */
	lus.pass1 = launch_data_alloc(LAUNCH_DATA_ARRAY);

	es = NSStartSearchPathEnumeration(NSLibraryDirectory, es);

	while ((es = NSGetNextSearchPathEnumeration(es, nspath))) {
		if (lus.session_type) {
			strcat(nspath, "/LaunchAgents");
		} else {
			strcat(nspath, "/LaunchDaemons");
		}

		bool should_glob = true;

#if TARGET_OS_EMBEDDED
		if (require_jobs_from_cache()) {
			CFDictionaryRef cache = GetPropertyListFromCache();
			if (cache) {
				CFDictionaryRef launchdJobs = CFDictionaryGetValue(cache, CFSTR(XPC_PLIST_CACHE_KEY));
				if (launchdJobs) {
					CFIndex sz = CFDictionaryGetCount(launchdJobs);

					CFStringRef *keys = malloc(sz * sizeof(CFStringRef));
					CFDictionaryGetKeysAndValues(launchdJobs, (const void**)keys, NULL);

					for (i=0; i < (size_t)sz; i++) {
						char path[PATH_MAX];
						if (CFStringGetCString(keys[i], path, PATH_MAX, kCFStringEncodingUTF8) && (strncmp(path, nspath, strlen(nspath)) == 0)) {
							readpath(path, &lus);
						}
					}
				}
			}

			should_glob = false;
		}
#endif

		if (should_glob) {
			glob_t g;

			if (glob(nspath, GLOB_TILDE|GLOB_NOSORT, NULL, &g) == 0) {
				for (i = 0; i < g.gl_pathc; i++) {
					readpath(g.gl_pathv[i], &lus);
				}
				globfree(&g);
			}
		}
	}

	for (i = 0; i < (size_t)argc; i++) {
		readpath(argv[i], &lus);
	}

	if (launch_data_array_get_count(lus.pass1) == 0) {
		if (!_launchctl_is_managed) {
			launchctl_log(LOG_ERR, "nothing found to %s", lus.load ? "load" : "unload");
		}
		launch_data_free(lus.pass1);
		return _launchctl_is_managed ? 0 : 1;
	}

	if (lus.load) {
		distill_jobs(lus.pass1);
		submit_job_pass(lus.pass1);
	} else {
		for (i = 0; i < launch_data_array_get_count(lus.pass1); i++) {
			unloadjob(launch_data_array_get_index(lus.pass1, i));
		}
	}

	if (_launchctl_overrides_db_changed) {
		WriteMyPropertyListToFile(_launchctl_overrides_db, _launchctl_job_overrides_db_path);
	}

	flock(dbfd, LOCK_UN);
	close(dbfd);
	return 0;
}

int
start_stop_remove_cmd(int argc, char *const argv[])
{
	launch_data_t resp, msg;
	const char *lmsgcmd = LAUNCH_KEY_STOPJOB;
	int e, r = 0;

	if (0 == strcmp(argv[0], "start"))
		lmsgcmd = LAUNCH_KEY_STARTJOB;

	if (0 == strcmp(argv[0], "remove"))
		lmsgcmd = LAUNCH_KEY_REMOVEJOB;

	if (argc != 2) {
		launchctl_log(LOG_ERR, "usage: %s %s <job label>", getprogname(), argv[0]);
		return 1;
	}

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	launch_data_dict_insert(msg, launch_data_new_string(argv[1]), lmsgcmd);

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		launchctl_log(LOG_ERR, "launch_msg(): %s", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
		if ((e = launch_data_get_errno(resp))) {
			launchctl_log(LOG_ERR, "%s %s error: %s", getprogname(), argv[0], strerror(e));
			r = 1;
		}
	} else {
		launchctl_log(LOG_ERR, "%s %s returned unknown response", getprogname(), argv[0]);
		r = 1;
	}

	launch_data_free(resp);
	return r;
}

int
list_cmd(int argc, char *const argv[])
{
	if (_launchctl_is_managed) {
		/* This output is meant for a command line, so don't print anything if
		 * we're managed by launchd.
		 */
		return 1;
	}

	launch_data_t resp, msg = NULL;
	int r = 0;

	bool plist_output = false;
	char *label = NULL;	
	if (argc > 3) {
		launchctl_log(LOG_ERR, "usage: %s list [-x] [label]", getprogname());
		return 1;
	} else if (argc >= 2) {
		plist_output = (strncmp(argv[1], "-x", sizeof("-x")) == 0);
		label = plist_output ? argv[2] : argv[1];
	}

	if (label) {
		msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		launch_data_dict_insert(msg, launch_data_new_string(label), LAUNCH_KEY_GETJOB);

		resp = launch_msg(msg);
		launch_data_free(msg);

		if (resp == NULL) {
			launchctl_log(LOG_ERR, "launch_msg(): %s", strerror(errno));
			r = 1;
		} else if (launch_data_get_type(resp) == LAUNCH_DATA_DICTIONARY) {
			if (plist_output) {
				CFDictionaryRef respDict = CFDictionaryCreateFromLaunchDictionary(resp);
				CFStringRef plistStr = NULL;
				if (respDict) {
					CFDataRef plistData = CFPropertyListCreateXMLData(NULL, (CFPropertyListRef)respDict);
					CFRelease(respDict);
					if (plistData) {
						plistStr = CFStringCreateWithBytes(NULL, CFDataGetBytePtr(plistData), CFDataGetLength(plistData), kCFStringEncodingUTF8, false);
						CFRelease(plistData);
					} else {
						r = 1;
					}
				} else {
					r = 1;
				}

				if (plistStr) {
					launchctl_log_CFString(LOG_NOTICE, plistStr);
					CFRelease(plistStr);
					r = 0;
				}
			} else {
				print_obj(resp, NULL, NULL);
				r = 0;
			}
			launch_data_free(resp);
		} else {
			launchctl_log(LOG_ERR, "%s %s returned unknown response", getprogname(), argv[0]);
			r = 1;
			launch_data_free(resp);
		}
	} else if (vproc_swap_complex(NULL, VPROC_GSK_ALLJOBS, NULL, &resp) == NULL) {
		fprintf(stdout, "PID\tStatus\tLabel\n");
		launch_data_dict_iterate(resp, print_jobs, NULL);
		launch_data_free(resp);

		r = 0;
	}

	return r;
}

int
stdio_cmd(int argc __attribute__((unused)), char *const argv[])
{
	launchctl_log(LOG_ERR, "%s %s: This sub-command no longer does anything", getprogname(), argv[0]);
	return 1;
}

int
fyi_cmd(int argc, char *const argv[])
{
	launch_data_t resp, msg;
	const char *lmsgk = NULL;
	int e, r = 0;

	if (argc != 1) {
		launchctl_log(LOG_ERR, "usage: %s %s", getprogname(), argv[0]);
		return 1;
	}

	if (!strcmp(argv[0], "shutdown")) {
		lmsgk = LAUNCH_KEY_SHUTDOWN;
	} else if (!strcmp(argv[0], "singleuser")) {
		lmsgk = LAUNCH_KEY_SINGLEUSER;
	} else {
		return 1;
	}

	msg = launch_data_new_string(lmsgk);
	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		launchctl_log(LOG_ERR, "launch_msg(): %s", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
		if ((e = launch_data_get_errno(resp))) {
			launchctl_log(LOG_ERR, "%s %s error: %s", getprogname(), argv[0], strerror(e));
			r = 1;
		}
	} else {
		launchctl_log(LOG_ERR, "%s %s returned unknown response", getprogname(), argv[0]);
		r = 1;
	}

	launch_data_free(resp);

	return r;
}

int
logupdate_cmd(int argc, char *const argv[])
{
	int64_t inval, outval;
	bool badargs = false, maskmode = false, onlymode = false, levelmode = false;
	static const struct {
		const char *name;
		int level;
	} logtbl[] = {
		{ "debug",	LOG_DEBUG },
		{ "info",	LOG_INFO },
		{ "notice",	LOG_NOTICE },
		{ "warning",	LOG_WARNING },
		{ "error",	LOG_ERR },
		{ "critical",	LOG_CRIT },
		{ "alert",	LOG_ALERT },
		{ "emergency",	LOG_EMERG },
	};
	size_t i, j, logtblsz = sizeof logtbl / sizeof logtbl[0];
	int m = 0;

	if (argc >= 2) {
		if (!strcmp(argv[1], "mask"))
			maskmode = true;
		else if (!strcmp(argv[1], "only"))
			onlymode = true;
		else if (!strcmp(argv[1], "level"))
			levelmode = true;
		else
			badargs = true;
	}

	if (maskmode)
		m = LOG_UPTO(LOG_DEBUG);

	if (argc > 2 && (maskmode || onlymode)) {
		for (i = 2; i < (size_t)argc; i++) {
			for (j = 0; j < logtblsz; j++) {
				if (!strcmp(argv[i], logtbl[j].name)) {
					if (maskmode)
						m &= ~(LOG_MASK(logtbl[j].level));
					else
						m |= LOG_MASK(logtbl[j].level);
					break;
				}
			}
			if (j == logtblsz) {
				badargs = true;
				break;
			}
		}
	} else if (argc > 2 && levelmode) {
		for (j = 0; j < logtblsz; j++) {
			if (!strcmp(argv[2], logtbl[j].name)) {
				m = LOG_UPTO(logtbl[j].level);
				break;
			}
		}
		if (j == logtblsz)
			badargs = true;
	} else if (argc != 1) {
		badargs = true;
	}

	if (badargs) {
		launchctl_log(LOG_ERR, "usage: %s [[mask loglevels...] | [only loglevels...] [level loglevel]]", getprogname());
		return 1;
	}

	inval = m;

	if (vproc_swap_integer(NULL, VPROC_GSK_GLOBAL_LOG_MASK, argc != 1 ? &inval : NULL, &outval) == NULL) {
		if (argc == 1) {
			for (j = 0; j < logtblsz; j++) {
				if (outval & LOG_MASK(logtbl[j].level)) {
					launchctl_log(LOG_NOTICE, "%s ", logtbl[j].name);
				}
			}
			launchctl_log(LOG_NOTICE, "");
		}
		return 0;
	} else {
		return 1;
	}
}

int
limit_cmd(int argc, char *const argv[])
{
	char slimstr[100];
	char hlimstr[100];
	struct rlimit *lmts = NULL;
	launch_data_t resp, resp1 = NULL, msg, tmp;
	int r = 0;
	size_t i, lsz = -1;
	ssize_t which = 0;
	rlim_t slim = -1, hlim = -1;
	bool badargs = false;

	if (argc > 4)
		badargs = true;

	if (argc >= 3 && str2lim(argv[2], &slim))
		badargs = true;
	else
		hlim = slim;

	if (argc == 4 && str2lim(argv[3], &hlim))
		badargs = true;

	if (argc >= 2 && -1 == (which = name2num(argv[1])))
		badargs = true;

	if (badargs) {
		launchctl_log(LOG_ERR, "usage: %s %s [", getprogname(), argv[0]);
		for (i = 0; i < sizeof limlookup / sizeof limlookup[0]; i++)
			launchctl_log(LOG_ERR, "%s %s", limlookup[i].name, (i + 1) == sizeof limlookup / sizeof limlookup[0] ? "" : "| ");
		launchctl_log(LOG_ERR, "[both | soft hard]]");
		return 1;
	}

	msg = launch_data_new_string(LAUNCH_KEY_GETRESOURCELIMITS);
	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		launchctl_log(LOG_ERR, "launch_msg(): %s", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_OPAQUE) {
		lmts = launch_data_get_opaque(resp);
		lsz = launch_data_get_opaque_size(resp);
		if (argc <= 2) {
			for (i = 0; i < (lsz / sizeof(struct rlimit)); i++) {
				if (argc == 2 && (size_t)which != i)
					continue;
				launchctl_log(LOG_NOTICE, "\t%-12s%-15s%-15s", num2name((int)i),
						lim2str(lmts[i].rlim_cur, slimstr),
						lim2str(lmts[i].rlim_max, hlimstr));
			}
		}
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_STRING) {
		launchctl_log(LOG_ERR, "%s %s error: %s", getprogname(), argv[0], launch_data_get_string(resp));
		r = 1;
	} else {
		launchctl_log(LOG_ERR, "%s %s returned unknown response", getprogname(), argv[0]);
		r = 1;
	}

	if (argc <= 2 || r != 0) {
		launch_data_free(resp);
		return r;
	} else {
		resp1 = resp;
	}

	lmts[which].rlim_cur = slim;
	lmts[which].rlim_max = hlim;

	bool maxfiles_exceeded = false;
	if (strncmp(argv[1], "maxfiles", sizeof("maxfiles")) == 0) {
		if (argc > 2) {
			maxfiles_exceeded = (strncmp(argv[2], "unlimited", sizeof("unlimited")) == 0);
		}

		if (argc > 3) {
			maxfiles_exceeded = (maxfiles_exceeded || strncmp(argv[3], "unlimited", sizeof("unlimited")) == 0);
		}

		if (maxfiles_exceeded) {
			launchctl_log(LOG_ERR, "Neither the hard nor soft limit for \"maxfiles\" can be unlimited. Please use a numeric parameter for both.");
			return 1;
		}
	}

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	tmp = launch_data_new_opaque(lmts, lsz);
	launch_data_dict_insert(msg, tmp, LAUNCH_KEY_SETRESOURCELIMITS);
	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		launchctl_log(LOG_ERR, "launch_msg(): %s", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_STRING) {
		launchctl_log(LOG_ERR, "%s %s error: %s", getprogname(), argv[0], launch_data_get_string(resp));
		r = 1;
	} else if (launch_data_get_type(resp) != LAUNCH_DATA_OPAQUE) {
		launchctl_log(LOG_ERR, "%s %s returned unknown response", getprogname(), argv[0]);
		r = 1;
	}

	launch_data_free(resp);
	launch_data_free(resp1);

	return r;
}

int
umask_cmd(int argc, char *const argv[])
{
	bool badargs = false;
	char *endptr;
	long m = 0;
	int64_t inval, outval;

	if (argc == 2) {
		m = strtol(argv[1], &endptr, 8);
		if (*endptr != '\0' || m > 0777)
			badargs = true;
	}

	if (argc > 2 || badargs) {
		launchctl_log(LOG_ERR, "usage: %s %s <mask>", getprogname(), argv[0]);
		return 1;
	}

	inval = m;

	if (vproc_swap_integer(NULL, VPROC_GSK_GLOBAL_UMASK, argc == 2 ? &inval : NULL, &outval) == NULL) {
		if (argc == 1) {
			launchctl_log(LOG_NOTICE, "%o", (unsigned int)outval);
		}
		return 0;
	} else {
		return 1;
	}
}

int
submit_cmd(int argc, char *const argv[])
{
	launch_data_t msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	launch_data_t job = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	launch_data_t resp, largv = launch_data_alloc(LAUNCH_DATA_ARRAY);
	int ch, i, r = 0;

	launch_data_dict_insert(job, launch_data_new_bool(false), LAUNCH_JOBKEY_ONDEMAND);

	while ((ch = getopt(argc, argv, "l:p:o:e:")) != -1) {
		switch (ch) {
		case 'l':
			launch_data_dict_insert(job, launch_data_new_string(optarg), LAUNCH_JOBKEY_LABEL);
			break;
		case 'p':
			launch_data_dict_insert(job, launch_data_new_string(optarg), LAUNCH_JOBKEY_PROGRAM);
			break;
		case 'o':
			launch_data_dict_insert(job, launch_data_new_string(optarg), LAUNCH_JOBKEY_STANDARDOUTPATH);
			break;
		case 'e':
			launch_data_dict_insert(job, launch_data_new_string(optarg), LAUNCH_JOBKEY_STANDARDERRORPATH);
			break;
		default:
			launchctl_log(LOG_ERR, "usage: %s submit ...", getprogname());
			return 1;
		}
	}
	argc -= optind;
	argv += optind;

	for (i = 0; argv[i]; i++) {
		launch_data_array_append(largv, launch_data_new_string(argv[i]));
	}

	launch_data_dict_insert(job, largv, LAUNCH_JOBKEY_PROGRAMARGUMENTS);

	launch_data_dict_insert(msg, job, LAUNCH_KEY_SUBMITJOB);

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		launchctl_log(LOG_ERR, "launch_msg(): %s", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
		errno = launch_data_get_errno(resp);
		if (errno) {
			launchctl_log(LOG_ERR, "%s %s error: %s", getprogname(), argv[0], strerror(errno));
			r = 1;
		}
	} else {
		launchctl_log(LOG_ERR, "%s %s error: %s", getprogname(), argv[0], "unknown response");
	}

	launch_data_free(resp);

	return r;
}

int
getrusage_cmd(int argc, char *const argv[])
{
	launch_data_t resp, msg;
	bool badargs = false;
	int r = 0;

	if (argc != 2)
		badargs = true;
	else if (strcmp(argv[1], "self") && strcmp(argv[1], "children"))
		badargs = true;

	if (badargs) {
		launchctl_log(LOG_ERR, "usage: %s %s self | children", getprogname(), argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], "self")) {
		msg = launch_data_new_string(LAUNCH_KEY_GETRUSAGESELF);
	} else {
		msg = launch_data_new_string(LAUNCH_KEY_GETRUSAGECHILDREN);
	}

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		launchctl_log(LOG_ERR, "launch_msg(): %s", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
		launchctl_log(LOG_ERR, "%s %s error: %s", getprogname(), argv[0], strerror(launch_data_get_errno(resp)));
		r = 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_OPAQUE) {
		struct rusage *rusage = launch_data_get_opaque(resp);
		launchctl_log(LOG_NOTICE, "\t%-10f\tuser time used",
				(double)rusage->ru_utime.tv_sec + (double)rusage->ru_utime.tv_usec / (double)1000000);
		launchctl_log(LOG_NOTICE, "\t%-10f\tsystem time used",
				(double)rusage->ru_stime.tv_sec + (double)rusage->ru_stime.tv_usec / (double)1000000);
		launchctl_log(LOG_NOTICE, "\t%-10ld\tmax resident set size", rusage->ru_maxrss);
		launchctl_log(LOG_NOTICE, "\t%-10ld\tshared text memory size", rusage->ru_ixrss);
		launchctl_log(LOG_NOTICE, "\t%-10ld\tunshared data size", rusage->ru_idrss);
		launchctl_log(LOG_NOTICE, "\t%-10ld\tunshared stack size", rusage->ru_isrss);
		launchctl_log(LOG_NOTICE, "\t%-10ld\tpage reclaims", rusage->ru_minflt);
		launchctl_log(LOG_NOTICE, "\t%-10ld\tpage faults", rusage->ru_majflt);
		launchctl_log(LOG_NOTICE, "\t%-10ld\tswaps", rusage->ru_nswap);
		launchctl_log(LOG_NOTICE, "\t%-10ld\tblock input operations", rusage->ru_inblock);
		launchctl_log(LOG_NOTICE, "\t%-10ld\tblock output operations", rusage->ru_oublock);
		launchctl_log(LOG_NOTICE, "\t%-10ld\tmessages sent", rusage->ru_msgsnd);
		launchctl_log(LOG_NOTICE, "\t%-10ld\tmessages received", rusage->ru_msgrcv);
		launchctl_log(LOG_NOTICE, "\t%-10ld\tsignals received", rusage->ru_nsignals);
		launchctl_log(LOG_NOTICE, "\t%-10ld\tvoluntary context switches", rusage->ru_nvcsw);
		launchctl_log(LOG_NOTICE, "\t%-10ld\tinvoluntary context switches", rusage->ru_nivcsw);
	} else {
		launchctl_log(LOG_ERR, "%s %s returned unknown response", getprogname(), argv[0]);
		r = 1;
	} 

	launch_data_free(resp);

	return r;
}

int
bslist_cmd(int argc, char *const argv[])
{
	if (_launchctl_is_managed) {
		/* This output is meant for a command line, so don't print anything if
		 * we're managed by launchd.
		 */
		return 1;
	}

	mach_port_t bport = bootstrap_port;
	bool show_jobs = false;
	if (argc > 2 && strcmp(argv[2], "-j") == 0) {
		show_jobs = true;
	}

	if (argc > 1) {
		if (show_jobs) {
			bport = str2bsport(argv[1]);
		} else if (strcmp(argv[1], "-j") == 0) {
			show_jobs = true;
		}
	}

	if (bport == MACH_PORT_NULL) {
		launchctl_log(LOG_ERR, "Invalid bootstrap port");
		return 1;
	}

	return _bslist_cmd(bport, 0, show_jobs, false);
}

int
bstree_cmd(int argc, char * const argv[])
{
	if (_launchctl_is_managed) {
		/* This output is meant for a command line, so don't print anything if
		 * we're managed by launchd.
		 */
		return 1;
	}

	bool show_jobs = false;
	if (geteuid() != 0) {
		launchctl_log(LOG_ERR, "You must be root to perform this operation.");
		return 1;
	} else {
		if (argc == 2 && strcmp(argv[1], "-j") == 0) {
			show_jobs = true;
		}
		fprintf(stdout, "System/\n");
	}

	return _bstree_cmd(str2bsport("/"), 4, show_jobs);
}

int
managerpid_cmd(int argc __attribute__((unused)), char * const argv[] __attribute__((unused)))
{
	int64_t manager_pid = 0;
	vproc_err_t verr = vproc_swap_integer(NULL, VPROC_GSK_MGR_PID, NULL, (int64_t *)&manager_pid);
	if (verr) {
		launchctl_log(LOG_NOTICE, "Unknown job manager!");
		return 1;
	}

	launchctl_log(LOG_NOTICE, "%d", (pid_t)manager_pid);
	return 0;
}

int
manageruid_cmd(int argc __attribute__((unused)), char * const argv[] __attribute__((unused)))
{
	int64_t manager_uid = 0;
	vproc_err_t verr = vproc_swap_integer(NULL, VPROC_GSK_MGR_UID, NULL, (int64_t *)&manager_uid);
	if (verr) {
		launchctl_log(LOG_NOTICE, "Unknown job manager!");
		return 1;
	}

	launchctl_log(LOG_NOTICE, "%lli", manager_uid);
	return 0;
}

int
managername_cmd(int argc __attribute__((unused)), char * const argv[] __attribute__((unused)))
{
	char *manager_name = NULL;
	vproc_err_t verr = vproc_swap_string(NULL, VPROC_GSK_MGR_NAME, NULL, &manager_name);
	if (verr) {
		launchctl_log(LOG_NOTICE, "Unknown job manager!");
		return 1;
	}

	launchctl_log(LOG_NOTICE, "%s", manager_name);
	free(manager_name);

	return 0;
}

int
asuser_cmd(int argc, char * const argv[])
{
	/* This code plays fast and loose with Mach ports. Do NOT use it as any sort
	 * of reference for port handling. Or really anything else in this file.
	 */
	uid_t req_uid = (uid_t)-2;
	if (argc > 2) {
		req_uid = atoi(argv[1]);
		if (req_uid == (uid_t)-2) {
			launchctl_log(LOG_ERR, "You cannot run a command nobody.");
			return 1;
		}
	} else {
		launchctl_log(LOG_ERR, "Usage: launchctl asuser <UID> <command> [arguments...].");
		return 1;
	}

	if (geteuid() != 0) {
		launchctl_log(LOG_ERR, "You must be root to run a command as another user.");
		return 1;
	}

	mach_port_t rbs = MACH_PORT_NULL;
	kern_return_t kr = bootstrap_get_root(bootstrap_port, &rbs);
	if (kr != BOOTSTRAP_SUCCESS) {
		launchctl_log(LOG_ERR, "bootstrap_get_root(): %u", kr);
		return 1;
	}

	mach_port_t bp = MACH_PORT_NULL;
	kr = bootstrap_look_up_per_user(rbs, NULL, req_uid, &bp);
	if (kr != BOOTSTRAP_SUCCESS) {
		launchctl_log(LOG_ERR, "bootstrap_look_up_per_user(): %u", kr);
		return 1;
	}

	bootstrap_port = bp;
	kr = task_set_bootstrap_port(mach_task_self(), bp);
	if (kr != KERN_SUCCESS) {
		launchctl_log(LOG_ERR, "task_set_bootstrap_port(): 0x%x: %s", kr, mach_error_string(kr));
		return 1;
	}

	name_t sockpath;
	sockpath[0] = 0;
	kr = _vprocmgr_getsocket(sockpath);
	if (kr != BOOTSTRAP_SUCCESS) {
		launchctl_log(LOG_ERR, "_vprocmgr_getsocket(): %u", kr);
		return 1;
	}

	setenv(LAUNCHD_SOCKET_ENV, sockpath, 1);
	setenv(LAUNCH_ENV_KEEPCONTEXT, "1", 1);
	if (fwexec((const char *const *)argv + 2, NULL) == -1) {
		launchctl_log(LOG_ERR, "Couldn't spawn command: %s", argv[2]);
		return 1;
	}

	return 0;
}
