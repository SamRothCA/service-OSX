/*
 * Copyright (c) 2005-2011 Apple Inc. All rights reserved.
 *
 * @APPLE_APACHE_LICENSE_HEADER_START@
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * @APPLE_APACHE_LICENSE_HEADER_END@
 */

#include "service.h"

bool _launchctl_verbose_boot = false;
bool _launchctl_startup_debugging = false;

bool _launchctl_overrides_db_changed = false;
CFMutableDictionaryRef _launchctl_overrides_db = NULL;

char *_launchctl_managername = NULL;

#if READ_JETSAM_DEFAULTS
CFDictionaryRef _launchctl_jetsam_defaults = NULL;
CFDictionaryRef _launchctl_jetsam_defaults_cached = NULL;
#endif

const struct limlookup_s limlookup[LIMLOOKUP_COUNT] = {
	{ "cpu",	RLIMIT_CPU },
	{ "filesize",	RLIMIT_FSIZE },
	{ "data",	RLIMIT_DATA },
	{ "stack",	RLIMIT_STACK },
	{ "core",	RLIMIT_CORE },
	{ "rss", 	RLIMIT_RSS },
	{ "memlock",	RLIMIT_MEMLOCK },
	{ "maxproc",	RLIMIT_NPROC },
	{ "maxfiles",	RLIMIT_NOFILE }
};

int
main(int argc, char *const argv[])
{
	char *l;

	if (getenv(LAUNCH_ENV_BOOTSTRAPPINGSYSTEM)) {
		/* We're bootstrapping the install environment, so we can't talk to
		 * mDNSResponder or opendirectoryd.
		 *
		 * See <rdar://problem/9877230>.
		 */
		si_search_module_set_flags("mdns", 1);
		si_search_module_set_flags("ds", 1);
	}

	int64_t is_managed = 0;
	(void)vproc_swap_integer(NULL, VPROC_GSK_IS_MANAGED, NULL, &is_managed);
	_launchctl_is_managed = is_managed;

	_launchctl_istty = isatty(STDIN_FILENO);
	argc--, argv++;

	if (argc > 0 && argv[0][0] == '-') {
		char *flago;

		for (flago = argv[0] + 1; *flago; flago++) {
			switch (*flago) {
			case 'v':
				_launchctl_verbose = true;
				break;
			case 'u':
				if (argc > 1) {
					if (strncmp(argv[1], "root", sizeof("root")) == 0) {
						_launchctl_uid0_context = true;
					} else {
						launchctl_log(LOG_ERR, "Unknown user: %s", argv[1]);
						exit(EXIT_FAILURE);
					}
					argc--, argv++;
				} else {
					launchctl_log(LOG_ERR, "-u option requires an argument.");
				}
				break;
			case '1':
				_launchctl_system_context = true;
				break;
			default:
				launchctl_log(LOG_ERR, "Unknown argument: '-%c'", *flago);
				break;
			}
		}
		argc--, argv++;
	}

	/* Running in the context of the root user's per-user launchd is only from
	 * within that session.
	 */
	if (_launchctl_uid0_context) {
		int64_t manager_uid = -1, manager_pid = -1;
		(void)vproc_swap_integer(NULL, VPROC_GSK_MGR_UID, NULL, &manager_uid);
		(void)vproc_swap_integer(NULL, VPROC_GSK_MGR_PID, NULL, &manager_pid);
		if (manager_uid || manager_pid == 1) {
			launchctl_log(LOG_ERR, "Running in the root user's per-user context is not supported outside of the root user's bootstrap.");
			exit(EXIT_FAILURE);
		}
	} else if (!(_launchctl_system_context || _launchctl_uid0_context)) {
		/* Running in the system context is implied when we're running as root
		 * and not running as a bootstrapper.
		 */
		_launchctl_system_context = (!_launchctl_is_managed && getuid() == 0);
	}

	if (_launchctl_system_context) {
		if (getuid() == 0) {
			setup_system_context();
		} else {
			launchctl_log(LOG_ERR, "You must be root to run in the system context.");
			exit(EXIT_FAILURE);
		}
	} else if (_launchctl_uid0_context) {
		if (getuid() != 0) {
			launchctl_log(LOG_ERR, "You must be root to run in the root user context.");
			exit(EXIT_FAILURE);
		}
	}

	if (!readline) {
		launchctl_log(LOG_ERR, "missing library: readline");
		exit(EXIT_FAILURE);
	}

	if (argc == 0) {
		while ((l = readline(_launchctl_istty ? "launchd% " : NULL))) {
			char *inputstring = l, *argv2[100], **ap = argv2;
			int i = 0;

			while ((*ap = strsep(&inputstring, " \t"))) {
				if (**ap != '\0') {
					ap++;
					i++;
				}
			}

			if (i > 0) {
				demux_cmd(i, argv2);
			}

			free(l);
		}

		if (_launchctl_istty) {
			fputc('\n', stdout);
		}
	}

	if (argc > 0) {
		exit(demux_cmd(argc, argv));
	}

	exit(EXIT_SUCCESS);
}

int
demux_cmd(int argc, char *const argv[])
{
	size_t i;

	optind = 1;
	optreset = 1;

	for (i = 0; i < (CMD_COUNT); i++) {
		if (!strcmp(cmds[i].name, argv[0])) {
			return cmds[i].func(argc, argv);
		}
	}

	launchctl_log(LOG_ERR, "%s: unknown subcommand \"%s\"", getprogname(), argv[0]);
	return 1;
}

void
launchctl_log(int level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (_launchctl_is_managed) {
		vsyslog(level, fmt, ap);
	} else {
		char *buff = NULL;
		(void)vasprintf(&buff, fmt, ap);

		FILE *where = stdout;
		if (level < LOG_NOTICE) {
			where = stderr;
		}

		fprintf(where, "%s\n", buff);
		free(buff);
	}

	va_end(ap);
}

void
launchctl_log_CFString(int level, CFStringRef string)
{
	// Big enough. Don't feel like jumping through CF's hoops.
	char *buff = malloc(4096);
	(void)CFStringGetCString(string, buff, 4096, kCFStringEncodingUTF8);
	launchctl_log(level, "%s", buff);
	free(buff);
}

void
read_launchd_conf(void)
{
#if !TARGET_OS_EMBEDDED
	char s[1000], *c, *av[100];
	const char *file;
	size_t len;
	int i;
	FILE *f;

	if (getppid() == 1) {
		file = "/etc/launchd.conf";
	} else {
		file = "/etc/launchd-user.conf";
	}

	if (!(f = fopen(file, "r"))) {
		return;
	}

	while ((c = fgets(s, (int) sizeof s, f))) {
		len = strlen(c);
		if (len && c[len - 1] == '\n') {
			c[len - 1] = '\0';
		}

		i = 0;

		while ((av[i] = strsep(&c, " \t"))) {
			if (*(av[i]) != '\0') {
				i++;
			}
		}

		if (i > 0) {
			demux_cmd(i, av);
		}
	}

	fclose(f);
#endif // !TARGET_OS_EMBEDDED
}

CFPropertyListRef
CFPropertyListCreateFromFile(CFURLRef plistURL)
{	
	CFReadStreamRef plistReadStream = CFReadStreamCreateWithFile(NULL, plistURL);

	CFErrorRef streamErr = NULL;
	if (!CFReadStreamOpen(plistReadStream)) {
		streamErr = CFReadStreamCopyError(plistReadStream);
		CFStringRef errString = CFErrorCopyDescription(streamErr);

		launchctl_log_CFString(LOG_ERR, errString);

		CFRelease(errString);
		CFRelease(streamErr);
	}

	CFPropertyListRef plist = NULL;
	if (plistReadStream) {
		CFStringRef errString = NULL;
		CFPropertyListFormat plistFormat = 0;
		plist = CFPropertyListCreateFromStream(NULL, plistReadStream, 0, kCFPropertyListImmutable, &plistFormat, &errString);
		if (!plist) {
			launchctl_log_CFString(LOG_ERR, errString);
			CFRelease(errString);
		}
	}

	CFReadStreamClose(plistReadStream);
	CFRelease(plistReadStream);

	return plist;
}

void
print_launchd_env(launch_data_t obj, const char *key, void *context)
{
	bool *is_csh = context;

	/* XXX escape the double quotes */
	if (*is_csh) {
		launchctl_log(LOG_NOTICE, "setenv %s \"%s\";", key, launch_data_get_string(obj));
	} else {
		launchctl_log(LOG_NOTICE, "%s=\"%s\"; export %s;", key, launch_data_get_string(obj), key);
	}
}

void
print_key_value(launch_data_t obj, const char *key, void *context)
{
	const char *k = context;

	if (!strcmp(key, k)) {
		launchctl_log(LOG_NOTICE, "%s", launch_data_get_string(obj));
	}
}

void
unloadjob(launch_data_t job)
{
	launch_data_t tmps;

	tmps = launch_data_dict_lookup(job, LAUNCH_JOBKEY_LABEL);

	if (!tmps) {
		launchctl_log(LOG_ERR, "%s: Error: Missing Key: %s", getprogname(), LAUNCH_JOBKEY_LABEL);
		return;
	}

	if (_vproc_send_signal_by_label(launch_data_get_string(tmps), VPROC_MAGIC_UNLOAD_SIGNAL) != NULL) {
		launchctl_log(LOG_ERR, "%s: Error unloading: %s", getprogname(), launch_data_get_string(tmps));
	}
}

#if READ_JETSAM_DEFAULTS

CFDictionaryRef
read_jetsam_defaults_from_cache(void) {
	CFPropertyListRef cache = GetPropertyListFromCache();
	CFPropertyListRef defaults = NULL;
	const void **keys = 0;
	CFIndex count, i;

	if (!cache) {
		return NULL;
	}
        
	CFPropertyListRef cachefiles = CFDictionaryGetValue(cache, CFSTR(XPC_PLIST_CACHE_KEY));
	if (!cachefiles) {
		return NULL;
	}

	count = CFDictionaryGetCount(cachefiles);
	keys = (const void **)malloc(sizeof(void *) * count);
	if (!keys) {
		return NULL;
	}
        
	CFDictionaryGetKeysAndValues(cachefiles, keys, NULL);
	for (i = 0; i < count; i++) {
		CFStringRef key = (CFStringRef)keys[i];
		CFIndex key_length = CFStringGetLength(key);

		if (key_length <= (CFIndex)(JETSAM_PROP_DIR_LENGTH + JETSAM_PROP_PREFIX_LENGTH + JETSAM_PROP_SUFFIX_LENGTH + 1)) {
			continue;
		}

		if (CFStringCompareWithOptions(key, CFSTR(JETSAM_PROP_DIR "/" JETSAM_PROP_PREFIX), 
			CFRangeMake(0, JETSAM_PROP_DIR_LENGTH + JETSAM_PROP_PREFIX_LENGTH + 1), 0)) {
			continue;
		}
	
		if (CFStringCompareWithOptions(key, CFSTR(JETSAM_PROP_SUFFIX), 
			CFRangeMake(key_length - JETSAM_PROP_SUFFIX_LENGTH, JETSAM_PROP_SUFFIX_LENGTH), 0)) {
			continue;
		}

		defaults = CFDictionaryGetValue(cachefiles, key);
		break;
	}

	free(keys);

	return defaults;
}

CFDictionaryRef
read_jetsam_defaults_from_file(void) {
	DIR *dirp;
	struct dirent *dp;
	CFDictionaryRef defaults = NULL;

	dirp = opendir(JETSAM_PROP_DIR);
	while ((dp = readdir(dirp)) != NULL) {
		char *fullpath;
    
		if (dp->d_namlen <= (JETSAM_PROP_PREFIX_LENGTH + JETSAM_PROP_SUFFIX_LENGTH)) {
			continue;
		}
	
		if (strncmp(dp->d_name, JETSAM_PROP_PREFIX, JETSAM_PROP_PREFIX_LENGTH)) {
			continue;
		}
	
		if (strncmp(dp->d_name + dp->d_namlen - JETSAM_PROP_SUFFIX_LENGTH, JETSAM_PROP_SUFFIX, JETSAM_PROP_SUFFIX_LENGTH)) {
			continue;
		}
	
		if (-1 != asprintf(&fullpath, "%s/%s", JETSAM_PROP_DIR, dp->d_name)) {
			defaults = (CFDictionaryRef)CreateMyPropertyListFromFile(fullpath);
			free(fullpath);
		}

		break;
	}

	if (dirp) {
		closedir(dirp);
	}
        
	return defaults;    
}

bool
submit_cached_defaults(void) {
	launch_data_t msg, resp;
	const void **keys = NULL;
	int i;
    
	if (_launchctl_jetsam_defaults_cached == NULL) {
        return false;
	}

	/* The dictionary to transmit */
	CFMutableDictionaryRef payload_dict = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    
	/* Add a key to indicate that this is a special job */
	CFBooleanRef ID = kCFBooleanTrue;
	CFDictionaryAddValue(payload_dict, CFSTR(LAUNCH_JOBKEY_DEFAULTS), ID);
  
 	CFMutableDictionaryRef defaults_dict = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	
	CFDictionaryAddValue(payload_dict, CFSTR(LAUNCHD_JOB_DEFAULTS), defaults_dict);
    
	/* Compile appropriate launchd dictionary... */
	CFIndex count = CFDictionaryGetCount(_launchctl_jetsam_defaults_cached);
	keys = (const void **)malloc(sizeof(void *) * count);
	if (!keys) {
		goto exit;
	}
    
	CFDictionaryGetKeysAndValues(_launchctl_jetsam_defaults_cached, keys, NULL);
    
	for (i = 0; i < count; i++) {
		CFStringRef label = (CFStringRef)keys[i];
        
		/* Get the defaults for the job */
		CFDictionaryRef job_defaults_dict = CFDictionaryGetValue(_launchctl_jetsam_defaults_cached, label);
		if (!(job_defaults_dict && CFTypeCheck(job_defaults_dict, CFDictionary))) {
			continue;
		}
        
		/* Create a new dictionary to represent the job */
		CFMutableDictionaryRef job_dict = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		
		/* Add the defaults */
		CFDictionaryAddValue(job_dict, CFSTR(LAUNCH_JOBKEY_JETSAMPROPERTIES), job_defaults_dict);
        
		/* Finally, add the result to the main dictionary */
		CFDictionaryAddValue(defaults_dict, label, job_dict);
        
		/* Cleanup */
		CFRelease(job_dict);
	}
    
	/* Send the payload */
	launch_data_t ldp = CF2launch_data(payload_dict);
    
	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	launch_data_dict_insert(msg, ldp, LAUNCH_KEY_SUBMITJOB);

	resp = launch_msg(msg);
	launch_data_free(msg);   

	launch_data_free(resp);

exit:
	CFRelease(defaults_dict);
	CFRelease(payload_dict);
    	
	free(keys);

	return true;
}

boolean_t
read_jetsam_defaults(void)
{
	/* Current supported version */
	const int v = 3;
    
	CFDictionaryRef jetsam_defaults = NULL;
    
	if (require_jobs_from_cache()) {
		jetsam_defaults = read_jetsam_defaults_from_cache();
	} else {
		jetsam_defaults = read_jetsam_defaults_from_file();
	}

	if (NULL == jetsam_defaults) {
		launchctl_log(LOG_NOTICE, "%s: no jetsam property file found", getprogname());
		return false;
	}

	/* Validate the version */
	CFNumberRef defaults_vers = CFDictionaryGetValue(jetsam_defaults, CFSTR("Version"));
	if (!(defaults_vers && CFTypeCheck(defaults_vers, CFNumber))) {
		return false;
	}
	
	CFNumberRef supported_vers = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &v);
	if (!(kCFCompareEqualTo == CFNumberCompare(defaults_vers, supported_vers, NULL ))) {
		return false;
	}

	/* These defaults are merged within launchctl prior to submitting the job */
	_launchctl_jetsam_defaults = CFDictionaryGetValue(jetsam_defaults, CFSTR(LAUNCHD_JOB_DEFAULTS));
	if (!(_launchctl_jetsam_defaults && CFTypeCheck(_launchctl_jetsam_defaults, CFDictionary))) {
		_launchctl_jetsam_defaults = NULL;
		return false;
	}

	/* Cached defaults (applied by launchd) - parse and submit immediately as a fake job */
	_launchctl_jetsam_defaults_cached = CFDictionaryGetValue(jetsam_defaults, CFSTR(LAUNCHD_JOB_DEFAULTS_CACHED));
	if (!(_launchctl_jetsam_defaults_cached && CFTypeCheck(_launchctl_jetsam_defaults_cached, CFDictionary))) {
		_launchctl_jetsam_defaults_cached = NULL;
		return false;
	}

	submit_cached_defaults();
	
	return true;
}

#endif /* READ_JETSAM_DEFAULTS */

launch_data_t
read_plist_file(const char *file, bool editondisk, bool load)
{
	CFPropertyListRef plist;
	launch_data_t r = NULL;
#if TARGET_OS_EMBEDDED
	if (require_jobs_from_cache()) {
		plist = CreateMyPropertyListFromCachedFile(file);
	} else {
		plist = CreateMyPropertyListFromFile(file);
	}
#else
	plist = CreateMyPropertyListFromFile(file);
#endif

	if (NULL == plist) {
		launchctl_log(LOG_ERR, "%s: no plist was returned for: %s", getprogname(), file);
		return NULL;
	}

	CFStringRef label = CFDictionaryGetValue(plist, CFSTR(LAUNCH_JOBKEY_LABEL));
	if (!(label && CFTypeCheck(label, CFString))) {
		return NULL;
	}

	if (_launchctl_overrides_db) {
		CFDictionaryRef overrides = CFDictionaryGetValue(_launchctl_overrides_db, label);
		if (overrides && CFTypeCheck(overrides, CFDictionary)) {
			CFBooleanRef disabled = CFDictionaryGetValue(overrides, CFSTR(LAUNCH_JOBKEY_DISABLED));
			if (disabled && CFTypeCheck(disabled, CFBoolean)) {
				CFDictionarySetValue((CFMutableDictionaryRef)plist, CFSTR(LAUNCH_JOBKEY_DISABLED), disabled);
			}
		}
	}

	if (editondisk) {
		if (_launchctl_overrides_db) {
			CFMutableDictionaryRef job = (CFMutableDictionaryRef)CFDictionaryGetValue(_launchctl_overrides_db, label);
			if (!job || !CFTypeCheck(job, CFDictionary)) {
				job = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
				CFDictionarySetValue(_launchctl_overrides_db, label, job);
				CFRelease(job);
			}

			CFDictionarySetValue(job, CFSTR(LAUNCH_JOBKEY_DISABLED), load ? kCFBooleanFalse : kCFBooleanTrue);
			CFDictionarySetValue((CFMutableDictionaryRef)plist, CFSTR(LAUNCH_JOBKEY_DISABLED), load ? kCFBooleanFalse : kCFBooleanTrue);
			_launchctl_overrides_db_changed = true;
		} else {
			if (load) {
				CFDictionaryRemoveValue((CFMutableDictionaryRef)plist, CFSTR(LAUNCH_JOBKEY_DISABLED));
			} else {
				CFDictionarySetValue((CFMutableDictionaryRef)plist, CFSTR(LAUNCH_JOBKEY_DISABLED), kCFBooleanTrue);
			}
			WriteMyPropertyListToFile(plist, file);
		}
	}

#if READ_JETSAM_DEFAULTS
	if (_launchctl_jetsam_defaults) {
		CFDictionaryRef job_defaults_dict = CFDictionaryGetValue(_launchctl_jetsam_defaults, label);
		if (job_defaults_dict) {
			CFDictionarySetValue((CFMutableDictionaryRef)plist, CFSTR(LAUNCH_JOBKEY_JETSAMPROPERTIES), job_defaults_dict);
		}
	} else {
		/* The plist is missing. Set a default memory limit, since the device will be otherwise unusable */
		long default_limit = 0;
		CFMutableDictionaryRef job_defaults_dict = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		CFNumberRef memory_limit = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongType, &default_limit);
		if (memory_limit) {
			CFDictionaryAddValue(job_defaults_dict, CFSTR(LAUNCH_JOBKEY_JETSAMMEMORYLIMIT), memory_limit);
			CFRelease(memory_limit);
		}
		CFDictionarySetValue((CFMutableDictionaryRef)plist, CFSTR(LAUNCH_JOBKEY_JETSAMPROPERTIES), job_defaults_dict);
		CFRelease(job_defaults_dict);
	}
#endif /* READ_JETSAM_DEFAULTS */

	r = CF2launch_data(plist);

	CFRelease(plist);

	return r;
}

bool
sysctl_hw_streq(int mib_slot, const char *str)
{
	char buf[1000];
	size_t bufsz = sizeof(buf);
	int mib[] = { CTL_HW, mib_slot };

	if (sysctl(mib, 2, buf, &bufsz, NULL, 0) != -1) {
		if (strcmp(buf, str) == 0) {
			return true;
		}
	}

	return false;
}

void
limitloadtohardware_iterator(launch_data_t val, const char *key, void *ctx)
{
	bool *result = ctx;

	char name[128];
	(void)snprintf(name, sizeof(name), "hw.%s", key);

	int mib[2];
	size_t sz = 2;
	if (*result != true && os_assumes_zero(sysctlnametomib(name, mib, &sz)) == 0) {
		if (launch_data_get_type(val) == LAUNCH_DATA_ARRAY) {
			size_t c = launch_data_array_get_count(val);

			size_t i = 0;
			for (i = 0; i < c; i++) {
				launch_data_t oai = launch_data_array_get_index(val, i);
				if (sysctl_hw_streq(mib[1], launch_data_get_string(oai))) {
					*result = true;
					i = c;
				}
			}
		}
	}
}

void
readfile(const char *what, struct load_unload_state *lus)
{
	char ourhostname[1024];
	launch_data_t tmpd, tmps, thejob, tmpa;
	bool job_disabled = false;
	size_t i, c;

	gethostname(ourhostname, sizeof(ourhostname));

	if (NULL == (thejob = read_plist_file(what, lus->editondisk, lus->load))) {
		launchctl_log(LOG_ERR, "%s: no plist was returned for: %s", getprogname(), what);
		return;
	}


	if (NULL == launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_LABEL)) {
		launchctl_log(LOG_ERR, "%s: missing the Label key: %s", getprogname(), what);
		goto out_bad;
	}

	if ((launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_PROGRAM) == NULL) && 
		(launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_PROGRAMARGUMENTS) == NULL)) {
		launchctl_log(LOG_ERR, "%s: neither a Program nor a ProgramArguments key was specified: %s", getprogname(), what);
		goto out_bad;
	}

	if (NULL != (tmpa = launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_LIMITLOADFROMHOSTS))) {
		c = launch_data_array_get_count(tmpa);

		for (i = 0; i < c; i++) {
			launch_data_t oai = launch_data_array_get_index(tmpa, i);
			if (!strcasecmp(ourhostname, launch_data_get_string(oai))) {
				goto out_bad;
			}
		}
	}

	if (NULL != (tmpa = launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_LIMITLOADTOHOSTS))) {
		c = launch_data_array_get_count(tmpa);

		for (i = 0; i < c; i++) {
			launch_data_t oai = launch_data_array_get_index(tmpa, i);
			if (!strcasecmp(ourhostname, launch_data_get_string(oai))) {
				break;
			}
		}

		if (i == c) {
			goto out_bad;
		}
	}

	if (NULL != (tmpd = launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_LIMITLOADTOHARDWARE))) {
		bool result = false;
		launch_data_dict_iterate(tmpd, limitloadtohardware_iterator, &result);
		if (!result) {
			goto out_bad;
		}
	}

	if (NULL != (tmpd = launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_LIMITLOADFROMHARDWARE))) {
		bool result = false;
		launch_data_dict_iterate(tmpd, limitloadtohardware_iterator, &result);
		if (result) {
			goto out_bad;
		}
	}

	/* If the manager is Aqua, the LimitLoadToSessionType should default to
	 * "Aqua".
	 *
	 * <rdar://problem/8297909>
	 */
	if (!_launchctl_managername) {
		if (vproc_swap_string(NULL, VPROC_GSK_MGR_NAME, NULL, &_launchctl_managername)) {
			if (bootstrap_port) {
				/* This is only an error if we are running with a neutered
				 * bootstrap port, otherwise we wouldn't expect this operating to
				 * succeed.
				 *
				 * <rdar://problem/10514286>
				 */
				launchctl_log(LOG_ERR, "Could not obtain manager name: ppid/bootstrap: %d/0x%x", getppid(), bootstrap_port);
			}

			_launchctl_managername = "";
		}
	}

	if (!lus->session_type) {
		if (strcmp(_launchctl_managername, "Aqua") == 0) {
			lus->session_type = "Aqua";
		}
	}

	if (lus->session_type && !(tmpa = launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_LIMITLOADTOSESSIONTYPE))) {
		tmpa = launch_data_new_string("Aqua");
		launch_data_dict_insert(thejob, tmpa, LAUNCH_JOBKEY_LIMITLOADTOSESSIONTYPE);
	}

	if ((tmpa = launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_LIMITLOADTOSESSIONTYPE))) {
		const char *allowed_session;
		bool skipjob = true;

		/* My sincere apologies to anyone who has to deal with this
		 * LimitLoadToSessionType madness. It was like this when I got here, but
		 * I've knowingly made it worse, hopefully to the benefit of the end
		 * user.
		 *
		 * See <rdar://problem/8769211> and <rdar://problem/7114980>.
		 */
		if (!lus->session_type && launch_data_get_type(tmpa) == LAUNCH_DATA_STRING) {
			if (strcasecmp("System", _launchctl_managername) == 0 && strcasecmp("System", launch_data_get_string(tmpa)) == 0) {
				skipjob = false;
			}
		}

		if (lus->session_type) switch (launch_data_get_type(tmpa)) {
		case LAUNCH_DATA_ARRAY:
			c = launch_data_array_get_count(tmpa);
			for (i = 0; i < c; i++) {
				tmps = launch_data_array_get_index(tmpa, i);
				allowed_session = launch_data_get_string(tmps);
				if (strcasecmp(lus->session_type, allowed_session) == 0) {
					skipjob = false;
					/* we have to do the following so job_reparent_hack() works within launchd */
					tmpa = launch_data_new_string(lus->session_type);
					launch_data_dict_insert(thejob, tmpa, LAUNCH_JOBKEY_LIMITLOADTOSESSIONTYPE);
					break;
				}
			}
			break;
		case LAUNCH_DATA_STRING:
			allowed_session = launch_data_get_string(tmpa);
			if (strcasecmp(lus->session_type, allowed_session) == 0) {
				skipjob = false;
			}
			break;
		default:
			break;
		}

		if (skipjob) {
			goto out_bad;
		}
	}

	if ((tmpd = launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_DISABLED))) {
		job_disabled = job_disabled_logic(tmpd);
	}

	if (lus->forceload) {
		job_disabled = false;
	}

	if (job_disabled && lus->load) {
		goto out_bad;
	}

	if (_launchctl_system_bootstrap || _launchctl_peruser_bootstrap) {
		uuid_t uuid;
		uuid_clear(uuid);

		launch_data_t lduuid = launch_data_new_opaque(uuid, sizeof(uuid_t));
		launch_data_dict_insert(thejob, lduuid, LAUNCH_JOBKEY_SECURITYSESSIONUUID);
	}

	launch_data_array_append(lus->pass1, thejob);

	if (_launchctl_verbose) {
		launchctl_log(LOG_NOTICE, "Will load: %s", what);
	}

	return;
out_bad:
	if (_launchctl_verbose) {
		launchctl_log(LOG_NOTICE, "Ignored: %s", what);
	}
	launch_data_free(thejob);
}

void
job_disabled_dict_logic(launch_data_t obj, const char *key, void *context)
{
	bool *r = context;

	if (launch_data_get_type(obj) != LAUNCH_DATA_STRING) {
		return;
	}

	if (strcasecmp(key, LAUNCH_JOBKEY_DISABLED_MACHINETYPE) == 0) {
		if (sysctl_hw_streq(HW_MACHINE, launch_data_get_string(obj))) {
			*r = true;
		}
	} else if (strcasecmp(key, LAUNCH_JOBKEY_DISABLED_MODELNAME) == 0) {
		if (sysctl_hw_streq(HW_MODEL, launch_data_get_string(obj))) {
			*r = true;
		}
	}
}

bool
job_disabled_logic(launch_data_t obj)
{
	bool r = false;

	switch (launch_data_get_type(obj)) {
		case LAUNCH_DATA_DICTIONARY:
			launch_data_dict_iterate(obj, job_disabled_dict_logic, &r);
			break;
		case LAUNCH_DATA_BOOL:
			r = launch_data_get_bool(obj);
			break;
		default:
			break;
	}

	return r;
}

bool
path_goodness_check(const char *path, bool forceload)
{
	struct stat sb;

	if (stat(path, &sb) == -1) {
		launchctl_log(LOG_ERR, "%s: Couldn't stat(\"%s\"): %s", getprogname(), path, strerror(errno));
		return false;
	}

	if (forceload) {
		return true;
	}

	if (sb.st_mode & (S_IWOTH|S_IWGRP)) {
		launchctl_log(LOG_ERR, "%s: Dubious permissions on file (skipping): %s", getprogname(), path);
		return false;
	}

	if (sb.st_uid != 0 && sb.st_uid != getuid()) {
		launchctl_log(LOG_ERR, "%s: Dubious ownership on file (skipping): %s", getprogname(), path);
		return false;
	}

	if (!(S_ISREG(sb.st_mode) || S_ISDIR(sb.st_mode))) {
		launchctl_log(LOG_ERR, "%s: Dubious path. Not a regular file or directory (skipping): %s", getprogname(), path);
		return false;
	}

	if ((!S_ISDIR(sb.st_mode)) && (fnmatch("*.plist", path, FNM_CASEFOLD) == FNM_NOMATCH)) {
		launchctl_log(LOG_ERR, "%s: Dubious file. Not of type .plist (skipping): %s", getprogname(), path);
		return false;
	}

	return true;
}

void
readpath(const char *what, struct load_unload_state *lus)
{
	char buf[MAXPATHLEN];
	struct stat sb;
	struct dirent *de;
	DIR *d;

	if (!path_goodness_check(what, lus->forceload)) {
		return;
	}

	if (stat(what, &sb) == -1) {
		return;
	}

	if (S_ISREG(sb.st_mode)) {
		readfile(what, lus);
	} else if (S_ISDIR(sb.st_mode)) {
		if ((d = opendir(what)) == NULL) {
			launchctl_log(LOG_ERR, "%s: opendir() failed to open the directory", getprogname());
			return;
		}

		while ((de = readdir(d))) {
			if (de->d_name[0] == '.') {
				continue;
			}
			snprintf(buf, sizeof(buf), "%s/%s", what, de->d_name);

			if (!path_goodness_check(buf, lus->forceload)) {
				continue;
			}

			readfile(buf, lus);
		}
		closedir(d);
	}
}

void
insert_event(launch_data_t job, const char *stream, const char *key, launch_data_t event)
{
	launch_data_t launchevents, streamdict;

	launchevents = launch_data_dict_lookup(job, LAUNCH_JOBKEY_LAUNCHEVENTS);
	if (launchevents == NULL) {
		launchevents = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		launch_data_dict_insert(job, launchevents, LAUNCH_JOBKEY_LAUNCHEVENTS);
	}

	streamdict = launch_data_dict_lookup(launchevents, stream);
	if (streamdict == NULL) {
		streamdict = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		launch_data_dict_insert(launchevents, streamdict, stream);
	}

	launch_data_dict_insert(streamdict, event, key);
}

struct distill_context {
	launch_data_t base;
	launch_data_t newsockdict;
};

void
distill_jobs(launch_data_t jobs)
{
	size_t i, c = launch_data_array_get_count(jobs);
	launch_data_t job;

	for (i = 0; i < c; i++) {
		job = launch_data_array_get_index(jobs, i);
		distill_config_file(job);
		distill_fsevents(job);
	}
}

void
distill_config_file(launch_data_t id_plist)
{
	struct distill_context dc = { id_plist, NULL };
	launch_data_t tmp;

	if ((tmp = launch_data_dict_lookup(dc.base, LAUNCH_JOBKEY_SOCKETS))) {
		dc.newsockdict = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		launch_data_dict_iterate(tmp, sock_dict_cb, &dc);
		launch_data_dict_insert(dc.base, dc.newsockdict, LAUNCH_JOBKEY_SOCKETS);
	}
}

void
sock_dict_cb(launch_data_t what, const char *key, void *context)
{
	struct distill_context *dc = context;
	launch_data_t fdarray = launch_data_alloc(LAUNCH_DATA_ARRAY);

	launch_data_dict_insert(dc->newsockdict, fdarray, key);

	if (launch_data_get_type(what) == LAUNCH_DATA_DICTIONARY) {
		sock_dict_edit_entry(what, key, fdarray, dc->base);
	} else if (launch_data_get_type(what) == LAUNCH_DATA_ARRAY) {
		launch_data_t tmp;
		size_t i;

		for (i = 0; i < launch_data_array_get_count(what); i++) {
			tmp = launch_data_array_get_index(what, i);
			sock_dict_edit_entry(tmp, key, fdarray, dc->base);
		}
	}
}

void
sock_dict_edit_entry(launch_data_t tmp, const char *key, launch_data_t fdarray, launch_data_t thejob)
{
	launch_data_t a, val;
	int sfd, st = SOCK_STREAM;
	bool passive = true;

	if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_TYPE))) {
		if (!strcasecmp(launch_data_get_string(val), "stream")) {
			st = SOCK_STREAM;
		} else if (!strcasecmp(launch_data_get_string(val), "dgram")) {
			st = SOCK_DGRAM;
		} else if (!strcasecmp(launch_data_get_string(val), "seqpacket")) {
			st = SOCK_SEQPACKET;
		}
	}

	if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_PASSIVE))) {
		passive = launch_data_get_bool(val);
	}

	if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_SECUREWITHKEY))) {
		char secdir[] = LAUNCH_SECDIR, buf[1024];
		launch_data_t uenv = launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_USERENVIRONMENTVARIABLES);

		if (NULL == uenv) {
			uenv = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
			launch_data_dict_insert(thejob, uenv, LAUNCH_JOBKEY_USERENVIRONMENTVARIABLES);
		}

		mkdtemp(secdir);

		sprintf(buf, "%s/%s", secdir, key);

		a = launch_data_new_string(buf);
		launch_data_dict_insert(tmp, a, LAUNCH_JOBSOCKETKEY_PATHNAME);
		a = launch_data_new_string(buf);
		launch_data_dict_insert(uenv, a, launch_data_get_string(val));
	}

	if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_PATHNAME))) {
		struct sockaddr_un sun;
		mode_t sun_mode = 0;
		mode_t oldmask;
		bool setm = false;

		memset(&sun, 0, sizeof(sun));

		sun.sun_family = AF_UNIX;

		strncpy(sun.sun_path, launch_data_get_string(val), sizeof(sun.sun_path));

		if (posix_assumes_zero(sfd = _fd(socket(AF_UNIX, st, 0))) == -1) {
			return;
		}

		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_PATHMODE))) {
			sun_mode = (mode_t)launch_data_get_integer(val);
			setm = true;
		}

		if (passive) {
			if (unlink(sun.sun_path) == -1 && errno != ENOENT) {
				close(sfd);
				return;
			}
			oldmask = umask(S_IRWXG|S_IRWXO);
			if (bind(sfd, (struct sockaddr *)&sun, (socklen_t) sizeof sun) == -1) {
				close(sfd);
				umask(oldmask);
				return;
			}
			umask(oldmask);
			if (setm) {
				chmod(sun.sun_path, sun_mode);
			}
			if ((st == SOCK_STREAM || st == SOCK_SEQPACKET) && listen(sfd, -1) == -1) {
				close(sfd);
				return;
			}
		} else if (connect(sfd, (struct sockaddr *)&sun, (socklen_t) sizeof sun) == -1) {
			close(sfd);
			return;
		}

		val = launch_data_new_fd(sfd);
		launch_data_array_append(fdarray, val);
	} else {
		launch_data_t rnames = NULL;
		const char *node = NULL, *serv = NULL, *mgroup = NULL;
		char servnbuf[50];
		struct addrinfo hints, *res0, *res;
		int gerr, sock_opt = 1;

		memset(&hints, 0, sizeof(hints));

		hints.ai_socktype = st;
		if (passive) {
			hints.ai_flags |= AI_PASSIVE;
		}

		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_NODENAME))) {
			node = launch_data_get_string(val);
		}
		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_MULTICASTGROUP))) {
			mgroup = launch_data_get_string(val);
		}
		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_SERVICENAME))) {
			if (LAUNCH_DATA_INTEGER == launch_data_get_type(val)) {
				sprintf(servnbuf, "%lld", launch_data_get_integer(val));
				serv = servnbuf;
			} else {
				serv = launch_data_get_string(val);
			}
		}
		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_FAMILY))) {
			if (!strcasecmp("IPv4", launch_data_get_string(val))) {
				hints.ai_family = AF_INET;
			} else if (!strcasecmp("IPv6", launch_data_get_string(val))) {
				hints.ai_family = AF_INET6;
			}
		}
		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_PROTOCOL))) {
			if (!strcasecmp("TCP", launch_data_get_string(val))) {
				hints.ai_protocol = IPPROTO_TCP;
			} else if (!strcasecmp("UDP", launch_data_get_string(val))) {
				hints.ai_protocol = IPPROTO_UDP;
			}
		}
		if ((rnames = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_BONJOUR))) {
			if (LAUNCH_DATA_BOOL != launch_data_get_type(rnames) || launch_data_get_bool(rnames)) {
				launch_data_t newevent;
				char eventkey[100];

				newevent = launch_data_copy(tmp);
				snprintf(eventkey, sizeof(eventkey), "com.apple.launchd.%s", key);
				insert_event(thejob, "com.apple.bonjour.registration", eventkey, newevent);
			}
		}

		if ((gerr = getaddrinfo(node, serv, &hints, &res0)) != 0) {
			launchctl_log(LOG_ERR, "getaddrinfo(): %s", gai_strerror(gerr));
			return;
		}

		for (res = res0; res; res = res->ai_next) {
			if ((sfd = _fd(socket(res->ai_family, res->ai_socktype, res->ai_protocol))) == -1) {
				launchctl_log(LOG_ERR, "socket(): %s", strerror(errno));
				return;
			}

			do_application_firewall_magic(sfd, thejob);

			if (hints.ai_flags & AI_PASSIVE) {
				if (AF_INET6 == res->ai_family && -1 == setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY,
							(void *)&sock_opt, (socklen_t) sizeof sock_opt)) {
					launchctl_log(LOG_ERR, "setsockopt(IPV6_V6ONLY): %m");
					return;
				}
				if (mgroup) {
					if (setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, (void *)&sock_opt, (socklen_t) sizeof sock_opt) == -1) {
						launchctl_log(LOG_ERR, "setsockopt(SO_REUSEPORT): %s", strerror(errno));
						return;
					}
				} else {
					if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void *)&sock_opt, (socklen_t) sizeof sock_opt) == -1) {
						launchctl_log(LOG_ERR, "setsockopt(SO_REUSEADDR): %s", strerror(errno));
						return;
					}
				}
				if (bind(sfd, res->ai_addr, res->ai_addrlen) == -1) {
					launchctl_log(LOG_ERR, "bind(): %s", strerror(errno));
					return;
				}
				/* The kernel may have dynamically assigned some part of the
				 * address. (The port being a common example.)
				 */
				if (getsockname(sfd, res->ai_addr, &res->ai_addrlen) == -1) {
					launchctl_log(LOG_ERR, "getsockname(): %s", strerror(errno));
					return;
				}

				if (mgroup) {
					do_mgroup_join(sfd, res->ai_family, res->ai_socktype, res->ai_protocol, mgroup);
				}
				if ((res->ai_socktype == SOCK_STREAM || res->ai_socktype == SOCK_SEQPACKET) && listen(sfd, -1) == -1) {
					launchctl_log(LOG_ERR, "listen(): %s", strerror(errno));
					return;
				}
			} else {
				if (connect(sfd, res->ai_addr, res->ai_addrlen) == -1) {
					launchctl_log(LOG_ERR, "connect(): %s", strerror(errno));
					return;
				}
			}
			val = launch_data_new_fd(sfd);
			launch_data_array_append(fdarray, val);
		}
	}
}

void
distill_fsevents(launch_data_t id_plist)
{
	launch_data_t copy, newevent;
	launch_data_t tmp, tmp2;

	if ((tmp = launch_data_dict_lookup(id_plist, LAUNCH_JOBKEY_QUEUEDIRECTORIES))) {
		copy = launch_data_copy(tmp);
		(void)launch_data_dict_remove(id_plist, LAUNCH_JOBKEY_QUEUEDIRECTORIES);

		newevent = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		launch_data_dict_insert(newevent, copy, LAUNCH_JOBKEY_QUEUEDIRECTORIES);
		insert_event(id_plist, "com.apple.fsevents.matching", "com.apple.launchd." LAUNCH_JOBKEY_QUEUEDIRECTORIES, newevent);
	}

	if ((tmp = launch_data_dict_lookup(id_plist, LAUNCH_JOBKEY_WATCHPATHS))) {
		copy = launch_data_copy(tmp);
		(void)launch_data_dict_remove(id_plist, LAUNCH_JOBKEY_WATCHPATHS);

		newevent = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		launch_data_dict_insert(newevent, copy, LAUNCH_JOBKEY_WATCHPATHS);
		insert_event(id_plist, "com.apple.fsevents.matching", "com.apple.launchd." LAUNCH_JOBKEY_WATCHPATHS, newevent);
	}

	if ((tmp = launch_data_dict_lookup(id_plist, LAUNCH_JOBKEY_KEEPALIVE))) {
		if ((tmp2 = launch_data_dict_lookup(tmp, LAUNCH_JOBKEY_KEEPALIVE_PATHSTATE))) {
			copy = launch_data_copy(tmp2);
			(void)launch_data_dict_remove(tmp, LAUNCH_JOBKEY_KEEPALIVE_PATHSTATE);

			newevent = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
			launch_data_dict_insert(newevent, copy, LAUNCH_JOBKEY_KEEPALIVE_PATHSTATE);
			insert_event(id_plist, "com.apple.fsevents.matching", "com.apple.launchd." LAUNCH_JOBKEY_KEEPALIVE_PATHSTATE, newevent);
		}
	}
}

void
do_mgroup_join(int fd, int family, int socktype, int protocol, const char *mgroup)
{
	struct addrinfo hints, *res0, *res;
	struct ip_mreq mreq;
	struct ipv6_mreq m6req;
	int gerr;

	memset(&hints, 0, sizeof(hints));

	hints.ai_flags |= AI_PASSIVE;
	hints.ai_family = family;
	hints.ai_socktype = socktype;
	hints.ai_protocol = protocol;

	if ((gerr = getaddrinfo(mgroup, NULL, &hints, &res0)) != 0) {
		launchctl_log(LOG_ERR, "getaddrinfo(): %s", gai_strerror(gerr));
		return;
	}

	for (res = res0; res; res = res->ai_next) {
		if (AF_INET == family) {
			memset(&mreq, 0, sizeof(mreq));
			mreq.imr_multiaddr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
			if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, (socklen_t) sizeof mreq) == -1) {
				launchctl_log(LOG_ERR, "setsockopt(IP_ADD_MEMBERSHIP): %s", strerror(errno));
				continue;
			}
			break;
		} else if (AF_INET6 == family) {
			memset(&m6req, 0, sizeof(m6req));
			m6req.ipv6mr_multiaddr = ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
			if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &m6req, (socklen_t) sizeof m6req) == -1) {
				launchctl_log(LOG_ERR, "setsockopt(IPV6_JOIN_GROUP): %s", strerror(errno));
				continue;
			}
			break;
		} else {
			launchctl_log(LOG_ERR, "unknown family during multicast group bind!");
			break;
		}
	}

	freeaddrinfo(res0);
}

#pragma mark XPC Cache

#if TARGET_OS_EMBEDDED

CFPropertyListRef
GetPropertyListFromCache(void)
{
	static CFPropertyListRef propertyList;
	CFDataRef cacheData;
	CFErrorRef error;

	if (!propertyList) {
		uint8_t *data = NULL;
		unsigned long sz = 0;

		void *handle = dlopen(XPC_PLIST_CACHE, RTLD_NOW);

		if (handle) {
			void *fnptr = dlsym(handle, "__xpcd_cache");

			if (fnptr) {
				Dl_info image_info;

				int rv = dladdr(fnptr, &image_info);
				if (rv != 0) {
					data = getsectiondata(image_info.dli_fbase, "__TEXT", "__xpcd_cache", &sz);
				} else {
					launchctl_log(LOG_ERR, "cache loading failed: failed to find address of __xpcd_cache symbol.");
				}
			} else {
				launchctl_log(LOG_ERR, "cache loading failed: failed to find __xpcd_cache symbol in cache.");
			}
		} else {
			launchctl_log(LOG_ERR, "cache loading failed: dlopen returned %s.", dlerror());
		}

		if (data) {
			cacheData = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, data, sz, kCFAllocatorNull);
			if (cacheData) {
				propertyList = CFPropertyListCreateWithData(kCFAllocatorDefault, cacheData, kCFPropertyListMutableContainersAndLeaves, NULL, &error);
				CFRelease(cacheData);
			} else {
				launchctl_log(LOG_ERR, "cache loading failed: unable to create data out of memory region.");
			}
		} else {
			launchctl_log(LOG_ERR, "cache loading failed: no cache data found in __TEXT,__xpcd_cache segment.");
		}
	}

	return propertyList;
}

CFPropertyListRef
CreateMyPropertyListFromCachedFile(const char *posixfile)
{
	CFPropertyListRef cache = GetPropertyListFromCache();
	CFPropertyListRef job = NULL;

	if (cache) {
		CFPropertyListRef jobs = CFDictionaryGetValue(cache, CFSTR(XPC_PLIST_CACHE_KEY));

		if (jobs) {
			CFStringRef key = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault, posixfile, kCFStringEncodingUTF8, kCFAllocatorNull);

			if (key) {
				job = CFDictionaryGetValue(jobs, key);
				CFRelease(key);
			}
		}
	}

	if (job) {
		CFRetain(job);
	}
	return job;
}

bool
require_jobs_from_cache(void)
{
	char buf[1024];
	size_t len;
	char *ptr;
	unsigned long val;
	bool cs_disabled = false;
	len = sizeof(buf);

	if (sysctlbyname("kern.bootargs", buf, &len, NULL, 0) == 0) {
		ptr = strnstr(buf, "cs_enforcement_disable=", len);
		if (ptr != NULL) {
			val = strtoul(ptr + strlen("cs_enforcement_disable="), NULL, 10);
			cs_disabled = (val != 0);
		}
		ptr = strnstr(buf, "launchctl_enforce_codesign=", len);
		if (ptr != NULL) {
			char *endptr = NULL;
			char *startptr = ptr + strlen("launchctl_enforce_codesign=");
			val = strtoul(startptr, &endptr, 10);
			cs_disabled = (val == 0 && startptr != endptr);
		}
	}

	return !cs_disabled;
}

#endif

#pragma mark File-based Property Lists

CFPropertyListRef
CreateMyPropertyListFromFile(const char *posixfile)
{
	CFPropertyListRef propertyList;
	CFStringRef       errorString;
	CFDataRef         resourceData;
	SInt32            errorCode;
	CFURLRef          fileURL;

	fileURL = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)posixfile, strlen(posixfile), false);
	if (!fileURL) {
		launchctl_log(LOG_ERR, "%s: CFURLCreateFromFileSystemRepresentation(%s) failed", getprogname(), posixfile);
	}
	if (!CFURLCreateDataAndPropertiesFromResource(kCFAllocatorDefault, fileURL, &resourceData, NULL, NULL, &errorCode)) {
		launchctl_log(LOG_ERR, "%s: CFURLCreateDataAndPropertiesFromResource(%s) failed: %d", getprogname(), posixfile, (int)errorCode);
	}

	propertyList = CFPropertyListCreateFromXMLData(kCFAllocatorDefault, resourceData, kCFPropertyListMutableContainersAndLeaves, &errorString);
	if (fileURL) {
		CFRelease(fileURL);
	}

	if (resourceData) {
		CFRelease(resourceData);
	}

	return propertyList;
}

void
WriteMyPropertyListToFile(CFPropertyListRef plist, const char *posixfile)
{
	CFDataRef	resourceData;
	CFURLRef	fileURL;
	SInt32		errorCode;

	fileURL = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)posixfile, strlen(posixfile), false);
	if (!fileURL) {
		launchctl_log(LOG_ERR, "%s: CFURLCreateFromFileSystemRepresentation(%s) failed", getprogname(), posixfile);
	}
	resourceData = CFPropertyListCreateXMLData(kCFAllocatorDefault, plist);
	if (resourceData == NULL) {
		launchctl_log(LOG_ERR, "%s: CFPropertyListCreateXMLData(%s) failed", getprogname(), posixfile);
	}
	if (!CFURLWriteDataAndPropertiesToResource(fileURL, resourceData, NULL, &errorCode)) {
		launchctl_log(LOG_ERR, "%s: CFURLWriteDataAndPropertiesToResource(%s) failed: %d", getprogname(), posixfile, (int)errorCode);
	}

	if (resourceData) {
		CFRelease(resourceData);
	}
}

inline Boolean
_is_launch_data_t(launch_data_t obj) 
{
	Boolean result = true;

	switch (launch_data_get_type(obj)) {
		case LAUNCH_DATA_STRING		: break;
		case LAUNCH_DATA_INTEGER	: break;
		case LAUNCH_DATA_REAL		: break;
		case LAUNCH_DATA_BOOL		: break;
		case LAUNCH_DATA_ARRAY		: break;
		case LAUNCH_DATA_DICTIONARY	: break;
		case LAUNCH_DATA_FD 		: break;
		case LAUNCH_DATA_MACHPORT	: break;
		default						: result = false;
	}

	return result;
}

void
_launch_data_iterate(launch_data_t obj, const char *key, CFMutableDictionaryRef dict)
{
	if (obj && _is_launch_data_t(obj)) {
		CFStringRef cfKey = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
		CFTypeRef cfVal = CFTypeCreateFromLaunchData(obj);

		if (cfVal) {
			CFDictionarySetValue(dict, cfKey, cfVal);
			CFRelease(cfVal);
		}
		CFRelease(cfKey);
	}
}

CFTypeRef
CFTypeCreateFromLaunchData(launch_data_t obj)
{
	CFTypeRef cfObj = NULL;

	switch (launch_data_get_type(obj)) {
	case LAUNCH_DATA_STRING: {
		const char *str = launch_data_get_string(obj);			
		cfObj = CFStringCreateWithCString(NULL, str, kCFStringEncodingUTF8);
		break;
	}			
	case LAUNCH_DATA_INTEGER: {
		long long integer = launch_data_get_integer(obj);
		cfObj = CFNumberCreate(NULL, kCFNumberLongLongType, &integer);
		break;
	}
	case LAUNCH_DATA_REAL: {
		double real = launch_data_get_real(obj);
		cfObj = CFNumberCreate(NULL, kCFNumberDoubleType, &real);
		break;
	}
	case LAUNCH_DATA_BOOL: {
		bool yesno = launch_data_get_bool(obj);
		cfObj = yesno ? kCFBooleanTrue : kCFBooleanFalse;
		break;
	}
	case LAUNCH_DATA_ARRAY: {
		cfObj = (CFTypeRef)CFArrayCreateFromLaunchArray(obj);
		break;
	}
	case LAUNCH_DATA_DICTIONARY: {
		cfObj = (CFTypeRef)CFDictionaryCreateFromLaunchDictionary(obj);
		break;
	}
	case LAUNCH_DATA_FD: {
		int fd = launch_data_get_fd(obj);
		cfObj = CFNumberCreate(NULL, kCFNumberIntType, &fd);
		break;
	}
	case LAUNCH_DATA_MACHPORT: {
		mach_port_t port = launch_data_get_machport(obj);
		cfObj = CFNumberCreate(NULL, kCFNumberIntType, &port);
		break;
	}
	default:
		break;
	}

	return cfObj;
}

#pragma mark CFArray
CFArrayRef
CFArrayCreateFromLaunchArray(launch_data_t arr)
{
	CFArrayRef result = NULL;	
	CFMutableArrayRef mutResult = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);

	if (launch_data_get_type(arr) == LAUNCH_DATA_ARRAY) {
		unsigned int count = launch_data_array_get_count(arr);
		unsigned int i = 0;

		for (i = 0; i < count; i++) {
			launch_data_t launch_obj = launch_data_array_get_index(arr, i);
			CFTypeRef obj = CFTypeCreateFromLaunchData(launch_obj);

			if (obj) {
				CFArrayAppendValue(mutResult, obj);
				CFRelease(obj);
			}
		}

		result = CFArrayCreateCopy(NULL, mutResult);
	}

	if (mutResult) {
		CFRelease(mutResult);
	}
	return result;
}

#pragma mark CFDictionary / CFPropertyList
CFDictionaryRef
CFDictionaryCreateFromLaunchDictionary(launch_data_t dict)
{
	CFDictionaryRef result = NULL;

	if (launch_data_get_type(dict) == LAUNCH_DATA_DICTIONARY) {
		CFMutableDictionaryRef mutResult = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

		launch_data_dict_iterate(dict, (void (*)(launch_data_t, const char *, void *))_launch_data_iterate, mutResult);

		result = CFDictionaryCreateCopy(NULL, mutResult);
		CFRelease(mutResult);	
	}

	return result;
}

void
myCFDictionaryApplyFunction(const void *key, const void *value, void *context)
{
	launch_data_t ik, iw, where = context;

	ik = CF2launch_data(key);
	iw = CF2launch_data(value);

	launch_data_dict_insert(where, iw, launch_data_get_string(ik));
	launch_data_free(ik);
}

launch_data_t
CF2launch_data(CFTypeRef cfr)
{
	launch_data_t r;
	CFTypeID cft = CFGetTypeID(cfr);

	if (cft == CFStringGetTypeID()) {
		char buf[4096];
		CFStringGetCString(cfr, buf, sizeof(buf), kCFStringEncodingUTF8);
		r = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(r, buf);
	} else if (cft == CFBooleanGetTypeID()) {
		r = launch_data_alloc(LAUNCH_DATA_BOOL);
		launch_data_set_bool(r, CFBooleanGetValue(cfr));
	} else if (cft == CFArrayGetTypeID()) {
		CFIndex i, ac = CFArrayGetCount(cfr);
		r = launch_data_alloc(LAUNCH_DATA_ARRAY);
		for (i = 0; i < ac; i++) {
			CFTypeRef v = CFArrayGetValueAtIndex(cfr, i);
			if (v) {
				launch_data_t iv = CF2launch_data(v);
				launch_data_array_set_index(r, iv, i);
			}
		}
	} else if (cft == CFDictionaryGetTypeID()) {
		r = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		CFDictionaryApplyFunction(cfr, myCFDictionaryApplyFunction, r);
	} else if (cft == CFDataGetTypeID()) {
		r = launch_data_alloc(LAUNCH_DATA_OPAQUE);
		launch_data_set_opaque(r, CFDataGetBytePtr(cfr), CFDataGetLength(cfr));
	} else if (cft == CFNumberGetTypeID()) {
		long long n;
		double d;
		CFNumberType cfnt = CFNumberGetType(cfr);
		switch (cfnt) {
		case kCFNumberSInt8Type:
		case kCFNumberSInt16Type:
		case kCFNumberSInt32Type:
		case kCFNumberSInt64Type:
		case kCFNumberCharType:
		case kCFNumberShortType:
		case kCFNumberIntType:
		case kCFNumberLongType:
		case kCFNumberLongLongType:
			CFNumberGetValue(cfr, kCFNumberLongLongType, &n);
			r = launch_data_alloc(LAUNCH_DATA_INTEGER);
			launch_data_set_integer(r, n);
			break;
		case kCFNumberFloat32Type:
		case kCFNumberFloat64Type:
		case kCFNumberFloatType:
		case kCFNumberDoubleType:
			CFNumberGetValue(cfr, kCFNumberDoubleType, &d);
			r = launch_data_alloc(LAUNCH_DATA_REAL);
			launch_data_set_real(r, d);
			break;
		default:
			r = NULL;
			break;
		}
	} else {
		r = NULL;
	}
	return r;
}

int
_fd(int fd)
{
	if (fd >= 0)
		fcntl(fd, F_SETFD, 1);
	return fd;
}

void
do_single_user_mode(bool sflag)
{
	if (sflag) {
		while (!do_single_user_mode2()) {
			sleep(1);
		}
	}
}

bool
do_single_user_mode2(void)
{
	bool runcom_fsck = true; /* should_fsck(); */
	int wstatus;
	int fd;
	pid_t p;

	switch ((p = fork())) {
	case -1:
		syslog(LOG_ERR, "can't fork single-user shell, trying again: %m");
		return false;
	case 0:
		break;
	default:
		(void)os_assumes_zero(waitpid(p, &wstatus, 0));
		if (WIFEXITED(wstatus)) {
			if (WEXITSTATUS(wstatus) == EXIT_SUCCESS) {
				return true;
			} else {
				launchctl_log(LOG_NOTICE, "single user mode: exit status: %d", WEXITSTATUS(wstatus));
			}
		} else {
			launchctl_log(LOG_NOTICE, "single user mode shell: %s", strsignal(WTERMSIG(wstatus)));
		}
		return false;
	}

	revoke(_PATH_CONSOLE);
	if (posix_assumes_zero((fd = open(_PATH_CONSOLE, O_RDWR))) == -1) {
		_exit(EXIT_FAILURE);
	}
	if (posix_assumes_zero(login_tty(fd)) == -1) {
		_exit(EXIT_FAILURE);
	}

	mach_timespec_t wt = { 5, 0 };
	IOKitWaitQuiet(kIOMasterPortDefault, &wt); /* This will hopefully return after all the kexts have shut up. */

	setenv("TERM", "vt100", 1);
	if (runcom_fsck) {
		fprintf(stdout, "Singleuser boot -- fsck not done\n");
		fprintf(stdout, "Root device is mounted read-only\n");
		fprintf(stdout, "If you want to make modifications to files:\n");
		fprintf(stdout, "\t/sbin/fsck -fy\n\t/sbin/mount -uw /\n");
		fprintf(stdout, "If you wish to boot the system:\n");
		fprintf(stdout, "\texit\n");
		fflush(stdout);
	}

	execl(_PATH_BSHELL, "-sh", NULL);
	fprintf(stderr, "can't exec %s for single user: %m\n", _PATH_BSHELL);
	_exit(EXIT_FAILURE);
}

void
do_crash_debug_mode(void)
{
	while (!do_crash_debug_mode2()) {
		sleep(1);
	}
}

bool
do_crash_debug_mode2(void)
{
	int wstatus;
	int fd;
	pid_t p;

	switch ((p = fork())) {
	case -1:
		syslog(LOG_ERR, "can't fork crash debug shell, trying again: %m");
		return false;
	case 0:
		break;
	default:
		(void)os_assumes_zero(waitpid(p, &wstatus, 0));
		if (WIFEXITED(wstatus)) {
			if (WEXITSTATUS(wstatus) == EXIT_SUCCESS) {
				return true;
			} else {
				launchctl_log(LOG_NOTICE, "crash debug mode: exit status: %d", WEXITSTATUS(wstatus));
			}
		} else {
			launchctl_log(LOG_NOTICE, "crash debug mode shell: %s", strsignal(WTERMSIG(wstatus)));
		}
		return false;
	}

	revoke(_PATH_CONSOLE);
	if (posix_assumes_zero((fd = open(_PATH_CONSOLE, O_RDWR))) == -1) {
		_exit(EXIT_FAILURE);
	}
	if (posix_assumes_zero(login_tty(fd)) == -1) {
		_exit(EXIT_FAILURE);
	}

	/* The idea is to wait until all the kexts have quiesced to prevent a bunch
	 * of log messages from being slammed onto the console prompt. It mostly
	 * works.
	 */
	mach_timespec_t wt = { 5, 0 };
	IOKitWaitQuiet(kIOMasterPortDefault, &wt);

	setenv("TERM", "vt100", 1);
	fprintf(stdout, "Entering boot-time debugging mode...\n");
	fprintf(stdout, "The system bootstrapper process has crashed. To debug:\n");
	fprintf(stdout, "\tgdb attach %i\n", getppid());
	fprintf(stdout, "You can try booting the system with:\n");
	fprintf(stdout, "\tlaunchctl load -S System -D All\n");

	execl(_PATH_BSHELL, "-sh", NULL);
	fprintf(stderr, "can't exec %s for crash debug: %m\n", _PATH_BSHELL);
	_exit(EXIT_FAILURE);
}

void
exit_at_sigterm(int sig)
{
	if (sig == SIGTERM) {
		_exit(EXIT_SUCCESS);
	}
}

void
fatal_signal_handler(int sig __attribute__((unused)), siginfo_t *si __attribute__((unused)), void *uap __attribute__((unused)))
{
	do_crash_debug_mode();
}

void
handle_system_bootstrapper_crashes_separately(void)
{
	if (!_launchctl_startup_debugging) {
		return;
	}

	fprintf(stdout, "com.apple.launchctl.System\t\t\t*** Handling system bootstrapper crashes separately. ***\n");
	struct sigaction fsa;

	fsa.sa_sigaction = fatal_signal_handler;
	fsa.sa_flags = SA_SIGINFO;
	sigemptyset(&fsa.sa_mask);

	(void)posix_assumes_zero(sigaction(SIGILL, &fsa, NULL));
	(void)posix_assumes_zero(sigaction(SIGFPE, &fsa, NULL));
	(void)posix_assumes_zero(sigaction(SIGBUS, &fsa, NULL));
	(void)posix_assumes_zero(sigaction(SIGTRAP, &fsa, NULL));
	(void)posix_assumes_zero(sigaction(SIGABRT, &fsa, NULL));
}

#if TARGET_OS_EMBEDDED
void
init_data_protection(void)
{
	if (path_check("/usr/libexec/init_data_protection")) {
		const char *init_cp[] = { "/usr/libexec/init_data_protection", NULL };
		if (fwexec(init_cp, NULL) == -1) {
			launchctl_log(LOG_ERR, "Couldn't init content protection: %d: %s", errno, strerror(errno));
			(void)reboot(RB_HALT);

			_exit(EXIT_FAILURE);
		}
	}
}
#endif

void
system_specific_bootstrap(bool sflag)
{
	int hnmib[] = { CTL_KERN, KERN_HOSTNAME };
	struct kevent kev;
	int kq;
#if HAVE_LIBAUDITD
	launch_data_t lda, ldb;
#endif

	handle_system_bootstrapper_crashes_separately();

	// Disable Libinfo lookups to mdns and ds while bootstrapping (8698260)
	si_search_module_set_flags("mdns", 1);
	si_search_module_set_flags("ds", 1);

	/* rc.cdrom's hack to load the system means that we're not the real system
	 * bootstrapper. So we set this environment variable, and if the real
	 * bootstrapper detects it, it will disable lookups to mDNSResponder and
	 * opendirectoryd to prevent deadlocks at boot.
	 *
	 * See <rdar://problem/9877230>.
	 */
	(void)setenv(LAUNCH_ENV_BOOTSTRAPPINGSYSTEM, "1", 1);

	do_sysversion_sysctl();

	do_single_user_mode(sflag);

	(void)posix_assumes_zero(kq = kqueue());
	EV_SET(&kev, 0, EVFILT_TIMER, EV_ADD|EV_ONESHOT, NOTE_SECONDS, 60, 0);
	(void)posix_assumes_zero(kevent(kq, &kev, 1, NULL, 0, NULL));

	__OS_COMPILETIME_ASSERT__(SIG_ERR == (typeof(SIG_ERR))-1);
	EV_SET(&kev, SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);
	(void)posix_assumes_zero(kevent(kq, &kev, 1, NULL, 0, NULL));
	(void)posix_assumes_zero(signal(SIGTERM, SIG_IGN));
	(void)posix_assumes_zero(sysctl(hnmib, 2, NULL, NULL, "localhost", sizeof("localhost")));

	loopback_setup_ipv4();
	loopback_setup_ipv6();

	apply_sysctls_from_file("/etc/sysctl.conf");

#if TARGET_OS_EMBEDDED
	if (path_check("/etc/rc.boot")) {
		const char *rcboot_tool[] = { "/etc/rc.boot", NULL };

		(void)posix_assumes_zero(signal(SIGTERM, exit_at_sigterm));
		(void)posix_assumes_zero(fwexec(rcboot_tool, NULL));
	}
#endif

	if (path_check("/etc/rc.cdrom")) {
		const char *rccdrom_tool[] = { _PATH_BSHELL, "/etc/rc.cdrom", "multiuser", NULL };

		/* The bootstrapper should always be killable during install-time. This 
		 * is a special case for /etc/rc.cdrom, which runs a process and never
		 * exits.
		 *
		 * <rdar://problem/6103485>
		 */
		(void)posix_assumes_zero(signal(SIGTERM, exit_at_sigterm));
		(void)posix_assumes_zero(fwexec(rccdrom_tool, NULL));
		(void)reboot(RB_HALT);
		_exit(EXIT_FAILURE);
	} else if (is_netboot()) {
		const char *rcnetboot_tool[] = { _PATH_BSHELL, "/etc/rc.netboot", "init", NULL };
		if (posix_assumes_zero(fwexec(rcnetboot_tool, NULL)) == -1) {
			(void)reboot(RB_HALT);
			_exit(EXIT_FAILURE);
		}
	} else {
		do_potential_fsck();
	}

#if TARGET_OS_EMBEDDED
	if (path_check("/usr/libexec/tzinit")) {
		const char *tzinit_tool[] = { "/usr/libexec/tzinit", NULL };
		(void)posix_assumes_zero(fwexec(tzinit_tool, NULL));
	}
#endif

#if TARGET_OS_EMBEDDED
	if (path_check("/usr/libexec/FinishRestoreFromBackup")) {
		const char *finish_restore[] = { "/usr/libexec/FinishRestoreFromBackup", NULL };
		if (fwexec(finish_restore, NULL) == -1) {
			launchctl_log(LOG_ERR, "Couldn't finish restore: %d: %s", errno, strerror(errno));
			(void)reboot(RB_HALT);

			_exit(EXIT_FAILURE);
		}
	}
#endif

	if (path_check("/usr/libexec/cc_fips_test")) {
		const char *fips_tool[] = { "/usr/libexec/cc_fips_test", "-P", NULL };
		if (fwexec(fips_tool, NULL) == -1) {
			launchctl_log(LOG_ERR, "FIPS self check failure: %d: %s", errno, strerror(errno));
			(void)reboot(RB_HALT);

			_exit(EXIT_FAILURE);
		}
	}

	if (path_check("/etc/rc.server")) {
		const char *rcserver_tool[] = { _PATH_BSHELL, "/etc/rc.server", NULL };
		(void)posix_assumes_zero(fwexec(rcserver_tool, NULL));
	}

	read_launchd_conf();

	if (path_check("/var/account/acct")) {
		(void)posix_assumes_zero(acct("/var/account/acct"));
	}

#if !TARGET_OS_EMBEDDED
	if (path_check("/etc/fstab")) {
		const char *mount_tool[] = { "mount", "-vat", "nonfs", NULL };
		(void)posix_assumes_zero(fwexec(mount_tool, NULL));
	}
#endif

	if (path_check("/etc/rc.installer_cleanup")) {
		const char *rccleanup_tool[] = { _PATH_BSHELL, "/etc/rc.installer_cleanup", "multiuser", NULL };
		(void)posix_assumes_zero(fwexec(rccleanup_tool, NULL));
	}

	if (path_check("/etc/rc.deferred_install")) {
		int status = 0;
		const char *deferredinstall_tool[] = { _PATH_BSHELL, "/etc/rc.deferred_install", NULL };
		if (posix_assumes_zero(fwexec(deferredinstall_tool, &status)) == 0) {
			if (WEXITSTATUS(status) == EXIT_SUCCESS) {
				if (_launchctl_apple_internal) {
					launchctl_log(LOG_NOTICE, "Deferred install script completed successfully. Rebooting in 3 seconds...");
					sleep(3);
				}

				(void)remove(deferredinstall_tool[1]);
				(void)reboot(RB_AUTOBOOT);
				exit(EXIT_FAILURE);
			} else {
				launchctl_log(LOG_NOTICE, "Deferred install script exited with status %i. Continuing boot and hoping it'll work...", WEXITSTATUS(status));
				(void)remove(deferredinstall_tool[1]);
			}
		}
	}

	empty_dir(_PATH_VARRUN, NULL);
	empty_dir(_PATH_TMP, NULL);
	(void)remove(_PATH_NOLOGIN);

	if (path_check("/usr/libexec/dirhelper")) {
		const char *dirhelper_tool[] = { "/usr/libexec/dirhelper", "-machineBoot", NULL };
		(void)posix_assumes_zero(fwexec(dirhelper_tool, NULL));
	}

	(void)posix_assumes_zero(touch_file(_PATH_UTMPX, DEFFILEMODE));
#if !TARGET_OS_EMBEDDED
	(void)posix_assumes_zero(touch_file(_PATH_VARRUN "/.systemStarterRunning", DEFFILEMODE));
#endif

#if HAVE_LIBAUDITD
	/* Only start auditing if not "Disabled" in auditd plist. */
	if ((lda = read_plist_file(AUDITD_PLIST_FILE, false, false)) != NULL && ((ldb = launch_data_dict_lookup(lda, LAUNCH_JOBKEY_DISABLED)) == NULL || job_disabled_logic(ldb) == false)) {
		(void)os_assumes_zero(audit_quick_start());
		launch_data_free(lda);	
	}
#else
	if (path_check("/etc/security/rc.audit")) {
		const char *audit_tool[] = { _PATH_BSHELL, "/etc/security/rc.audit", NULL };
		(void)posix_assumes_zero(fwexec(audit_tool, NULL));
	}
#endif

#if HAVE_SYSTEMSTATS
	systemstats_boot();
#endif

	do_BootCache_magic(BOOTCACHE_START);

	preheat_page_cache_hack();

	_vproc_set_global_on_demand(true);

	char *load_launchd_items[] = { "load", "-D", "all", NULL };
	int load_launchd_items_cnt = 3;

	if (is_safeboot()) {
		load_launchd_items[2] = "system";
	}

	(void)posix_assumes_zero(load_and_unload_cmd(load_launchd_items_cnt, load_launchd_items));

	/* See <rdar://problem/5066316>. */
	if (!_launchctl_apple_internal) {
		mach_timespec_t w = { 5, 0 };
		IOKitWaitQuiet(kIOMasterPortDefault, &w);
	}

	do_BootCache_magic(BOOTCACHE_TAG);

	do_bootroot_magic();

	_vproc_set_global_on_demand(false);

	(void)posix_assumes_zero(kevent(kq, NULL, 0, &kev, 1, NULL));

	/* warmd now handles cutting off the BootCache. We just kick it off. */
	(void)close(kq);
}

void
do_BootCache_magic(BootCache_action_t what)
{
	const char *bcc_tool[] = { "/usr/sbin/BootCacheControl", NULL, NULL };

	if (is_safeboot() || !path_check(bcc_tool[0])) {
		return;
	}

	switch (what) {
	case BOOTCACHE_START:
		bcc_tool[1] = "start";
		break;
	case BOOTCACHE_TAG:
		bcc_tool[1] = "tag";
		break;
	case BOOTCACHE_STOP:
		bcc_tool[1] = "stop";
		break;
	}

	fwexec(bcc_tool, NULL);
}

void
submit_job_pass(launch_data_t jobs)
{
	launch_data_t msg, resp;
	size_t i;
	int e;

	if (launch_data_array_get_count(jobs) == 0)
		return;

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	launch_data_dict_insert(msg, jobs, LAUNCH_KEY_SUBMITJOB);

	resp = launch_msg(msg);

	if (resp) {
		switch (launch_data_get_type(resp)) {
		case LAUNCH_DATA_ERRNO:
			if ((e = launch_data_get_errno(resp)))
				launchctl_log(LOG_ERR, "%s", strerror(e));
			break;
		case LAUNCH_DATA_ARRAY:
			for (i = 0; i < launch_data_array_get_count(jobs); i++) {
				launch_data_t obatind = launch_data_array_get_index(resp, i);
				launch_data_t jatind = launch_data_array_get_index(jobs, i);
				const char *lab4job = launch_data_get_string(launch_data_dict_lookup(jatind, LAUNCH_JOBKEY_LABEL));
				if (LAUNCH_DATA_ERRNO == launch_data_get_type(obatind)) {
					e = launch_data_get_errno(obatind);
					switch (e) {
					case EEXIST:
						launchctl_log(LOG_ERR, "%s: %s", lab4job, "Already loaded");
						break;
					case ESRCH:
						launchctl_log(LOG_ERR, "%s: %s", lab4job, "Not loaded");
						break;
					case ENEEDAUTH:
						launchctl_log(LOG_ERR, "%s: %s", lab4job, "Could not set security session");
					default:
						launchctl_log(LOG_ERR, "%s: %s", lab4job, strerror(e));
					case 0:
						break;
					}
				}
			}
			break;
		default:
			launchctl_log(LOG_ERR, "unknown respose from launchd!");
			break;
		}
		launch_data_free(resp);
	} else {
		launchctl_log(LOG_ERR, "launch_msg(): %s", strerror(errno));
	}

	launch_data_free(msg);
}

void
print_jobs(launch_data_t j, const char *key __attribute__((unused)), void *context __attribute__((unused)))
{
	static size_t depth = 0;
	launch_data_t lo = launch_data_dict_lookup(j, LAUNCH_JOBKEY_LABEL);
	launch_data_t pido = launch_data_dict_lookup(j, LAUNCH_JOBKEY_PID);
	launch_data_t stato = launch_data_dict_lookup(j, LAUNCH_JOBKEY_LASTEXITSTATUS);
	const char *label = launch_data_get_string(lo);
	size_t i;

	if (pido) {
		fprintf(stdout, "%lld\t-\t%s\n", launch_data_get_integer(pido), label);
	} else if (stato) {
		int wstatus = (int)launch_data_get_integer(stato);
		if (WIFEXITED(wstatus)) {
			fprintf(stdout, "-\t%d\t%s\n", WEXITSTATUS(wstatus), label);
		} else if (WIFSIGNALED(wstatus)) {
			fprintf(stdout, "-\t-%d\t%s\n", WTERMSIG(wstatus), label);
		} else {
			fprintf(stdout, "-\t???\t%s\n", label);
		}
	} else {
		fprintf(stdout, "-\t-\t%s\n", label);
	}
	for (i = 0; i < depth; i++) {
		fprintf(stdout, "\t");
	}
}

void
print_obj(launch_data_t obj, const char *key, void *context __attribute__((unused)))
{
	static size_t indent = 0;
	size_t i, c;

	for (i = 0; i < indent; i++) {
		fprintf(stdout, "\t");
	}

	if (key) {
		fprintf(stdout, "\"%s\" = ", key);
	}

	switch (launch_data_get_type(obj)) {
	case LAUNCH_DATA_STRING:
		fprintf(stdout, "\"%s\";\n", launch_data_get_string(obj));
		break;
	case LAUNCH_DATA_INTEGER:
		fprintf(stdout, "%lld;\n", launch_data_get_integer(obj));
		break;
	case LAUNCH_DATA_REAL:
		fprintf(stdout, "%f;\n", launch_data_get_real(obj));
		break;
	case LAUNCH_DATA_BOOL:
		fprintf(stdout, "%s;\n", launch_data_get_bool(obj) ? "true" : "false");
		break;
	case LAUNCH_DATA_ARRAY:
		c = launch_data_array_get_count(obj);
		fprintf(stdout, "(\n");
		indent++;
		for (i = 0; i < c; i++) {
			print_obj(launch_data_array_get_index(obj, i), NULL, NULL);
		}
		indent--;
		for (i = 0; i < indent; i++) {
			fprintf(stdout, "\t");
		}
		fprintf(stdout, ");\n");
		break;
	case LAUNCH_DATA_DICTIONARY:
		fprintf(stdout, "{\n");
		indent++;
		launch_data_dict_iterate(obj, print_obj, NULL);
		indent--;
		for (i = 0; i < indent; i++) {
			fprintf(stdout, "\t");
		}
		fprintf(stdout, "};\n");
		break;
	case LAUNCH_DATA_FD:
		fprintf(stdout, "file-descriptor-object;\n");
		break;
	case LAUNCH_DATA_MACHPORT:
		fprintf(stdout, "mach-port-object;\n");
		break;
	default:
		fprintf(stdout, "???;\n");
		break;
	}
}

ssize_t
name2num(const char *n)
{
	size_t i;

	for (i = 0; i < LIMLOOKUP_COUNT; i++) {
		if (!strcmp(limlookup[i].name, n)) {
			return limlookup[i].lim;
		}
	}
	return -1;
}

const char *
num2name(int n)
{
	size_t i;

	for (i = 0; i < LIMLOOKUP_COUNT; i++) {
		if (limlookup[i].lim == n)
			return limlookup[i].name;
	}
	return NULL;
}

const char *
lim2str(rlim_t val, char *buf)
{
	if (val == RLIM_INFINITY)
		strcpy(buf, "unlimited");
	else
		sprintf(buf, "%lld", val);
	return buf;
}

bool
str2lim(const char *buf, rlim_t *res)
{
	char *endptr;
	*res = strtoll(buf, &endptr, 10);
	if (!strcmp(buf, "unlimited")) {
		*res = RLIM_INFINITY;
		return false;
	} else if (*endptr == '\0') {
		 return false;
	}
	return true;
}

void
setup_system_context(void)
{
	if (getenv(LAUNCHD_SOCKET_ENV)) {
		return;
	}

	if (getenv(LAUNCH_ENV_KEEPCONTEXT)) {
		return;
	}

	if (geteuid() != 0) {
		launchctl_log(LOG_ERR, "You must be the root user to perform this operation.");
		return;
	}

	/* Use the system launchd's socket. */
	setenv("__USE_SYSTEM_LAUNCHD", "1", 0);

	/* Put ourselves in the system launchd's bootstrap. */
	mach_port_t rootbs = str2bsport("/");
	mach_port_deallocate(mach_task_self(), bootstrap_port);
	task_set_bootstrap_port(mach_task_self(), rootbs);
	bootstrap_port = rootbs;
}

bool
launch_data_array_append(launch_data_t a, launch_data_t o)
{
	size_t offt = launch_data_array_get_count(a);

	return launch_data_array_set_index(a, o, offt);
}

mach_port_t
str2bsport(const char *s)
{
	bool getrootbs = strcmp(s, "/") == 0;
	mach_port_t last_bport, bport = bootstrap_port;
	task_t task = mach_task_self();
	kern_return_t result;

	if (strcmp(s, "..") == 0 || getrootbs) {
		do {
			last_bport = bport;
			result = bootstrap_parent(last_bport, &bport);

			if (result == BOOTSTRAP_NOT_PRIVILEGED) {
				launchctl_log(LOG_ERR, "Permission denied");
				return 1;
			} else if (result != BOOTSTRAP_SUCCESS) {
				launchctl_log(LOG_ERR, "bootstrap_parent() %d", result);
				return 1;
			}
		} while (getrootbs && last_bport != bport);
	} else if (strcmp(s, "0") == 0 || strcmp(s, "NULL") == 0) {
		bport = MACH_PORT_NULL;
	} else {
		int pid = atoi(s);

		result = task_for_pid(mach_task_self(), pid, &task);

		if (result != KERN_SUCCESS) {
			launchctl_log(LOG_ERR, "task_for_pid() %s", mach_error_string(result));
			return 1;
		}

		result = task_get_bootstrap_port(task, &bport);

		if (result != KERN_SUCCESS) {
			launchctl_log(LOG_ERR, "Couldn't get bootstrap port: %s", mach_error_string(result));
			return 1;
		}
	}

	return bport;
}

int
bsexec_cmd(int argc, char *const argv[])
{
	kern_return_t result;
	mach_port_t bport;

	if (argc < 3) {
		launchctl_log(LOG_ERR, "usage: %s bsexec <PID> prog...", getprogname());
		return 1;
	}

	bport = str2bsport(argv[1]);

	result = task_set_bootstrap_port(mach_task_self(), bport);

	if (result != KERN_SUCCESS) {
		launchctl_log(LOG_ERR, "Couldn't switch to new bootstrap port: %s", mach_error_string(result));
		return 1;
	}

	setgid(getgid());
	setuid(getuid());

	setenv(LAUNCH_ENV_KEEPCONTEXT, "1", 1);
	if (fwexec((const char *const *)argv + 2, NULL) == -1) {
		launchctl_log(LOG_ERR, "%s bsexec failed: %s", getprogname(), strerror(errno));
		return 1;
	}

	return 0;
}

int
_bslist_cmd(mach_port_t bport, unsigned int depth, bool show_job, bool local_only)
{
	kern_return_t result;
	name_array_t service_names;
	name_array_t service_jobs;
	mach_msg_type_number_t service_cnt, service_jobs_cnt, service_active_cnt;
	bootstrap_status_array_t service_actives;
	unsigned int i;

	if (bport == MACH_PORT_NULL) {
		launchctl_log(LOG_ERR, "Invalid bootstrap port");
		return 1;
	}

	uint64_t flags = 0;
	flags |= local_only ? BOOTSTRAP_FORCE_LOCAL : 0;
	result = bootstrap_info(bport, &service_names, &service_cnt, &service_jobs, &service_jobs_cnt, &service_actives, &service_active_cnt, flags);
	if (result != BOOTSTRAP_SUCCESS) {
		launchctl_log(LOG_ERR, "bootstrap_info(): %d", result);
		return 1;
	}

#define bport_state(x)	(((x) == BOOTSTRAP_STATUS_ACTIVE) ? "A" : ((x) == BOOTSTRAP_STATUS_ON_DEMAND) ? "D" : "I")

	for (i = 0; i < service_cnt ; i++) {
		if (!show_job) {
			fprintf(stdout, "%*s%-3s%s\n", depth, "", bport_state((service_actives[i])), service_names[i]);
		} else {
			fprintf(stdout, "%*s%-3s%s (%s)\n", depth, "", bport_state((service_actives[i])), service_names[i], service_jobs[i]);
		}
	}

	return 0;
}

int
_bstree_cmd(mach_port_t bsport, unsigned int depth, bool show_jobs)
{
	if (bsport == MACH_PORT_NULL) {
		launchctl_log(LOG_ERR, "No root port!");
		return 1;
	}

	mach_port_array_t child_ports = NULL;
	name_array_t child_names = NULL;
	bootstrap_property_array_t child_props = NULL;
	unsigned int cnt = 0;

	kern_return_t kr = bootstrap_lookup_children(bsport, &child_ports, &child_names, &child_props, (mach_msg_type_number_t *)&cnt);
	if (kr != BOOTSTRAP_SUCCESS && kr != BOOTSTRAP_NO_CHILDREN) {
		if (kr == BOOTSTRAP_NOT_PRIVILEGED) {
			launchctl_log(LOG_ERR, "You must be root to perform this operation.");
		} else {
			launchctl_log(LOG_ERR, "bootstrap_lookup_children(): %d", kr);
		}

		return 1;
	}

	unsigned int i = 0;
	_bslist_cmd(bsport, depth, show_jobs, true);

	for (i = 0; i < cnt; i++) {
		char *type = NULL;
		if (child_props[i] & BOOTSTRAP_PROPERTY_PERUSER) {
			type = "Per-user";
		} else if (child_props[i] & BOOTSTRAP_PROPERTY_EXPLICITSUBSET) {
			type = "Explicit Subset";
		} else if (child_props[i] & BOOTSTRAP_PROPERTY_IMPLICITSUBSET) {
			type = "Implicit Subset";
		} else if (child_props[i] & BOOTSTRAP_PROPERTY_MOVEDSUBSET) {
			type = "Moved Subset";
		} else if (child_props[i] & BOOTSTRAP_PROPERTY_XPC_SINGLETON) {
			type = "XPC Singleton Domain";
		} else if (child_props[i] & BOOTSTRAP_PROPERTY_XPC_DOMAIN) {
			type = "XPC Private Domain";
		} else {
			type = "Unknown";
		}

		fprintf(stdout, "%*s%s (%s)/\n", depth, "", child_names[i], type);
		if (child_ports[i] != MACH_PORT_NULL) {
			_bstree_cmd(child_ports[i], depth + 4, show_jobs);
		}
	}

	return 0;
}

void
loopback_setup_ipv4(void)
{
	struct ifaliasreq ifra;
	struct ifreq ifr;
	int s;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo0");

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return;

	if (posix_assumes_zero(ioctl(s, SIOCGIFFLAGS, &ifr)) != -1) {
		ifr.ifr_flags |= IFF_UP;
		(void)posix_assumes_zero(ioctl(s, SIOCSIFFLAGS, &ifr));
	}

	memset(&ifra, 0, sizeof(ifra));
	strcpy(ifra.ifra_name, "lo0");
	((struct sockaddr_in *)&ifra.ifra_addr)->sin_family = AF_INET;
	((struct sockaddr_in *)&ifra.ifra_addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	((struct sockaddr_in *)&ifra.ifra_addr)->sin_len = sizeof(struct sockaddr_in);
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_family = AF_INET;
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_addr.s_addr = htonl(IN_CLASSA_NET);
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_len = sizeof(struct sockaddr_in);

	(void)posix_assumes_zero(ioctl(s, SIOCAIFADDR, &ifra));
	(void)close(s);
}

void
loopback_setup_ipv6(void)
{
	struct in6_aliasreq ifra6;
	struct ifreq ifr;
	int s6;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo0");

	if ((s6 = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)
		return;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo0");

	if (posix_assumes_zero(ioctl(s6, SIOCGIFFLAGS, &ifr)) != -1) {
		ifr.ifr_flags |= IFF_UP;
		(void)posix_assumes_zero(ioctl(s6, SIOCSIFFLAGS, &ifr));
	}

	memset(&ifra6, 0, sizeof(ifra6));
	strcpy(ifra6.ifra_name, "lo0");

	ifra6.ifra_addr.sin6_family = AF_INET6;
	ifra6.ifra_addr.sin6_addr = in6addr_loopback;
	ifra6.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
	ifra6.ifra_prefixmask.sin6_family = AF_INET6;
	memset(&ifra6.ifra_prefixmask.sin6_addr, 0xff, sizeof(struct in6_addr));
	ifra6.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
	ifra6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifra6.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

	if (ioctl(s6, SIOCAIFADDR_IN6, &ifra6) == -1 && errno != EEXIST) {
		(void)os_assumes_zero(errno);
	}

	(void)close(s6);
}

pid_t
fwexec(const char *const *argv, int *wstatus)
{
	int wstatus2;
	pid_t p;

	/* We'd use posix_spawnp(), but we want to workaround: 6288899 */
	if ((p = vfork()) == -1) {
		return -1;
	} else if (p == 0) {
		execvp(argv[0], (char *const *)argv);
		_exit(EXIT_FAILURE);
	}

	if (waitpid(p, wstatus ? wstatus : &wstatus2, 0) == -1) {
		return -1;
	}

	if (wstatus) {
		return p;
	} else if (WIFEXITED(wstatus2) && WEXITSTATUS(wstatus2) == EXIT_SUCCESS) {
		return p;
	}

	return -1;
}

void
do_potential_fsck(void)
{
	/* XXX: This whole function's logic needs to be redone. */

	const char *safe_fsck_tool[] = { "fsck", "-fy", NULL };
	const char *fsck_tool[] = { "fsck", "-q", NULL };
	const char *remount_tool[] = { "mount", "-uw", "/", NULL };
#if TARGET_OS_EMBEDDED
	const char *nvram_tool[] = { "/usr/sbin/nvram", "auto-boot=false", NULL };
#endif /* TARGET_OS_EMBEDDED */
	struct statfs sfs;
	int status = 0;

	if (posix_assumes_zero(statfs("/", &sfs)) == -1) {
		return;
	}

	if (!(sfs.f_flags & MNT_RDONLY)) {
		return;
	}

	if (!is_safeboot()) {
#if 0
		/* We have disabled this block for now. We need to revisit this optimization after Leopard. */
		if (sfs.f_flags & MNT_JOURNALED) {
			goto out;
		}
#endif
		launchctl_log(LOG_NOTICE, "Running fsck on the boot volume...");
		if (fwexec(fsck_tool, &status) != -1) {
			if (WEXITSTATUS(status) != 0) {
				launchctl_log(LOG_NOTICE, "fsck exited with status: %d", WEXITSTATUS(status));
			} else {
				goto out;
			}
		} else {
			launchctl_log(LOG_NOTICE, "fwexec(): %d: %s", errno, strerror(errno));
		}
	}

	launchctl_log(LOG_NOTICE, "Running safe fsck on the boot volume...");
	if (fwexec(safe_fsck_tool, &status) != -1) {
		if (WEXITSTATUS(status) != 0) {
			launchctl_log(LOG_NOTICE, "Safe fsck exited with status: %d", WEXITSTATUS(status));
		} else {
			goto out;
		}
	} else {
		launchctl_log(LOG_NOTICE, "fwexec(): %d: %s", errno, strerror(errno));
	}

	/* someday, we should keep booting read-only, but as of today, other sub-systems cannot handle that scenario */
#if TARGET_OS_EMBEDDED
	launchctl_log(LOG_NOTICE, "fsck failed! Booting into restore mode...");
	(void)posix_assumes_zero(fwexec(nvram_tool, NULL));
	(void)reboot(RB_AUTOBOOT);
#else
	launchctl_log(LOG_NOTICE, "fsck failed! Shutting down in 3 seconds.");
	sleep(3);
	(void)reboot(RB_HALT);
#endif

	return;
out:

#if TARGET_OS_EMBEDDED
	/* Once we've validated the root filesystem, kick off any
	 * tasks needed for data protection before we mount other file
	 * systems.
	 */
	init_data_protection();
#endif

	/* 
	 * Once this is fixed:
	 *
	 * <rdar://problem/3948774> Mount flag updates should be possible with NULL as the forth argument to mount()
	 *
	 * We can then do this one system call instead of calling out a full blown process.
	 *
	 * assumes(mount(sfs.f_fstypename, "/", MNT_UPDATE, NULL) != -1);
	 */
#if TARGET_OS_EMBEDDED
	if (path_check("/etc/fstab")) {
		const char *mount_tool[] = { "mount", "-vat", "nonfs", NULL };
		if (posix_assumes_zero(fwexec(mount_tool, NULL)) == -1) {
			(void)fwexec(nvram_tool, NULL);
			(void)reboot(RB_AUTOBOOT);
		}
	} else
#endif
	{
		(void)posix_assumes_zero(fwexec(remount_tool, NULL));
	}

	fix_bogus_file_metadata();
}

void
fix_bogus_file_metadata(void)
{
	// Don't do any of this on embedded: <rdar://problem/13212363>
#if !TARGET_OS_EMBEDDED
	static const struct {
		const char *path;
		const uid_t owner;
		const gid_t group;
		const mode_t needed_bits;
		const mode_t bad_bits;
		const bool create;
	} f[] = {
		{ "/sbin/launchd", 0, 0, S_IRUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH, S_ISUID|S_ISGID|S_ISVTX|S_IWOTH, false },
		{ _PATH_TMP, 0, 0, S_ISTXT|S_IRWXU|S_IRWXG|S_IRWXO, S_ISUID|S_ISGID, true },
		{ _PATH_VARTMP, 0, 0, S_ISTXT|S_IRWXU|S_IRWXG|S_IRWXO, S_ISUID|S_ISGID, true },
		{ "/var/folders", 0, 0, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, S_ISUID | S_ISGID, true },
		{ LAUNCHD_DB_PREFIX, 0, 0, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, S_IWGRP | S_IWOTH, true },
		{ LAUNCHD_DB_PREFIX "/com.apple.launchd", 0, 0, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, S_IWGRP | S_IWOTH, true },
		// Fixing <rdar://problem/7571633>.
		{ _PATH_VARDB, 0, 0, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, S_IWGRP | S_IWOTH | S_ISUID | S_ISGID, true },
		{ _PATH_VARDB "mds/", 0, 0, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, S_IWGRP | S_IWOTH | S_ISUID | S_ISGID, true },
		// Similar fix for <rdar://problem/6550172>.
		{ "/Library/StartupItems", 0, 0, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, S_IWGRP | S_IWOTH | S_ISUID | S_ISGID, true },
	};
	struct stat sb;
	size_t i;

	for (i = 0; i < (sizeof(f) / sizeof(f[0])); i++) {
		mode_t i_needed_bits;
		mode_t i_bad_bits;
		bool fix_mode = false;
		bool fix_id = false;

		if (stat(f[i].path, &sb) == -1) {
			launchctl_log(LOG_NOTICE, "Crucial filesystem check: Path not present: %s. %s", f[i].path, f[i].create ? "Will create." : "");
			if (f[i].create) {
				if (posix_assumes_zero(mkdir(f[i].path, f[i].needed_bits)) == -1) {
					continue;
				} else if (posix_assumes_zero(stat(f[i].path, &sb)) == -1) {
					continue;
				}
			} else {
				continue;
			}
		}

		i_needed_bits = ~sb.st_mode & f[i].needed_bits;
		i_bad_bits = sb.st_mode & f[i].bad_bits;

		if (i_bad_bits) {
			launchctl_log(LOG_ERR, "Crucial filesystem check: Removing bogus mode bits 0%o on path: %s", i_bad_bits, f[i].path);
			fix_mode = true;
		}
		if (i_needed_bits) {
			launchctl_log(LOG_ERR, "Crucial filesystem check: Adding missing mode bits 0%o on path: %s", i_needed_bits, f[i].path);
			fix_mode = true;
		}
		if (sb.st_uid != f[i].owner) {
			launchctl_log(LOG_ERR, "Crucial filesystem check: Fixing bogus UID %u on path: %s", sb.st_uid, f[i].path);
			fix_id = true;
		}
		if (sb.st_gid != f[i].group) {
			launchctl_log(LOG_ERR, "Crucial filesystem check: Fixing bogus GID %u on path: %s", sb.st_gid, f[i].path);
			fix_id = true;
		}

		if (fix_mode) {
			(void)posix_assumes_zero(chmod(f[i].path, (sb.st_mode & ~i_bad_bits) | i_needed_bits));
		}
		if (fix_id) {
			(void)posix_assumes_zero(chown(f[i].path, f[i].owner, f[i].group));
		}
	}
#endif
}


bool
path_check(const char *path)
{
	struct stat sb;

	if (stat(path, &sb) == 0)
		return true;
	return false;
}

bool
is_safeboot(void)
{
	int sbmib[] = { CTL_KERN, KERN_SAFEBOOT };
	uint32_t sb = 0;
	size_t sbsz = sizeof(sb);

	if (posix_assumes_zero(sysctl(sbmib, 2, &sb, &sbsz, NULL, 0)) == -1) {
		return false;
	}

	return (bool)sb;
}

bool
is_netboot(void)
{
	int nbmib[] = { CTL_KERN, KERN_NETBOOT };
	uint32_t nb = 0;
	size_t nbsz = sizeof(nb);

	if (posix_assumes_zero(sysctl(nbmib, 2, &nb, &nbsz, NULL, 0)) == -1) {
		return false;
	}

	return (bool)nb;
}

void
empty_dir(const char *thedir, struct stat *psb)
{
	struct dirent *de;
	struct stat psb2;
	DIR *od;
	int currend_dir_fd;

	if (!psb) {
		psb = &psb2;
		if (posix_assumes_zero(lstat(thedir, psb)) == -1) {
			return;
		}
	}

	if (posix_assumes_zero(currend_dir_fd = open(".", 0)) == -1) {
		return;
	}

	if (posix_assumes_zero(chdir(thedir)) == -1) {
		goto out;
	}

	if (!(od = opendir("."))) {
		(void)os_assumes_zero(errno);
		goto out;
	}

	while ((de = readdir(od))) {
		struct stat sb;

		if (strcmp(de->d_name, ".") == 0) {
			continue;
		}

		if (strcmp(de->d_name, "..") == 0) {
			continue;
		}

		if (posix_assumes_zero(lstat(de->d_name, &sb)) == -1) {
			continue;
		}

		if (psb->st_dev != sb.st_dev) {
			(void)posix_assumes_zero(unmount(de->d_name, MNT_FORCE));

			/* Let's lstat() again to see if the unmount() worked and what was
			 * under it.
			 */
			if (posix_assumes_zero(lstat(de->d_name, &sb)) == -1) {
				continue;
			}

			if (os_assumes(psb->st_dev == sb.st_dev)) {
				continue;
			}
		}

		if (S_ISDIR(sb.st_mode)) {
			empty_dir(de->d_name, &sb);
		}

		(void)posix_assumes_zero(lchflags(de->d_name, 0));
		(void)posix_assumes_zero(remove(de->d_name));
	}

	(void)closedir(od);

out:
	(void)posix_assumes_zero(fchdir(currend_dir_fd));
	(void)posix_assumes_zero(close(currend_dir_fd));
}

int
touch_file(const char *path, mode_t m)
{
	int fd = open(path, O_CREAT, m);

	if (fd == -1)
		return -1;

	return close(fd);
}

void
apply_sysctls_from_file(const char *thefile)
{
	const char *sysctl_tool[] = { "sysctl", "-w", NULL, NULL };
	size_t ln_len = 0;
	char *val, *tmpstr;
	FILE *sf;

	if (!(sf = fopen(thefile, "r")))
		return;

	while ((val = fgetln(sf, &ln_len))) {
		if (ln_len == 0) {
			continue;
		}
		if (!(tmpstr = malloc(ln_len + 1))) {
			(void)os_assumes_zero(errno);
			continue;
		}
		memcpy(tmpstr, val, ln_len);
		tmpstr[ln_len] = 0;
		val = tmpstr;

		if (val[ln_len - 1] == '\n' || val[ln_len - 1] == '\r') {
			val[ln_len - 1] = '\0';
		}

		while (*val && isspace(*val))
			val++;
		if (*val == '\0' || *val == '#') {
			goto skip_sysctl_tool;
		}
		sysctl_tool[2] = val;
		(void)posix_assumes_zero(fwexec(sysctl_tool, NULL));
skip_sysctl_tool:
		free(tmpstr);
	}

	(void)fclose(sf);
}

CFStringRef
copySystemBuildVersion(void)
{
    CFStringRef build = NULL;
    const char path[] = "/System/Library/CoreServices/SystemVersion.plist";
    CFURLRef plistURL = CFURLCreateFromFileSystemRepresentation(kCFAllocatorSystemDefault, (const uint8_t *)path, sizeof(path) - 1, false);

	CFPropertyListRef plist = NULL;
    if (plistURL && (plist = CFPropertyListCreateFromFile(plistURL))) {
		if (CFTypeCheck(plist, CFDictionary)) {
			build = (CFStringRef)CFDictionaryGetValue((CFDictionaryRef)plist, _kCFSystemVersionBuildVersionKey);
			if (build && CFTypeCheck(build, CFString)) {
				CFRetain(build);
			} else {
				build = CFSTR("99Z999");
			}
		}

		CFRelease(plist);
    } else {
		build = CFSTR("99Z999");
	}

	if (plistURL) {
		CFRelease(plistURL);
	}

    return build;
}

void
do_sysversion_sysctl(void)
{
	int mib[] = { CTL_KERN, KERN_OSVERSION };
	CFStringRef buildvers;
	char buf[1024];
	size_t bufsz = sizeof(buf);

	/* <rdar://problem/4477682> ER: launchd should set kern.osversion very early in boot */

	if (sysctl(mib, 2, buf, &bufsz, NULL, 0) == -1) {
		launchctl_log(LOG_ERR, "sysctl(): %s", strerror(errno));
		return;
	}

	if (buf[0] != '\0') {
		return;
	}

	buildvers = copySystemBuildVersion();
	if (buildvers) {
		CFStringGetCString(buildvers, buf, sizeof(buf), kCFStringEncodingUTF8);
		(void)posix_assumes_zero(sysctl(mib, 2, NULL, 0, buf, strlen(buf) + 1));
	}

	CFRelease(buildvers);
}

void
do_application_firewall_magic(int sfd, launch_data_t thejob)
{
	const char *prog = NULL, *partialprog = NULL;
	char *path, *pathtmp, **pathstmp;
	char *paths[100];
	launch_data_t tmp;

	/*
	 * Sigh...
	 * <rdar://problem/4684434> setsockopt() with the executable path as the argument
	 */

	if ((tmp = launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_PROGRAM))) {
		prog = launch_data_get_string(tmp);
	}

	if (!prog) {
		if ((tmp = launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_PROGRAMARGUMENTS))) {
			if ((tmp = launch_data_array_get_index(tmp, 0))) {
				if ((partialprog = launch_data_get_string(tmp))) {
					if (partialprog[0] == '/') {
						prog = partialprog;
					}
				}
			}
		}
	}

	if (!prog) {
		pathtmp = path = strdup(getenv("PATH"));

		pathstmp = paths;

		while ((*pathstmp = strsep(&pathtmp, ":"))) {
			if (**pathstmp != '\0') {
				pathstmp++;
			}
		}

		free(path);
		pathtmp = alloca(MAXPATHLEN);

		pathstmp = paths;

		for (; *pathstmp; pathstmp++) {
			snprintf(pathtmp, MAXPATHLEN, "%s/%s", *pathstmp, partialprog);
			if (path_check(pathtmp)) {
				prog = pathtmp;
				break;
			}
		}
	}

	if (prog != NULL) {
		/* The networking team has asked us to ignore the failure of this API if
		 * errno == ENOPROTOOPT.
		 */
		if (setsockopt(sfd, SOL_SOCKET, SO_EXECPATH, prog, (socklen_t)(strlen(prog) + 1)) == -1 && errno != ENOPROTOOPT) {
			(void)os_assumes_zero(errno);
		}
	}
}


void
preheat_page_cache_hack(void)
{
	struct dirent *de;
	DIR *thedir;

	/* Disable this hack for now */
	return;

	if ((thedir = opendir("/etc/preheat_at_boot")) == NULL) {
		return;
	}

	while ((de = readdir(thedir))) {
		struct stat sb;
		void *junkbuf;
		int fd;

		if (de->d_name[0] == '.') {
			continue;
		}

		if ((fd = open(de->d_name, O_RDONLY)) == -1) {
			continue;
		}

		if (fstat(fd, &sb) != -1) { 
			if ((sb.st_size < 10*1024*1024) && (junkbuf = malloc((size_t)sb.st_size)) != NULL) {
				ssize_t n = read(fd, junkbuf, (size_t)sb.st_size);
				if (posix_assumes_zero(n) != -1 && n != (ssize_t)sb.st_size) {
					(void)os_assumes_zero(n);
				}
				free(junkbuf);
			}
		}

		close(fd);
	}

	closedir(thedir);
}

void
do_bootroot_magic(void)
{
	const char *kextcache_tool[] = { "kextcache", "-U", "/", NULL };
	CFTypeRef bootrootProp;
	io_service_t chosen;
	int wstatus;
	pid_t p;

	chosen = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen");

	if (!os_assumes(chosen)) {
		return;
	}

	bootrootProp = IORegistryEntryCreateCFProperty(chosen, CFSTR(kBootRootActiveKey), kCFAllocatorDefault, 0);

	IOObjectRelease(chosen);

	if (!bootrootProp) {
		return;
	}

	CFRelease(bootrootProp);

	if (posix_assumes_zero(p = fwexec(kextcache_tool, &wstatus)) == -1) {
		return;
	}

	if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == EX_OSFILE) {
		(void)reboot(RB_AUTOBOOT);
	}
}

void
do_file_init(void)
{
	struct stat sb;

	if (stat("/AppleInternal", &sb) == 0 && stat("/var/db/disableAppleInternal", &sb) == -1) {
		_launchctl_apple_internal = true;
	}

	char bootargs[128];
	size_t len = sizeof(bootargs);
	int r = sysctlbyname("kern.bootargs", bootargs, &len, NULL, 0);
	if (r == 0 && (strnstr(bootargs, "-v", len) != NULL || strnstr(bootargs, "-s", len))) {
		_launchctl_verbose_boot = true;
	}

	if (stat("/var/db/.launchd_shutdown_debugging", &sb) == 0 && _launchctl_verbose_boot) {
		_launchctl_startup_debugging = true;
	}
}
