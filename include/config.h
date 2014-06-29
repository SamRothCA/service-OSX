//
//  config.h
//  service
//
//  Created by Sam Rothenberg on 6/28/14.
//
//

#ifndef service_config_h
#define service_config_h


#define LIBC_NO_LIBCRASHREPORTERCLIENT

#define kBootRootActiveKey "bootroot-active"

#define	SO_EXECPATH	0x1085


#include <TargetConditionals.h>

#if __has_include(<quarantine.h>)
#define HAVE_QUARANTINE 1
#else
#define HAVE_QUARANTINE 0
#endif

#if __has_include(<responsibility.h>)
#define HAVE_RESPONSIBILITY 1
#else
#define HAVE_RESPONSIBILITY 0
#endif

#if __has_include(<sandbox.h>)
#define HAVE_SANDBOX 1
#else
#define HAVE_SANDBOX 0
#endif

#define HAVE_LIBAUDITD !TARGET_OS_EMBEDDED

#if !TARGET_OS_EMBEDDED && __has_include(<systemstats/systemstats.h>)
#define HAVE_SYSTEMSTATS 1
#else
#define HAVE_SYSTEMSTATS 0
#endif

#endif
