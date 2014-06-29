service-OSX
===========
  In OS X, the spawning of daemon and agent processes is handled by `launchd`, a remarkably powerful equivalent to systems such as `init` or `systemd`. While its adoption is almost entirely limited to OS X, `launchd` has in fact been open-sourced by Apple under the Apache 2 license, allowing projects such as [openlaunchd](https://github.com/rtyler/openlaunchd) to bring the technology to other platforms.

  As extensive as it is, a major shortcoming in OS X's init system is its "minimalistic" management utilities. Simple tasks such as restarting a daemon, or enabling a new one, are made less convenient by the lack of a utility similar to `/usr/bin/service` or `init.d` scripts. There is the `launchctl` utility, however this leaves much to be desired in the way of workflow, and provides shell access only to a small portion a the functionality offered by `launchd`.
  
  This project aims to take advantage of Apple's open sourcing `launchd` in order to rewrite `launchctl` as the powerful administrative tool it should have been, giving it the appropriately simple name "`service`." As a proof of concept, I have completed its first milestone; the `service` project now configures and builds entirely from source, yielding an actual, working twin of `launchctl`, ready to be modified in any way desired.
