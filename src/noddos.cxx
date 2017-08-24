/*
   Copyright 2017 Steven Hessing

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

 * noddos.cxx
 *
 *  Created on: Mar 11, 2017
 *      Author: steven
 */
#include <map>
#include <string>
#include <system_error>

#include <ctime>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <unordered_set>
#include <csignal>
#include <sys/epoll.h>
#include <stdlib.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <stdio.h>
#include <net/if.h>
#include <getopt.h>

#include <curl/curl.h>

#include "noddosconfig.h"
#include "HostCache.h"
#include "SsdpServer.h"
#include "FlowTrack.h"
#include "iDeviceInfoSource.h"
#include "DeviceProfile.h"
#include "Host.h"
#include "PacketSnoop.h"
#include "InterfaceMap.h"
#include "Config.h"
#include "noddos.h"

#define MAXEPOLLEVENTS 64

bool drop_process_privileges(Config &inConfig);
int setup_signal_fd(int sfd);
bool add_epoll_filehandle(int epfd, std::map<int, iDeviceInfoSource *> & epollmap,  iDeviceInfoSource& i);
bool daemonize(Config &inConfig);
bool write_pidfile(std::string pidfile);
void parse_commandline(int argc, char** argv, bool& debug, std::string& configfile, bool& daemon);

int main(int argc, char** argv) {
    bool debug = false;
	std::string configfile = "/etc/noddos/noddos.conf";
	bool daemon = true;

	//
	// Process management :
	// - Command line args
	// - daemonize the process
	// - load configuration file,
	// - write pid file
	//
	parse_commandline(argc, argv, debug, configfile, daemon);

	if (daemon) {
		openlog(argv[0], LOG_NOWAIT | LOG_PID, LOG_UUCP);
	} else {
		openlog(argv[0], LOG_NOWAIT | LOG_PID | LOG_PERROR, LOG_UUCP);
	}
	Config config(configfile, debug);
	InterfaceMap ifMap(config.LanInterfaces,config.WanInterfaces, true);

	if (daemon) {
		daemonize(config);
	}
	write_pidfile(config.PidFile);

	CURLcode cc = curl_global_init(CURL_GLOBAL_ALL);
	if (cc != 0) {
	    syslog (LOG_CRIT, "Noddos: Curl init failure: %d", cc);
	}


	//
	// Set up HostCache instance
	//
	HostCache hC(ifMap, config.DnsCacheFile, config.TrafficReportInterval,
	        config.FirewallRulesFile, config.FirewallBlockTraffic, config.Debug);
	hC.loadDeviceProfiles(config.DeviceProfilesFile);
	hC.ImportDeviceProfileMatches(config.MatchFile);
	hC.Whitelists_set(config.WhitelistedIpv4Addresses, config.WhitelistedIpv6Addresses, config.WhitelistedMacAddresses);


	//
	// Set up epoll
	//
	std::map<int,iDeviceInfoSource *> epollmap;
    int epfd = epoll_create1(0);
    if (epfd < 0) {
    	syslog(LOG_CRIT, "Noddos: Can't create epoll instance");
    	throw std::system_error(errno, std::system_category());;
    }

    //
    // Signal handler for SIGHUP, SIGUSR1, SIGUSR2, SIGTERM
    //
    auto sfd = setup_signal_fd(-1);
    if (sfd < 0) {
    	syslog(LOG_ERR, "Noddos: Setting up signal fd");
    	throw std::system_error(errno, std::system_category());
    } else {
    	syslog(LOG_INFO, "Noddos: Signal FD is: %d", sfd);
        struct epoll_event event;
        memset (&event, 0, sizeof (event));
        event.data.fd = sfd;
        event.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, event.data.fd, &event) < 0) {
        	syslog(LOG_ERR, "Noddos: Can't add signal file handle to epoll");
        	throw std::system_error(errno, std::system_category());
        } else {
        	if (config.Debug) {
        		syslog(LOG_DEBUG, "Noddos: Signal file handle %d", sfd);
        	}
        }
    }

    //
    // Set up all the DeviceInfoSources
    //
    std::unordered_set<PacketSnoop *> pInstances;
    std::unordered_set<std::string> allInterfaces = config.LanInterfaces;
    allInterfaces.insert(config.WanInterfaces.begin(), config.WanInterfaces.end());
    for (auto iface: allInterfaces) {
        PacketSnoop *p = new PacketSnoop(hC, 64, config.Debug);
        p->Open(iface, 64);
        add_epoll_filehandle(epfd, epollmap, *p);
        pInstances.insert(p);
    }

    SsdpServer s(hC, 86400, "", config.Debug);
    add_epoll_filehandle(epfd, epollmap, s);

    FlowTrack ft(hC, config) ;
    ft.Open();
   	add_epoll_filehandle(epfd, epollmap, ft);

    if (config.User != "" && config.Group != "") {
    	drop_process_privileges(config);
    }
    uint32_t NextMatch = time(nullptr) + config.MatchInterval + rand() % 15;
    uint32_t NextPrune = time(nullptr) + config.PruneInterval + rand() % 15;
	uint32_t NextDeviceUpload = time(nullptr) + config.DeviceReportInterval + rand() %5;
	uint32_t NextTrafficUpload = time(nullptr) + config.TrafficReportInterval + rand() %5;

	struct epoll_event* epoll_events = static_cast<epoll_event*>(calloc(MAXEPOLLEVENTS, sizeof (epoll_event)));
	while (true) {
    	if (config.Debug) {
    		syslog(LOG_DEBUG, "Noddos: Starting epoll event wait");
    	}
		int eCnt = epoll_wait(epfd, epoll_events, MAXEPOLLEVENTS, 60000);
    	if (eCnt < 0) {
    		syslog(LOG_ERR, "Noddos: Epoll event wait error");
    	}
    	if (config.Debug) {
    		syslog(LOG_DEBUG, "Noddos: Received %d events", eCnt);
    	}
		int ev;
    	for (ev = 0; ev< eCnt; ev++) {

			if ((epoll_events[ev].events & EPOLLERR) || (epoll_events[ev].events & EPOLLHUP) ||
                    (not epoll_events[ev].events & EPOLLIN)) {
				syslog(LOG_ERR, "Noddos: Epoll event error for FD %d", epoll_events[ev].data.fd);
				epollmap.erase(epoll_events[ev].data.fd);
				if (epoll_events[ev].data.fd == ft.getFileHandle() && geteuid() == 0) {
					ft.Close();
					ft.Open();
			    	add_epoll_filehandle(epfd, epollmap, ft);
				} else {
					syslog(LOG_ERR, "Noddos: Closing file description without re-opening it %d", epoll_events[ev].data.fd);
				    close(epoll_events[ev].data.fd);
				}
			} else {
				if (config.Debug) {
					syslog(LOG_DEBUG, "Noddos: Handling event for FD %d", epoll_events[ev].data.fd);
				}
				if (epoll_events[ev].data.fd == sfd) {
					// Signal received
					if (config.Debug) {
						syslog(LOG_DEBUG, "Processing signal event");
					}
					struct signalfd_siginfo si;
 					auto res = read (sfd, &si, sizeof(si));
					if (res < 0) {
						syslog(LOG_ERR, "Noddos: reading from signal event filehandle");
                    }
					if (res != sizeof(si)) {
						syslog(LOG_ERR, "Noddos: Something wrong with reading from signal event filehandle");
                    }
					if (si.ssi_signo == SIGTERM ) {
						syslog(LOG_INFO, "Noddos: Processing signal event SIGTERM");
						goto exitprog;
					} else if (si.ssi_signo == SIGHUP) {
						syslog(LOG_INFO, "Noddos: Processing signal event SIGHUP");
						config.Load(configfile);
						hC.loadDeviceProfiles(config.DeviceProfilesFile);
					} else if (si.ssi_signo == SIGUSR1) {
						syslog(LOG_INFO, "Noddos: Processing signal event SIGUSR1");
						hC.Match();
						NextMatch = time(nullptr) + config.MatchInterval;
						hC.ExportDeviceProfileMatches(config.MatchFile, false);
						hC.ExportDeviceProfileMatches(config.DumpFile, true);
						hC.exportDnsCache(config.DnsCacheFile);
					} else if (si.ssi_signo == SIGUSR2) {
						syslog(LOG_INFO, "Noddos: Processing signal event SIGUSR2");
						hC.Match();
						hC.UploadDeviceStats(config.ClientApiCertFile, config.ClientApiKeyFile, config.DeviceReportInterval != 0);
						hC.UploadTrafficStats(config.TrafficReportInterval, config.ReportTrafficToRfc1918,
								config.ClientApiCertFile, config.ClientApiKeyFile, config.TrafficReportInterval != 0);
						NextDeviceUpload = time(nullptr) + config.DeviceReportInterval;
						NextTrafficUpload = time(nullptr) + config.TrafficReportInterval;
					} else  {
						syslog(LOG_ERR, "Noddos: Got some unhandled signal: %zu", res);
					}
					setup_signal_fd(sfd);
				} else {
					iDeviceInfoSource &i = *(epollmap[epoll_events[ev].data.fd]);
					i.processEvent(epoll_events[ev]);
				}
				auto t = time(nullptr);
				if (t > NextMatch) {
					hC.Match();
					NextMatch = time(nullptr) + config.MatchInterval;
					hC.ExportDeviceProfileMatches(config.MatchFile, false);
					hC.ExportDeviceProfileMatches(config.DumpFile, true);
				}
				if (t > NextDeviceUpload && config.DeviceReportInterval > 0) {
					hC.UploadDeviceStats(config.ClientApiCertFile, config.ClientApiKeyFile, config.DeviceReportInterval != 0);
					NextDeviceUpload = t + config.DeviceReportInterval;
				}
				if (t > NextTrafficUpload && config.TrafficReportInterval > 0) {
					if (config.Debug) {
						syslog(LOG_DEBUG, "Noddos: Starting traffic upload");
					}
					hC.UploadTrafficStats(config.TrafficReportInterval, config.ReportTrafficToRfc1918, config.ClientApiCertFile,
							config.ClientApiKeyFile, config.TrafficReportInterval != 0);
					NextTrafficUpload = t + config.TrafficReportInterval;
				}
				if (t > NextPrune) {
					if (config.Debug == true) {
						syslog(LOG_DEBUG, "Noddos: Starting prune");
					}
					hC.Prune();
					for (auto p: pInstances) {
					    p->pruneTcpSnoopInstances();
					}
					NextPrune = t + config.PruneInterval;
				}
    		}
    	}

    }
exitprog:
	hC.ExportDeviceProfileMatches(config.MatchFile);
    hC.exportDnsCache(config.DnsCacheFile);
    hC.Prune();
	s.Close();
	for (auto p: pInstances) {
	    p->Close();
	}
	ft.Close();
	close (epfd);
	close (sfd);
	closelog();
	unlink (config.PidFile.c_str());
	free (epoll_events);
	curl_global_cleanup();
}

bool add_epoll_filehandle(int epfd, std::map<int,iDeviceInfoSource*> &epollmap, iDeviceInfoSource& i) {
	struct epoll_event event;
    memset (&event, 0, sizeof (event));
	event.data.fd = i.getFileHandle();
    event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, event.data.fd, &event) < 0) {
    	syslog(LOG_ERR, "Noddos: Can't add file handle to epoll");
    	throw std::system_error(errno, std::system_category());
    }
    epollmap[event.data.fd] = &i;
    return true;
}


int setup_signal_fd (int sfd) {
	sigset_t mask;
	sigemptyset (&mask);
	sigaddset (&mask, SIGTERM);  // Terminate
	sigaddset (&mask, SIGHUP);   // Reload noddos.conf and DeviceProfiles.json
	sigaddset (&mask, SIGUSR1);  // Save basic device match info
	sigaddset (&mask, SIGUSR2);  // Save all device info and upload devices and traffic to cloud
	/* Block the signals thet we handle using signalfd(), so they don't
	 * cause signal handlers or default signal actions to execute. */
	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
	    throw std::system_error(errno, std::system_category());
	}
	return signalfd (sfd, &mask, 0);
}

bool drop_process_privileges(Config &inConfig) {
	size_t bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) {         /* Value was indeterminate */
        bufsize = 16384;         /* Should be more than enough */
    }
    if (sysconf(_SC_GETGR_R_SIZE_MAX) > bufsize) {
    	bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
    }

    struct passwd *accountresult;
    struct passwd accountdetails;

	if (getuid() != 0) {
        syslog(LOG_ERR, "Noddos: Can't change user to %s as root privileges were previously dropped", inConfig.User.c_str());
	    throw std::runtime_error ("Can't change user as no root privileges");
	} else {
		int s;
		char buf[bufsize];
		if ((s = getpwnam_r(inConfig.User.c_str(), &accountdetails, buf, bufsize, &accountresult)) != 0) {
		    if (accountresult == NULL) {
		        if (s == 0) {
		            syslog(LOG_CRIT, "Noddos: Username %s not found\n", inConfig.User.c_str());
		        } else {
		            syslog(LOG_CRIT, "Noddos: getpwnam_r");
		        }
		        throw std::system_error(errno, std::system_category());
		    }
		}
	    struct group *groupresult;
		struct group groupdetails;
		if ((s = getgrnam_r(inConfig.Group.c_str(), &groupdetails, buf, (unsigned long int) bufsize, &groupresult)) != 0) {
			if (groupresult == NULL) {
		        if (s == 0) {
		            syslog(LOG_CRIT, "Group %s not found\n", inConfig.Group.c_str());
		        } else {
		            syslog(LOG_CRIT, "getgrnam_r");
		        }
		        throw std::system_error(errno, std::system_category());
		    }
		}
		if (initgroups(inConfig.User.c_str(), groupdetails.gr_gid) != 0) {
			syslog (LOG_CRIT, "Noddos: initgroups for user %s to %d failed", inConfig.User.c_str(), groupdetails.gr_gid);
			throw std::system_error(errno, std::system_category());
		}
		if (setuid(accountdetails.pw_uid) != 0) {
			syslog (LOG_CRIT, "Noddos: dropping privileges to %d failed", accountdetails.pw_uid);
			throw std::system_error(errno, std::system_category());
		}
		if (setuid(0) != -1) {
		     syslog(LOG_CRIT, "Noddos: Managed to regain root privileges?");
		     throw std::system_error(errno, std::system_category());
		}
		syslog (LOG_NOTICE, "Noddos: Dropped process privileges to user %s and group %s", inConfig.User.c_str(), inConfig.Group.c_str());
	}
	return true;
}


bool daemonize (Config &inConfig) {
    std::ifstream ifs;
    try {
	    ifs.open(inConfig.PidFile);
	} catch (...) {
	}
	std::string origpid;
	if (ifs.is_open()) {
		ifs >> origpid;
		std::string pidprocpath = "/proc/" + origpid + "/stat";
		fprintf (stderr, "Checking if pid file %s exists\n", pidprocpath.c_str());
		struct stat buf;
		if (stat (pidprocpath.c_str(), &buf) == 0) {
		    throw std::runtime_error ("Pid file " + inConfig.PidFile + " exists and contains PID of a running process ");
		}
		fprintf (stderr, "Deleting stale pid file %s\n", pidprocpath.c_str());
		unlink(inConfig.PidFile.c_str());
		ifs.close();
	}

	// Define variables
	pid_t pid, sid;

	// Fork the current process
	pid = fork();
	// The parent process continues with a process ID greater than 0
	if(pid > 0)	{
	    fprintf (stderr, "We've forked so existing parent process\n");
	    exit(0);
	}
	// A process ID lower than 0 indicates a failure in either process
	else if(pid < 0) {
	    throw std::system_error(errno, std::system_category());
	}
	// The parent process has now terminated, and the forked child process will continue
	// (the pid of the child process was 0)

	// Since the child process is a daemon, the umask needs to be set so files and logs can be written
	umask(0);

	syslog(LOG_INFO, "Noddos: Successfully started noddos client");

	// Generate a session ID for the child process
	sid = setsid();
	// Ensure a valid SID for the child process
	if(sid < 0) {
		// Log failure and exit
		syslog(LOG_ERR, "Noddos: Could not generate session ID for child process");

		// If a new session ID could not be generated, we must terminate the child process
		// or it will be orphaned
		throw std::system_error(errno, std::system_category());
    }

    // Change the current working directory to a directory guaranteed to exist
	if((chdir("/")) < 0) {
	   // Log failure and exit
	   syslog(LOG_ERR, "Noddos: Could not change working directory to /");

	   // If our guaranteed directory does not exist, terminate the child process to ensure
	   // the daemon has not been hijacked
	   throw std::system_error(errno, std::system_category());
	}

	// A daemon cannot use the terminal, so close standard file descriptors for security reasons
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	return true;
}

bool write_pidfile(std::string pidfile) {
	std::ofstream ofs(pidfile);
	if (ofs.is_open()) {
		ofs << getpid();
		ofs.close();
	} else {
		syslog(LOG_ERR, "Noddos: Error creating PID file %s", pidfile.c_str());
		return true;
	}
	return false;

}

void parse_commandline(int argc, char** argv, bool& debug, std::string& configfile, bool& daemon) {
	int debug_flag = 0;
	int daemon_flag = 1;
	int prune_flag = 1;
	int help_flag = 0;
	while (1) {
		static struct option long_options[] = {
	        {"debug",       no_argument,       &debug_flag, 1},
	        {"nodaemon",    no_argument,       &daemon_flag, 0},
	        {"help",        no_argument,       &help_flag, 0},
	        {"configfile",  required_argument, 0, 'c'},
	        {0, 0, 0, 0}
	    };
	    /* getopt_long stores the option index here. */
	    int option_index = 0;
		int c = getopt_long (argc, argv, "dnpfhc:", long_options, &option_index);

		/* Detect the end of the options. */
	    if (c == -1) {
	    	break;
	    }
		switch (c) {
	        case 0:
	            break;
	        case 'd':
	        	debug_flag = 1;
	        	break;
	        case 'n':
	        	daemon_flag = 0;
	        	break;
	        case 'c':
	        	configfile = optarg;
	        	break;
	        case '?':
	        case 'h':
	        default:
	        	printf ("Noddos usage: -d/--debug -n/--nodaemon -c/--configfile <filename>\n");
	        	exit (0);
	    }
    }
	if (debug_flag == 1) {
		debug = true;
	}
	if (daemon_flag == 0) {
		daemon = false;
    }
}

