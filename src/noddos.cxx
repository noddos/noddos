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

#include <sys/epoll.h>
#include <stdlib.h>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <unordered_set>
#include <csignal>
#include <sys/signalfd.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <stdio.h>

#include <getopt.h>

#include "noddosconfig.h"
#include "DnsmasqLogFile.h"
#include "HostCache.h"
#include "SsdpServer.h"
#include "FlowTrack.h"
#include "iDeviceInfoSource.h"
#include "DeviceProfile.h"
#include "Host.h"
#include "Config.h"
#include "noddos.h"

#define MAXEPOLLEVENTS 64

bool drop_process_privileges(Config &inConfig);
int setup_signal_fd(int sfd);
bool add_epoll_filehandle(int epfd, std::map<int, iDeviceInfoSource *> & epollmap,  iDeviceInfoSource& i);
bool daemonize(Config &inConfig);

void parse_commandline(int argc, char** argv, bool& debug, bool& flowtrack, std::string& configfile, bool& daemon, bool& prune);

int main(int argc, char** argv) {
    bool debug = false;
    bool flowtrack = true;
	std::string configfile = "/etc/noddos/noddos.conf";
	bool daemon = true;
	bool prune = true;

	parse_commandline(argc, argv, debug, flowtrack, configfile, daemon, prune);

	Config config(configfile, debug);

	if (daemon) {
		openlog(argv[0], LOG_NOWAIT | LOG_PID, LOG_UUCP);
		daemonize(config);
	} else
		openlog(argv[0], LOG_NOWAIT | LOG_PID | LOG_PERROR, LOG_UUCP);

	HostCache hC(config.TrafficReportInterval, config.Debug);

	hC.DeviceProfiles_load(config.DeviceProfilesFile);
	hC.ImportDeviceProfileMatches(config.MatchFile);
	hC.Whitelists_set(config.WhitelistedIpv4Addresses, config.WhitelistedIpv6Addresses, config.WhitelistedMacAddresses);
	std::map<int,iDeviceInfoSource *> epollmap;

    int epfd = epoll_create1(0);
    if (epfd < 0) {
    	syslog(LOG_CRIT, "Can't create epoll instance");
    	exit(1);
    }

    auto sfd = setup_signal_fd(-1);
    if (sfd < 0) {
    	syslog(LOG_ERR, "Setting up signal fd");
    } else {
    	syslog(LOG_INFO, "Signal FD is: %d", sfd);
    	struct epoll_event event;
        event.data.fd = sfd;
        event.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, event.data.fd, &event) < 0) {
        	syslog(LOG_ERR, "Can't add signal file handle to epoll");
        } else {
        	if (config.Debug) {
        		syslog(LOG_DEBUG, "Signal file handle %d", sfd);
        	}
        }
    }

	struct epoll_event event;


    DnsmasqLogFile f(config.DnsmasqLogFile, hC, 86400, config.Debug);
    // add_epoll_filehandle(epfd, epollmap, f);
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = f.GetFileHandle();
    syslog (LOG_INFO, "DnsmasqLogFile FD %d", event.data.fd);
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, event.data.fd, &event) < 0) {
    	syslog(LOG_ERR, "Can't add file handle to epoll");
    	return false;
    }
    epollmap[event.data.fd] = &f;

    SsdpServer s(hC, 86400, "", config.Debug);
    // add_epoll_filehandle(epfd, epollmap, s);
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = s.GetFileHandle();
    syslog (LOG_INFO, "SsdpServer FD %d", event.data.fd);
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, event.data.fd, &event) < 0) {
    	syslog(LOG_ERR, "Can't add file handle to epoll");
    	return false;
    }
    epollmap[event.data.fd] = &s;


    FlowTrack *t_ptr = nullptr;
    if (flowtrack) {
    	t_ptr = new FlowTrack(hC, config);
    	// add_epoll_filehandle(epfd, epollmap, *t_ptr);
    	event.events = EPOLLIN;
    	event.data.fd = t_ptr->GetFileHandle();
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, event.data.fd, &event) < 0) {
        	syslog(LOG_ERR, "Can't add file handle to epoll");
        	return false;
        }
        epollmap[event.data.fd] = t_ptr;
        syslog (LOG_INFO, "Conntrack FD %d", event.data.fd);
    }

    if (config.User != "" && config.Group != "") {
    	drop_process_privileges(config);
    }
	uint32_t NextPrune = time(nullptr) + config.PruneInterval + rand() % 15;
	uint32_t NextDeviceUpload = time(nullptr) + config.DeviceReportInterval + rand() %5;
	uint32_t NextTrafficUpload = time(nullptr) + config.TrafficReportInterval + rand() %5;


	struct epoll_event* epoll_events = static_cast<epoll_event*>(calloc(MAXEPOLLEVENTS, sizeof (epoll_event)));
	while (true) {
    	if (config.Debug) {
    		syslog(LOG_DEBUG, "Starting epoll event wait");
    	}
		int eCnt = epoll_wait(epfd, epoll_events, MAXEPOLLEVENTS, 60000);
    	if (eCnt < 0) {
    		syslog(LOG_ERR, "Epoll event wait error");
    	}
    	if (config.Debug) {
    		syslog(LOG_DEBUG, "Received %d events", eCnt);
    	}
		int ev;
    	for (ev = 0; ev< eCnt; ev++) {

			if ((epoll_events[ev].events & EPOLLERR) || (epoll_events[ev].events & EPOLLHUP) ||
                    (not epoll_events[ev].events & EPOLLIN)) {
				syslog(LOG_ERR, "Epoll event error for FD %d", epoll_events[ev].data.fd);
				close(epoll_events[ev].data.fd);
				epollmap.erase(epoll_events[ev].data.fd);
				if (t_ptr != nullptr && epoll_events[ev].data.fd == t_ptr->GetFileHandle() && geteuid() == 0) {
					t_ptr->Open();
			    	event.events = EPOLLIN;
			    	event.data.fd = t_ptr->GetFileHandle();
			        if (epoll_ctl(epfd, EPOLL_CTL_ADD, event.data.fd, &event) < 0) {
			        	syslog(LOG_ERR, "Can't add file handle to epoll");
			        	return false;
			        }
			        epollmap[event.data.fd] = t_ptr;
			        syslog (LOG_INFO, "Re-opened conntrack with FD %d", event.data.fd);

				}
			} else {
				if (config.Debug) {
					syslog(LOG_DEBUG, "Handling event for FD %d", epoll_events[ev].data.fd);
				}
				if (epoll_events[ev].data.fd == sfd) {
					// Signal received
					if (config.Debug) {
						syslog(LOG_DEBUG, "Processing signal event");
					}
					struct signalfd_siginfo si;
 					auto res = read (sfd, &si, sizeof(si));
					if (res < 0) {
						syslog(LOG_ERR, "reading from signal event filehandle");
                    }
					if (res != sizeof(si)) {
						syslog(LOG_ERR, "Something wrong with reading from signal event filehandle");
                    }
					if (si.ssi_signo == SIGTERM ) {
						syslog(LOG_INFO, "Processing signal event SIGTERM");
						goto exitprog;
					} else if (si.ssi_signo == SIGHUP) {
						syslog(LOG_INFO, "Processing signal event SIGHUP");
						config.Load(configfile);
						hC.DeviceProfiles_load(config.DeviceProfilesFile);
					} else if (si.ssi_signo == SIGUSR1) {
						syslog(LOG_INFO, "Processing signal event SIGUSR1");
						hC.ExportDeviceProfileMatches(config.MatchFile, false);
					} else if (si.ssi_signo == SIGUSR2) {
						syslog(LOG_INFO, "Processing signal event SIGUSR2");
						hC.Match();
						if (config.DeviceReportInterval) {
							hC.UploadDeviceStats(config.ClientApiCertFile, config.ClientApiKeyFile);
						}
						if (flowtrack && config.TrafficReportInterval) {
							hC.UploadTrafficStats(config.TrafficReportInterval, config.ReportTrafficToRfc1918, config.ClientApiCertFile, config.ClientApiKeyFile);
						}
						hC.ExportDeviceProfileMatches(config.DumpFile, true);
						NextDeviceUpload = time(nullptr) + config.DeviceReportInterval;
					} else  {
						syslog(LOG_ERR, "Got some unhandled signal: %ld", res);
					}
					setup_signal_fd(sfd);
				} else {
					iDeviceInfoSource &i = *(epollmap[epoll_events[ev].data.fd]);
					i.ProcessEvent(epoll_events[ev]);
				}
				auto t = time(nullptr);
				if (t > NextDeviceUpload) {
					if (config.Debug) {
						syslog(LOG_DEBUG, "Starting matching");
					}
					hC.Match();
					if (config.DeviceReportInterval) {
						hC.UploadDeviceStats(config.ClientApiCertFile, config.ClientApiKeyFile);
					}
					NextDeviceUpload = t + config.DeviceReportInterval;
				}
				if (t > NextTrafficUpload && flowtrack && config.TrafficReportInterval) {
					if (config.Debug) {
						syslog(LOG_DEBUG, "Starting traffic upload");
					}
					hC.UploadTrafficStats(config.TrafficReportInterval, config.ReportTrafficToRfc1918, config.ClientApiCertFile, config.ClientApiKeyFile);
					NextTrafficUpload = t + config.TrafficReportInterval;
				}
				if (prune && t > NextPrune) {
					if (config.Debug) {
						syslog(LOG_DEBUG, "Starting prune");
					}
					hC.Prune();
					NextPrune = t + config.PruneInterval;
				}
    		}
    	}

    }
exitprog:
	hC.ExportDeviceProfileMatches(config.MatchFile);
	hC.Prune();
	f.Close();
	s.Close();
	if (flowtrack && t_ptr != nullptr) {
		t_ptr->Close();
		// Is this crashing when noddos exits?
		// delete t_ptr;
	}
	close (epfd);
	close (sfd);
	closelog();
	unlink (config.PidFile.c_str());
	free (epoll_events);
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
		syslog(LOG_ERR, "sigprocmask");
		return -1;
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
		syslog(LOG_ERR, "Can't change user to %s as root privileges were previously dropped", inConfig.User.c_str());
	} else {
		int s;
		char buf[bufsize];
		if ((s = getpwnam_r(inConfig.User.c_str(), &accountdetails, buf, bufsize, &accountresult)) != 0) {
		    if (accountresult == NULL) {
		        if (s == 0) {
		            syslog(LOG_CRIT, "Username %s not found\n", inConfig.User.c_str());
		        } else {
		            syslog(LOG_CRIT, "getpwnam_r");
		        }
		        exit(EXIT_FAILURE);
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
		        exit(EXIT_FAILURE);
		    }
		}
		if (initgroups(inConfig.User.c_str(), groupdetails.gr_gid) != 0) {
			syslog (LOG_CRIT, "initgroups for user %s to %d failed", inConfig.User.c_str(), groupdetails.gr_gid);
			exit(EXIT_FAILURE);
		}
		if (setuid(accountdetails.pw_uid) != 0) {
			syslog (LOG_CRIT, "dropping privileges to %d failed", accountdetails.pw_uid);
			exit(EXIT_FAILURE);
		}
		if (setuid(0) != -1) {
		     syslog(LOG_CRIT, "Managed to regain root privileges?");
		     exit(EXIT_FAILURE);
		}
		syslog (LOG_NOTICE, "Dropped process privileges to user %s and group %s", inConfig.User.c_str(), inConfig.Group.c_str());
	}
	return true;
}

bool add_epoll_filehandle(int epfd, std::map<int,iDeviceInfoSource*> &epollmap, iDeviceInfoSource& i) {
	struct epoll_event event;
    event.data.fd = i.GetFileHandle();
    event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, event.data.fd, &event) < 0) {
    	syslog(LOG_ERR, "Can't add file handle to epoll");
    	return false;
    }
    epollmap[event.data.fd] = &i;
    return true;
}

bool daemonize (Config &inConfig) {
	std::ifstream ifs(inConfig.PidFile);
	std::string origpid;
	if (ifs.is_open()) {
		ifs >> origpid;
		std::string pidprocpath = "/proc/" + origpid + "/stat";
		fprintf (stderr, "Checking if pid file %s exists\n", pidprocpath.c_str());
		struct stat buf;
		if (stat (pidprocpath.c_str(), &buf) == 0) {
			fprintf (stderr, "Pid file %s exists and contains PID of a running process\n", inConfig.PidFile.c_str());
			exit(EXIT_FAILURE);
		}
		fprintf (stderr, "Deleting stale pid file %s\n", pidprocpath.c_str());
		unlink(inConfig.PidFile.c_str());
	}
	ifs.close();

	// Define variables
	pid_t pid, sid;

	// Fork the current process
	pid = fork();
	// The parent process continues with a process ID greater than 0
	if(pid > 0)
	{
		exit(EXIT_SUCCESS);
	}
	// A process ID lower than 0 indicates a failure in either process
	else if(pid < 0)
	{
		exit(EXIT_FAILURE);
	}
	// The parent process has now terminated, and the forked child process will continue
	// (the pid of the child process was 0)

	// Since the child process is a daemon, the umask needs to be set so files and logs can be written
	umask(0);

	syslog(LOG_INFO, "Successfully started noddos client");

	// Generate a session ID for the child process
	sid = setsid();
	// Ensure a valid SID for the child process
	if(sid < 0) {
		// Log failure and exit
		syslog(LOG_ERR, "Could not generate session ID for child process");

		// If a new session ID could not be generated, we must terminate the child process
		// or it will be orphaned
		exit(EXIT_FAILURE);
    }

    // Change the current working directory to a directory guaranteed to exist
	if((chdir("/")) < 0) {
	   // Log failure and exit
	   syslog(LOG_ERR, "Could not change working directory to /");

	   // If our guaranteed directory does not exist, terminate the child process to ensure
	   // the daemon has not been hijacked
	   exit(EXIT_FAILURE);
	}

	// A daemon cannot use the terminal, so close standard file descriptors for security reasons
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	std::ofstream ofs(inConfig.PidFile);
	if (ofs.is_open()) {
		ofs << sid;
		ofs.close();
	} else {
		syslog(LOG_ERR, "Error creating PID file %s", inConfig.PidFile.c_str());
	}

	return true;
}

void parse_commandline(int argc, char** argv, bool& debug, bool& flowtrack, std::string& configfile, bool& daemon, bool& prune) {
	int debug_flag = 0;
	int daemon_flag = 1;
	int prune_flag = 1;
	int flowtrack_flag = 1;
	int help_flag = 0;
	while (1) {
		static struct option long_options[] = {
	        {"debug",       no_argument,       &debug_flag, 1},
	        {"nodaemon",    no_argument,       &daemon_flag, 0},
	        {"noprune",     no_argument,       &prune_flag, 0},
	        {"noflowtrack", no_argument,       &flowtrack_flag, 0},
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
	        case 'p':
	        	prune_flag = 0;
	        	break;
	        case 'f':
	        	flowtrack_flag = 0;
	        	break;
	        case 'c':
	        	configfile = optarg;
	        	break;
	        case '?':
	        	break;
	        case 'h':
	        default:
	        	printf ("Noddos usage: -d/--debug -n/--nodaemon -c/--configfile <filename> -f/--noflowtrack\n");
	        	exit (0);
	    }
    }
	if (debug_flag == 1) {
		debug = true;
	}
	if (daemon_flag == 0) {
		daemon = false;
       }
	if (prune_flag == 0) {
		prune = false;
	}
	if (flowtrack_flag == 0) {
		flowtrack = false;
	}
}

