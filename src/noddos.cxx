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
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */
#include <map>
#include <string>
#include <system_error>
#include <future>
#include <fstream>
#include <iostream>
#include <memory>
#include <unordered_set>
#include <vector>
#include <chrono>
#include <ctime>
#include <cstring>
#include <csignal>
#include <sys/epoll.h>
#include <stdlib.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <stdio.h>
#include <net/if.h>
#include <getopt.h>

#include <curl/curl.h>

#include <glog/logging.h>

#include "noddosconfig.h"
#include "HostCache.h"
#include "SsdpServer.h"
#include "FlowTrack.h"
#include "iDeviceInfoSource.h"
#include "DeviceProfile.h"
#include "Host.h"
#include "PacketSnoop.h"
#include "WsDiscovery.h"
#include "Mdns.h"
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

/*! \brief Provides all initialization and the event loop
 *
 * Main parses command line arguments, daemonizes the process, loads the configuration file, writes the PID file,
 * initializes all the listeners and starts the main process loop. Finally, it makes sure all outbound API calls
 * complete, persists cached data to disk and exits the program.
 */
int main(int argc, char** argv) {
    bool debug = false;
	std::string configfile = "/etc/noddos/noddos.yml";
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
		google::InitGoogleLogging(argv[0]);
		FLAGS_stderrthreshold = google::FATAL;
	} else {
		google::InitGoogleLogging(argv[0]);
		FLAGS_logtostderr= true;
	}
	Config config(debug);
	try {
	    config.Load(configfile);
	} catch (std::exception& e) {
        LOG (FATAL) << "Config: couldn't open, read or parse config file" << configfile << " :" << e.what();
        exit (1);
    }
	InterfaceMap ifMap(config.LanInterfaces, config.WanInterfaces, config.DebugHostCache);

	if (daemon) {
		daemonize(config);
	}
	write_pidfile(config.PidFile);

	//
	// Set up CURL initializer
	//
	CURLcode cc = curl_global_init(CURL_GLOBAL_ALL);
	if (cc != 0) {
	    LOG(ERROR) << "Curl init failure: " << cc;
	}

	// Vector containing threads for HTTPS API calls to Noddos cloud
	std::vector<std::future<uint32_t>> futures;

	//
	// Set up HostCache instance
	//
	HostCache hC(ifMap, config.DnsCacheFile, config.TrafficReportInterval,
	        config.TrafficReportInterval > config.DeviceReportInterval ? config.TrafficReportInterval : config.DeviceReportInterval,
	        config.FirewallRulesFile, config.FirewallBlockTraffic, config.Debug && config.DebugHostCache);
	hC.loadDeviceProfiles(config.DeviceProfilesFile);
	hC.ImportDeviceProfileMatches(config.MatchFile);
	hC.Whitelists_set(config.WhitelistedIpv4Addresses, config.WhitelistedIpv6Addresses, config.WhitelistedMacAddresses);


	//
	// Set up epoll
	//
	std::map<int,iDeviceInfoSource *> epollmap;
    int epfd = epoll_create1(0);
    if (epfd < 0) {
    	PLOG(FATAL) << "Can't create epoll instance";
    	throw std::system_error(errno, std::system_category());;
    }

    //
    // Signal handler for SIGHUP, SIGUSR1, SIGUSR2, SIGTERM
    //
    auto sfd = setup_signal_fd(-1);
    if (sfd < 0) {
    	PLOG(ERROR) << "Setting up signal fd";
    	throw std::system_error(errno, std::system_category());
    } else {
    	DLOG_IF(INFO, config.DebugEvents) << "Signal FD is: " << sfd;
        struct epoll_event event;
        memset (&event, 0, sizeof (event));
        event.data.fd = sfd;
        event.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, event.data.fd, &event) < 0) {
        	LOG(ERROR) << "Can't add signal file handle to epoll";
        	throw std::system_error(errno, std::system_category());
        } else {
        	DLOG_IF(INFO, config.DebugEvents) << "Signal file handle " << sfd;
        }
    }

    //
    // Set up all the DeviceInfoSources
    //
    std::unordered_set<PacketSnoop *> pInstances;
    std::unordered_set<std::string> allInterfaces = config.LanInterfaces;
    allInterfaces.insert(config.WanInterfaces.begin(), config.WanInterfaces.end());
    for (auto iface: allInterfaces) {
        PacketSnoop *p = new PacketSnoop(hC, 64, config.Debug && config.DebugPacketSnoop);
        p->Open(iface, 64);
        add_epoll_filehandle(epfd, epollmap, *p);
        DLOG_IF(INFO, config.DebugEvents) << "PacketSnoop for interface " << iface << " file handle " << p->getFileHandle();
        pInstances.insert(p);
    }

    SsdpServer s(hC, 86400, "", config.Debug && config.DebugSsdp);
    add_epoll_filehandle(epfd, epollmap, s);
    DLOG_IF(INFO, config.DebugEvents) << "SSDP file handle " << s.getFileHandle();

    WsDiscovery w(hC, 86400, "", config.Debug && config.DebugWsDiscovery);
    add_epoll_filehandle(epfd, epollmap, w);
    DLOG_IF(INFO, config.DebugEvents) << "WS-Discovery file handle ", w.getFileHandle();

    Mdns m(hC, 86400, "", config.Debug && config.DebugMdns);
    add_epoll_filehandle(epfd, epollmap, m);
    DLOG_IF(INFO, config.DebugEvents) << "mDNS file handle " << m.getFileHandle();

    std::set<std::string> localIpAddresses = hC.getLocalIpAddresses();
    FlowTrack ft(hC, config, localIpAddresses) ;
    ft.Open();
   	add_epoll_filehandle(epfd, epollmap, ft);
    DLOG_IF(INFO, config.DebugEvents) << "FlowTrack file handle " << ft.getFileHandle();


    //
    // If User is defined in noddos config files and we drop privs then
    // we can't re-open nf_conntrack if necessary and
    // we can't manage IPsets
    //
    if (config.User != "" && config.Group != "") {
    	drop_process_privileges(config);
    	LOG(WARNING) << "Running as non-root, firewall capability disabled";
    }
    uint32_t NextMatch = time(nullptr) + config.MatchInterval + rand() % 15;
    uint32_t NextPrune = time(nullptr) + config.PruneInterval + rand() % 15;
	uint32_t NextDeviceUpload = time(nullptr) + config.DeviceReportInterval + rand() % 5;
	uint32_t NextTrafficUpload = time(nullptr) + config.TrafficReportInterval + rand() % 5;
	uint32_t NextWsDiscoveryProbe = 0; // Send out probe at first opportunity

	struct epoll_event* epoll_events = static_cast<epoll_event*>(calloc(MAXEPOLLEVENTS, sizeof (epoll_event)));

	//
	// epoll setup complete
	//

	//
	// main program loop waiting for events
	//
	while (true) {
  	    DLOG_IF(INFO, config.DebugEvents) << "Starting epoll event wait";
		int eCnt = epoll_wait(epfd, epoll_events, MAXEPOLLEVENTS, 60000);
    	if (eCnt < 0) {
    		PLOG(ERROR) << "Epoll event wait error";
    	}
    	DLOG_IF(INFO, config.DebugEvents) << "Received " << eCnt << " events";
		int ev;
    	for (ev = 0; ev< eCnt; ev++) {

			//
    	    // epoll event error handling
    	    //
    	    if ((epoll_events[ev].events & EPOLLERR) || (epoll_events[ev].events & EPOLLHUP) ||
                    (not epoll_events[ev].events & EPOLLIN)) {
				PLOG(ERROR) << "Epoll event error for FD " << epoll_events[ev].data.fd;
				epollmap.erase(epoll_events[ev].data.fd);
				if (epoll_events[ev].data.fd == ft.getFileHandle() && geteuid() == 0) {
					// Connection tracking has shown it can have hickups so we re-initiate it when that happens
				    ft.Close();
					ft.Open();
			    	add_epoll_filehandle(epfd, epollmap, ft);
				} else {
					LOG(ERROR) << "Closing file description without re-opening it ", epoll_events[ev].data.fd;
				    close(epoll_events[ev].data.fd);
				}
			} else {
			    //
			    // epoll event processing
			    //
			    DLOG_IF(INFO, config.DebugEvents) << "Handling event for FD " << epoll_events[ev].data.fd;
				if (epoll_events[ev].data.fd == sfd) {
					//
				    // Signal processing
				    //
				    DLOG_IF(INFO, config.DebugEvents) << "Processing signal event";
					struct signalfd_siginfo si;
 					auto res = read (sfd, &si, sizeof(si));
					if (res < 0) {
						PLOG(ERROR) << "reading from signal event filehandle";
                    }
					if (res != sizeof(si)) {
						LOG(ERROR) << "Something wrong with reading from signal event filehandle";
                    }
					if (si.ssi_signo == SIGTERM ) {
						DLOG(INFO) << "Processing signal event SIGTERM";
						goto exitprog;
					} else if (si.ssi_signo == SIGHUP) {
						DLOG(INFO) << "Processing signal event SIGHUP";
						try {
						    config.Load(configfile);
						} catch (std::exception& e) {
				            LOG(ERROR) << "Config: couldn't open, read or parse config file " << configfile.c_str() << ": " << e.what();
				        }
						hC.loadDeviceProfiles(config.DeviceProfilesFile);
					} else if (si.ssi_signo == SIGUSR1) {
						DLOG(INFO) << "Processing signal event SIGUSR1";
						hC.Match();
						NextMatch = time(nullptr) + config.MatchInterval;
						hC.ExportDeviceProfileMatches(config.MatchFile, false);
						hC.ExportDeviceProfileMatches(config.DumpFile, true);
						hC.exportDnsCache(config.DnsCacheFile);
					} else if (si.ssi_signo == SIGUSR2) {
						DLOG(INFO) << "Processing signal event SIGUSR2";
						hC.Match();
						hC.UploadDeviceStats(futures, config.ClientApiCertFile, config.ClientApiKeyFile, config.DeviceReportInterval != 0);
						hC.UploadTrafficStats(futures, config.TrafficReportInterval, config.ReportTrafficToRfc1918,
								config.ClientApiCertFile, config.ClientApiKeyFile, config.TrafficReportInterval != 0);
						NextDeviceUpload = time(nullptr) + config.DeviceReportInterval;
						NextTrafficUpload = time(nullptr) + config.TrafficReportInterval;
					} else  {
						LOG(ERROR) << "Got some unhandled signal: " << res;
					}
					setup_signal_fd(sfd);
				} else {
				    //
				    // event for on of the iDeviceInfoSource child classes
				    //
					iDeviceInfoSource &i = *(epollmap[epoll_events[ev].data.fd]);
					i.processEvent(epoll_events[ev]);
				}
				//
				// Timer handling
				auto t = time(nullptr);
				if (t > NextMatch) {
					hC.Match();
					NextMatch = time(nullptr) + config.MatchInterval;
					hC.ExportDeviceProfileMatches(config.MatchFile, false);
					hC.ExportDeviceProfileMatches(config.DumpFile, true);
				}
				if (t > NextDeviceUpload && config.DeviceReportInterval > 0) {
					hC.UploadDeviceStats(futures, config.ClientApiCertFile, config.ClientApiKeyFile, config.DeviceReportInterval != 0);
					NextDeviceUpload = t + config.DeviceReportInterval;
				}
				if (t > NextTrafficUpload && config.TrafficReportInterval > 0) {
				    DLOG_IF(INFO, config.DebugEvents) << "Starting traffic upload";
					hC.UploadTrafficStats(futures, config.TrafficReportInterval, config.ReportTrafficToRfc1918, config.ClientApiCertFile,
							config.ClientApiKeyFile, config.TrafficReportInterval != 0);
					NextTrafficUpload = t + config.TrafficReportInterval;
				}
				if (t > NextPrune) {
				    DLOG_IF(INFO, config.DebugEvents) << "Starting prune";
					hC.Prune(false);
					for (auto p: pInstances) {
					    p->pruneTcpSnoopInstances();
					}
					NextPrune = t + config.PruneInterval;
				}
				if (t > NextWsDiscoveryProbe && config.WsDiscoveryProbeInterval > 0) {
				    DLOG_IF(INFO, config.DebugEvents)  << "Starting WS-Discovery Probe";
				    w.Probe();
				    NextWsDiscoveryProbe = t + config.WsDiscoveryProbeInterval;
				}

    		}
    	    //
    	    // Processing of completion of HTTPS API calls
    	    //
			if (futures.size() > 0) {
			    for (auto future_it = futures.begin(); future_it != futures.end();) {
			        if (future_it->valid()) {
			            if (future_it->wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
		                        DLOG_IF(INFO, config.DebugHostCache == true) << "Upload of data returned HTTP status ", future_it->get();
			                future_it = futures.erase(future_it);
			            } else {
			                future_it++;
			            }
			        }
			    }
			}
    	}

    }
exitprog:
	hC.ExportDeviceProfileMatches(config.MatchFile);
    hC.exportDnsCache(config.DnsCacheFile);
    hC.Prune();
	s.Close();
	w.Close();
	for (auto p: pInstances) {
	    p->Close();
	}
	ft.Close();
	close (epfd);
	close (sfd);
	LOG(INFO) << "Exiting";
	unlink (config.PidFile.c_str());
	free (epoll_events);
	curl_global_cleanup();
}

/*! \brief Add a iDeviceInfoSource filehandle to the map for epoll
 *
 * Each DeviceInfoSource has a filehandle. This filehandle is added to the epoll map that the main eventloop uses
 * to wait for events to process
  */
bool add_epoll_filehandle(int epfd, std::map<int,iDeviceInfoSource*> &epollmap, iDeviceInfoSource& i) {
	struct epoll_event event;
    memset (&event, 0, sizeof (event));
	event.data.fd = i.getFileHandle();
    event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, event.data.fd, &event) < 0) {
    	PLOG(ERROR) << "Can't add file handle to epoll";
    	throw std::system_error(errno, std::system_category());
    }
    epollmap[event.data.fd] = &i;
    return true;
}


/*! \brief set up the signals that need to be acted upon
 *
 * Setup of signal mask so that certain signals are processed by the application instead of
 * by their default signal actions
 */
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

/*! \brief Run as non-root user
 *
 * Drop root privileges securely. Note that we can't re-open nf_conntrack and can't change firewall
 * rules if we run without root privileges
 */
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
        LOG(ERROR) << "Can't change user to " << inConfig.User << " as root privileges were previously dropped";
	    throw std::runtime_error ("Can't change user as no root privileges");
	} else {
		int s;
		char buf[bufsize];
		if ((s = getpwnam_r(inConfig.User.c_str(), &accountdetails, buf, bufsize, &accountresult)) != 0) {
		    if (accountresult == NULL) {
		        if (s == 0) {
		            PLOG(FATAL) << "Username %s not found\n" << inConfig.User;
		        } else {
		            PLOG(FATAL) << "getpwnam_r";
		        }
		        throw std::system_error(errno, std::system_category());
		    }
		}
	    struct group *groupresult;
		struct group groupdetails;
		if ((s = getgrnam_r(inConfig.Group.c_str(), &groupdetails, buf, (unsigned long int) bufsize, &groupresult)) != 0) {
			if (groupresult == NULL) {
		        if (s == 0) {
		            LOG(FATAL) << "Group %s not found\n" << inConfig.Group;
		        } else {
		            LOG(FATAL) << "getgrnam_r";
		        }
		        throw std::system_error(errno, std::system_category());
		    }
		}
		if (initgroups(inConfig.User.c_str(), groupdetails.gr_gid) != 0) {
			PLOG(FATAL) << "initgroups for user " << inConfig.User << " to " << groupdetails.gr_gid << " failed";
			throw std::system_error(errno, std::system_category());
		}
		if (setuid(accountdetails.pw_uid) != 0) {
			PLOG(FATAL) << "dropping privileges to " << accountdetails.pw_uid << " failed";
			throw std::system_error(errno, std::system_category());
		}
		if (setuid(0) != -1) {
		     PLOG(FATAL) << "Managed to regain root privileges?";
		     throw std::system_error(errno, std::system_category());
		}
		LOG(INFO) << "Dropped process privileges to user " << inConfig.User << " and group " << inConfig.Group;
	}
	return true;
}

/*! \brief Run as service daemon, detached from the terminal
 *
 */

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
		DLOG(INFO) << "Checking if pid file " << pidprocpath << " exists";
		struct stat buf;
		if (stat (pidprocpath.c_str(), &buf) == 0) {
		    throw std::runtime_error ("Pid file " + inConfig.PidFile + " exists and contains PID of a running process ");
		}
        DLOG(INFO) << "Deleting stale pid file " << pidprocpath;
		unlink(inConfig.PidFile.c_str());
		ifs.close();
	}

	// Define variables
	pid_t pid, sid;

	// Fork the current process
	pid = fork();
	// The parent process continues with a process ID greater than 0
	if(pid > 0)	{
	    // fprintf (stderr, "We've forked so existing parent process\n");
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

	LOG(INFO) << "Successfully started noddos client";

	// Generate a session ID for the child process
	sid = setsid();
	// Ensure a valid SID for the child process
	if(sid < 0) {
		// Log failure and exit
		PLOG(FATAL) << "Could not generate session ID for child process";

		// If a new session ID could not be generated, we must terminate the child process
		// or it will be orphaned
		throw std::system_error(errno, std::system_category());
    }

    // Change the current working directory to a directory guaranteed to exist
	if((chdir("/")) < 0) {
	   // Log failure and exit
	   PLOG(FATAL) << "Could not change working directory to /";

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

/*! \brief Write pid file to disk
 *
 * By writing the pid file to disk we avoid two processes trying to open sockets at the same time
 */
bool write_pidfile(std::string pidfile) {
	std::ofstream ofs(pidfile);
	if (ofs.is_open()) {
		ofs << getpid();
		ofs.close();
	} else {
		PLOG(ERROR) <<  "Error creating PID file " << pidfile;
		return true;
	}
	return false;

}

/*! \brief Command line parser
 *
 */
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

