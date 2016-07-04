#!/usr/bin/env python
"""
Brother Scan Key Daemon - brotherscankeyd
Frank Abelbeck (c) 2016

- Daemon registers itself with known Brother scanners via SNMP
- Daemon listens for certain UDP packets (scan button notifications)
- Daemon calls scripts according to its rules given in the configuation file
"""

import sys,os,os.path,subprocess,argparse,configparser
import socket
import linuxfd
import select
import signal
import syslog
import shlex
import errno

from pysnmp.entity.rfc3413.oneliner import cmdgen # one-liner SNMP commands
from pysnmp.proto.rfc1902 import OctetString # create SNMP variable value strings
import pysnmp.error

EPOLLRDHUP = 0x2000 # see /usr/include/sys/epoll.h, defined since kernel 2.6.17
PIDFILE    = "/tmp/brotherscankeyd.pid"
CONFIGFILE = "/usr/local/etc/brotherscankeyd.ini"


class Daemon:
	
	def __init__(self):
		"""Create a Daemon process on this machine."""
		try:
			# check if a PID file already exists
			with open(PIDFILE,"r") as f:
				self._pid = int(f.read())
			# check if given PID points to an existing process
			if subprocess.call(["/bin/ps","--pid",str(self._pid)],stdout=subprocess.DEVNULL) > 0:
				# /bin/ps failed: there is no process with this PID;
				# assume invalid PID file: remove it, reset _pid
				os.remove(PIDFILE)
				self._pid = None
		except FileNotFoundError:
			# no PID file: reset _pid
			self._pid = None
		self._doLog = False
		syslog.openlog("brotherscankeyd.py",syslog.LOG_PID,syslog.LOG_DAEMON)
	
	
	def print(self,priority=syslog.LOG_INFO,*args):
		"""The daemon's own version of print(); acts like Python's print(), but also prints
to syslog with given priority and facility "brotherscankeyd.py" if desired.

Args:
   priority: an interger; cf. syslog documentation for valid values.
   *args: one or more Python types passed to print"""
		if self._doLog:	syslog.syslog(priority," ".join(*args))
		print(*args)
	
	
	def start(self,configfile,port,doLog,daemonise=False):
		"""Start the daemon.

Args:
   configfile: a file-type object refering to an existing configuration file.
   port: an integer; the UDP port to be used by this daemon.
   doLog: a boolean; if True, the daemon will print messages to syslog.
   daemonise: a boolean; if True, the daemon will detach itself from the
              controlling terminal and continue as a background process."""
		if self._pid:
			print("Won't start because there can be only one brotherscankeyd process.")
			sys.exit(1)
		
		# process program configuration
		print("Processing configuation file")
		if not configfile:
			# no config file given: fall back to default config file in /etc
			configfile = CONFIGFILE
		try:
			# parse config
			cfg = configparser.RawConfigParser()
			cfg.optionxform = lambda option: option # don't convert to lowercase
			cfg.read_file(configfile)
			#
			# accepted ini structure:
			#  - section General
			#  - one or more Device sections not named "General" and not ending in :IMAGE, :FILE, :OCR or :EMAIL
			#  - zero or more sections ending with :IMAGE
			#  - zero or more sections ending with :FILE
			#  - zero or more sections ending with :OCR
			#  - zero or more sections ending with :EMAIL
			#
			# check section "General"
			self._firstcycle = cfg.getint("General","first cycle",fallback=3)
			self._cycle      = cfg.getint("General","cycle",fallback=300)
			self._buffersize = cfg.getint("General","buffer size",fallback=4096)
			
			# collect all device sections
			self._scanners = dict()
			self._devices  = dict()
			self._timers = dict()
			
			secDevs  = list()
			secRules = list()
			for section in cfg.sections():
				if section == "General":
					# ignore general parameters, already processed
					continue
				elif section in ("IMAGE","FILE","OCR","EMAIL") or section.endswith(":IMAGE") or section.endswith(":FILE") or section.endswith(":OCR") or section.endswith(":EMAIL"):
					# section named IMAGE|FILE|OCR|EMAIL or ending in these strings: a menu definition, add to rules
					secRules.append(section)
				elif "ip" in cfg[section].keys() and "dev" in cfg[section].keys():
					# any remaining section containing fields "ip" and "dev" is a device definition
					secDevs.append(section)
			
			# iterate over all device definitions
			devips = dict()
			devnames = dict()
			for device in secDevs:
					try:
						# create UDP transport; fails if ip is invalid
						transport = cmdgen.UdpTransportTarget((cfg[device]["ip"],161))
						timer = linuxfd.timerfd(rtc=True,nonBlocking=True)
						# map timer fileno to UDP transport: timer expires --> send new request to scanner IP
						self._timers[timer.fileno()] = timer
						self._scanners[timer.fileno()] = transport
						# activate timer, so that after self._firstcycle seconds the first request is sent
						# and then every self._cycle seconds this request is renewed
						timer.settime(self._firstcycle,self._cycle)
						# map scanner's IP address to a device name (used when processing notifications)
						if cfg[device]["ip"] in self._devices or cfg[device]["dev"] in self._devices.values():
							print(" * Not adding device {devname} because its parameters were already used")
						else:
							self._devices[cfg[device]["ip"]] = cfg[device]["dev"]
							devips[device] = cfg[device]["ip"]
							devnames[cfg[device]["ip"]] = device
							print(" * Adding device {devname} (IP={ip},dev={address})...".format(devname=device,ip=cfg[device]["ip"],address=cfg[device]["dev"]))
					except (pysnmp.error.PySnmpError,OSError):
						# pysnmp: transport target could not be set up
						# OSError: timer creation failed
						# in any case: don't add device
						pass
			
			# iterate over all rule definitions
			self._config = dict()
			for menutype in secRules:
				try:
					devname,menu = menutype.rsplit(":",1)
					devs = [devips[devname]]
				except ValueError:
					# tuple unpacking failed: must be a global IMAGE|FILE|OCR|EMAIL
					menu = menutype
					devs = self._devices.keys()
				# iterate over all found devices
				for dev in devs:
					# iterate over all entries beneath the menu type
					for entry,path in cfg[menutype].items():
						pathargs = shlex.split(path) # split path according to BASh syntax
						script = pathargs[0] # isolate script name
						if os.path.isfile(script) and os.path.isabs(script):
							# script file exists: create entry
							try:
								# add path to script for this device's menu entry
								self._config[dev][menu][entry] = pathargs
							except KeyError:
								try:
									# one of the dictionarys uninitialised:
									# step one level up, create dict
									self._config[dev][menu] = dict()
									self._config[dev][menu][entry] = pathargs
								except KeyError:
									# still one of the dictionarys uninitialised:
									# step one level up, create dict
									self._config[dev] = dict()
									self._config[dev][menu] = dict()
									self._config[dev][menu][entry] = pathargs
							print(" * Adding entry {device} / {menu} / {entry}...".format(entry=entry,menu=menu,device=devnames[dev]))
		except configparser.DuplicateSectionError:
			# one duplicate section found: invalid config, exit with error
			print("Duplicate Section found in configuration file. Terminating.")
			sys.exit(1)
		except (ValueError,TypeError,KeyError,configparser.Error):
			# invalid config: since there are no scan targets further program execution is futile
			print("Error reading the configuration file. Terminating.")
			sys.exit(1)
		
		# prepare SNMP generator
		self._generator = cmdgen.CommandGenerator()
		self._community = cmdgen.CommunityData("internal", mpModel=0) # mpModel == 0 --> SNMP version 1 
		
		# create non-blocking server socket
		try:
			print("Opening UDP socket...",end="")
			self._socket_server = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
			self._socket_server.bind(( socket.gethostbyname(socket.gethostname()), port ))
			self._socket_server.setblocking(False)
			self._hostname,self._port = self._socket_server.getsockname()
			print(" done ({0}:{1})".format(self._hostname,self._port))
		except OSError as e:
			if e.errno == errno.EADDRINUSE: # error: address already in use
				# another process is using this address
				print("Address {hostname} already in use!".format(hostname=self._hostname))
				sys.exit(1)
			elif e.errno == errno.EACCES: # error: permission denied
				# most probably a port <1024 should be bound by a non-root process
				print("Permission denied!")
				sys.exit(1)
			elif isinstance(e,socket.gaierror):
				# unexpected error...
				print("Socket error:",e)
				sys.exit(1)
		
		if daemonise:
			print("Daemonising...")
			self.daemonise() # detach from terminal
		
		self.main() # start main loop
	
	
	def stop(self):
		"""Stop the daemon by sending a SIGTERM signal"""
		if self._pid:
			os.kill(self._pid,signal.SIGTERM)
			print("Sent SIGTERM to {0}".format(self._pid))
		else:
			print("There is no process to terminate.")
	
	
	def daemonise(self):
		"""Daemonise: do a double fork to prevent zombies; second fork prevents child from
	being session leader and thus prevents it from acquire a (controlling) terminal"""
		
		# do first fork, i.e. split a child process and exit if successful
		# fork() clones the process and lets both processes continue at this
		# position; the parent process receives the child's PID as result,
		# while the child receives a 0.
		# might raise OSError
		pid = os.fork()
		if pid > 0: # fork returned a PID: this is the parent process, exit!
			sys.exit(0)
		
		# now this process continues as the first child
		# let this first child process become a session leader
		os.setsid()
		
		# do 2nd fork, i.e. split another child process and exit if successful
		# might raise OSError
		pid = os.fork()
		if pid > 0:
			# first child as a session leader should exit, thus leaving
			# child no. 2 orphaned without ability to open a controlling
			# terminal and thus preventing zombie processes
			sys.exit(0)
		
		# detach from environment
		os.chdir("/") # switch to the directory root as it's always present
		os.umask(0)   # reset file creation permissions mask to "u=rwx,g=rwx,o=rwx"
		
		# now this process continues as the second child
		# next step: redirect input/output/error file descriptors
		# try to redirect them to a logfile (may fail)
		sys.stdout.flush()
		sys.stderr.flush()
		stdin  = open(os.devnull,"r")
		stdout = open(os.devnull,"a+")
		stderr = open(os.devnull,"a+")
		os.dup2(stdin.fileno(),sys.stdin.fileno())
		os.dup2(stdout.fileno(),sys.stdout.fileno())
		os.dup2(stderr.fileno(),sys.stderr.fileno())
	
	
	def genAppNum(self,function):
		"""Generate the internal function number (=APPNUM) for given function.

Args:
   function: a string; either "IMAGE", "EMAIL", "OCR" or "FILE".

Returns:
   An integer of set (1,2,3,5).

Raises:
   ValueError: invalid function string."""
		if function == "IMAGE":
			return 1 # as seen in the wireshark dump
		elif function == "EMAIL":
			return 2
		elif function == "OCR":
			return 3
		elif function == "FILE":
			return 5
		else:
			raise ValueError
	
	
	def snmpSetRequest(self,printerTransport,function,user):
		"""Issue an SNMP set request for a Brother variable in order to register with a
printer's scan key.

According to a wireshark dump, SNMP version 1 is used with community "internal".

Args:
   printerTransport: a pySNMP UdpTransportTarget object addressing the
                     printer's SNMP service; usually port 161 UDP is used.
   function: a string, either "IMAGE", "EMAIL", "OCR" or "FILE".
   user: a string; the target name shown on the printer's display.

Raises:
   ValueError: function not in set ("IMAGE","EMAIL","OCR","FILE").
   OSError: an SNMP error occured.
   pysnmp.error.PySnmpError: malformed printer address or an SNMP error occured."""
		appnum = self.genAppNum(function)
		
		errIndication, errStatus, errIndex, varBinds = self._generator.setCmd(
			self._community,
			printerTransport,
			(
				'1.3.6.1.4.1.2435.2.3.9.2.11.1.1.0', # OID
				OctetString( # value
					'TYPE=BR;BUTTON=SCAN;USER="{user}";FUNC={function};HOST={hostname}:{port};APPNUM={appnum};DURATION=360;BRID=;'.format(
						user     = user,
						function = function,
						hostname = self._hostname,
						port     = self._port,
						appnum   = appnum
					)
				)
			)
		)
		if errIndication:
			self.print(syslog.LOG_ERR,errIndication)
		else:
			if errStatus:
				self.print(syslog.LOG_ERR,"{} at {}".format(errStatus.prettyPrint(),errIndex and varBinds[int(errIndex)-1] or '?'))
	
	
	def main(self):
		"""Main program loop"""
		
		# store the process identifier and create the PID file
		self._pid = os.getpid()
		with open(PIDFILE,"w") as f:
			f.write(str(self._pid))
		
		# prepare asynchronous I/O using epoll
		self._epoll = select.epoll()
		
		# prepare process and sequence management
		processes = dict()
		seqnum = dict()
		
		# register all timers
		for fd in self._timers.keys():
			self._epoll.register(fd,select.EPOLLIN)
		
		# register with epoll object in level-triggered mode
		# (EPOLLET = default; neccessary because the socket might hold
		# more data then a read might fetch...
		fd_server = self._socket_server.fileno()
		self._epoll.register(fd_server,select.EPOLLIN)
		
		# intercept incoming signals with signalfd and register with epoll
		self._signalfile = linuxfd.signalfd((signal.SIGTERM,signal.SIGINT),nonBlocking=True)
		self._epoll.register(self._signalfile.fileno(),select.EPOLLIN)
		# and now block these signals
		signal.pthread_sigmask(signal.SIG_SETMASK,{signal.SIGTERM,signal.SIGINT})
		
		# enter main loop
		self.isrunning = True
		while self.isrunning:
		
			# epoll.poll() has to be enclosed in try..except because
			# signals might interrupt it -- this case is intercepted and handled
			# by catching EINTR errors
			try:
				fdevents = self._epoll.poll(-1)
			except OSError as e:
				if e.errno == errno.EINTR:
					continue # system call was interrupted: enter next loop iteration
				raise # re-raise uncaught OSError
			
			for fd,fdevent in fdevents:
				
				if fd == fd_server:
					#
					# server socket became readable: new input
					#
					data,address = self._socket_server.recvfrom(self._buffersize)
					datastr = data.decode()
					self.print(syslog.LOG_INFO,"incoming UDP packet:",data,address)
					try:
						datadict = dict([i.split("=",1) for i in datastr[datastr.index("TYPE=BR;"):].split(";") if "=" in i])
					except ValueError:
						# index() failed --> no TYPE=BR field --> invalid packet
						break
					# sanity check:
					#  - scan button?
					#  - appnum corresponds to function?
					#  - correct hostname:port?
					#  - sequence number not yet seen?
					# (at least my scanner sends two identical packets)
					try:
						hostname,port = datadict["HOST"].rsplit(":",1)
						port = int(port)
						user = datadict["USER"].strip('"')
						function = datadict["FUNC"]
						button = datadict["BUTTON"]
						appnum = int(datadict["APPNUM"])
						seq = datadict["SEQ"]
					except (ValueError,KeyError):
						# erroneous message/invalid port: ignore
						break
					
					if button == "SCAN" and appnum == self.genAppNum(function) and \
						hostname == self._hostname and port == self._port and \
						seq not in seqnum.values():
						# scan button message; appnum equivalent to function name
						# correct hostname/port and sequence number not seen yet
						# -> call a script associated with given function/user name
						self.print(syslog.LOG_INFO,'scan button event "{0}/{1}" received from {2}'.format(function,user,address[0]))
						try:
							device = self._devices[address[0]]
						except KeyError:
							break # a deviced called in that is not registered? nevermind
						try:
							# call script as background process
							command = list(self._config[address[0]][function][user]) # copy script command
							command.insert(1,device) # insert device name into script command
							process = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True)
							processes[process.stdout.fileno()] = process
							seqnum[process.stdout.fileno()] = seq
							self._epoll.register(process.stdout.fileno(),select.EPOLLHUP | EPOLLRDHUP)
						except:
							# either call() failed or no script is connected to said device/function/user:
							# need to think of a way to send an error message to the scanner?
							pass
				
				elif fd in self._scanners:
					#
					# a timer expired: repeat SNMP SET requests
					#
					self._timers[fd].read() # read timer to disarm epoll on this fd
					self.print(syslog.LOG_INFO,"sending SNMP SET request to {0}:{1}...".format(*self._scanners[fd].getTransportInfo()[1]))
					for function in self._config.keys():
						for user in self._config[function].keys():
							try:
								self.snmpSetRequest(self._scanners[fd],function,user)
							except OSError:
								pass
				
				elif fd in processes:
					#
					# process management: stdout of a process hung up
					#
					if processes[fd].poll() != None:
						# process has not yet terminated, but stdout hung up: zombie? kill it
						processes[fd].kill()
					# print stdout and sterr, reps.
					self.print(syslog.LOG_INFO,processes[fd].stdout.read())
					if processes[fd].returncode != 0:
						self.print(syslog.LOG_ERR,processes[fd].stderr.read())
					# unregister stdout fileno
					self._epoll.unregister(fd)
					# remove from list
					del processes[fd]
					del seqnum[fd]
				
				elif fd == self._signalfile.fileno():
					#
					# pending signal
					#
					try:
						siginfo = self._signalfile.read()
						if siginfo["signo"] == signal.SIGTERM:
							# should terminate: end loop
							self.print(syslog.LOG_INFO,"received SIGTERM: terminating...")
							self.isrunning = False
						# SIGINT is silently ignored
					except:
						pass
		
		# daemon is terminating...
		os.remove(PIDFILE)
		syslog.closelog()


if __name__ == '__main__':
	# setup argument parser and parse commandline arguments
	parser = argparse.ArgumentParser(
		formatter_class=argparse.RawDescriptionHelpFormatter,
		description="Start or manage a Brother Scan Key Daemon.",
		epilog="""Configuration file layout (ini file style):
   [General]
   ; General parameters; this example shows the default values;
   ;   first cycle: delay in seconds until first SNMP request is sent;
   ;   cycle: delay in seconds between consecutive SNMP requests;
   ;   buffer size: number of bytes to read when new UDP packets arrive.
   first cycle = 3
   cycle = 300
   buffer size = 4096
   ; If one or all of these parameters are not defined, the program will fall
   ; back to the default values.
   
   [Device Name]
   ; definition of device "Device Name"
   ip = hostname.or.ip.address
   dev = sane device address
   
   ; What follows are optional entries for the scanners' various scan-to menus;
   ; definitions here will create an entry of given name below the given menu
   ; of each device defined above.
   ; When activated, the given _absolute_ script path is called and the device
   ; address is passed as first argument; if any arguments are specified
   ; (cf. FILE/"Another entry"), these will be passed as 2nd arg and following.
   ;
   ; To define a device-specific menu entry, prepend a colon : and the device
   ; name (see above) to FILE|IMAGE|OCR|EMAIL (cf. entry OCR)
   
   ; menu: scan to file
   [FILE]
   Entry name = /absolute/path/to/scanscript
   Another entry = /absolute/path/to/scanscript arg1 arg2

   ; menu: scan to image
   [IMAGE]
   Entry name = /absolute/path/to/scanscript

   ; menu: scan to OCR/text file; here only specific to device "Device Name"
   [Device Name:OCR]
   Entry name = /absolute/path/to/scanscript

   ; menu: scan to e-mail
   [EMAIL]
   Entry name = /absolute/path/to/scanscript
""")
	parser.add_argument("command",choices=("start","daemon","stop"),help="start, start daemonised or stop this daemon")
	parser.add_argument("-c","--config",metavar="CFG",type=argparse.FileType("r"),help="load configuration file CFG")
	parser.add_argument("-p","--port",metavar="PORT",type=int,default=54925,help="use UDP port PORT (default 54925)")
	parser.add_argument("-s","--syslog",action='store_true',help="write information to syslog")
	# default port 54925: it seems Brother scanners address their notifications to this UDP port,
	# ignoring the port value passed via SNMP request?
	# cf. Brother website: 54925 = scanning, 54926 = PC fax receiving
	args = parser.parse_args()
	
	# create daemon and execute given command
	daemon = Daemon()
	if args.command == "start":
		daemon.start(args.config,args.port,args.syslog)
	elif args.command == "daemon":
		daemon.start(args.config,args.port,args.syslog,daemonise=True)
	elif args.command == "stop":
		daemon.stop()

