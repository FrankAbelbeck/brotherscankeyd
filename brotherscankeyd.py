#!/usr/bin/env python
"""
Brother Scan Key Daemon - brotherscankeyd
Frank Abelbeck (c) 2016

- Daemon registers itself with the scanner via SNMP (which events to watch)
- Daemon listens for UDP packets originating at the scanner (actual event notifications)
- Daemon acts according to its rules

User = BlackBox
Scan to Image ---> HiRes image scanning, output PNG file on server
Scan to File ----> MedRes image scanning, output to PDF (OCRed) on server
"""

import sys,os.path,subprocess,argparse,configparser
import socket
import linuxfd
import select
import signal
from pysnmp.entity.rfc3413.oneliner import cmdgen # one-liner SNMP commands
from pysnmp.proto.rfc1902 import OctetString # create SNMP variable value strings


EPOLLRDHUP = 0x2000 # see /usr/include/sys/epoll.h, defined since kernel 2.6.17
PIDFILE    = "/tmp/brotherscankeyd.pid"
CONFIGFILE = "/etc/brotherscankeyd.ini"

class Daemon:
	
	def __init__(self):
		"""Create a Daemon process on this machine, opening a free UDP port."""
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
	
	
	def start(self,configfile,port,daemonise=False):
		if self._pid:
			print("There can be only one brotherscankeyd process.")
			sys.exit(1)
		
		# process program configuration
		print("Processing configuation file")
		if not configfile:
			# no config file given: fall back to default config file in /etc
			configfile = CONFIGFILE
		try:
			# parse config
			cfg = configparser.RawConfigParser(defaults={"first cycle":3,"cycle":3600,"buffer size":4096})
			cfg.optionxform = lambda option: option # don't convert to lowercase
			cfg.read_file(configfile)
			self._firstcycle = int(cfg["General"]["first cycle"])
			self._cycle      = int(cfg["General"]["cycle"])
			self._buffersize = int(cfg["General"]["buffer size"])
			# obtain menu entries
			self._config = dict()
			for menutype in ("IMAGE","FILE","OCR","EMAIL"):
				if menutype in cfg:
					self._config[menutype] = dict()
					for entry,path in cfg[menutype].items():
						if os.path.isfile(path) and os.path.isabs(path):
							self._config[menutype][entry] = path
							print("   Adding entry '{entry}' to scan-to-{type} menu...".format(entry=entry,type=menutype))
		except (ValueError,TypeError,KeyError,configparser.Error):
			# invalid config: since there are no scan targets further program execution is futile
			print("Error reading the configuration file. Terminating.")
			sys.exit(1)
		
		# prepare SNMP generator
		self._generator = cmdgen.CommandGenerator()
		self._community = cmdgen.CommunityData("internal", mpModel=0) # mpModel == 0 --> SNMP version 1 
		
		# obtain a list of known scanner IP addresses and map it to timers/device names
		devicequery = [ i.split("#")[1:] for i in subprocess.check_output(["/usr/bin/scanimage","-f",'%v # %m # %d%n']).decode().splitlines() if i.startswith("Brother") ]
		devnames    = { k.strip():v.strip() for k,v in devicequery }
		sanequery    = subprocess.check_output(["/usr/bin/brsaneconfig4","-q"]).decode().splitlines()
		
		self._scanners = dict()
		self._devices  = dict()
		self._timers = dict()
		print("Collecting list of active scanners on the net")
		while len(sanequery) > 0:
			# output of brsaneconfig4:
			#    <list of supported devices>
			# 
			#    Devices on network
			#    <list of registered devices>
			#
			# pop(): remove last item --> process query string lines from back to front
			line = sanequery.pop()
			if line.startswith("Devices on network"):
				# found delimiting string: exit iteration
				break
			else:
				# output of brsaneconfig4:
				#  0 MFC-L2720DW         "MFC-L2720DW"       I:192.168.1.3
				# we need the part after "I:" and the first word after the inital index number
				ipAddress = line.partition("I:")[2]
				name      = line.split()[1]
				# map timer fileno to UDP transport: timer expires --> send new request to scanner IP
				timer = linuxfd.timerfd(rtc=True,nonBlocking=True)
				self._timers[timer.fileno()] = timer
				self._scanners[timer.fileno()] = cmdgen.UdpTransportTarget((ipAddress,161))
				# activate timer, so that after self._firstcycle seconds the first request is sent
				# and then every self._cycle seconds this request is renewed
				timer.settime(self._firstcycle,self._cycle)
				# map scanner's IP address to a device name (used when processing notifications)
				self._devices[ipAddress] = devnames[name]
				print("   Adding device {devname} (IP {ip}, address {address}...".format(devname=name,ip=ipAddress,address=devnames[name]))
		
		# create non-blocking server socket
		
		# prepare hostname and port this client will use
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
			else:
				# unexpected error...
				print("Unknown error!")
				sys.exit(1)
		
		if daemonise:
			print("Daemonising...")
			self.daemonise() # detach from terminal
		
		self.main() # start main loop
	
	
	def stop(self):
		# send stop message via SIGTERM signal
		if self._pid:
			os.kill(self._pid,signal.SIGTERM)
			os.remove(PIDFILE)
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
	
	
	def snmpSetRequest(self,printerTransport,user,function):
		"""Issue an SNMP set request for a Brother variable in order to register with a
printer's scan key.

According to a wireshark dump, SNMP version 1 is used with community "internal".

Args:
   printerTransport: a pySNMP UdpTransportTarget object addressing the
                     printer's SNMP service; usually port 161 UDP is used.
   user: a string; the target name shown on the printer's display.
   function: a string, either "IMAGE", "EMAIL", "OCR" or "FILE".

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
		if errIndication or errStatus:
			print(errIndex,errStatus.prettyPrint(),errIndex,varBinds)
			raise OSError
	
	
	def main(self):
		"""Main program loop"""
		
		# store the process identifier and create the PID file
		self._pid = os.getpid()
		with open(PIDFILE,"w") as f:
			f.write(str(self._pid))
		
		# prepare asynchronous I/O using epoll
		self._epoll = select.epoll()
		
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
		
#
# test routine: start daemon, register FILE and IMAGE entries,
# do scan-to-image,
# do scan-to-file,
# do scan-to-file,
# stop daemon
#
#Processing configuation file
   #Adding entry 'Test entry' to scan-to-IMAGE menu...
   #Adding entry 'Test entry' to scan-to-FILE menu...
#Collecting list of active scanners on the net
   #Adding device MFC-L2720DW (IP 192.168.1.3, address brother4:net1;dev0...
#Opening UDP socket... done (192.168.1.31:54925)
#sending SNMP SET request to 192.168.1.3:161...
#incoming UDP packet: b'\x02\x00}0TYPE=BR;BUTTON=SCAN;USER="Test entry";FUNC=IMAGE;HOST=192.168.1.31:54925;APPNUM=1;P1=0;P2=0;P3=0;P4=0;REGID=13382;SEQ=3;' ('192.168.1.3', 58971)
#incoming UDP packet: b'\x02\x00}0TYPE=BR;BUTTON=SCAN;USER="Test entry";FUNC=IMAGE;HOST=192.168.1.31:54925;APPNUM=1;P1=0;P2=0;P3=0;P4=0;REGID=13382;SEQ=3;' ('192.168.1.3', 58971)
#incoming UDP packet: b'\x02\x00|0TYPE=BR;BUTTON=SCAN;USER="Test entry";FUNC=FILE;HOST=192.168.1.31:54925;APPNUM=5;P1=0;P2=0;P3=0;P4=0;REGID=13078;SEQ=4;' ('192.168.1.3', 51461)
#incoming UDP packet: b'\x02\x00|0TYPE=BR;BUTTON=SCAN;USER="Test entry";FUNC=FILE;HOST=192.168.1.31:54925;APPNUM=5;P1=0;P2=0;P3=0;P4=0;REGID=13078;SEQ=4;' ('192.168.1.3', 51461)
#incoming UDP packet: b'\x02\x00|0TYPE=BR;BUTTON=SCAN;USER="Test entry";FUNC=FILE;HOST=192.168.1.31:54925;APPNUM=5;P1=0;P2=0;P3=0;P4=0;REGID=13078;SEQ=5;' ('192.168.1.3', 57965)
#incoming UDP packet: b'\x02\x00|0TYPE=BR;BUTTON=SCAN;USER="Test entry";FUNC=FILE;HOST=192.168.1.31:54925;APPNUM=5;P1=0;P2=0;P3=0;P4=0;REGID=13078;SEQ=5;' ('192.168.1.3', 57965)
#sending SNMP SET request to 192.168.1.3:161...
#received SIGTERM: terminating...
		
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
					# server socket became readable: new input
					data,address = self._socket_server.recvfrom(self._buffersize)
					datastr = data.decode()
					print("incoming UDP packet:",data,address)
					try:
						datadict = dict([i.split("=",1) for i in datastr[datastr.index("TYPE=BR;"):].split(";") if "=" in i])
					except ValueError:
						# index() failed --> no TYPE=BR field --> invalid packet
						datadict = dict()
					# sanity check: appnum corresponds to function? correct hostname:port?
					# at least my scanner sends two identical packets
					# -> identify check: SEQ, scanner port sending the packet
					#
					# TODO: expanded sanity check with SEQ number checking
					#       call script in the background, manage PIDs (prevent blocking by script, prevent multiple scans)
					#
					hostname,port = datadict["HOST"].rsplit(":",1)
					if datadict["BUTTON"] == "SCAN" and datadict["APPNUM"] == self.genAppNum(datadict["FUNC"]) and \
						hostname == self._hostname and port == self._port and \
						"USER" in datadict and "FUNC" in datadict:
						#
						# call a script associated with given function/user name
						#
						print('scan button event "{0}/{1}" received from {2}'.format(
							datadict["FUNC"],
							datadict["USER"],
							address[0]
						))
						try:
							device = self._devices[address[0]]
						except KeyError:
							break # a deviced called in that is not registered? nevermind
						try:
							# call script in background, memorise PID?
							subprocess.call([
								self._config[datadict["FUNC"]][datadict["USER"].strip('"')],
								device
							])
						except:
							# either call() failed or no script is connected to said device/function/user:
							# call scanimage with --dont-scan as fallback
							subprocess.call(["/usr/bin/scanimage","--device-name",device,"--dont-scan"])
				
				elif fd in self._scanners:
					# a timer expired: repeat SNMP SET requests
					self._timers[fd].read() # read timer to disarm epoll on this fd
					print("sending SNMP SET request to {0}:{1}...".format(*self._scanners[fd].getTransportInfo()[1]))
					for function in self._config.keys():
						for user in self._config[function].keys():
							try:
								self.snmpSetRequest(self._scanners[fd],user,function)
							except OSError:
								pass
					
				elif fd == self._signalfile.fileno():
					# pending signal
					try:
						siginfo = self._signalfile.read()
						if siginfo["signo"] == signal.SIGTERM:
							# should terminate: end loop
							print("received SIGTERM: terminating...")
							self.isrunning = False
						# SIGINT is silently ignored
					except:
						pass


if __name__ == '__main__':
	# setup argument parser and parse commandline arguments
	parser = argparse.ArgumentParser(
		formatter_class=argparse.RawDescriptionHelpFormatter,
		description="Start or manage a Brother Scan Key Daemon.",
		epilog="""Configuration file layout (ini file style):
   [General]
   ; general parameters; example shows the default values 
   ;   first cycle: delay in seconds until first SNMP request is sent
   ;   cycle: delay in seconds between consecutive SNMP requests
   ;   buffer size: number of bytes to read when new UDP packets arrive
   first cycle = 3
   cycle = 3600
   buffer size = 4096
   
   ; what follows are optional entries for the scanner's various scan-to menus
   ; definitions here will create an entry of given name below the given menu
   ; if called a single parameter with the device name is passed to scanscript 
   
   ; menu: scan to file
   [FILE]
   Entry name = /absolute/path/to/scanscript
   ...

   ; menu: scan to image
   [IMAGE]
   Entry name = /absolute/path/to/scanscript
   ...

   ; menu: scan to OCR/text file
   [OCR]
   Entry name = /absolute/path/to/scanscript
   ...

   ; menu: scan to e-mail
   [EMAIL]
   Entry name = /absolute/path/to/scanscript
   ...
""")
	parser.add_argument("command",choices=("start","daemon","stop"),help="start, start daemonised or stop this daemon")
	parser.add_argument("-c","--config",metavar="CFG",type=argparse.FileType("r"),help="load configuration file CFG")
	parser.add_argument("-p","--port",metavar="PORT",type=int,default=54925,help="use UDP port PORT (default 54925)")
	# default port 54925: it seems Brother scanners address their notifications to this UDP port,
	# ignoring the port value passed via SNMP request?
	# cf. Brother website: 54925 = scanning, 54926 = PC fax receiving
	args = parser.parse_args()
	
	# create daemon and execute given command
	daemon = Daemon()
	if args.command == "start":
		daemon.start(args.config,args.port)
	elif args.command == "daemon":
		daemon.start(True)
	elif args.command == "stop":
		daemon.stop()

