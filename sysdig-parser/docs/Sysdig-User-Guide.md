![](https://ga-beacon.appspot.com/UA-40398182-5/sysdig/Sysdig-User-Guide?pixel)

### Table of Contents  

* [The Basics](#user-content-the-basics)  
* [Capture Files](#user-content-capture-files)  
* [Filtering](#user-content-filtering)  
* [Output Formatting](#user-content-output-formatting)  
* [Chisels](#user-content-chisels)

### The Basics

The simplest way to use sysdig is by invoking it without any argument. Doing this will cause sysdig to capture every event and write it to standard output, very much like strace does.

> $ sysdig  
34378 12:02:36.269753803 2 echo (7896) > close fd=3(<f>/usr/lib/locale/locale-archive)  
34379 12:02:36.269754164 2 echo (7896) < close res=0  
34380 12:02:36.269781699 2 echo (7896) > fstat fd=1(<f>/dev/pts/3)  
34381 12:02:36.269783882 2 echo (7896) < fstat res=0  
34382 12:02:36.269784970 2 echo (7896) > mmap  
34383 12:02:36.269786575 2 echo (7896) < mmap  
34384 12:02:36.269827674 2 echo (7896) > write fd=1(<f>/dev/pts/3) size=12  
34385 12:02:36.269839477 2 echo (7896) < write res=12 data=hello world.  
34386 12:02:36.269843986 2 echo (7896) > close fd=1(<f>/dev/pts/3)  
34387 12:02:36.269844466 2 echo (7896) < close res=0  
34388 12:02:36.269844816 2 echo (7896) > munmap  
34389 12:02:36.269850803 2 echo (7896) < munmap  
34390 12:02:36.269851915 2 echo (7896) > close fd=2(<f>/dev/pts/3)  
34391 12:02:36.269852314 2 echo (7896) < close res=0  

By default, sysdig prints the information for each event on a single line, with the following format:

```*%evt.num %evt.time %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.args```

where:
* evt.num is the incremental event number
* evt.time is the event timestamp
* evt.cpu is the CPU number where the event was captured
* proc.name is the name of the process that generated the event
* thread.tid is the TID that generated the event, which corresponds to the PID for single thread processes
* evt.dir is the event direction, > for enter events and < for exit events
* evt.type is the name of the event, e.g. 'open' or 'read'
* evt.args is the list of event arguments. In case of system calls, these tend to correspond to the system call arguments, but that’s not always the case: some system call arguments are excluded for simplicity or performance reasons.

**NOTE**: 
Not all of the system calls are currently decoded by sysdig. Non-decoded system calls are still shown in the output, but with no arguments.

By looking at the output, you can immediately spot some key differences between this output and the strace one:
* For most system calls, sysdig shows two separate entries: an enter one (marked with a ‘>’) and an exit one (marked with a ‘<’). This makes it easier to follow the output in multi-process environments.
* File descriptors are resolved. This means that, whenever possible, the FD number is followed by a human-readable representation of the FD itself: the tuple for network connections, the name for files, and so on. 
The exact format used to render an FD is the following: 
num(\<type\>resolved_string)
where: 
 * num is the FD number
 * resolved_string is the resolved representation of the FD, e.g. 127.0.0.1:40370->127.0.0.1:80 for a TCP socket
 * type is a single-letter-encoding of the fd type, and can be one of the following:
   * f for files  
    * 4 for IPv4 sockets
    * 6 for IPv6 sockets
    * u for unix sockets
    * s for signal FDs
    * e for event FDs
    * i for inotify FDs
    * t for timer FDs

At this point you should be able to understand the basics of sysdig output, but of course sysdig is a powerful tool that can show a lot of interesting things. These two blog posts will give you more details and context:
 * [Interpreting Sysdig Output](http://sysdigcloud.com/interpreting-sysdig-output/)
 * [The Fascinating World of Linux System Calls](http://sysdigcloud.com/fascinating-world-linux-system-calls/)

### Capture Files

Sysdig lets you save the captured events to disk so that they can be analyzed at a later time. The syntax is the following:

>$ sysdig –w myfile.scap

If you want to limit the number of events saved to the file to 100, you can use the –n flag:

>$ sysdig –n 100 –w myfile.scap

The -C command line flag lets you split a capture into files of a specific size. For example, use this to generate files that are 1MB in size:

> sudo sysdig -C 1 -w dump.scap

You can combine the -C flag with the -W one to tell sysdig how many files to keep. For example, this command line captures events into files that are 1MB in size, and keeps only the last 5 files on disk:

> sudo sysdig -C 1 -W 5 -w dump.scap

[See here for more details on using file rotation for continuous capture.](https://sysdig.com/sysdig-continuous-capture-with-file-rotation/)

Reading a previously saved capture file can be done with the –r flag:

>$ sysdig –r myfile.scap

Note that sysdig saves a full snapshot of the OS in each capture file (running processes, open files, user names…), and this means that no information is lost when doing offline analysis.
Note also that you can download a MAC and Windows version of sysdig. They won’t be able to do live capture, but they can be used to analyze capture files that have been gathered under Linux.

### Filtering

Now that we took care of the basics, let’s start having some fun. Sysdig’s filtering system is powerful and versatile, and is designed to look for needles in a haystack. Filters are specified at the end of the command line, like in tcpdump, and can be applied to both a live capture or a capture file. For example, let’s look at the activity of a specific command, in this case cat:
> $ ./sysdig proc.name=cat  
21368 13:10:15.384878134 1 cat (8298) < execve res=0 exe=cat args=index.html. tid=8298(cat) pid=8298(cat) ptid=1978(bash) cwd=/root fdlimit=1024  
21371 13:10:15.384948635 1 cat (8298) > brk size=0  
21372 13:10:15.384949909 1 cat (8298) < brk res=10665984  
21373 13:10:15.384976208 1 cat (8298) > mmap  
21374 13:10:15.384979452 1 cat (8298) < mmap  
21375 13:10:15.384990980 1 cat (8298) > access  
21376 13:10:15.384999211 1 cat (8298) < access  
21377 13:10:15.385008602 1 cat (8298) > open  
21378 13:10:15.385014374 1 cat (8298) < open fd=3(<f>/etc/ld.so.cache) name=/etc/ld.so.cache flags=0(O_NONE) mode=0  
21379 13:10:15.385015508 1 cat (8298) > fstat fd=3(<f>/etc/ld.so.cache)  
21380 13:10:15.385016588 1 cat (8298) < fstat res=0  
21381 13:10:15.385017033 1 cat (8298) > mmap  
21382 13:10:15.385019763 1 cat (8298) < mmap  
21383 13:10:15.385020047 1 cat (8298) > close fd=3(<f>/etc/ld.so.cache)  
21384 13:10:15.385020556 1 cat (8298) < close res=0  

As you can see, sysdig doesn’t attach to processes. It just captures everything and then lets you filter out what you’re not interested in. Filter statements can use comparison operators (=, !=, <, <=, >, >=, contains, icontains, in, exists) and can be combined using Boolean operators (and, or and not) and parentheses. For example

>$ sysdig proc.name=cat or proc.name=vi

captures the activity of both cat and vi, while

>$ sysdig proc.name!=cat and evt.type=open

shows all the files that are opened by programs that are not cat. 

#### Filtering by connection domain names

Some filters use external information such as dns information to match events and filtering expressions. See [this page](Domain-Name-Resolution-for-Connections) for more detail.

#### All Supported Filters

Filter fields are expressed as '_class.field_'. A quick way to get a list of the available classes and the fields they include is

>$ sysdig -l

As a reference, here’s a list of the fields you can use (*Note: The list changes with every new release, so make sure to use the program for the most updated one*):

```

----------------------
Field Class: fd

fd.num          the unique number identifying the file descriptor.
fd.type         type of FD. Can be 'file', 'directory', 'ipv4', 'ipv6', 'unix',
                 'pipe', 'event', 'signalfd', 'eventpoll', 'inotify' or 'signal
                fd'.
fd.typechar     type of FD as a single character. Can be 'f' for file, 4 for IP
                v4 socket, 6 for IPv6 socket, 'u' for unix socket, p for pipe, 
                'e' for eventfd, 's' for signalfd, 'l' for eventpoll, 'i' for i
                notify, 'o' for unknown.
fd.name         FD full name. If the fd is a file, this field contains the full
                 path. If the FD is a socket, this field contain the connection
                 tuple.
fd.directory    If the fd is a file, the directory that contains it.
fd.filename     If the fd is a file, the filename without the path.
fd.ip           (FILTER ONLY) matches the ip address (client or server) of the 
                fd.
fd.cip          client IP address.
fd.sip          server IP address.
fd.lip          local IP address.
fd.rip          remote IP address.
fd.port         (FILTER ONLY) matches the port (either client or server) of the
                 fd.
fd.cport        for TCP/UDP FDs, the client port.
fd.sport        for TCP/UDP FDs, server port.
fd.lport        for TCP/UDP FDs, the local port.
fd.rport        for TCP/UDP FDs, the remote port.
fd.l4proto      the IP protocol of a socket. Can be 'tcp', 'udp', 'icmp' or 'ra
                w'.
fd.sockfamily   the socket family for socket events. Can be 'ip' or 'unix'.
fd.is_server    'true' if the process owning this FD is the server endpoint in 
                the connection.
fd.uid          a unique identifier for the FD, created by chaining the FD numb
                er and the thread ID.
fd.containername
                chaining of the container ID and the FD name. Useful when tryin
                g to identify which container an FD belongs to.
fd.containerdirectory
                chaining of the container ID and the directory name. Useful whe
                n trying to identify which container a directory belongs to.
fd.proto        (FILTER ONLY) matches the protocol (either client or server) of
                 the fd.
fd.cproto       for TCP/UDP FDs, the client protocol.
fd.sproto       for TCP/UDP FDs, server protocol.
fd.lproto       for TCP/UDP FDs, the local protocol.
fd.rproto       for TCP/UDP FDs, the remote protocol.
fd.net          (FILTER ONLY) matches the IP network (client or server) of the 
                fd.
fd.cnet         (FILTER ONLY) matches the client IP network of the fd.
fd.snet         (FILTER ONLY) matches the server IP network of the fd.
fd.lnet         (FILTER ONLY) matches the local IP network of the fd.
fd.rnet         (FILTER ONLY) matches the remote IP network of the fd.
fd.connected    for TCP/UDP FDs, 'true' if the socket is connected.
fd.name_changed True when an event changes the name of an fd used by this event
                . This can occur in some cases such as udp connections where th
                e connection tuple changes.
fd.cip.name     Domain name associated with the client IP address.
fd.sip.name     Domain name associated with the server IP address.
fd.lip.name     Domain name associated with the local IP address.
fd.rip.name     Domain name associated with the remote IP address.

----------------------
Field Class: process

proc.pid        the id of the process generating the event.
proc.exe        the first command line argument (usually the executable name or
                 a custom one).
proc.name       the name (excluding the path) of the executable generating the 
                event.
proc.args       the arguments passed on the command line when starting the proc
                ess generating the event.
proc.env        the environment variables of the process generating the event.
proc.cmdline    full process command line, i.e. proc.name + proc.args.
proc.exeline    full process command line, with exe as first argument, i.e. pro
                c.exe + proc.args.
proc.cwd        the current working directory of the event.
proc.nthreads   the number of threads that the process generating the event cur
                rently has, including the main process thread.
proc.nchilds    the number of child threads that the process generating the eve
                nt currently has. This excludes the main process thread.
proc.ppid       the pid of the parent of the process generating the event.
proc.pname      the name (excluding the path) of the parent of the process gene
                rating the event.
proc.pcmdline   the full command line (proc.name + proc.args) of the parent of 
                the process generating the event.
proc.apid       the pid of one of the process ancestors. E.g. proc.apid[1] retu
                rns the parent pid, proc.apid[2] returns the grandparent pid, a
                nd so on. proc.apid[0] is the pid of the current process. proc.
                apid without arguments can be used in filters only and matches 
                any of the process ancestors, e.g. proc.apid=1234.
proc.aname      the name (excluding the path) of one of the process ancestors. 
                E.g. proc.aname[1] returns the parent name, proc.aname[2] retur
                ns the grandparent name, and so on. proc.aname[0] is the name o
                f the current process. proc.aname without arguments can be used
                 in filters only and matches any of the process ancestors, e.g.
                 proc.aname=bash.
proc.loginshellid
                the pid of the oldest shell among the ancestors of the current 
                process, if there is one. This field can be used to separate di
                fferent user sessions, and is useful in conjunction with chisel
                s like spy_user.
proc.duration   number of nanoseconds since the process started.
proc.fdopencount
                number of open FDs for the process
proc.fdlimit    maximum number of FDs the process can open.
proc.fdusage    the ratio between open FDs and maximum available FDs for the pr
                ocess.
proc.vmsize     total virtual memory for the process (as kb).
proc.vmrss      resident non-swapped memory for the process (as kb).
proc.vmswap     swapped memory for the process (as kb).
thread.pfmajor  number of major page faults since thread start.
thread.pfminor  number of minor page faults since thread start.
thread.tid      the id of the thread generating the event.
thread.ismain   'true' if the thread generating the event is the main one in th
                e process.
thread.exectime CPU time spent by the last scheduled thread, in nanoseconds. Ex
                ported by switch events only.
thread.totexectime
                Total CPU time, in nanoseconds since the beginning of the captu
                re, for the current thread. Exported by switch events only.
thread.cgroups  all the cgroups the thread belongs to, aggregated into a single
                 string.
thread.cgroup   the cgroup the thread belongs to, for a specific subsystem. E.g
                . thread.cgroup.cpuacct.
thread.vtid     the id of the thread generating the event as seen from its curr
                ent PID namespace.
proc.vpid       the id of the process generating the event as seen from its cur
                rent PID namespace.
thread.cpu      the CPU consumed by the thread in the last second.
thread.cpu.user the user CPU consumed by the thread in the last second.
thread.cpu.system
                the system CPU consumed by the thread in the last second.
thread.vmsize   For the process main thread, this is the total virtual memory f
                or the process (as kb). For the other threads, this field is ze
                ro.
thread.vmrss    For the process main thread, this is the resident non-swapped m
                emory for the process (as kb). For the other threads, this fiel
                d is zero.
proc.sid        the session id of the process generating the event.
proc.sname      the name of the current process's session leader. This is eithe
                r the process with pid=proc.sid or the eldest ancestor that has
                 the same sid as the current process.
proc.tty        The controlling terminal of the process. 0 for processes withou
                t a terminal.
proc.exepath    The full executable path of the process.
proc.vpgid      the process group id of the process generating the event, as se
                en from its current PID namespace.

----------------------
Field Class: evt

evt.num         event number.
evt.time        event timestamp as a time string that includes the nanosecond p
                art.
evt.time.s      event timestamp as a time string with no nanoseconds.
evt.datetime    event timestamp as a time string that includes the date.
evt.rawtime     absolute event timestamp, i.e. nanoseconds from epoch.
evt.rawtime.s   integer part of the event timestamp (e.g. seconds since epoch).
evt.rawtime.ns  fractional part of the absolute event timestamp.
evt.reltime     number of nanoseconds from the beginning of the capture.
evt.reltime.s   number of seconds from the beginning of the capture.
evt.reltime.ns  fractional part (in ns) of the time from the beginning of the c
                apture.
evt.latency     delta between an exit event and the correspondent enter event, 
                in nanoseconds.
evt.latency.s   integer part of the event latency delta.
evt.latency.ns  fractional part of the event latency delta.
evt.latency.human
                delta between an exit event and the correspondent enter event, 
                as a human readable string (e.g. 10.3ms).
evt.deltatime   delta between this event and the previous event, in nanoseconds
                .
evt.deltatime.s integer part of the delta between this event and the previous e
                vent.
evt.deltatime.ns
                fractional part of the delta between this event and the previou
                s event.
evt.outputtime  this depends on -t param, default is %evt.time ('h').
evt.dir         event direction can be either '>' for enter events or '<' for e
                xit events.
evt.type        The name of the event (e.g. 'open').
evt.type.is     allows one to specify an event type, and returns 1 for events t
                hat are of that type. For example, evt.type.is.open returns 1 f
                or open events, 0 for any other event.
syscall.type    For system call events, the name of the system call (e.g. 'open
                '). Unset for other events (e.g. switch or sysdig internal even
                ts). Use this field instead of evt.type if you need to make sur
                e that the filtered/printed value is actually a system call.
evt.category    The event category. Example values are 'file' (for file operati
                ons like open and close), 'net' (for network operations like so
                cket and bind), memory (for things like brk or mmap), and so on
                .
evt.cpu         number of the CPU where this event happened.
evt.args        all the event arguments, aggregated into a single string.
evt.arg         one of the event arguments specified by name or by number. Some
                 events (e.g. return codes or FDs) will be converted into a tex
                t representation when possible. E.g. 'evt.arg.fd' or 'evt.arg[0
                ]'.
evt.rawarg      one of the event arguments specified by name. E.g. 'evt.rawarg.
                fd'.
evt.info        for most events, this field returns the same value as evt.args.
                 However, for some events (like writes to /dev/log) it provides
                 higher level information coming from decoding the arguments.
evt.buffer      the binary data buffer for events that have one, like read(), r
                ecvfrom(), etc. Use this field in filters with 'contains' to se
                arch into I/O data buffers.
evt.buflen      the length of the binary data buffer for events that have one, 
                like read(), recvfrom(), etc.
evt.res         event return value, as a string. If the event failed, the resul
                t is an error code string (e.g. 'ENOENT'), otherwise the result
                 is the string 'SUCCESS'.
evt.rawres      event return value, as a number (e.g. -2). Useful for range com
                parisons.
evt.failed      'true' for events that returned an error status.
evt.is_io       'true' for events that read or write to FDs, like read(), send,
                 recvfrom(), etc.
evt.is_io_read  'true' for events that read from FDs, like read(), recv(), recv
                from(), etc.
evt.is_io_write 'true' for events that write to FDs, like write(), send(), etc.
evt.io_dir      'r' for events that read from FDs, like read(); 'w' for events 
                that write to FDs, like write().
evt.is_wait     'true' for events that make the thread wait, e.g. sleep(), sele
                ct(), poll().
evt.wait_latency
                for events that make the thread wait (e.g. sleep(), select(), p
                oll()), this is the time spent waiting for the event to return,
                 in nanoseconds.
evt.is_syslog   'true' for events that are writes to /dev/log.
evt.count       This filter field always returns 1 and can be used to count eve
                nts from inside chisels.
evt.count.error This filter field returns 1 for events that returned with an er
                ror, and can be used to count event failures from inside chisel
                s.
evt.count.error.file
                This filter field returns 1 for events that returned with an er
                ror and are related to file I/O, and can be used to count event
                 failures from inside chisels.
evt.count.error.net
                This filter field returns 1 for events that returned with an er
                ror and are related to network I/O, and can be used to count ev
                ent failures from inside chisels.
evt.count.error.memory
                This filter field returns 1 for events that returned with an er
                ror and are related to memory allocation, and can be used to co
                unt event failures from inside chisels.
evt.count.error.other
                This filter field returns 1 for events that returned with an er
                ror and are related to none of the previous categories, and can
                 be used to count event failures from inside chisels.
evt.count.exit  This filter field returns 1 for exit events, and can be used to
                 count single events from inside chisels.
evt.around      (FILTER ONLY) Accepts the event if it's around the specified ti
                me interval. The syntax is evt.around[T]=D, where T is the valu
                e returned by %evt.rawtime for the event and D is a delta in mi
                lliseconds. For example, evt.around[1404996934793590564]=1000 w
                ill return the events with timestamp with one second before the
                 timestamp and one second after it, for a total of two seconds 
                of capture.
evt.abspath     Absolute path calculated from dirfd and name during syscalls li
                ke renameat and symlinkat. Use 'evt.abspath.src' or 'evt.abspat
                h.dst' for syscalls that support multiple paths.
evt.is_open_read
                'true' for open/openat events where the path was opened for rea
                ding
evt.is_open_write
                'true' for open/openat events where the path was opened for wri
                ting

----------------------
Field Class: user

user.uid        user ID.
user.name       user name.
user.homedir    home directory of the user.
user.shell      user's shell.
user.loginuid   audit user id (auid).
user.loginname  audit user name (auid).

----------------------
Field Class: group

group.gid       group ID.
group.name      group name.

----------------------
Field Class: syslog

syslog.facility.str
                facility as a string.
syslog.facility facility as a number (0-23).
syslog.severity.str
                severity as a string. Can have one of these values: emerg, aler
                t, crit, err, warn, notice, info, debug
syslog.severity severity as a number (0-7).
syslog.message  message sent to syslog.

----------------------
Field Class: container

container.id    the container id.
container.name  the container name.
container.image the container image name (e.g. sysdig/sysdig:latest for docker,
                 ).
container.image.id
                the container image id (e.g. 6f7e2741b66b).
container.type  the container type, eg: docker or rkt
container.privileged
                true for containers running as privileged, false otherwise
container.mounts
                A space-separated list of mount information. Each item in the l
                ist has the format <source>:<dest>:<mode>:<rdrw>:<propagation>
container.mount Information about a single mount, specified by number (e.g. con
                tainer.mount[0]) or mount source (container.mount[/usr/local]).
                 The pathname can be a glob (container.mount[/usr/local/*]), in
                 which case the first matching mount will be returned. The info
                rmation has the format <source>:<dest>:<mode>:<rdrw>:<propagati
                on>. If there is no mount with the specified index or matching 
                the provided source, returns the string "none" instead of a NUL
                L value.
container.mount.source
                the mount source, specified by number (e.g. container.mount.sou
                rce[0]) or mount destination (container.mount.source[/host/lib/
                modules]). The pathname can be a glob.
container.mount.dest
                the mount destination, specified by number (e.g. container.moun
                t.dest[0]) or mount source (container.mount.dest[/lib/modules])
                . The pathname can be a glob.
container.mount.mode
                the mount mode, specified by number (e.g. container.mount.mode[
                0]) or mount source (container.mount.mode[/usr/local]). The pat
                hname can be a glob.
container.mount.rdwr
                the mount rdwr value, specified by number (e.g. container.mount
                .rdwr[0]) or mount source (container.mount.rdwr[/usr/local]). T
                he pathname can be a glob.
container.mount.propagation
                the mount propagation value, specified by number (e.g. containe
                r.mount.propagation[0]) or mount source (container.mount.propag
                ation[/usr/local]). The pathname can be a glob.
container.image.repository
                the container image repository (e.g. sysdig/sysdig).
container.image.tag
                the container image tag (e.g. stable, latest).
container.image.digest
                the container image registry digest (e.g. sha256:d977378f890d44
                5c15e51795296e4e5062f109ce6da83e0a355fc4ad8699d27).

----------------------
Field Class: fdlist

fdlist.nums     for poll events, this is a comma-separated list of the FD numbe
                rs in the 'fds' argument, returned as a string.
fdlist.names    for poll events, this is a comma-separated list of the FD names
                 in the 'fds' argument, returned as a string.
fdlist.cips     for poll events, this is a comma-separated list of the client I
                P addresses in the 'fds' argument, returned as a string.
fdlist.sips     for poll events, this is a comma-separated list of the server I
                P addresses in the 'fds' argument, returned as a string.
fdlist.cports   for TCP/UDP FDs, for poll events, this is a comma-separated lis
                t of the client TCP/UDP ports in the 'fds' argument, returned a
                s a string.
fdlist.sports   for poll events, this is a comma-separated list of the server T
                CP/UDP ports in the 'fds' argument, returned as a string.

----------------------
Field Class: k8s

k8s.pod.name    Kubernetes pod name.
k8s.pod.id      Kubernetes pod id.
k8s.pod.label   Kubernetes pod label. E.g. 'k8s.pod.label.foo'.
k8s.pod.labels  Kubernetes pod comma-separated key/value labels. E.g. 'foo1:bar
                1,foo2:bar2'.
k8s.rc.name     Kubernetes replication controller name.
k8s.rc.id       Kubernetes replication controller id.
k8s.rc.label    Kubernetes replication controller label. E.g. 'k8s.rc.label.foo
                '.
k8s.rc.labels   Kubernetes replication controller comma-separated key/value lab
                els. E.g. 'foo1:bar1,foo2:bar2'.
k8s.svc.name    Kubernetes service name (can return more than one value, concat
                enated).
k8s.svc.id      Kubernetes service id (can return more than one value, concaten
                ated).
k8s.svc.label   Kubernetes service label. E.g. 'k8s.svc.label.foo' (can return 
                more than one value, concatenated).
k8s.svc.labels  Kubernetes service comma-separated key/value labels. E.g. 'foo1
                :bar1,foo2:bar2'.
k8s.ns.name     Kubernetes namespace name.
k8s.ns.id       Kubernetes namespace id.
k8s.ns.label    Kubernetes namespace label. E.g. 'k8s.ns.label.foo'.
k8s.ns.labels   Kubernetes namespace comma-separated key/value labels. E.g. 'fo
                o1:bar1,foo2:bar2'.
k8s.rs.name     Kubernetes replica set name.
k8s.rs.id       Kubernetes replica set id.
k8s.rs.label    Kubernetes replica set label. E.g. 'k8s.rs.label.foo'.
k8s.rs.labels   Kubernetes replica set comma-separated key/value labels. E.g. '
                foo1:bar1,foo2:bar2'.
k8s.deployment.name
                Kubernetes deployment name.
k8s.deployment.id
                Kubernetes deployment id.
k8s.deployment.label
                Kubernetes deployment label. E.g. 'k8s.rs.label.foo'.
k8s.deployment.labels
                Kubernetes deployment comma-separated key/value labels. E.g. 'f
                oo1:bar1,foo2:bar2'.

----------------------
Field Class: mesos

mesos.task.name Mesos task name.
mesos.task.id   Mesos task id.
mesos.task.label
                Mesos task label. E.g. 'mesos.task.label.foo'.
mesos.task.labels
                Mesos task comma-separated key/value labels. E.g. 'foo1:bar1,fo
                o2:bar2'.
mesos.framework.name
                Mesos framework name.
mesos.framework.id
                Mesos framework id.
marathon.app.name
                Marathon app name.
marathon.app.id Marathon app id.
marathon.app.label
                Marathon app label. E.g. 'marathon.app.label.foo'.
marathon.app.labels
                Marathon app comma-separated key/value labels. E.g. 'foo1:bar1,
                foo2:bar2'.
marathon.group.name
                Marathon group name.
marathon.group.id
                Marathon group id.

----------------------
Field Class: span

span.id         ID of the span. This is a unique identifier that is used to mat
                ch the enter and exit tracer events for this span. It can also 
                be used to match different spans belonging to a trace.
span.time       time of the span's enter tracer as a human readable string that
                 includes the nanosecond part.
span.ntags      number of tags that this span has.
span.nargs      number of arguments that this span has.
span.tags       dot-separated list of all of the span's tags.
span.tag        one of the span's tags, specified by 0-based offset, e.g. 'span
                .tag[1]'. You can use a negative offset to pick elements from t
                he end of the tag list. For example, 'span.tag[-1]' returns the
                 last tag.
span.args       comma-separated list of the span's arguments.
span.arg        one of the span arguments, specified by name or by 0-based offs
                et. E.g. 'span.arg.xxx' or 'span.arg[1]'. You can use a negativ
                e offset to pick elements from the end of the tag list. For exa
                mple, 'span.arg[-1]' returns the last argument.
span.enterargs  comma-separated list of the span's enter tracer event arguments
                . For enter tracers, this is the same as evt.args. For exit tra
                cers, this is the evt.args of the corresponding enter tracer.
span.enterarg   one of the span's enter arguments, specified by name or by 0-ba
                sed offset. For enter tracer events, this is the same as evt.ar
                g. For exit tracer events, this is the evt.arg of the correspon
                ding enter event.
span.duration   delta between this span's exit tracer event and the enter trace
                r event.
span.duration.human
                delta between this span's exit tracer event and the enter event
                , as a human readable string (e.g. 10.3ms).

----------------------
Field Class: evtin

evtin.span.id   accepts all the events that are between the enter and exit trac
                ers of the spans with the given ID and are generated by the sam
                e thread that generated the tracers.
evtin.span.ntags
                accepts all the events that are between the enter and exit trac
                ers of the spans with the given number of tags and are generate
                d by the same thread that generated the tracers.
evtin.span.nargs
                accepts all the events that are between the enter and exit trac
                ers of the spans with the given number of arguments and are gen
                erated by the same thread that generated the tracers.
evtin.span.tags accepts all the events that are between the enter and exit trac
                ers of the spans with the given tags and are generated by the s
                ame thread that generated the tracers.
evtin.span.tag  accepts all the events that are between the enter and exit trac
                ers of the spans with the given tag and are generated by the sa
                me thread that generated the tracers. See the description of sp
                an.tag for information about the syntax accepted by this field.
evtin.span.args accepts all the events that are between the enter and exit trac
                ers of the spans with the given arguments and are generated by 
                the same thread that generated the tracers.
evtin.span.arg  accepts all the events that are between the enter and exit trac
                ers of the spans with the given argument and are generated by t
                he same thread that generated the tracers. See the description 
                of span.arg for information about the syntax accepted by this f
                ield.
evtin.span.p.id same as evtin.span.id, but also accepts events generated by oth
                er threads in the same process that produced the span.
evtin.span.p.ntags
                same as evtin.span.ntags, but also accepts events generated by 
                other threads in the same process that produced the span.
evtin.span.p.nargs
                same as evtin.span.nargs, but also accepts events generated by 
                other threads in the same process that produced the span.
evtin.span.p.tags
                same as evtin.span.tags, but also accepts events generated by o
                ther threads in the same process that produced the span.
evtin.span.p.tag
                same as evtin.span.tag, but also accepts events generated by ot
                her threads in the same process that produced the span.
evtin.span.p.args
                same as evtin.span.args, but also accepts events generated by o
                ther threads in the same process that produced the span.
evtin.span.p.arg
                same as evtin.span.arg, but also accepts events generated by ot
                her threads in the same process that produced the span.
evtin.span.s.id same as evtin.span.id, but also accepts events generated by the
                 script that produced the span, i.e. by the processes whose par
                ent PID is the same as the one of the process generating the sp
                an.
evtin.span.s.ntags
                same as evtin.span.id, but also accepts events generated by the
                 script that produced the span, i.e. by the processes whose par
                ent PID is the same as the one of the process generating the sp
                an.
evtin.span.s.nargs
                same as evtin.span.id, but also accepts events generated by the
                 script that produced the span, i.e. by the processes whose par
                ent PID is the same as the one of the process generating the sp
                an.
evtin.span.s.tags
                same as evtin.span.id, but also accepts events generated by the
                 script that produced the span, i.e. by the processes whose par
                ent PID is the same as the one of the process generating the sp
                an.
evtin.span.s.tag
                same as evtin.span.id, but also accepts events generated by the
                 script that produced the span, i.e. by the processes whose par
                ent PID is the same as the one of the process generating the sp
                an.
evtin.span.s.args
                same as evtin.span.id, but also accepts events generated by the
                 script that produced the span, i.e. by the processes whose par
                ent PID is the same as the one of the process generating the sp
                an.
evtin.span.s.arg
                same as evtin.span.id, but also accepts events generated by the
                 script that produced the span, i.e. by the processes whose par
                ent PID is the same as the one of the process generating the sp
                an.
evtin.span.m.id same as evtin.span.id, but accepts all the events generated on 
                the machine during the span, including other threads and other 
                processes.
evtin.span.m.ntags
                same as evtin.span.id, but accepts all the events generated on 
                the machine during the span, including other threads and other 
                processes.
evtin.span.m.nargs
                same as evtin.span.id, but accepts all the events generated on 
                the machine during the span, including other threads and other 
                processes.
evtin.span.m.tags
                same as evtin.span.id, but accepts all the events generated on 
                the machine during the span, including other threads and other 
                processes.
evtin.span.m.tag
                same as evtin.span.id, but accepts all the events generated on 
                the machine during the span, including other threads and other 
                processes.
evtin.span.m.args
                same as evtin.span.id, but accepts all the events generated on 
                the machine during the span, including other threads and other 
                processes.
evtin.span.m.arg
                same as evtin.span.id, but accepts all the events generated on 
                the machine during the span, including other threads and other 
                processes.

```

As you can see, enough to do plenty of creative digging. For example, thanks to the fact that sysdig resolves file descriptors, you can do stuff like this:

>$ sysdig evt.type=accept and proc.name!=apache

to see the incoming network connections received by processes other than apache.  
But that’s not all.  
There are a couple of special fields, evt.arg and evt.rawarg, that deserve additional explanation. Every event that sysdig captures has a type (e.g. 'open', 'read'...), and a set of parameters (e.g. 'fd', 'name'...) that are encoded using a standardize type system. I know this sounds boring, so let’s just talk about the benefits of it: any parameter of any event can be used in filters. For example this command line shows the programs that are run by interactive users:

>$ sysdig evt.type=execve and evt.arg.ptid=bash

The filter accepts the execve system calls (which are used to execute programs), but only if the parent process name is ‘bash’.
The difference between evt.arg and event.rawarg is that the second doesn’t do resolution of PIDs, FDs, error codes, etc, and leaves the argument in its raw numeric form. For example, you can use

>$ sysdig evt.arg.res=ENOENT

To filter on a specific I/O error code or, since error codes are negative, this

>$ sysdig " evt.rawarg.res<0 or evt.rawarg.fd<0"

will give you all the system calls that produced errors.
To get a list of all the events you can use in your filters, plus their parameters, type

>$ sysdig –L

And, for your reference, here’s the list, where ‘>’ indicates an enter event and ‘<’ indicates an exit event (*Note: The list changes with every new release, so make sure to use the program for the most updated one*):

```
> syscall(SYSCALLID ID, UINT16 nativeID)
< syscall(SYSCALLID ID)
> open()
< open(FD fd, FSPATH name, FLAGS32 flags, UINT32 mode)
> close(FD fd)
< close(ERRNO res)
> read(FD fd, UINT32 size)
< read(ERRNO res, BYTEBUF data)
> write(FD fd, UINT32 size)
< write(ERRNO res, BYTEBUF data)
> socket(FLAGS32 domain, UINT32 type, UINT32 proto)
< socket(FD fd)
> bind(FD fd)
< bind(ERRNO res, SOCKADDR addr)
> connect(FD fd)
< connect(ERRNO res, SOCKTUPLE tuple)
> listen(FD fd, UINT32 backlog)
< listen(ERRNO res)
> send(FD fd, UINT32 size)
< send(ERRNO res, BYTEBUF data)
> sendto(FD fd, UINT32 size, SOCKTUPLE tuple)
< sendto(ERRNO res, BYTEBUF data)
> recv(FD fd, UINT32 size)
< recv(ERRNO res, BYTEBUF data)
> recvfrom(FD fd, UINT32 size)
< recvfrom(ERRNO res, BYTEBUF data, SOCKTUPLE tuple)
> shutdown(FD fd, FLAGS8 how)
< shutdown(ERRNO res)
> getsockname()
< getsockname()
> getpeername()
< getpeername()
> socketpair(FLAGS32 domain, UINT32 type, UINT32 proto)
< socketpair(ERRNO res, FD fd1, FD fd2, UINT64 source, UINT64 peer)
> setsockopt()
< setsockopt()
> getsockopt()
< getsockopt()
> sendmsg(FD fd, UINT32 size, SOCKTUPLE tuple)
< sendmsg(ERRNO res, BYTEBUF data)
> sendmmsg()
< sendmmsg()
> recvmsg(FD fd)
< recvmsg(ERRNO res, UINT32 size, BYTEBUF data, SOCKTUPLE tuple)
> recvmmsg()
< recvmmsg()
> creat()
< creat(FD fd, FSPATH name, UINT32 mode)
> pipe()
< pipe(ERRNO res, FD fd1, FD fd2, UINT64 ino)
> eventfd(UINT64 initval, FLAGS32 flags)
< eventfd(FD res)
> futex(UINT64 addr, FLAGS16 op, UINT64 val)
< futex(ERRNO res)
> stat()
< stat(ERRNO res, FSPATH path)
> lstat()
< lstat(ERRNO res, FSPATH path)
> fstat(FD fd)
< fstat(ERRNO res)
> stat64()
< stat64(ERRNO res, FSPATH path)
> lstat64()
< lstat64(ERRNO res, FSPATH path)
> fstat64(FD fd)
< fstat64(ERRNO res)
> epoll_wait(ERRNO maxevents)
< epoll_wait(ERRNO res)
> poll(FDLIST fds, INT64 timeout)
< poll(ERRNO res, FDLIST fds)
> select()
< select(ERRNO res)
> select()
< select(ERRNO res)
> lseek(FD fd, UINT64 offset, FLAGS8 whence)
< lseek(ERRNO res)
> llseek(FD fd, UINT64 offset, FLAGS8 whence)
< llseek(ERRNO res)
> getcwd()
< getcwd(ERRNO res, CHARBUF path)
> chdir()
< chdir(ERRNO res, CHARBUF path)
> fchdir(FD fd)
< fchdir(ERRNO res)
> mkdir(FSPATH path, UINT32 mode)
< mkdir(ERRNO res)
> rmdir(FSPATH path)
< rmdir(ERRNO res)
> openat(FD dirfd, CHARBUF name, FLAGS32 flags, UINT32 mode)
< openat(FD fd)
> link(FSPATH oldpath, FSPATH newpath)
< link(ERRNO res)
> linkat(FD olddir, CHARBUF oldpath, FD newdir, CHARBUF newpath)
< linkat(ERRNO res)
> unlink(FSPATH path)
< unlink(ERRNO res)
> unlinkat(FD dirfd, CHARBUF name)
< unlinkat(ERRNO res)
> pread(FD fd, UINT32 size, UINT64 pos)
< pread(ERRNO res, BYTEBUF data)
> pwrite(FD fd, UINT32 size, UINT64 pos)
< pwrite(ERRNO res, BYTEBUF data)
> readv(FD fd)
< readv(ERRNO res, UINT32 size, BYTEBUF data)
> writev(FD fd, UINT32 size)
< writev(ERRNO res, BYTEBUF data)
> preadv(FD fd, UINT64 pos)
< preadv(ERRNO res, UINT32 size, BYTEBUF data)
> pwritev(FD fd, UINT32 size, UINT64 pos)
< pwritev(ERRNO res, BYTEBUF data)
> dup(FD fd)
< dup(FD res)
> signalfd(FD fd, UINT32 mask, FLAGS8 flags)
< signalfd(FD res)
> kill(PID pid, SIGTYPE sig)
< kill(ERRNO res)
> tkill(PID tid, SIGTYPE sig)
< tkill(ERRNO res)
> tgkill(PID pid, PID tid, SIGTYPE sig)
< tgkill(ERRNO res)
> nanosleep(RELTIME interval)
< nanosleep(ERRNO res)
> timerfd_create(UINT8 clockid, FLAGS8 flags)
< timerfd_create(FD res)
> inotify_init(FLAGS8 flags)
< inotify_init(FD res)
> getrlimit(FLAGS8 resource)
< getrlimit(ERRNO res, INT64 cur, INT64 max)
> setrlimit(FLAGS8 resource)
< setrlimit(ERRNO res, INT64 cur, INT64 max)
> prlimit(PID pid, FLAGS8 resource)
< prlimit(ERRNO res, INT64 newcur, INT64 newmax, INT64 oldcur, INT64 oldmax)
> fcntl(FD fd, FLAGS8 cmd)
< fcntl(FD res)
> switch(PID next, UINT64 pgft_maj, UINT64 pgft_min, UINT32 vm_size, UINT32 vm_rss, UINT32 vm_swap)
> brk(UINT64 addr)
< brk(UINT64 res, UINT32 vm_size, UINT32 vm_rss, UINT32 vm_swap)
> mmap(UINT64 addr, UINT64 length, FLAGS32 prot, FLAGS32 flags, FD fd, UINT64 offset)
< mmap(UINT64 res, UINT32 vm_size, UINT32 vm_rss, UINT32 vm_swap)
> mmap2(UINT64 addr, UINT64 length, FLAGS32 prot, FLAGS32 flags, FD fd, UINT64 pgoffset)
< mmap2(UINT64 res, UINT32 vm_size, UINT32 vm_rss, UINT32 vm_swap)
> munmap(UINT64 addr, UINT64 length)
< munmap(ERRNO res, UINT32 vm_size, UINT32 vm_rss, UINT32 vm_swap)
> splice(FD fd_in, FD fd_out, UINT64 size, FLAGS32 flags)
< splice(ERRNO res)
> ptrace(FLAGS16 request, PID pid)
< ptrace(ERRNO res, DYNAMIC addr, DYNAMIC data)
> ioctl(FD fd, UINT64 request, UINT64 argument)
< ioctl(ERRNO res)
> rename()
< rename(ERRNO res, FSPATH oldpath, FSPATH newpath)
> renameat()
< renameat(ERRNO res, FD olddirfd, CHARBUF oldpath, FD newdirfd, CHARBUF newpath)
> symlink()
< symlink(ERRNO res, CHARBUF target, FSPATH linkpath)
> symlinkat()
< symlinkat(ERRNO res, CHARBUF target, FD linkdirfd, CHARBUF linkpath)
> procexit(ERRNO status)
> sendfile(FD out_fd, FD in_fd, UINT64 offset, UINT64 size)
< sendfile(ERRNO res, UINT64 offset)
> quotactl(FLAGS16 cmd, FLAGS8 type, UINT32 id, FLAGS8 quota_fmt)
> setresuid(UID ruid, UID euid, UID suid)
< setresuid(ERRNO res)
> setresgid(GID rgid, GID egid, GID sgid)
< setresgid(ERRNO res)
> setuid(UID uid)
< setuid(ERRNO res)
> setgid(GID gid)
< setgid(ERRNO res)
> getuid()
< getuid(UID uid)
> geteuid()
< geteuid(UID euid)
> getgid()
< getgid(GID gid)
> getegid()
< getegid(GID egid)
> getresuid()
< getresuid(ERRNO res, UID ruid, UID euid, UID suid)
> getresgid()
< getresgid(ERRNO res, GID rgid, GID egid, GID sgid)
> clone()
< clone(PID res, CHARBUF exe, BYTEBUF args, PID tid, PID pid, PID ptid, CHARBUF cwd, INT64 fdlimit, UINT64 pgft_maj, UINT64 pgft_min, UINT32 vm_size, UINT32 vm_rss, UINT32 vm_swap, CHARBUF comm, BYTEBUF cgroups, FLAGS32 flags, UINT32 uid, UINT32 gid, PID vtid, PID vpid)
> fork()
< fork(PID res, CHARBUF exe, BYTEBUF args, PID tid, PID pid, PID ptid, CHARBUF cwd, INT64 fdlimit, UINT64 pgft_maj, UINT64 pgft_min, UINT32 vm_size, UINT32 vm_rss, UINT32 vm_swap, CHARBUF comm, BYTEBUF cgroups, FLAGS32 flags, UINT32 uid, UINT32 gid, PID vtid, PID vpid)
> vfork()
< vfork(PID res, CHARBUF exe, BYTEBUF args, PID tid, PID pid, PID ptid, CHARBUF cwd, INT64 fdlimit, UINT64 pgft_maj, UINT64 pgft_min, UINT32 vm_size, UINT32 vm_rss, UINT32 vm_swap, CHARBUF comm, BYTEBUF cgroups, FLAGS32 flags, UINT32 uid, UINT32 gid, PID vtid, PID vpid)
> execve()
< execve(ERRNO res, CHARBUF exe, BYTEBUF args, PID tid, PID pid, PID ptid, CHARBUF cwd, UINT64 fdlimit, UINT64 pgft_maj, UINT64 pgft_min, UINT32 vm_size, UINT32 vm_rss, UINT32 vm_swap, CHARBUF comm, BYTEBUF cgroups, BYTEBUF env)
> signaldeliver(PID spid, PID dpid, SIGTYPE sig)
> getdents(FD fd)
< getdents(ERRNO res)
> getdents64(FD fd)
< getdents64(ERRNO res)
> setns(FD fd, FLAGS32 nstype)
< setns(ERRNO res)
> flock(FD fd, FLAGS32 operation)
< flock(ERRNO res)
> cpu_hotplug(UINT32 cpu, UINT32 action)
> accept()
< accept(FD fd, SOCKTUPLE tuple, UINT8 queuepct, UINT32 queuelen, UINT32 queuemax)
> accept(INT32 flags)
< accept(FD fd, SOCKTUPLE tuple, UINT8 queuepct, UINT32 queuelen, UINT32 queuemax)
> semop(INT32 semid)
< semop(ERRNO res, UINT32 nsops, UINT16 sem_num_0, INT16 sem_op_0, FLAGS16 sem_flg_0, UINT16 sem_num_1, INT16 sem_op_1, FLAGS16 sem_flg_1)
> semctl(INT32 semid, INT32 semnum, FLAGS16 cmd, INT32 val)
< semctl(ERRNO res)
> ppoll(FDLIST fds, RELTIME timeout, SIGSET sigmask)
< ppoll(ERRNO res, FDLIST fds)
> mount(FLAGS32 flags)
< mount(ERRNO res, CHARBUF dev, FSPATH dir, CHARBUF type)
> umount(FLAGS32 flags)
< umount(ERRNO res, FSPATH name)
> semget(INT32 key, INT32 nsems, FLAGS32 semflg)
< semget(ERRNO res)
> access(FLAGS32 mode)
< access(ERRNO res, FSPATH name)
> chroot()
< chroot(ERRNO res, FSPATH path)
> tracer(INT64 id, CHARBUFARRAY tags, CHARBUF_PAIR_ARRAY args)
< tracer(INT64 id, CHARBUFARRAY tags, CHARBUF_PAIR_ARRAY args)
> setsid()
< setsid(PID res)
> mkdir(UINT32 mode)
< mkdir(ERRNO res, FSPATH path)
> rmdir()
< rmdir(ERRNO res, FSPATH path)
> notification(CHARBUF id, CHARBUF desc)
> execve()
< execve(ERRNO res, CHARBUF exe, BYTEBUF args, PID tid, PID pid, PID ptid, CHARBUF cwd, UINT64 fdlimit, UINT64 pgft_maj, UINT64 pgft_min, UINT32 vm_size, UINT32 vm_rss, UINT32 vm_swap, CHARBUF comm, BYTEBUF cgroups, BYTEBUF env, INT32 tty)
> unshare(FLAGS32 flags)
< unshare(ERRNO res)
```

### Output Formatting 

Did you take some time to experiment with filtering and filter fields? Good, because now we’re going to learn how to use the same fields to customize what sysdig prints to the screen. Another really nice benefit of the type system sysdig uses to encode fields is that they can all be used to customize the program output. Output customization happens with the –p command line flag, and works somewhat similarly to the C printf syntax. Here’s an example:

>$ sysdig -p"user:%user.name dir:%evt.arg.path" evt.type=chdir  
user:ubuntu dir:/root  
user:ubuntu dir:/root/tmp  
user:ubuntu dir:/root/Download  

This one-liner filters on the chdir system calls (the ones that get called every time a user does a cd), and prints the user name and the directory where the user is going. Essentially, it lets you follow a user as she moves in the file system.

Some notes about the –p formatting syntax:
* Fields must be prepended with a %
* You can add arbitrary text in the string, exactly as you would do in the C printf.
* By default, a line is printed only if **all** the fields specified by –p are present in the event. You can, however, prepend the string with a * to make it print no matter what. In that case, the missing fields will be rendered as \<NA\>.

For example,

>$ sysdig -p"%evt.type %evt.dir %evt.arg.name" evt.type=open

will only print exit open events, like this 

>open < /proc/1285/task/1399/stat  
open < /proc/1285/task/1400/io  
open < /proc/1285/task/1400/statm  

because the enter events don’t contain the name argument, while 

>$ sysdig -p"*%evt.type %evt.dir %evt.arg.name" evt.type=open

will print both enter and exit open events, with a line finishing with \<NA\> for enter events:

>open > \<NA\>  
open < /proc/1285/task/1399/stat  
open > \<NA\>  
open < /proc/1285/task/1400/io  
open > \<NA\>  
open < /proc/1285/task/1400/statm  
open > \<NA\>  

Putting together filtering and output formatting makes sysdig a very flexible and powerful tool. Here are some examples:

>$ sysdig -A -s 65000 -p"%evt.buffer" "proc.name=cat and evt.type=write and fd.num=1"

prints the standard output of a process (cat in this case). Note how we use the -A switch to render the result as a human readable string, and the –s switch to capture more than the usual 80 bytes of each write. Use -s with caution, it can generate huge capture files!

>$ sysdig -p"%user.name) %proc.name %proc.args" evt.type=execve and evt.arg.ptid=bash

shows user, command name and arguments for every program launched by a real user (i.e. from bash).

>$ sysdig -p"%user.name) %evt.arg.path" "evt.type=chdir"

shows the directories that interactive users visit

>$ sysdig -p"user:%user.name process:%proc.name file:%fd.name" "evt.type=write and fd.name contains /etc/"

prints user, process, and file name for all the accesses to the /etc directory.

>$ sysdig -p"%fd.name" "proc.name=apache and evt.type=accept"

lists TCP/IP endpoint information for all the connections received by apache.
I can go on and on, but, well, you get the idea. :-)
Are you interested in learning more useful sysdig one-liners? Visit the sysdig website or, even better, follow us on twitter. We’ll post new one-liners on a regular basis.

### Chisels

Sysdig’s chisels are little scripts that analyze the sysdig event stream to perform useful actions. Essentially, they enable you to do really cool stuff with your sysdig data. Just dig the data up, and then use a chisel to shape it into something beautiful. Get it? Awesome!

Chisels are written in Lua, a well known, powerful, and extremely efficient scripting language.

[[Go here |Chisels User Guide]] for a full tutorial.