# CaptureProcess
Capture tcp flow(s) of running process(es) on your machine
按进程抓取TCP网络数据包

One day, I used a network packet capture tool such as wireshark to check the TCP connection interaction of a specific application on my computer. But I soon discovered that I needed to do a lot of preliminary work for this, such as locating the application's pid, application port, destination IP port and many other things, so I suddenly wondered whether I could capture TCP network packets by process. So there is this project.

The project is written in python3 and involves third-party libraries such as psutil and scapy. For normal use, you need to install it in advance. In addition, the project has been developed in the win10 operating system and there is no more testing yet, but due to the python language and dependencies With cross-platform features of the library, this project should be able to run normally on Unix, windows and linux systems. Finally, if you are interested in this project, joint development is welcome.

Environment of dev

OS: Windows 10 21H1;
IDE: VScode;
Python: Python 3.9.2 (tags/v3.9.2:1a79785, Feb 19 2021, 13:44:55) [MSC v.1928 64 bit (AMD64)] on win32;
Dependency: psutil(5.8.0) scapy(2.4.5);

Prepare:

pip3 install scapy psutil

usage: CaptureProcess2.0.py [-h] [--process PROCESS] [--status STATUS] [--list] [--timeout TIMEOUT]

Capture tcp flow(s) of running process(es) on your machine

optional arguments:
  -h, --help            show this help message and exit
  --process PROCESS, -p PROCESS
                        NAME(S) or PID(S) of process which you want to capture, default is "ALL" if you are not set this. -p
  --status STATUS, -s STATUS
                        Possible value of tcp status, supported in this version has LISTEN, SYN_SENT, SYN_RECV and ESTABLISHED. default is "ESTABLISHED" if you are not set this.
  --list, -l            List all tcp status of target process
  --timeout TIMEOUT, -t TIMEOUT
                        time interval you want to pass default is 10s



