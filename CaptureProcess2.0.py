import time
import argparse
import psutil
import threading
from scapy.all import *

# ip4 type in ether is 0x0800
# ip6 type in ether is 0x86dd

lockHere = threading.Lock()
directionStr = 'src -> dst'
splitStr = '+' * 150
splitStarStr = '*' * 150
timeFmt = '%Y/%m/%d %A %H:%M:%S %Z'
filterPrefix = '(host {} and port {}) or (host {} and port {})'

# parse packet of ethernet
def parsePkt(pkt):
    with lockHere:
        # iface nameOfProcess timeOfCapture
        print('*' * 1, pkt.sniffed_on, threading.current_thread().name, time.strftime(timeFmt, time.localtime(pkt.time)))
        rawTmp = None
        etherTmp = pkt.sprintf('{Ether:%Ether.src% -> %Ether.dst% %Ether.type%\n}')
        if IP in pkt:
            ipTmp = pkt.sprintf('{IP:%IP.src% -> %IP.dst% %IP.len%\n}')
        elif IPv6 in pkt:
            ipTmp = pkt.sprintf('{IPv6:%IPv6.src% -> %IPv6.dst% %IPv6.plen%\n}')
        else:
            pass

        tcpTmp = pkt.sprintf('{TCP:%TCP.sport% -> %TCP.dport% %TCP.flags%\n}')

        if Raw in pkt:
            rawTmp = pkt.sprintf('{Raw:%Raw.load%\n}')

        print('*' * 2, directionStr, etherTmp, end='')
        print('*' * 3, directionStr, ipTmp, end='')
        print('*' * 4, directionStr, tcpTmp, end='')
        if rawTmp:
            print('*' * 5, 'raw', rawTmp, end='')
        print(splitStr)

def sniffFun(yourFilter, yourProcess):
    sniff(filter=yourFilter, prn=yourProcess)


def listRunningProcess(processSet, statusSet, interval):
    while 1:
        flagProc, flagConn = False, False
        print('List', processSet, statusSet, interval)
        for subProcess in psutil.process_iter(['name', 'pid', 'create_time', 'connections']):
            tmpDict = subProcess.info
            processNameUpper = tmpDict['name'].upper()
            if 'ALL' not in processSet and processNameUpper not in processSet and str(tmpDict['pid']) not in processSet:
                continue
            if not flagProc:
                flagProc = True
            tmpName = '{}#{}#{}'.format(processNameUpper, tmpDict['pid'], tmpDict['create_time'])
            if tmpDict['connections']:
                for subConn in tmpDict['connections']:
                    if subConn.status.upper() in statusSet:
                        if not flagConn:
                            flagConn = True
                        print(tmpName, subConn.laddr, subConn.raddr, subConn.status)
        if not flagProc:
            print('There is no process(es) which you want to capture.')
            print(splitStarStr)
            time.sleep(interval)
            continue
        if not flagConn:
            print('There is no connections in your process(es). ')
            print(splitStarStr)
            time.sleep(interval)
            continue

        print(splitStarStr)
        time.sleep(interval)

def captureRunningProcess(processSet, statusSet, interval):
    filterSet = set()
    flagProc, flagConn = False, False
    while 1:
        threadList = []
        print('Capture', processSet, statusSet, interval)
        for subProcess in psutil.process_iter(['name', 'pid', 'create_time', 'connections']):
            tmpDict = subProcess.info
            processNameUpper = tmpDict['name'].upper()
            if 'ALL' not in processSet and processNameUpper not in processSet and str(tmpDict['pid']) not in processSet:
                continue
            if not flagProc:
                flagProc = True
            tmpName = '{}#{}#{}'.format(processNameUpper, tmpDict['pid'], tmpDict['create_time'])
            if tmpDict['connections']:
                for subConn in tmpDict['connections']:
                    statusTmp = subConn.status.upper()
                    if statusTmp in statusSet:
                        if statusTmp == 'LISTEN':
                            # LISTEN
                            # print(tmpName, subConn.laddr, subConn.raddr, subConn.status)
                            continue
                        else:
                            # SYN_SENT, SYN_RECV, ESTABLISHED
                            sip, sport, dip, dport = subConn.laddr.ip, subConn.laddr.port, subConn.raddr.ip, subConn.raddr.port
                            filterTmp = filterPrefix.format(sip, sport, dip, dport)
                            # ip1:sport -> ip1:dport ip1:dport -> ip1:sport is the same
                            # ip1:sport -> ip2:dport ip2:dport -> ip1:sport is the same
                            if filterTmp in filterSet or filterPrefix.format(dip, dport, sip, sport) in filterSet:
                                continue
                            # for debug
                            # print(tmpName, filterTmp)
                            if not flagConn:
                                flagConn = True
                            filterSet.add(filterTmp)
                            threadList.append(threading.Thread(daemon=True, name=tmpName, target=sniffFun, args=(filterTmp, parsePkt)))
                            # print(tmpName, subConn.laddr, subConn.raddr, subConn.status)
        if not flagProc:
            print('There is no process(es) which you want to capture.')
            print(splitStr)
            time.sleep(interval)
            continue
        if not flagConn:
            print('There is no connections in your process(es). ')
            print(splitStr)
            time.sleep(interval)
            continue

        for subThread in threadList:
            if subThread.is_alive():
                continue
            subThread.start()
        print(splitStr)
        time.sleep(interval)
    
if __name__ == "__main__":
    descrp = 'Capture tcp flow(s) of running process(es) on your machine'

    parse = argparse.ArgumentParser(description=descrp)
    # default is valid if no use the option explicitly
    # otherwise you must pass a value according to the usage
    parse.add_argument('--process', '-p', default='ALL', help='NAME(S) or PID(S) of process which you want to capture, default is "ALL" if you are not set this.\n-p ')
    parse.add_argument('--status', '-s', default='ESTABLISHED', help='Possible value of tcp status, supported in this version has LISTEN, SYN_SENT, SYN_RECV and ESTABLISHED. default is "ESTABLISHED" if you are not set this.')
    parse.add_argument('--list', '-l', help='List all tcp status of target process', action='store_true')
    parse.add_argument('--timeout', '-t', type=int, help='time interval you want to pass default is 10s', default=10)

    args = parse.parse_args()

    processVal, statusVal, listVal, timeVal = args.process, args.status, args.list, args.timeout

    processSet = set(map(lambda x: x.upper(), set(processVal.split(' '))))
    statusSet = set(map(lambda x: x.upper(), set(statusVal.split(' '))))

    for subItem in statusSet:
        if 'ALL' == subItem:
            continue
        if subItem not in ['LISTEN', 'SYN_SENT', 'SYN_RECV', 'ESTABLISHED']:
            print('input status is not in the support range.')
            exit(0)
    
    if listVal:
        # only list no capture
        # only list status of target process
        # print('List', processSet, statusSet, timeVal)
        listRunningProcess(processSet, statusSet, timeVal)
    else:
        # only capture
        # print('Capture', processSet, statusSet, timeVal)
        captureRunningProcess(processSet, statusSet, timeVal)