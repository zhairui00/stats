#!/bin/env python
# -*- coding: UTF-8 -*-
#
# script_name ssh_channel.py
# ssh_channel.py /CFG/${job_id}/config.cfg
# liyu  20170607

import sys
import json
import os
import shlex
import re
import paramiko
import time
import socket
import copy

def disable_paging(remote_conn):
    remote_conn.send("terminal length 0 \n")
    time.sleep(1)
    output= remote_conn.recv(1000)
    return  output

def security_check(command_line):
    dict_cmd = ['rm', 'delete', 'echo', 'mv', 'cp', '', 'chown', 'chmod', 'sync', 'rsync', 'tar', 'tail', 'alias',
                '/usr/bin/rm', '/bin/rm', '/usr/bin/rm']
    for x_line in shlex.split(command_line):
        ##print "security_check::x_line=%s" %(x_line)
        if x_line in dict_cmd:
            return 'ranfail'
    return "security"

def ssh_connect(host_ip, host_port, host_username, host_passwd, command):
    paramiko.util.log_to_file("/var/log/paramiko.log")
    remote_conn_pre = paramiko.SSHClient()
    remote_conn_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    #remote_conn_pre.connect(hostname=host_ip, port=host_port, username=host_username, password=host_passwd,look_for_keys=False, allow_agent=False,banner_timeout=None)
    try:
        remote_conn_pre.connect(hostname=host_ip, port=host_port, username=host_username, password=host_passwd,look_for_keys=False, allow_agent=False)
        remote_conn = remote_conn_pre.invoke_shell()
        output_line = remote_conn.recv(1000)
        disable_paging(remote_conn)
        #stdout = remote_conn.send(exec_command)
        #stdin, stdout, stderr = ssh_connect.exec_command(exec_command)
        #stdin.write("Y")  # Generally speaking, the first connection, need a simple interaction.
        remote_conn.send(command + "\n")
        time.sleep(3)
        remote_conn.send("\n")
        stdout_line = remote_conn.recv(5000)
        #stderr_line = stderr.read()
        #ssh_connect.close()
        ##print stdout_line + ";\n---\n" + stderr_line
        #remote_conn.send("exit\n")
        #return output_line + ' ' + stdout_line
    except Exception, e:
        stdout_line=str(e)
    return  stdout_line


def run_command_return_result(parameter_file_content_line):
    ##IP::PORT::username::password::uuid11##command11::uuid22##command22::uuid33##command33
    # 10.0.224.31::22::root::123456::d41d8cd98f00b204e9800998ecf8427e##ifconfig -a::u41d8cd98f00b206e9800998ecf8427F##hostname
    #('d41d8cd98f00b204e9800998ecf8427e1\n',{'username': 'root', 'ip': '192.168.2.1', 'password': '1q2w3e4r', 'command': 'ifconfig -a', 'port': '22'})
    command_result_list = []
    command_result = {}
    file_line=parameter_file_content_line.split('::')
    host_ip = file_line[0]
    host_port = file_line[1]
    host_username = file_line[2]
    host_passwd = file_line[3]
    uuid_command_list=file_line[4:]
    ##ssh 接口 paramiko
    for uuid_command in uuid_command_list:
        uuid_command = uuid_command.split('##')
        command_result["MESSAGE"] = ssh_connect(host_ip, int(host_port), host_username, host_passwd, uuid_command[1])
        if command_result["MESSAGE"] :
            command_result['STATUS'] = 'ran'
        else:
            command_result['STATUS'] = 'ranfail'
        command_result["uuid"] = uuid_command[0]
        command_result_list.append(copy.deepcopy(command_result))
    return command_result_list

def checkip(ip):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(ip):
        return True
    else:
        return False

def main():
    messgae_result = {}
    result = []
    ##print "main::sys.argv[1]=%s" %(sys.argv[1])
    #/CFG/job_id/config.cfg
    if  sys.argv[1] :
        pass
    else:
        messgae_result["sender"] = socket.gethostname()
        messgae_result["statusmsg"] = "args is null"
        messgae_result["statuscode"] = "42"
        result.append(messgae_result)
        encodedjson = json.dumps(result)
        print encodedjson
        sys.exit(0)
    parameter_file_path=sys.argv[1]
    ##print "main::job_id=%s" %(job_id)
    if (type(parameter_file_path) is str) and os.path.isfile(parameter_file_path):
        with open(parameter_file_path, 'r') as parameter_file_context:
            parameter_file_content_line = parameter_file_context.readline()
            while parameter_file_content_line:
                if checkip(parameter_file_content_line.split('::')[0]):
                    messgae_result["sender"] = parameter_file_content_line.split('::')[0]
                    messgae_result["statusmsg"] = run_command_return_result(parameter_file_content_line)
                    if messgae_result["statusmsg"] :
                        messgae_result["statuscode"] =0
                    else:
                        messgae_result["statuscode"] = 42
                result.append(copy.deepcopy(messgae_result))
                parameter_file_content_line = parameter_file_context.readline()
    else:
        messgae_result["sender"] = socket.gethostname()
        messgae_result["statusmsg"] = "arguments = [ " + sys.argv[1] + " ] " + "format error"
        messgae_result["statuscode"] = 42
        result.append(messgae_result)

    print json.dumps(result)

if __name__ == "__main__":
    main()
