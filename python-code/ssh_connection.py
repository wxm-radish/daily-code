#coding:utf-8
import paramiko

def ssh_init(ip,username,password,port=22):
    conn = paramiko.SSHClient()#建立一个sshclient对象
    conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())# 允许将信任的主机自动加入到host_allow 列表，此方法必须放在connect方法的前面
    conn.connect(hostname=ip, port=port, username=username, password=password)
    return conn

def execve(conn,command):
    stdin, stdout, stderr = conn.exec_command(command)
    print(stdout.read().decode())

def shutdown(conn):
    conn.close()

if __name__ == "__main__":
    ip = "radishes.top"
    username="root"
    password="LUObo666"
    conn = ssh_init(ip=ip,username=username,password=password)
    execve(conn,"ls")
    shutdown(conn)
