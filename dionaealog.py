#!/usr/bin/env python
import sqlite3
import time
import os
import sys
import commands


dbfile = "/opt/dionaea/var/dionaea/logsql.sqlite"
pidfile = "/var/run/dionaealog.pid"
logfile = "/var/log/ossim/dionaea.log"

sleep = 1

cid = 0
did = 0

def checkIfRunning():
    if os.path.exists(pidfile):
        print "Exists"
        sys.exit()
    else:
        pid = os.getpid()
        print "Pull script pid : %s " % pid
        f = open(pidfile, "w")
        f.write(str(pid))
        f.close()
        print "dionaealog.py process didn't existed before this one"

def getLastConnId():
    conn = sqlite3.connect(dbfile)
    c = conn.cursor()
    sql = "select connection from connections order by connection desc limit 1"
    c.execute(sql)
    id = 0
    for v in c:
        id = v[0]
    c.close()
    return id

def getLastDownId():
    conn = sqlite3.connect(dbfile)
    c = conn.cursor()
    sql = "select download from downloads order by download desc limit 1"
    c.execute(sql)
    id = 0
    for v in c:
        id = v[0]
    c.close()
    return id

def getDcerpcrequests(id_conn):
    conn = sqlite3.connect(dbfile)
    c = conn.cursor()
    sql = """
        SELECT dcerpcserviceops.dcerpcserviceop_vuln, emu_services.emu_service_url
        FROM dcerpcrequests 
        LEFT OUTER JOIN dcerpcservices ON (dcerpcrequest_uuid = dcerpcservice_uuid) 
        LEFT OUTER JOIN dcerpcserviceops ON (dcerpcservices.dcerpcservice = dcerpcserviceops.dcerpcservice AND dcerpcrequest_opnum = dcerpcserviceop_opnum)
        LEFT OUTER JOIN connections ON (connections.connection=  dcerpcrequests.connection) 
        LEFT OUTER JOIN emu_services ON (emu_services.connection=  connections.connection) 
        WHERE connections.connection = """ + str(id_conn)
    c.execute(sql)
    result = c.fetchone()
    c.close()
    if result != None:
        return result
    else:
        return (None,None)

def getSipCommands(id_conn):
    conn = sqlite3.connect(dbfile)
    c = conn.cursor()
    sql = """
        SELECT sip_command_method, sip_command_user_agent
        FROM sip_commands 
        WHERE connection = """ + str(id_conn)
    c.execute(sql)
    result = c.fetchone()
    c.close()
    if result != None:
        return result
    else:
        return (None,None)

def getLogins(id_conn):
    conn = sqlite3.connect(dbfile)
    c = conn.cursor()
    sql = """
        SELECT login_username,login_password 
        FROM logins 
        WHERE connection = """ + str(id_conn)
    c.execute(sql)
    result = c.fetchone()
    c.close()
    if result != None:
        password = None
        user = None
        if result[0]:
            user = result[0]
        if result[1]:
            password = result[1]
        return (user,password)
    else:
        return (None,None)

def getOffers(id_conn):
    conn = sqlite3.connect(dbfile)
    c = conn.cursor()
    sql = """
        SELECT offer_url 
        FROM offers 
        WHERE connection = """ + str(id_conn)
    c.execute(sql)
    result = c.fetchone()
    c.close()
    if result != None:
        return result[0]
    else:
        return None

def getHashInfo(id_hash):
    conn = sqlite3.connect(dbfile)
    c = conn.cursor()
    sql = """
        SELECT virustotalscan_result
        FROM virustotals
        LEFT OUTER JOIN virustotalscans ON (virustotalscans.virustotal = virustotals.virustotal)
        WHERE virustotalscan_scanner = 'Sophos'
        AND virustotal_md5_hash= '""" + str(id_hash) + "'"
    c.execute(sql)
    result = c.fetchone()
    c.close()
    if result != None:
        return result[0]
    else:
        return None

def main():
    global cid
    global did
    lastC = cid
    lastD = did
    while True:
        f = open(logfile, "a+")
        conn = sqlite3.connect(dbfile)
        c = conn.cursor()
        sql = "select connection,connection_type,connection_transport,connection_protocol,connection_timestamp,local_host,local_port,remote_host,remote_port from connections where connection > %s order by connection asc" % cid
        c.execute(sql)
        for v in c:
            if v[7] != '192.168.222.1':
                data = None
                if v[3] == 'epmapper':
                    result = getDcerpcrequests(v[0])
                    data = "connection\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (v[0],v[1],v[2],v[3],v[4],v[7],v[8],v[5],v[6],result[0],result[1])
                elif v[3] == 'SipSession' or v[3] == 'SipCall':
                    result = getSipCommands(v[0])
                    data = "connection\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (v[0],v[1],v[2],v[3],v[4],v[7],v[8],v[5],v[6],result[0],result[1])
                elif v[3] == 'mysqld' or v[3] == 'mssqld':
                    result = getLogins(v[0])
                    data = "connection\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (v[0],v[1],v[2],v[3],v[4],v[7],v[8],v[5],v[6],result[0],result[1])
                elif v[3] == 'smbd':
                    result = getOffers(v[0])
                    data = "connection\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (v[0],v[1],v[2],v[3],v[4],v[7],v[8],v[5],v[6],result,"None")
                else:
                    data = "connection\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (v[0],v[1],v[2],v[3],v[4],v[7],v[8],v[5],v[6],"None","None")
                print data
                f.write(data)
            cid = v[0]
        c.close()
        conn = sqlite3.connect(dbfile)
        c = conn.cursor()
        sql = "select d.download,d.download_url,d.download_md5_hash,c.local_host,c.local_port,c.remote_host,c.remote_port,c.connection_timestamp,c.connection_type,c.connection_transport,c.connection_protocol from downloads as d, connections as c where d.download > %s and d.connection = c.connection order by d.download asc" % did
        c.execute(sql)
        for v in c:
            result = getHashInfo(v[2])
            data = "download\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (v[0],v[1],v[2],v[5],v[6],v[3],v[4],v[7],v[8],v[9],v[10],result)
            print data
            f.write(data)
            did = v[0]
        c.close()
        f.close()
        time.sleep(sleep)
        
checkIfRunning()
cid = getLastConnId()
did = getLastDownId()
main()
