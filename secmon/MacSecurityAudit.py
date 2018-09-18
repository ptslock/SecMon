import re
import subprocess
import json
from datetime import datetime
from elasticsearch import Elasticsearch

es = Elasticsearch(['http://192.168.0.13:9200'])
1

class audit:
    def getVers(self):
        ret = str(subprocess.check_output("sw_vers", shell=True))
        rProductName = re.compile(r"ProductName:(.+?)$")
        rProductVersion = re.compile(r"ProductVersion:(.+?)$")
        rBuildVersion = re.compile(r"BuildVersion:(.+?)$")
        return rProductName.search(ret).group(1), rProductVersion.search(ret).group(1), rBuildVersion(ret).group(1)
    def getHostName(self):
        return str(subprocess.check_output('hostname', shell=True))
    
    def getUserAcc(self):
        return str(subprocess.check_output('whoami', shell=True))
    
    def getIPnMAC(self):
        ret = str(subprocess.check_output("ifconfig en0", shell=True))
        rIP = re.compile(r"(inet )(((\d{1,3}[.]){3})\d{1,3})")
        rMAC = re.compile(r"(..[:]){5}..")
        return rIP.search(ret).group(2), rMAC.search(ret).group()
    
    def getUpdateHistory(self): # 1-1  update history
        output = str(subprocess.check_output('softwareupdate --history', shell=True))
        output = output.split("\\n")
        pDate = re.compile(r"(\d{4})[.]\s?(\d{2}[.]\s?){2}\s?\d+:\d+:\d+")
        pName = re.compile(r".*\d{4}-\d{3}")
        updates = []
        for line in output:
            name = pName.search(line)
            if name != None:
                update = {
                     "name" : name.group(),
                     "date" : pDate.search(line).group()
                }
                updates.append(update)
        return json.dumps(updates)
    
    def getSleepTime(self): # 2-4 screen sleep time
        output = str(subprocess.check_output('systemsetup -getcomputersleep', shell=True))
        pTime = re.compile("\d(?=\s?minutes)")
        search = pTime.search(output)
        if search != None:
             return "None"
        else:
             return search.group()
    
    def getJavaVersion(self): # 1-3 java -version
        output = subprocess.check_output(['java', '-version'], stderr=subprocess.STDOUT)
        mjavav = pJavav.search(output)
        if mjavav == None:
            java = {
                "javav" : "None"
            }
        else: 
            java = {
                "javav" : mjavav.group()
            }
        return json.dumps(java)
    
    def getTime(self): # 2-3 network_time status ( On / Off )
        output = subprocess.check_output(['sudo', 'systemsetup', '-getusingnetworktime'], stderr=subprocess.STDOUT)
        pTime = re.compile("On")
        mTime = pTime.search(output)
        if mTime == None:
            time = {
                "time" : "Off"
            }
        else:
            time = {
                "time" : mTime.group()
            }
        return json.dumps(time)
    def getAutoUpdate(self): # 1-2 AutomaticUpdate
        output = subprocess.check_output('defaults read /library/preferences/com.apple.commerce', shell=True)
        pAutoUpdate = re.compile(r'(?<=AutoUpdate\s=\s)\d')
        AutoUpdate = pAutoUpdate.search(output)
        #pVersion = re.compile(r'(?<=AutoUpdateMajorOSVersion\s=\s["])\d*[.]\d*')
        #Version = pVersion.search(output)
        return AutoUpdate.group()
    def getGatekeeper(self): # 2-0 Gatekeeper
        output = subprocess.check_output('spctl --status', shell=True)
        pStatus = re.compile("enable")
        mStatus = pStatus.search(output)
        if mStatus == "enable":
            status = {
                "status" : 1
            }
        elif mStatus == "disable":
            status = {
                "status" : 0
                }
        else:
            status = {
                "status" : -1
            }
        return json.dumps(status)
    def getRemoteLogin(self): # 2-7 RemoteLogin
        output = subprocess.check_output('sudo systemsetup -getremotelogin', shell=True)
        pRlogin = re.compile(r'(?<=Remote\sLogin:\s)\w*')
        Rlogin = pRlogin.search(output)
        # return Rlogin.group()
        if Rlogin == None:
            Rlogin = {
                "Rlogin" : -1
            }
        else:
            Rlogin = {
                "Rlogin" : Rlogin.group()
            }
        return json.dumps(Rlogin)
    def getWebSandbox(self): # 2-11 WebSandbox
        output = subprocess.check_output('defaults read com.apple.Safari AutoOpenSafeDownloads', shell=True)
        pWebsandbox = re.compile("\d")
        Websandbox = pWebsandbox.search(output)
        # string 처리가 되는지, 안된다면 if elif else 구문으로 각각 string 값으로 지정해야함
        if Websandbox == None:
            Websandbox = {
                "Websandbox" : -1
            }
        else:
            Websandbox = {
                "Websandbox" : Websandbox.group()
            }
        return json.dumps(Websandbox)
    def getBuildnVer(self):
            output = str(subprocess.check_output('sw_vers', shell=True))
            rBuild = re.compile(r"(?<=BuildVersion:\\t).+(?=\\n)")
            print(rBuild.search(output).group())
    def isBluetoothOn(self): # 3.0 Bluetooth
            output = str(subprocess.check_output('Defaults read /library/preferences/com.apple.bluetooth ControllerPowerState', shell=True))
            if output.find('1') != -1:
                    return 1
            else:
                    return 0
    def isScreenShareOn(self): #2-6
            output = str(subprocess.check_output('launchctl load /System/Library/LaunchDaemons/com.apple.screensharing.plist', shell=True))
            if output.find("disabled") == -1:
                    return 0
            else:
                    return 1
    def isBluetoothMode(self): #3-0-1
            output = str(subprocess.check_output('/usr/sbin/system_profiler SPBluetoothDataType | grep –i discoverable', shell=True))
            if output.find("off") == -1:
                    return 0
            else:
                    return 1
    def isBluetoothHotspot(self): #3-0-2
            output = str(subprocess.check_output('defaults read /Library/Preferences/SystemConfiguration/com.apple.nat | grep -i enable', shell=True))
            hotspot = re.compile('(.+?(\d)){,2}')
            print (hotspot.search(output).group(2))
    def isOnAppFileServer(self): # 3-2
            #launchctl list | egrep AppleFileServer output = str(subprocess.check_output('',shell=True)
            output = str(subprocess.check_output('launchctl list | egrep AppleFileServer',shell=True))
            if output.find('0') != -1:
                    return 1 # 0 if there is '0' in result, AppFileServer is On
            else:            # as we discussed, 1 dose mean turn on
                    return 0
    def isSmbOn(self): # 3-3
            output = str(subprocess.check_output('launchctl list | egrep smbd',shell=True))
            if output.find('0') != -1:
                    return 1
            else:
                    return 0
    def isFWOn(self): # 3-4
            output = str(subprocess.check_output('Defaults read /library/preferences/com.apple.alf globalstate',shell=True))
            if output.find('1') != -1:
                    return 1
            else:
                    return 0

#test  = audit()
#print(test.getIP())


aud = audit()
IP, MAC = aud.getIPnMAC()
result = {
        'ip': IP,
        'mac':MAC,
        'time': datetime.now(),
        'AudidtResult' :     {
             "-1-CurrentOSVersion" : getHostName()
            }
    }

#es = es.delete(index="test-index", doc_type='audit-result',id=1)
#es.reindex(body=result)
#res = es.index(index="test-index", doc_type='audit-result1',id=1,body=result)
#print(res['result'])

res = es.get(index="test-index", doc_type='_all',id=1)
#res = es.mget(index="test-index",body=1)
print(res['_source']) 
