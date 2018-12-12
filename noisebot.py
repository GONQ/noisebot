#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# PyBitmessage Noisebot - fake Bitmessage generator
# (c) 2018, Ber Saxon (GONQ) <auto@eagle.icu> https://eagle.icu

# License: use or redistribution subject to license included herewith.
# This copyright notice must be included with any fork or distribution.

'''
### Noisebot sends randomly-timed noise messages via the PyBitmessage API.

- Noisebot creates temporary secret chans using random keys, sends messages to the secret chans, then eventually cleans up the fake messages and deletes the chans.

- Such fake messages are called _noise._ Adding noise to the network makes more work for malicious traffic analysis. Blackhat hackers, criminals, and spooks need to do more work to try sorting fake messages from real messages when noise is mixed in.

- Attackers can't tell the difference between real and fake messages. Noise strengthens anonymity on the network.

# Installation:

- Shut down PyBitmessage. It must be closed for installation hook.
- Copy the noisebot script to the PyBitmessage /src/ directory.
- Enable the Bitmessage API in your keys.dat file. Add API credentials.
- Set permissions on noisebot.py as executable so it can run as a program.
- Run noisebot from the command line to install. **[$ python noisebot.py]**
- On Linux **[$ ./noisebot.py]** should do.
- Restart PyBitmessage.

Noisebot will add the proper API configuration. Noisebot will detect your API credentials on each run.

After the first run noisebot will run in the background when Bitmessage is running. When you receive a message to your inbox the noisebot will activate. To activate it immediately send a blank message to yourself. There is no need to invoke it from the command line after install.

Use is subject to the SSSS License included herewith. Licensee may choose between MIT, BSD, and Apache licenses. See LICENSE for details.
'''

import os
import time
import sys
import threading
import random

# define a hard exit function

def die():
    raise SystemExit
    os._exit(0) # make sure!

def wait(secs):
   time.sleep(secs)

# If Bitmessage is calling the script, restart in a shell without sys.argv
print "(noisebot)(command)",
print sys.argv

if "NOARGV" not in sys.argv:
    import subprocess as spawn
    boot = spawn.Popen(__file__ + ' NOARGV', shell=True) #, stdout=spawn.PIPE, stderr=spawn.PIPE)
    print "(noisebot)(bitmessage) apinotify path call - restarting in shell."
    print "(noisebot)(noargv)(spawn)", str(boot)
    wait(0.25)
    die()

# check for bitmessage installation in same folder

if not os.path.isfile("bitmessagemain.py"):
    print "(noisebot)(error) could not find 'bitmessagemain.py.'"
    print "(noisebot)(error) " + __file__ + " must be in bitmessage /src/ directory to run."
    print "(noisebot)(error) cannot proceed. exiting."
    die()

# before running check and get the file lock to prevent multiple instances.
# rather than messing with pids and os-level stuff, just use a time lock file.
# this function runs only once per instance and instance dies on fail

def checklock():
    print "(noisebot)(checklock)"
    if os.path.isfile("noisebot.time.lock"):
        print "(noisebot)(checklock) existing lockfile found."
        lockfile1 = "noisebot.time.lock"

        lockx = open(lockfile1, 'r')
        clock1 = lockx.read()
        lockx.close()

        print "(noisebot)(checklock)(locktime)", str(clock1)

        now = time.time()
        print "(noisebot)(checklock)(timestamp)", str(now)
        sched = float(clock1)
        print "(noisebot)(checklock)(timestamp - locktime)", str(now - sched)
        if now - sched < 1:
            print "(noisebot)(checklock) ANOTHER INSTANCE OF NOISEBOT IS RUNNING. EXITING."
            print "(noisebot)(checklock)(exit) [+]"
            die()
        else:
            print "(noisebot)(checklock) NO OTHER INSTANCE DETECTED. RUNNING LOCK THREAD."

checklock()

def timelock(sched_time):

    clock = str(sched_time)
    lockfile1 = "noisebot.time.lock"
    lox = open(lockfile1, 'w')
    lox.write(clock)
    print "(noisebot)(timelock) LOCK IS ACTIVE.", clock

# grab the initial lock right away before any wait() execution
def lockthread():
    locktime = time.time() + 1
    print "(noisebot)(lockthread)", str(locktime)
    timelock(locktime)

def unlock():
    lockfile = "noisebot.time.lock"
    if os.path.isfile(lockfile):
        os.remove(lockfile)
        print "(noisebot)(unlock) removed lockfile."
    else:
        print "(noisebot)(unlock) no lockfile detected."

def waitlock():
    sched_time = time.time()
    losec = 0
    hisec = 0
    roundsec = rnd(1, 27)
    for x in range(0, roundsec):
        minsec = rnd(1, 9)
        maxsec = rnd(10, 108)
        losec += minsec
        hisec += maxsec
    print "(noisebot)(losec, hisec) ", losec, hisec
    secs = rnd(losec, hisec)
    sched_time += secs
    sched_time += 60
    timelock(sched_time)
    print "(noisebot)(waitlock) ", str(secs), "seconds"
    wait(secs)
    print "(noisebot)(waitlock) done."

# play nice with Bitmessage - only run if locked shell signal sent

if "NOARGV" in sys.argv:
    lockthread()

from bmconfigparser import BMConfigParser
from random import randrange as rnd
from os import urandom as urand
import ConfigParser
import xmlrpclib
import socket
import base64
import random
import json
import time
import api
import sys
import os

# some globals since this script will not be imported

global defaultDifficulty
defaultDifficulty = "1000"

global api
global globalPassPhrase
global noisebotPath
global globalSubjectPrefix

app_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(app_dir)

print "(noisebot)(app dir) ", app_dir
print "(noisebot)(file) ", __file__

# check if counter file exists
if not os.path.isfile("noisebot_counter.txt"):
    countfile = open("noisebot_counter.txt", "w")
    countfile.write("0")
    countfile.close()
    print "(noisebot)(counter) created new file noisebot_counter.txt"
else:
    print "(noisebot)(counter) noisebot_counter.txt detected."
def findKeysFolder(): # Ref. {PyBitmessage/bminterface.py}
    import sys
    APPNAME = "PyBitmessage"
    from os import path, environ
    if sys.platform == 'darwin':
        if "HOME" in environ:
            dataFolder = path.join(os.environ["HOME"], "Library/Application support/", APPNAME) + '/'
        else:
            print '(noisebot) [ ERROR ] (install) OS X: Unable to find keys directory.'
            print '(noisebot) [ ERROR ] (install) Try to configure keys.dat manually.'
            print '(noisebot) [ ERROR ] (install) noisebot may not run on your system. exiting.'
            die()

    elif 'win32' in sys.platform or 'win64' in sys.platform:
        dataFolder = path.join(environ['APPDATA'], APPNAME) + '\\'
    else:
        dataFolder = path.expanduser(path.join("~", "." + "config", APPNAME + "/"))
    return dataFolder

def getApiString():
    global keysPath
    config = ConfigParser.SafeConfigParser()
    keysPath = 'keys.dat'
    config.read(keysPath) # first try to load keys.dat from source directory.
    try:
        config.get('bitmessagesettings','settingsversion')
        keysFolder = ''
    except:
        # keys.dat not found in source directory. Try appdata directory.
        keysFolder = findKeysFolder()
        keysPath = keysFolder + 'keys.dat'
        config = ConfigParser.SafeConfigParser()
        config.read(keysPath)
        try:
            config.get('bitmessagesettings','settingsversion')
        except:
            # keys.dat not there either. something is wrong.
            print ' '
            print '+--------------------------------------------------------------------+'
            print '|      noisebot is unable to access the Bitmessage keys.dat file.     |'
            print '|      check to ensure noisebot is in Bitmessage src/ directory.      |'
            print '+--------------------------------------------------------------------+'
            print ' '
            print config
            print ' '
    try:
        apiPort = config.getint('bitmessagesettings', 'apiport')
    except:
        print '(noisebot)(error) unable to access keys.dat'
    try:
        apiInterface = config.get('bitmessagesettings', 'apiinterface')
    except:
        print '(noisebot)(error) unable to access keys.dat'
    try:
        apiUsername = config.get('bitmessagesettings', 'apiusername')
    except:
        print '(noisebot)(error) unable to access keys.dat'
    try:
        apiPassword = config.get('bitmessagesettings', 'apipassword')
    except:
        print '(noisebot)(error) unable to access keys.dat'
    try:
        apiTTL = config.get('bitmessagesettings', 'ttl')
    except:
        print '(noisebot)(error) unable to access keys.dat'
    apiString = "http://" + apiUsername + ":" + apiPassword + "@" + apiInterface+ ":" + str(apiPort) + "/"
    return apiString, int(apiTTL)

# set api URL

api_string, apiTTL = getApiString()

print "(noisebot)(api string) ", api_string

api = xmlrpclib.ServerProxy(api_string)

# begin install wizard

def apiData():
    global keysPath

    config = ConfigParser.SafeConfigParser()
    keysPath = 'keys.dat'
    config.read(keysPath) # first try to load keys.dat from source directory.

    try:
        config.get('bitmessagesettings','settingsversion')
        keysFolder = ''
    except:
        # keys.dat not found in source directory. Try appdata directory.
        keysFolder = findKeysFolder()
        keysPath = keysFolder + 'keys.dat'
        config = ConfigParser.SafeConfigParser()
        config.read(keysPath)

        try:
            config.get('bitmessagesettings','settingsversion')
        except:
            # keys.dat not there either. something is wrong.
            print ' '
            print '+--------------------------------------------------------------------+'
            print '|      noisebot is unable to access the Bitmessage keys.dat file.     |'
            print '|   Check to ensure noisebot is in the same directory as Bitmessage.  |'
            print '+--------------------------------------------------------------------+'
            print ' '
            print config
            print ' '
    try:
        apiConfigured = config.getboolean('bitmessagesettings','apienabled')
        apiEnabled = apiConfigured
    except:
        apiConfigured = False # if not found set to false to force configuration.
        print "(noisebot)(error) API is disabled. Enable the Bitmessage API to use noisebot."
        exit()

# keys.dat found. retrieve data.
# if any setting is null, false, or incorrect flag a boolean to make setup run.

    misconfigured = False
    try:
        apiEnabled = config.getboolean('bitmessagesettings','apienabled')
    except:
        apiEnabled = False
    if apiEnabled != True:
        misconfigured = True
    try:
        apiPort = config.getint('bitmessagesettings', 'apiport')
    except:
        misconfigured = True
    try:
        apiInterface = config.get('bitmessagesettings', 'apiinterface')
    except:
        misconfigured = True
    if "." not in apiInterface:
        misconfigured = True
    try:
        apiUsername = config.get('bitmessagesettings', 'apiusername')
    except:
        misconfigured = True
    try:
        apiPassword = config.get('bitmessagesettings', 'apipassword')
    except:
        misconfigured = True
    if misconfigured == True:
        print "(noisebot)(error) API configuration error. exiting."
        exit()

# Check apinotifypath in keys.dat
noisebotPath = os.path.abspath((__file__))
print "(noisebot)(noisebot path) ", noisebotPath
print "(noisebot)(apinotify path)(checking)"

if not os.path.isfile("keys.dat"):
    keysdatdir = findKeysFolder()
else:
    keysdatdir = app_dir

# read current file to var
thisFile = os.path.abspath(__file__)

#remove trailing slash to get consistent output for concatenation
if keysdatdir[-1] == "/":
    keysdatdir = keysdatdir[0:-1]

print "(noisebot)(keys.dat) ", keysdatdir

keysdatfile = keysdatdir + "/keys.dat"

print "(noisebot)(keysdatfile)", keysdatfile

# check apinotifypath configuration in keys.dat
f = open(keysdatfile, 'r')
try:
    contents = f.read()
except:
    print "(noisebot)(error) keys.dat unreadable. exiting."

notifystring = "\napinotifypath = "
notifystring += thisFile

# append noisebot apinotify path to keys.dat

print "(noisebot)(notify string) checking apinotify path in keys.dat"
if notifystring not in contents:
    f = open(keysdatfile, 'a')
    f.write("\n")
    f.write("\n[bitmessagesettings]\n")
    f.write("apinotifypath = ")
    f.write(thisFile)
    f.write("\ndefaultnoncetrialsperbyte = " + defaultDifficulty)
    f.write("\ndefaultpayloadlengthextrabytes = " + defaultDifficulty)
    f.write("\n\n")
    f.close()
    print "**** NOISEBOT INSTALLATION COMPLETE ****"
    print "**** RESTART BITMESSAGE TO ACTIVATE ****"
    die()
else:
    print "**** NOISEBOT APPEARS PROPERLY CONFIGURED ****"

################################################################################

# begin noisebot routine

# characters for passphrase

chan_chars = [
                "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
                "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
                "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
                "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
                "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"
                ]

# Build a random chan passphrase from the chan_chars
len_chan_chars = len(chan_chars)

chan_name = ''

for incr in range (0, 40):
    slot = rnd(0, len_chan_chars)
    chosen_char = chan_chars[slot]
    chan_name += chosen_char

globalPassPhrase = chan_name

# store chan names in a file for cleanup (in case of sigkill or shutdown)

chanfile = open("noisebot_chans.txt", 'a')
chanfile.write("\n" + chan_name)
chanfile.close()

# create a subject prefix for final message deletion to clear orphaned messages

globalSubjectPrefix = "//// noisebot ////"

# push values to stdout

print "(noisebot)(chan chars) ", chan_chars
print "(noisebot)(global passphrase) ", globalPassPhrase
print "(noisebot)(global subject prefix) ", globalSubjectPrefix
print "(noisebot)(api_string) ", api_string

# ensure we can connect to the Bitmessage API, die hard exit on failure
def apiTest():
    try:
        result = api.add(4,5)
        if result == 9:
            print "(noisebot) bitmessage API is enabled and responding. proceeding."
        elif result != 9:
            print "(noisebot) bitmessage API error. check keys.dat configuration."
            print "(noisebot) bitmessage API error. is bitmessage running?. exiting."
            die()
    except:
        print "(noisebot) bitmessage API error. check keys.dat configuration. is API enabled?"
        print "(noisebot) bitmessage API error. is bitmessage running?. exiting."
        die()

# exit if api test fails

apiTest()

# create the noisebot address to guarantee availability

def checkBotAddress(noisebotAddressPassphrase):
    try:
        passphrase = noisebotAddressPassphrase.encode('base64')
        api.createChan(passphrase)
        checkphrase = api.getDeterministicAddress(passphrase, 4, 1)
        api.statusBar("(noisebot) checking address exists.")
    except ValueError:
        print "(noisebot) [ ERROR 00 ] unable to create address."
        print "(noisebot) [ ERROR 00 ] if address exists this is not an error. continuing."
        api.statusBar("(noisebot) checking noisebot address.")
    return checkphrase

noisebotAddressPassphrase = globalPassPhrase
checkphrase = checkBotAddress(noisebotAddressPassphrase)
api.statusBar("(noisebot) checking if noisebot address exists.")

if "address is already present" in checkphrase:
    print "(noisebot) success. Address for " + noisebotAddressPassphrase + " exists. proceeding."
elif checkphrase[:3] == "BM-":
    f = open("noisebot_address.dat", 'w')
    f.write(checkphrase)
    f.close()
    print "(noisebot) success. Address for " + noisebotAddressPassphrase + " created. proceeding."
elif checkphrase != "":
    print "(noisebot) [ ERROR 01 ] [ BM-API ] error creating address for ", checkphrase, "exiting."
    api.statusBar("(noisebot) [ ERROR 01 ] exiting.")
    die()

def getAddress(passphrase):
    passphrase = passphrase.encode('base64')
    return api.getDeterministicAddress(passphrase, 4, 1)
    api.statusBar("(noisebot) getting noisebot address.")

def totalcount():
    count = open("noisebot_counter.txt", 'r')
    hist_count = count.read()
    count.close()
    print "(noisebot)(historical count) {", str(hist_count), "} messages"

def sendMsg():
    delMsg0()
    global globalSubjectPrefix
    bigmsg = rnd(0, 20)
    if bigmsg == 0:
        maxlen = 16000
    else:
        lenswitch = rnd(0, 10)
        maxis = [1000, 900, 800, 700, 600, 500, 400, 300, 200, 100]
        maxlen = maxis[lenswitch]
    msglen = rnd(16, maxlen)
    msg = urand(msglen).encode('base64')
    sub = globalSubjectPrefix
    sub += " "
    sub += str(urand(15).encode('base64'))[0:12]
    print "(noisebot)(message) composing message."
    fromaddress = getAddress(globalPassPhrase)
    print "(noisebot)(message)(address) ", fromaddress
    toaddress = fromaddress
    print "(noisebot)(message)(sample) ", msg[0:40]
    message = msg.encode('base64')
    subject = sub.encode('base64')
    ttl = apiTTL # get value from keys.dat
    ttl_switch = rnd(0,2) # plus or minus
    ttl_random = rnd(0, 300) # random bump to ttl
    if ttl_switch == 0:
        ttl -= ttl_random
    else:
        ttl += ttl_random
    print "(noisebot)(ttl) ", str(ttl)
    try:
        api.sendMessage(toaddress, fromaddress, subject, message, 2, ttl)
        countfile = open("noisebot_counter.txt", "r")
        counter = int(countfile.read())
        countfile.close()
        counter += 1
        countfile = open("noisebot_counter.txt", "w")
        countfile.write(str(counter))
        countfile.close()
        totalcount()
    except:
        print "(noisebot)(error)(api error) could not send msg."

# loop to delete all inbox messages of the current globalPassPhrase
def delMsg0():
    global api
    global globalPassPhrase
    address = getAddress(globalPassPhrase)
    inboxMessages = json.loads(api.getInboxMessagesByReceiver(address))
    numMessages = len(inboxMessages['inboxMessages'])
    print "(noisebot)(garbage cleanup 0)"
    print "(noisebot)(number of inbox msgs) {", numMessages, "}"
    if (numMessages > 0):
        for incr in range (0, numMessages):

            # Get the msgid of the first message, which is a hex number.
            msgID = inboxMessages['inboxMessages'][incr]['msgid'] #was 0 #[incr]
            print "(noisebot)(delete) ", str(msgID)[:55]
            api.trashMessage(msgID)

            # delete message notification
            print "(noisebot)(message deleted) {", numMessages, "}"
            return "message deleted."

# loop to delete all inbox messages with noisebot prefix in subject
def delMsg1():
    global api
    inboxMessages = json.loads(api.getAllInboxMessages())
    numMessages = len(inboxMessages['inboxMessages'])
    print "(noisebot)(garbage cleanup 1)"
    print "(noisebot)(number of inbox msgs) {", numMessages, "}"
    if (numMessages > 0):
        for incr in range (0, numMessages):

            # Get the msgid of the first message, which is a hex number.
            msgID = inboxMessages['inboxMessages'][incr]['msgid'] #was 0 #[incr]
            subject = inboxMessages['inboxMessages'][incr]['subject'].decode('base64')
            if globalSubjectPrefix in subject:
                print "[[[ delMsg1 ]]] ", subject
                print "(noisebot)(delete) ", str(msgID)[:55]
                api.trashMessage(msgID)

                # delete message notification
                print "(noisebot)(message deleted) {", numMessages, "}"

def delSentMsg0():
    global api
    global globalPassPhrase
    address = getAddress(globalPassPhrase)
    sentMessages = json.loads(api.getSentMessagesBySender(address))
    numMessages = len(sentMessages['sentMessages'])
    print "(noisebot)(sent message cleanup)"
    print "(noisebot)(number of sent msgs) {", numMessages, "}"
    if (numMessages > 0):
        for incr in range (0, numMessages):

            # Get the msgid of the first message, which is a hex number.
            subject = sentMessages['sentMessages'][incr]['subject']
            print "(noisebot) sent subject: ", subject
            msgID = sentMessages['sentMessages'][incr]['msgid']
            if globalSubjectPrefix in subject:
                print "(noisebot)(delete) ", str(msgID)[:55]
                api.trashMessage(msgID)

                # delete message notification
                print "(noisebot)(message deleted) {", numMessages, "}"

# choose a random number of consecutive messages for this script instance

randomruns = rnd(1, 6)
print "(noisebot)(random runs) {", str(randomruns), "} rounds"
for incr in (0, randomruns):
    msgbatch = rnd(1, 4)
    print "(noisebot)(message batch) {", msgbatch, "} messages"
    for incr in range (0, msgbatch):
        sendMsg()
    waitlock()
    delMsg0()
    delMsg1()

# read counter to variable
countfile = open("noisebot_counter.txt", "r")
lastcount = int(countfile.read())
countfile.close()

# pause before exit - repeat waitlock a random number of times
print "(noisebot)(final cleanup pause)"
exitDelayLoops = rnd(1, 4)
print "(noisebot)(cleanup delay loops) {", str(exitDelayLoops), "}"
for incr in range (0, exitDelayLoops):
    waitlock()
print ""

# count total noise messages sent
countfile = open("noisebot_counter.txt", "r")
noisecount = countfile.read()
countfile.close()
print "(noisebot)(noise message count) {", noisecount, "}"

print "(noisebot)(purge) delete fake messages."
delMsg0()
delMsg1()
delSentMsg0()

# delete the randomly created chan and messages
print "deleting temporary chan (", globalPassPhrase, ")"
print "(noisebot)(message deletion)"

print "(noisebot)(delete chan) "
api.deleteAddress(checkphrase)

# delete orphaned chans from chanfile

print "(noisebot)(chanfile) removing temporary and orphaned chans."
with open("noisebot_chans.txt") as chanfile:
    for channame in chanfile:
        channame = channame.strip()
        channame = channame.strip("\t")
        channame = channame.strip("\n")
        channame = channame.strip("\r")
        channame = channame.strip(" ")
        if "\n" not in channame and "\r" not in channame and channame != '':
            chanaddy = checkBotAddress(channame)
            api.deleteAddress(chanaddy)
os.remove("noisebot_chans.txt")
chanx = open("noisebot_chans.txt", 'w')
chanx.write("")
chanx.close()
print "(noisebot)(chanfile) done."

# output total number of historical noise messages

totalcount()

# final stdout notices
print "(noisebot)(run complete) [+]"

# remove the timelock before restarting script

print "(noisebot)(unlock) removing time file."
unlock()

print "(noisebot)(finish) : noisebot is going down [+]"

# restart the script indefinitely
def main():
    print "(noisebot)(reboot) executing new process."
    os.execv(sys.executable, ['python'] + [__file__] + ['NOARGV'])
    wait(0.25)
    print "(noisebot)(reboot) [+]"

main()