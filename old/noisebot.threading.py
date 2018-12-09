#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Noisebot sends noise messages via the Bitmessage API.
# Noisebot creates temporary secret chans using random keys, sends messages to the secret chans, then deletes the chans.
# Such fake messages are called noise. Adding noise to the network to make more work for malicious traffic analysis.
# Attackers can't tell the difference between real and fake messages. Noise strengthens anonymity on the network.
# Noisebot will send every few minutes on average. It chooses random times to send and random pauses between sends.

# This version uses python threading for the locking mechanism.
# It requires a hard kill to stop the locking thread.

''' To install:

- Copy the noisebot script to the Bitmessage keys directory.
- Enable the Bitmessage API in your keys.dat file.
- Run noisebot from the command line to install. [$ python noisebot.py]
- Shut down and restart Bitmessage.

After the first run noisebot will run in the background when running Bitmessage.
When you receive a message to your inbox the noisebot will activate.
To activate it immediately send a blank message to yourself.
There is no need to invoke it from the command line after first install.

'''

# ------------------------------------------------------------------------------
import os
import time
import sys
import threading
import random

# ------------------------------------------------------------------------------
# define a hard exit function

def die():
    os._exit(0)

# ------------------------------------------------------------------------------
# check for bitmessage installation in same folder

if not os.path.isfile("bitmessagemain.py"):
    print "(noisebot)(error) could not find 'bitmessagemain.py.'"
    print "(noisebot)(error) noisebot.py must be in bitmessage /src/ directory to run."
    print "(noisebot)(error) cannot proceed. exiting."
    die()
        
# ------------------------------------------------------------------------------
# before running check and get the file lock to prevent multiple instances.
# rather than messing with pids and os-level stuff, just use a time lock file.

def checklock():
    if os.path.isfile("time.lock"):
        lockfile1 = "time.lock"

        lockx = open(lockfile1, 'r')
        clock1 = lockx.read()
        
        now = int(str(time.time())[0:10])
        past = int(clock1)

        if now - past < 60:
            print "(noisebot) ANOTHER INSTANCE OF NOISEBOT IS RUNNING. EXITING."
            print "(noisebot)(exit) [+]"
            die()
        else:
            print "(noisebot) NO OTHER INSTANCE DETECTED. RUNNING THE LOCK THREAD."

checklock()

# ------------------------------------------------------------------------------
def timelock():

    clock = str(time.time())[0:10]
    lockfile1 = "time.lock"
    lox = open(lockfile1, 'w')
    lox.write(clock)
    print "(noisebot) LOCK IS ACTIVE.", str(time.time())[0:10]
    
# ------------------------------------------------------------------------------
def lockthread():
  threading.Timer(30, lockthread).start()
  timelock()

# ------------------------------------------------------------------------------  
def unlock():
    lockfile = "time.lock"
    os.remove(lockfile)

# ------------------------------------------------------------------------------
# play nice with Bitmessage - only run if newMessage signal sent

if "newMessage" in sys.argv:
    lockthread()

# ------------------------------------------------------------------------------

from random import randrange as rnd
from os import urandom as urand
from bmconfigparser import BMConfigParser
import ConfigParser
import subprocess
import xmlrpclib
import ntpath
import socket
import base64
import random
import json
import time
import api
import sys
import os

# ------------------------------------------------------------------------------
# some globals since this script will not be imported
# ------------------------------------------------------------------------------
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

# ------------------------------------------------------------------------------
# check if counter file exists
if not os.path.isfile("noisebot_counter.txt"):
    countfile = open("noisebot_counter.txt", "w")
    countfile.write("0")
    countfile.close()
    print ""
    print "created new file noisebot_counter.txt"
    print ""

# ------------------------------------------------------------------------------
def wait(secs):
   time.sleep(secs)

# ------------------------------------------------------------------------------   
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
    
# ------------------------------------------------------------------------------
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
            drawHeader()
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
    apiString = "http://" + apiUsername + ":" + apiPassword + "@" + apiInterface+ ":" + str(apiPort) + "/"
    return apiString

# ------------------------------------------------------------------------------
# set api URL
# ------------------------------------------------------------------------------
api_string = getApiString()

print "(noisebot)(api string) ", api_string

api = xmlrpclib.ServerProxy(api_string)

# ------------------------------------------------------------------------------
# begin install wizard
# ------------------------------------------------------------------------------
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
            drawHeader()
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

# ------------------------------------------------------------------------------
# keys.dat found. retrieve data.
# if any setting is null, false, or incorrect, increment a boolean match, to ensure setup runs.

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

# ------------------------------------------------------------------------------
# Check apinotifypath in keys.dat
noisebotPath = os.path.abspath(__file__)
print "(noisebot)(noisebot path) ", noisebotPath
print "(noisebot)(apinotify path)(checking)"

if not os.path.isfile("keys.dat"):
    keysdatdir = findKeysFolder()
else:
    keysdatdir = app_dir

# ------------------------------------------------------------------------------
# read current file to var
thisFile = os.path.abspath(__file__)

# ------------------------------------------------------------------------------
#remove trailing slash to get consistent output for concatenation
if keysdatdir[-1] == "/":
    keysdatdir = keysdatdir[0:-1]
    
print "(noisebot)(keys.dat) ", keysdatdir

keysdatfile = keysdatdir + "/keys.dat"

print "(noisebot)(keysdatfile)", keysdatfile

# ------------------------------------------------------------------------------
# check apinotifypath configuration in keys.dat
f = open(keysdatfile, 'r')
try:
    contents = f.read()
except:
    print "(noisebot)(error) keys.dat unreadable. exiting."

notifystring = "\napinotifypath = "
notifystring += thisFile

# ------------------------------------------------------------------------------
# append noisebot apinotify path to keys.dat

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

# ------------------------------------------------------------------------------
# play nice with Bitmessage - only run if newMessage signal sent

if "newMessage" not in sys.argv:
    print "(noisebot) the bot will run when the first new message arrives."
    print "(noisebot) (exit) [+]"
    die()

# ------------------------------------------------------------------------------
def randwait():
    print "(noisebot)(random wait) ",
    secs = rnd(120, 300)
    print secs, "seconds"
    wait(secs)

# ------------------------------------------------------------------------------    
# pause before every run
randwait()

# ------------------------------------------------------------------------------
# randomly assemble a global passphrase for the temporary chan

chan_chars = [
                "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
                "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
                "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
                "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
                "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"
                ]

# ------------------------------------------------------------------------------
# Build a random chan passphrase from the chan_chars
len_chan_chars = len(chan_chars)

chan_name = ''

for incr in range (0, 40):
    slot = rnd(0, len_chan_chars)
    chosen_char = chan_chars[slot]
    chan_name += chosen_char
    
globalPassPhrase = chan_name

# ------------------------------------------------------------------------------
# store chan names in a file for cleanup (in case of sigkill or shutdown)

chanfile = open("noisebot_chans.txt", 'a')
chanfile.write("\n" + chan_name)
chanfile.close()

# ------------------------------------------------------------------------------
# create a subject prefix for final message deletion to clear junk messages

globalSubjectPrefix = "//// noisebot ////"

# ------------------------------------------------------------------------------
# push values to stdout

print "(noisebot)(chan chars) ", chan_chars
print "(noisebot)(global passphrase) ", globalPassPhrase
print "(noisebot)(global subject prefix) ", globalSubjectPrefix
print "(noisebot)(api_string) ", api_string

# ------------------------------------------------------------------------------
# ensure we can connect to the Bitmessage API, hard exit on failure
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

# ------------------------------------------------------------------------------
# exit if api test fails
# ------------------------------------------------------------------------------
apiTest()

# ------------------------------------------------------------------------------    
# create the noisebot address to guarantee availability
# ------------------------------------------------------------------------------
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

# ------------------------------------------------------------------------------
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

# ------------------------------------------------------------------------------    
def getAddress(passphrase):
    passphrase = passphrase.encode('base64')
    return api.getDeterministicAddress(passphrase, 4, 1)
    api.statusBar("(noisebot) getting noisebot address.")

# ------------------------------------------------------------------------------
def totalcount():
    count = open("noisebot_counter.txt", 'r')
    hist_count = count.read()
    count.close()
    print "(noisebot)(historical count) {", str(hist_count), "} messages"

# ------------------------------------------------------------------------------    
def sendMsg():
    delMsg0()
    global globalSubjectPrefix
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
    ttl = rnd(345600, 367200) # time to live between 1 hour to 4 days
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
    
# ------------------------------------------------------------------------------
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

# ------------------------------------------------------------------------------
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

# ------------------------------------------------------------------------------
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

# ------------------------------------------------------------------------------
# choose a random number of consecutive messages for this script instance
# ------------------------------------------------------------------------------
randomruns = rnd(1, 9)
print "(noisebot)(random runs) {", str(randomruns), "} messages"
for incr in (0, randomruns):
    randwait()
    sendMsg()
    randwait()
    delSentMsg0()
    randwait()
    delMsg0()

# ------------------------------------------------------------------------------
# read counter to variable
countfile = open("noisebot_counter.txt", "r")
lastcount = int(countfile.read())
countfile.close()

# ------------------------------------------------------------------------------
# pause before exit - repeat randwait a random number of times
print "(noisebot)(final exit pause)"
exitDelayLoops = rnd(1, 4)
print "(noisebot)(exit delay loops) {", str(exitDelayLoops), "}"
for incr in range (0, exitDelayLoops):
    randwait()
print ""

# ------------------------------------------------------------------------------
# count total noise messages sent   
countfile = open("noisebot_counter.txt", "r")
noisecount = countfile.read()
countfile.close()
print "(noisebot)(noise message count) {", noisecount, "}"

# ------------------------------------------------------------------------------
# delete the randomly created chan and messages
wait(30)
print "deleting temporary chan (", globalPassPhrase, ")"
print "(noisebot)(message deletion)"

delSentMsg0()
delMsg0()
delMsg1()

print "(noisebot)(delete chan) "
api.deleteAddress(checkphrase)

# ------------------------------------------------------------------------------
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
print "(noisebot)(chanfile) done."


# ------------------------------------------------------------------------------
# output total number of historical noise messages

totalcount()

# ------------------------------------------------------------------------------
# final stdout notices
print "(noisebot)(run complete) [+]"

# ------------------------------------------------------------------------------
# random toggle : extra random noisebot will delay on restart half the time

endpause = rnd (0, 300)
if endpause < 150: # add random to the spans between half of run times
    print "(noisebot)(endpause)(random wait) {", endpause, "} seconds"
    wait(endpause)

# ------------------------------------------------------------------------------
# remove the timelock before restarting script

print "(noisebot)(unlock) removing time file."
unlock()

print "(noisebot)(finish) : noisebot is going down [+]"

# ------------------------------------------------------------------------------
# restart the script indefinitely
def main():
    os.execv(sys.executable, ['python2'] + sys.argv)

if __name__ == "__main__":
    main()