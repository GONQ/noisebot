from random import randrange as rnd

global avglo
global avghi
global avgsec

avglo = 0
avghi = 0
avgsec = 0

def wait(secs):
    time.sleep(secs)
    
def waitlock():
    global avglo
    global avghi
    global avgsec
    losec = 0
    hisec = 0
    roundsec = rnd(1, 27)
    for x in range(0, roundsec):
        minsec = rnd(1, 9)
        maxsec = rnd(10, 108)
        losec += minsec
        hisec += maxsec
    secs = rnd(losec, hisec)
    avglo += losec
    avghi += hisec
    avgsec += secs

print "\navglo\tavghi\tavgsec"

def stats():
    global avglo
    global avghi
    global avgsec
    x = 0
    while x < 100000:
        x += 1
        waitlock()
        
    avglo /= x
    avghi /= x
    avgsec /= x

    print avglo, "\t", avghi, "\t", avgsec
    
for x in range (0, 10):
    stats()