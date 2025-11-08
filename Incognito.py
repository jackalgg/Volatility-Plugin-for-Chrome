Incognito

# Names: Inayah O'Neil & Michael Ott
# Class: CMSC 654
# Professor: Dr. Ahmed
# Assignment: Volatility Plugin for Chrome Incognito

# Purpose: Scan memory for URL strings left by incognito sessions on chrome.
#          Supports windows and linux by using the profile. 

# Flow of Program:
#   - detect which OS using profiles
#   - list processes    
#   - fileter chrome
#   - iterate user memory
#   - read bytes and regex scan for URLS
#   - yield PID, name, VA, and preview 

# Import both Windows and Linux helpers
# importing both OS so we can choos at running time
import volatility.plugins.taskmods as taskmods      #Windows process list
import volatility.plugins.linux.pslist as linux_pslist #Linux process list

# detect if image is windows or linux

# get process address space

#read user memory region

#regex scan (for shared lgocig)