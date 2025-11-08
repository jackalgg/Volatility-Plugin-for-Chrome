Incognito

# Names: Inayah O'Neil & Michael Ott
# Class: CMSC 654
# Professor: Dr. Ahmed
# Assignment: Volatility Plugin for Chrome Incognito

# Purpose: Scan memory for URL strings left by incognito sessions on chrome.
#          Supports windows and linux by using the profile. 

# Import both Windows and Linux helpers
# importing both OS so we can choos at running time
import volatility.plugins.taskmods as taskmods      #Windows process list
import volatility.plugins.linux.pslist as linux_pslist #Linux process list