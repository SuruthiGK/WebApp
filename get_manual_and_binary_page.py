import sys
import pdb
import subprocess
from subprocess import PIPE, Popen
cmd=sys.argv[1]

def get_man_path(cmd):
	'''Function to return man path and binary path'''
	cmd = 'whereis '+cmd
	cmd_obj = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
	stdout, stderr = cmd_obj.communicate()
	return stdout.strip()

print ('binary:'+get_man_path('-b '+cmd).replace(cmd+':',''))
print ('man page:'+get_man_path(cmd).replace(cmd+':',''))
