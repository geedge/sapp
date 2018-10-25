import os
import sys
import subprocess
from optparse import OptionParser
from ftplib import FTP
from pprint import pprint #del later

dic={}
contact={}
date={}
filename_default="version.conf"
ftpserver='10.0.6.235'
directory='./MESA/'

def getconf(confname):
	with open(confname) as f:
		for line in f.readlines():
			if line.startswith('#'):
				continue
			parts=line.split()
			if len(parts)>=3:
				name=parts[0].strip().replace('version','')
				name=name.replace('VERSION','')
				name=name.replace('_','')
				dic[name]=parts[1]
				contact[name]=parts[2]
				date[name]=parts[3]

def getfile(path):
	for root,dirs,files in os.walk(path):
		for f in files:
			if f.endswith('.so'):
				#print(f)
				fname=os.path.join(root,f)
				yield fname

def getversion(f):
	vers=subprocess.Popen('nm '+f+'|grep VERSION',shell=True,stdout=subprocess.PIPE)
	for line in vers.stdout.readlines():
		i=line.split()
		#print(i[-1])
		yield(i[-1])

def checkversion(v):
	name=v.strip().replace('version','')
	name=name.replace('VERSION','')
	name=name.replace('_','')
	name=filter(lambda ch:ch not in '0123456789',name)
	#newv=dic[name]
	newv=dic.get(name,None)
	if newv==None:
		print('\033[1;33m %s \033[1;m' % ('\t+++'+name+' is not found in your config file.'))
		return None
	if newv==v:
		print('\t\033[1;32m%-120s\033[1;32m%s \033[1;m' % (v,'[LASTEST]'))
	else:
		vnow=v.strip().split()
		vnew=newv.strip().split()
		if vnow[-1]<vnew[-1]:
			print('\t\033[1;31m%-120s\033[1;31m%s \033[1;m' % (v,'[OUTDATED]'))
			print('\t[+]The latest version is '+vnew[-1]+', build in '+ date[name]+'. Please contact '+contact[name]+' to verifiy the version.')
		elif vnow[-1]>vnew[-1]:
			print('\t\033[1;33m%-120s\033[1;33m%s \033[1;m' % (v,'[WARNING]'))
			print('\t[+]Newer than your latest config version!')
		else:
			print('\033[1;33m %s \033[1;m' % ('#####cannot check '+v))

def ftp_down(fname=filename_default):
	try:
		ftp=FTP(ftpserver)
		ftp.login()
		ftp.cwd(directory)
		#version.conf->version.conf.bak
		if os.path.exists(filename_default):
			#os.name(filename_default,filename_default+'.bak')
			if os.system('mv '+filename_default+' '+filename_default+'.bak')==0:
				print(filename_default+' has been renamed as '+filename_default+'.bak')
		file_handler=open(filename_default,'wb').write
		ftp.retrbinary("RETR %s" % os.path.basename(filename_default),file_handler,1024)
		ftp.close()
		print("get "+filename_default+" from "+ftpserver+" successfully.")
	except:
		print("get "+filename_default+" from "+ftpserver+" failed.")

'''def main(argv):
	getconf()
	if len(argv)==1:
		print("arg error")
		print("please input the dir path!")
		exit()
	for f in getfile(argv[1]):
		print(f)
		for i in getversion(f):
			#print('\t'+i)
			checkversion(i)
	#print('------')
	#pprint(dic)'''

def main():
	useage="usage:%prog [options arg]"
	parser=OptionParser(useage)
	parser.add_option("-f","--file",dest="filename",default=filename_default,help="FILENAME of your config. Default file is "+filename_default)
	parser.add_option("-p","--path",dest="path",default="./",help="lib PATH that you want to verifiy. Default path is ./")
	parser.add_option("-u","--update",dest="update",action="store_true",default=False,help="update config from ftp.")
	(options,args)=parser.parse_args()
	#print(options.filename)
	#print(options.path)
	if options.update:
		ftp_down()
	else:
		if not os.path.exists(options.filename):
			print(options.filename+" not exists")
			exit()
	getconf(options.filename)
	for f in getfile(options.path):
		print(f)
		for i in getversion(f):
			#print('\t'+i)
			checkversion(i)

if __name__=="__main__":
	#main(sys.argv)
	main()

