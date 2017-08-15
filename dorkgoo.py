#!/usr/bin/env python
import requests
import urllib2
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
#Disable warning by SSL certificate
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
#Libraries to export results
import xlsxwriter
import json
from urlparse import urlparse
from bs4 import BeautifulSoup
import optparse
#Parser arguments
import argparse
from argparse import RawTextHelpFormatter
import socket
# encoding=utf8
import sys
reload(sys)
sys.setdefaultencoding('utf8')
import re #Expression regular to parse Google with Beautifoul Soup
#define global vars
url_google =[]

""" FUNCTION DELETE DUPLICATES """

def DeleteDuplicate(data):
	urls_union = []
	for i in data:
		if i not in urls_union:
			urls_union.append(i)
	return urls_union

"""FUNCTION WHO IS MY IP"""
def WhoismyIP(domain):
	ip=""
	try:
		ip = socket.gethostbyname(domain)
	except Exception as e:
		#print e
		ip = "0.0.0.0"	
		print "It can't obtain the reverse IP"
	return ip
def SearchGoogle(num,target,language):
	start_page = 0
	nlink = ""
	user_agent = {'User-agent': 'Mozilla/5.0'}
	nlink_clean = ""
	response =""
	soup = ""
	raw_links = ""
	#Split the target in domain and extension
	domain = target.replace(".es",'')
	extension = target.split(".")[1]
	print "\nLooking domains and subdomains of target",target
	for start in range(start_page, (start_page + num)):
		SearchGoogle = "https://www.google.com/search?q=(site:*."+target+"+OR+site:*"+target+"+OR+site:"+domain+"*."+extension+")+-site:www."+target+"&lr=lang_"+language+"&filter=&num=100"
	try:
		response = requests.get(SearchGoogle, headers = user_agent)
	except requests.exceptions.RequestException as e:
		print "\nError connection to server!"
		pass	
	except requests.exceptions.ConnectTimeout as e:
		print "\nError Timeout",target
		pass
	try:
		#Parser HTML of BeautifulSoup
		soup = BeautifulSoup(response.text, "html.parser")
		if response.text.find("Our systems have detected unusual traffic") != -1:
			print "CAPTCHA detected - Plata or captcha !!!Maybe try form another IP..."
			return True
		#Parser url's throught regular expression
		raw_links = soup.find_all("a",href=re.compile("(?<=/url\?q=)(htt.*://.*)"))
		#print raw_links
		for link in raw_links:
			#Cache Google
			if link["href"].find("webcache.googleusercontent.com") == -1:
				nlink = link["href"].replace("/url?q=","")
			#Parser links
			nlink = re.sub(r'&sa=.*', "", nlink)
			nlink = urllib2.unquote(nlink).decode('utf8')
			nlink_clean = nlink.split("//")[-1].split("/")[0]
			url_google.append(nlink_clean)
	except Exception as e:
		print e
	if len(raw_links) < 2:
		#Verify if the search has taken some results
		print "No more results!!!"
		#captcha = True
		return True
	else:
		return False

"""FUNCTION EXPORT RESULTS"""
def ExportResults(data,output,array_ip):
	# Start from the first cell. Rows and columns are zero indexed.
	row = 0
	col = 0
	if output == "js": 
		#Export the results in json format
		print "Exporting the results in an json"
		with open ('output.json','w') as f:
			json.dump(data,f)
	elif (output == "xl"):
		#Export the results in excel format
		print "\nExporting the results in an excel"
		# Create a workbook and add a worksheet.
		workbook = xlsxwriter.Workbook('output.xlsx')
		worksheet = workbook.add_worksheet()
		worksheet.write(row, col, "Domain")
		worksheet.write(row, col+1, "IP")
		row +=1
		for domain in data:
			col = 0
			worksheet.write(row, col, domain)
			row += 1
		#update row
		row = 1
		for ip in array_ip:
			col = 1
			worksheet.write(row, col, ip)
			row += 1
		#close the excel
		workbook.close()
	else:
		exit(1)

#********************************************************#
#Definition and treatment of the parameters
def ShowResults(newlist,target,output,export,catpcha):
	ip = ""
	direction_ip = []
	url_google_final =[]
	url_google_final =DeleteDuplicate(url_google)
	if catpcha == False:
		print "Subdomains found of target "+target+" are:\n",len (url_google_final)
		for i in url_google_final:
			newlist.append(i)
			ip=WhoismyIP(i)
			direction_ip.append(ip)
			print "\n"
			print "\t- " + i+ " ["+ip+"]"
	#verify if the user wants to export results
	if (output =='y'):
		#Only it can enter if -j is put in the execution
		ExportResults(newlist,export,direction_ip)
#MAIN
parser = argparse.ArgumentParser(description="This script searchs files indexed in the main searches of a domain to detect a possible leak information", formatter_class=RawTextHelpFormatter)
parser.add_argument('-d','--domain', help="The domain which it wants to search",required=True)
parser.add_argument('-n','--search', help="Indicate the number of the search which you want to do",required=True)
parser.add_argument('-o','--output', help="Export the results in a file (Y/N)\n Format available:\n\t1.json\n\t2.xlsx", required=False)
parser.add_argument('-l','--language', help="Indicate the language of the search\n\t(es)-Spanish(default)", required=False)
args = parser.parse_args()
print """" 
  _____   ___       _     _____        ___   
 |  __ \ / _ \     | |   / ____|      / _ \  
 | |  | | | | |_ __| | _| |  __  ___ | | | | 
 | |  | | | | | '__| |/ / | |_ |/ _ \| | | | 
 | |__| | |_| | |  |   <| |__| | (_) | |_| | 
 |_____/ \___/|_|  |_|\_\\_____|\___/ \___/  """
                                             
print "\n"
print """** Tool to enumerate subdomains using hacking with search enignes, mainly Google
** Version 1.0
** Author: Ignacio Brihuega Rodriguez a.k.a N4xh4ck5
** DISCLAMER This tool was developed for educational goals. 
** The author is not responsible for using to others goals.
** A high power, carries a high responsibility!"""
newlist=[]
N = int (args.search)
target=args.domain
language = args.language
if language is None:
	language = "es"
output=args.output
if output is None:
	output = 'n'
output = output.lower()
if (output == 'y'):
	print "Select the output format:"
	print "\n\t(js).json"
	print "\n\t(xl).xlsx"
	export = raw_input ().lower()
	if ((export != "js") and (export != "xl")):
		print "Incorrect output format selected."
		exit(1)
else:
	export = "js"
print "Searching subdomains through Google..."
try:
	catpcha = SearchGoogle(N,target,language)
	#Called the function to display the results
	ShowResults(newlist,target,output,export,catpcha)
except Exception as e:
	print e
	pass