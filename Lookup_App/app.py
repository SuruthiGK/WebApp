# -*- coding: utf-8 -*-
from flask import Flask,redirect,render_template,request,url_for,abort
import os
import re
import whois
from ipwhois import IPWhois
import datetime
from json2html import *
import smtplib
import datetime
from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from mail_config import *

app = Flask(__name__)

@app.route('/',methods =['POST','GET'])
def index():
	'''Index Page'''
	return render_template("index.html")

def send_mail(message,to_address):
	'''Function contains Logic to send e-mail with the report attached'''
	fromaddr = SENDER
	toaddr = to_address.split(',')
	password =  PASSWORD
	outgoing_mail_id = OUTGOING_MAIL_ID
	#Mail to multiple e-mail address logic
	for val in toaddr:
		msg = MIMEMultipart()
		msg['From'] = fromaddr
		msg['To'] = val
		msg['Subject'] = "DNS/Ip Look up Report"
		body = "PFA Report"
		msg.attach(MIMEText(body, 'plain'))
		report_file = 'report.html'
		part = MIMEApplication(message, Name=basename(report_file))
		part['Content-Disposition'] = 'attachment; filename="%s"' % basename(report_file)
		msg.attach(part)			
		server = smtplib.SMTP(SMTP_SERVER)
		server.ehlo()
		server.starttls()
		server.ehlo()
		server.login(outgoing_mail_id, password)
		text = msg.as_string()
		server.sendmail(fromaddr,val,text)

@app.route('/result',methods = ['POST'])
def search_dns():
	'''Function contains the logic for whois'''
	dns_lookup = []
	url = request.form['nm']
	if not url:
		return render_template('index.html', error='Please enter DNS/IP')
	email_input = request.form['email']
	url_regex = r"""(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@)))"""
	ip_regex = "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
	url_list = re.findall(url_regex,url)
	ip_list = re.findall(ip_regex,url)
	try:
		for dns in url_list:
			dns_lookup.append(whois.whois(dns))
		for ip in ip_list:
			obj = IPWhois(ip)
			dns_lookup.extend([obj.lookup_rdap()])
		#Mail is sent if e-mail input is given	
		if email_input:
			send_mail(str(json2html.convert(json = dns_lookup)),email_input)
		return str(json2html.convert(json = dns_lookup))
	except Exception,e:
		abort(404,'Error: {}'.format(e))

if __name__ == '__main__':
	app.secret_key = os.urandom(12)
	app.run(port=5000, debug=True)
#