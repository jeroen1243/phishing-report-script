import os
import socket
import time
import json
import datetime

import dns.resolver
import requests
import smtplib
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from dotenv import load_dotenv

from tldextract import extract
from selenium import webdriver
from selenium.webdriver import FirefoxOptions
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions

from abuse_finder import domain_abuse
import querycontacts

dns.resolver.default_resolver=dns.resolver.Resolver(configure=False)
dns.resolver.default_resolver.nameservers=['8.8.8.8']



# load variables from .env file
load_dotenv()

# debug mode
DEBUG = os.getenv('DEBUG')

# SMTP settings
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = os.getenv('SMTP_PORT')
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

# other settings
EMAIL_COPY = os.getenv('EMAIL_COPY')
EMAIL_FROM = os.getenv('EMAIL_FROM')
REPORTER_NAME = os.getenv('REPORTER_NAME')
XARF = os.getenv('XARF')
REPORTER_ORG = os.getenv('ReporterOrg')
REPORTER_ORG_DOMAIN = os.getenv('ReporterOrgDomain')
REPORTER_ORG_EMAIL = os.getenv('ReporterOrgEmail')
REPORTER_CONTACT_EMAIL = os.getenv('ReporterContactEmail')
REPORTER_CONTACT_NAME = os.getenv('ReporterContactName')
REPORTER_CONTACT_PHONE = os.getenv('ReporterContactPhone')

NETCRAFT_EMAIL = os.getenv('NETCRAFT_EMAIL')
CRDF_API_KEY = os.getenv('CRDF_API_KEY')


def get_date():
    utc_dt_aware = datetime.datetime.now(datetime.timezone.utc)
    return utc_dt_aware.strftime("%Y-%m-%dT%H:%M:%SZ")

def get_ip(url):
    tsd, td, tsu = extract(url) 
    domain = td + '.' + tsu 
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as err:
        if DEBUG == True:
            print(err)
        return None

# extract abuse e-mail from ip
def get_abuse_email_host(ip):
    cf = querycontacts.ContactFinder()
    return(cf.find(ip))

# extract abuse e-mail from url
def get_abuse_email_host_from_url(url):
    ip = get_ip(url)
    if ip:
        abuse_email_host= get_abuse_email_host(ip)
        print("Abuse contact host " + ip + ": " + abuse_email_host[0])
        return abuse_email_host
    else:
        print("No IP found")
        return None

def get_abuse_email_registrar(url):
    tsd, td, tsu = extract(url) 
    domain = td + '.' + tsu 
    try:
        domain_abuse_info = domain_abuse(domain)
        print("\nAbuse contact registrar " + domain + ": " + domain_abuse_info["abuse"][0])
        return (domain_abuse_info["abuse"])
    except Exception as err:
        if DEBUG == 'True':
            print(err)
            print("WHOIS data:\n " + domain_abuse(domain) + "\n")

def fill_in_cloudflare_form(url, reason):
    try:
        opts = FirefoxOptions()
        opts.add_argument("--headless")
        web = webdriver.Firefox(options=opts)
        web.get("https://abuse.cloudflare.com/phishing")
        time.sleep(3)
        name = web.find_element("xpath",'//*[@id="root"]/main/div/div[2]/form/div[1]/label/div/div[2]/div/input')
        name.send_keys(REPORTER_NAME)
        email1 = web.find_element("xpath",'/html/body/div/main/div/div[2]/form/div[2]/label/div/div[2]/div/input')
        email2 = web.find_element("xpath",'/html/body/div/main/div/div[2]/form/div[3]/label/div/div[2]/div/input')
        email1.send_keys(REPORTER_CONTACT_EMAIL)
        email2.send_keys(REPORTER_CONTACT_EMAIL)
        url1 = web.find_element("xpath",'//*[@id="root"]/main/div/div[2]/form/div[7]/label/div/div[2]/div/textarea')
        url1.click()
        
        url1.send_keys(url)
        evidence = web.find_element("xpath",'//*[@id="root"]/main/div/div[2]/form/div[8]/label/div/div[2]/div/textarea')
        evidence.send_keys("Report reason: "+ reason)
        # click on button to provide contact info to hosting provider
        button = web.find_element("xpath",'/html/body/div/main/div/div[2]/form/div[10]/div/div[2]/div[2]/label/input')
        button.click()
        # click on button to send report
        button = web.find_element("xpath",'/html/body/div/main/div/div[2]/form/div[11]/div/button')
        button.click()
        print("Abuse report send to Cloudflare")
    except Exception as err:
        if DEBUG == 'True':
            print(err)
        print("Something went wrong with Cloudflare form")
    

def report_domain_to_registrar(url, reason, abuse_email_registrar):
    ip = get_ip(url) 
    if XARF:   
        msg = MIMEMultipart('report', report_type='feedback-report')
        msg['From'] = EMAIL_FROM
        msg['To'] = str(abuse_email_registrar[0])
        msg['Cc'] = EMAIL_COPY
        msg['Subject'] = 'Report malicious domain'
        msg['MIME-Version'] = '1.0'

        # Create human-readable part
        human_part = MIMEText('Dear,\n\nPlease find the reported url below:\n' + url + '\nReport reason: '+ reason, _subtype='plain')
        msg.attach(human_part)

        # Create machine-readable part
        machine_part = MIMEText('Feedback-Type: xarf\nUser-Agent: Abusix/1.0\nVersion: 1', _subtype='feedback-report')
        msg.attach(machine_part)

        # Create XARF report part
        xarf_report = {
            "Version": "2",
            "ReporterInfo": {
                "ReporterOrg": REPORTER_ORG,
                "ReporterOrgDomain": REPORTER_ORG_DOMAIN,
                "ReporterOrgEmail": REPORTER_ORG_EMAIL,
                "ReporterContactEmail": REPORTER_CONTACT_EMAIL,
                "ReporterContactName": REPORTER_CONTACT_NAME,
                "ReporterContactPhone": REPORTER_CONTACT_PHONE
            },
            "Disclosure": 'true',
            "Report": {
                "ReportClass": "Content",
                "ReportType": "Phishing",
                "Date": str(get_date()),
                "SourceIp": str(ip),
                "SourcePort": 80,
                "SourceUrl": url,
                "Ongoing": 'true'
            }
            }
        xarf_part = MIMEApplication(json.dumps(xarf_report), _subtype='json', name='xarf.json')
        xarf_part.add_header('Content-Disposition', 'attachment', filename='xarf.json')
        msg.attach(xarf_part)
    else:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_FROM
        msg['To'] = str(abuse_email_registrar[0])
        msg['Cc'] = EMAIL_COPY
        msg['Subject'] = 'Report malicious domain'
        msg.attach(MIMEText('Dear,\n\nPlease find the reported url below:\n' + url + '\nReport reason: '+ reason, 'plain'))

    # Send the message via  SMTP server
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, abuse_email_registrar, msg.as_string())
            print("Abuse report send to:" + msg['to'])   
    except Exception as e:
        if DEBUG == True:
            print(f'Error: {e}')       

def report_abuse_to_host(url, reason, abuse_email_host):
    ip = get_ip(url)
    if abuse_email_host[0] == 'abuse@cloudflare.com': 
          fill_in_cloudflare_form(url, reason)  
    else:
        if XARF:
            msg = MIMEMultipart('report', report_type='feedback-report')
            msg['From'] = EMAIL_FROM
            msg['To'] = str(abuse_email_host[0])
            msg['Cc'] = EMAIL_COPY
            msg['Subject'] = 'Report malicious site hosted on IP: ' + ip
            msg['MIME-Version'] = '1.0'

            # Create human-readable part
            human_part = MIMEText("Dear,\n\nPlease find the reported url below:\n" + url + "\nHosted on IP: " + ip + "\nReport reason: " + reason + "\nReport time stamp (UTC):" + str(get_date()) + "\n\nKind regards,\n "+REPORTER_NAME +  + """\n\n\n\n\n\nThe recipient address of this report was provided by the Abuse Contact DB by Abusix.
    Abusix provides a free IP address to abuse@ address lookup service.  Abusix does not maintain the core database content but provides a service built on top of the RIR databases.
    If you wish to change or report a non-working abuse contact address, please contact the appropriate RIR responsible for managing the underlying data.
    If you have any further questions about using the Abusix Abuse Contact DB, please either contact us via email at support@abusix.ai or visit https://abusix.com/contactdb
    Abusix is neither responsible nor liable for the content or accuracy of this message.""", _subtype='plain')
            msg.attach(human_part)

            # Create machine-readable part
            machine_part = MIMEText('Feedback-Type: xarf\nUser-Agent: Abusix/1.0\nVersion: 1', _subtype='feedback-report')
            msg.attach(machine_part)

            # Create XARF report part
            xarf_report = {
                "Version": "2",
                "ReporterInfo": {
                    "ReporterOrg": REPORTER_ORG,
                    "ReporterOrgDomain": REPORTER_ORG_DOMAIN,
                    "ReporterOrgEmail": REPORTER_ORG_EMAIL,
                    "ReporterContactEmail": REPORTER_CONTACT_EMAIL,
                    "ReporterContactName": REPORTER_CONTACT_NAME,
                    "ReporterContactPhone": REPORTER_CONTACT_PHONE
                },
                "Disclosure": 'true',
                "Report": {
                    "ReportClass": "Content",
                    "ReportType": "Phishing",
                    "Date": str(get_date()),
                    "SourceIp": str(ip),
                    "SourcePort": 80,
                    "SourceUrl": url,
                    "Ongoing": 'true'
                }
                }
            xarf_part = MIMEApplication(json.dumps(xarf_report), _subtype='json', name='xarf.json')
            xarf_part.add_header('Content-Disposition', 'attachment', filename='xarf.json')
            msg.attach(xarf_part)
        else:
            msg = MIMEMultipart()
            msg['From'] = EMAIL_FROM
            msg['To'] = str(abuse_email_host[0])
            msg['Cc'] = EMAIL_COPY
            msg['Subject'] = 'Report malicious site hosted on IP: ' + ip
            msg.attach(MIMEText("Dear,\n\nPlease find the reported url below:\n" + url + "\nHosted on IP: " + ip + "\nReport reason: " + reason + "\nReport time stamp (UTC):" + str(get_date()) + "\n\nKind regards,\n "+REPORTER_NAME +  + """\n\n\n\n\n\nThe recipient address of this report was provided by the Abuse Contact DB by Abusix.
    Abusix provides a free IP address to abuse@ address lookup service.  Abusix does not maintain the core database content but provides a service built on top of the RIR databases.
    If you wish to change or report a non-working abuse contact address, please contact the appropriate RIR responsible for managing the underlying data.
    If you have any further questions about using the Abusix Abuse Contact DB, please either contact us via email at support@abusix.ai or visit https://abusix.com/contactdb
    Abusix is neither responsible nor liable for the content or accuracy of this message.""", _subtype='plain'))

        # Send the message via SMTP server
        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.ehlo()
                server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_USER, abuse_email_host, msg.as_string())
                print("Abuse report send to:" + msg['to'])   
        except Exception as e:
            print(f'Error: {e}')


# report site to abuse e-mail
def report_abuse(url, reason):
    now = get_date()

    abuse_email_host = get_abuse_email_host_from_url(url)
    abuse_email_registrar = get_abuse_email_registrar(url)
    ip = get_ip(url)

    if abuse_email_registrar:
        if(input("\nDo you want to report this domain to the registrar ? (y/n): ") == "y") :
            report_domain_to_registrar(url, reason, abuse_email_registrar)
    else:
        print("No abuse email found for this domain")
    if abuse_email_host:
        if(input("\nDo you want to report this site to the hosting provider? (y/n): ") == "y"):
            report_abuse_to_host(url, reason, abuse_email_host)
    else:
        print("No abuse email found for this IP")
    
    if(input("\nDo you want to report it to other phishing instances via mail? (y/n): ") == "y"):
        receivers = 'report@openphish.com,suspicious@safeonweb.be,phishing-report@us-cert.gov,reportphishing@apwg.org,report@phishing.gov.uk,reportphishing@reportphishing.net'
        email = EmailMessage()
        email['from'] = EMAIL_FROM
        email['to'] = receivers
        email['cc'] = EMAIL_COPY
        email['subject'] = 'Report malicious site'
        email.set_content("Dear,\n\nPlease find the reported url below:\n" + url + "\nHosted on IP: " + ip + "\nReport reason: " + reason + "\nReport time stamp (UTC):" + str(now) + "\n\nKind regards,\n"+REPORTER_NAME + "")
        with smtplib.SMTP(host=SMTP_SERVER, port=SMTP_PORT) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(email)
        print("Abuse report send to:" + email['to'])

    if NETCRAFT_EMAIL:
        if (input("\nDo you want to report it to Netcraft? (y/n): ") == "y"):
            headers = {'Content-Type': 'application/json', 'Accept':'application/json'}
            data =  []
            data.append({'url': url, 'country': 'BE'})
            r = requests.post('https://report.netcraft.com/api/v3/report/urls', json={ "email": NETCRAFT_EMAIL, "urls": data,
            }, headers=headers)
            print(r.text)

    if CRDF_API_KEY:
        if (input("\nDo you want to report it to CRDF? (y/n): ") == "y"):
            crdf_urls = []
            crdf_urls.append(url)
            r = requests.post('https://threatcenter.crdf.fr/api/v0/submit_url.json', json={
            "token": CRDF_API_KEY,
            "method": "submit_url",
            "urls": crdf_urls
            })
            print(r.text)

        

report_abuse(input("Enter url: "), input("Enter reason: "))

