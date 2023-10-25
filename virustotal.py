##
##github
##

import requests
import json
import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sys


##manuel doldurulması gereken alan başlangıç

api_key=''#api key , virustotal üye olarak alabilrisiniz,üye olduktan sonra sağ üst api_key kısmından alabilrisniz.

urls=['yandex.com','google.com','duckduckgo.com']  #taranmasını istediginiz alan adları.

mail_server='' #mail sunucu ayarları smtp.google.com gibi

port='587' #email sunucu portu default 587 

email_user=''  #mail sunucuda kullanılcacak olan mail adresi 

email_pass=''  #mail sunucuda kullanılcacak olan mail şifresi

email_from=''  #mail gönderici adresi , email_user ile aynı olabilir

email_recipient="exampl@google.com,example@yandex.com"   #tek mail yazılabilir yada çoklu mail olursa aralarında , olmalı.

email_subject='Konu'  #Email konu başlıgı

##manuel doldurulması gereken alan bitişi

kontrol=[]


def kota_ogren():
    url = "https://www.virustotal.com/api/v3/users/"+api_key

    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)

    data=json.loads(response.text)

    used=data['data']['attributes']['quotas']['api_requests_hourly']['used']
    limit=data['data']['attributes']['quotas']['api_requests_hourly']['allowed']

    used_gunluk=data['data']['attributes']['quotas']['api_requests_daily']['used']
    limit_gunluk=data['data']['attributes']['quotas']['api_requests_daily']['allowed']


    oran=(int(used)*100)/int(limit)
    oran=int(oran)

    oran_gunluk=(int(used_gunluk)*100)/int(limit_gunluk)
    oran_gunluk=int(oran_gunluk)


    print("Saatlik Kullanım "+str(used)+" Sattlik Limit "+str(limit))
    print("Saatlik api Kullanım oranı limiti %"+str(oran))

    print("Günlük Kullanım "+str(used_gunluk)+" Günlük Limit "+str(limit_gunluk))
    print("Günlük api Kullanım oranı limiti %"+str(oran_gunluk))


def parse_id(x):
    id = x.split("-")
    return id[1]

def time_convert(x):
    x = datetime.datetime.fromtimestamp(x)
    return x

print("merhaba virustotal app hoşgeldiniz \n")

def ilk_sorgu(urls):

    url = "https://www.virustotal.com/api/v3/urls"

    payload = { "url": urls }
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded"
    }

    response = requests.post(url, data=payload, headers=headers)

    data=json.loads(response.text)

    veri=data['data']['id']

    return parse_id(veri)

def re_scan(x):

    url = "https://www.virustotal.com/api/v3/urls/"+x+"/analyse"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    response = requests.post(url, headers=headers)

def sonuc_getir(id):
    url = "https://www.virustotal.com/api/v3/urls/"+id

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)

    #print(response.text)

    data=json.loads(response.text)

    #print(data['data']['attributes']['last_analysis_stats'])
    #print(time_convert(data['data']['attributes']['last_analysis_date']))

    return data['data']['attributes']['last_analysis_stats'],time_convert(data['data']['attributes']['last_analysis_date']),data['data']['attributes']['last_analysis_stats']['malicious']

def all():    
    global kontrol

    kota_ogren()

    for x in urls:
        try:
            id=ilk_sorgu(x)
            re_scan(id)
            print(x)
            a,b,c,=sonuc_getir(id) 
            if c!=0:    #full liste gönderimi isteniliyorsa bu satır kaldırılmalı.
                kontrol.append(x+" Tarama istatistikleri : "+str(a)+" Son analiz zamani : "+str(b))

        except:
            print(x + " olmadı")
        
        


        #bu kısım botun düzgün çalıştıgından emin olunduktan sonra açılacak.
        #if c!=0:
        #    kontrol.append(x+" Tarama istatistikleri : "+str(a)+" Son analiz zamani : "+str(b))
        

    kota_ogren()


def mail_gonder(x):
    global kontrol
    dize='\n'.join(x)

    try:
        mail = smtplib.SMTP(mail_server,port) 
        mail.ehlo()
        mail.starttls()
        mail.login(email_user, email_pass)

        mesaj = MIMEMultipart()
        mesaj["From"] = email_from           
        mesaj["To"] = email_recipient
        mesaj["Subject"] =email_subject   



        body = """

        """+dize+"""

        """

        body_text = MIMEText(body, "plain")  
        mesaj.attach(body_text)

        mail.sendmail(mesaj["From"], mesaj["To"].split(','), mesaj.as_string())
        print("success.")
        mail.close()

    except:
        print("Error:", sys.exc_info()[0])

all()

mail_gonder(kontrol)
