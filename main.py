from curl_cffi import requests
import re
import sys
import encrypt_password

user_id = "아이디"
user_pw = "비밀번호"

service_name = "SCSP_CLOUD" # 나이스플러스 용
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

session = requests.Session()
enc_user_pw = encrypt_password.enc(user_pw)


# 나이스플러스
secret_key_url = "https://neisplus.kr/oauth/oauth_csp_login_nxt.jsp"
headers = {
    "user-agent": user_agent,
    "referer": "https://edupass.neisplus.kr/",
}
response = session.get(secret_key_url, headers=headers)
data = response.text


# 시크릿 키 파싱
match = re.search(r'name="secretKey"[^>]*value="([^"]+)"', data)
if match:
    secret_key = match.group(1)
else:
    print("SecretKey를 찾을 수 없습니다.")
    sys.exit(1)


# 세션 획득
url = f"https://edupass.neisplus.kr/{service_name}/login.do"
payload = {
    "secretKey": secret_key,
    "mhrlsNo": ""
}
headers = {
    "origin": "https://neisplus.kr",
}
response = session.post(url, data=payload, headers=headers)

cookies = session.cookies.get_dict()
wmonid = cookies.get('WMONID', '')
jsessionid = cookies.get('JSESSIONID', '')
routeid = cookies.get('ROUTEID', '')


# 로그인 요청
url = "https://edupass.neisplus.kr/edo_edo_li01_002.do"
payload = f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Root xmlns=\"http://www.nexacroplatform.com/platform/dataset\">\n\t<Parameters>\n\t\t<Parameter id=\"jsessionidTest\" />\n\t\t<Parameter id=\"WMONID\">{wmonid}</Parameter>\n\t\t<Parameter id=\"JSESSIONID\">{jsessionid}</Parameter>\n\t\t<Parameter id=\"ROUTEID\">{routeid}</Parameter>\n\t\t<Parameter id=\"svcId\" />\n\t\t<Parameter id=\"voId\" />\n\t\t<Parameter id=\"method\" />\n\t</Parameters>\n\t<Dataset id=\"dsSearch\">\n\t\t<ColumnInfo>\n\t\t\t<Column id=\"userDtcNo\" type=\"STRING\" size=\"256\" />\n\t\t\t<Column id=\"userId\" type=\"STRING\" size=\"256\" />\n\t\t\t<Column id=\"userPswd\" type=\"STRING\" size=\"256\" />\n\t\t\t<Column id=\"eduDgtlOpsUserScCd\" type=\"STRING\" size=\"256\" />\n\t\t\t<Column id=\"lgnMthScCd\" type=\"STRING\" size=\"256\" />\n\t\t\t<Column id=\"cntnDvcsClfCd\" type=\"STRING\" size=\"256\" />\n\t\t\t<Column id=\"autoLoginYn\" type=\"STRING\" size=\"256\" />\n\t\t\t<Column id=\"mhrlsNo\" type=\"STRING\" size=\"256\" />\n\t\t\t<Column id=\"shlCd\" type=\"STRING\" size=\"256\" />\n\t\t</ColumnInfo>\n\t\t<Rows>\n\t\t\t<Row>\n\t\t\t\t<Col id=\"userId\">{user_id}</Col>\n\t\t\t\t<Col id=\"userPswd\">{enc_user_pw}</Col>\n\t\t\t\t<Col id=\"eduDgtlOpsUserScCd\">1</Col>\n\t\t\t\t<Col id=\"lgnMthScCd\">01</Col>\n\t\t\t\t<Col id=\"cntnDvcsClfCd\">10</Col>\n\t\t\t\t<Col id=\"autoLoginYn\">N</Col>\n\t\t\t</Row>\n\t\t</Rows>\n\t</Dataset>\n</Root>"
headers = {
    "content-type": "text/xml",
    "ui": "nexacro",
    "referer": f"https://edupass.neisplus.kr/{service_name}/login.do",
}
response = session.post(url, data=payload, headers=headers)
data = response.text

url = f"https://edupass.neisplus.kr/test_edo_edo_of01_002.do?siteId={service_name}"

response = session.get(url, allow_redirects=False)
location = response.headers.get('Location')
auth_code = (m.group(1) if (m := re.search(r'authCode=([^&]+)', location)) else None)

headers = {
    "user-agent": user_agent,
    "referer": "https://edupass.neisplus.kr/",
}

response = session.get(location, headers=headers)
data = response.text

url_matches = re.findall(r'url\s*=\s*["\']([^"\']+)["\']', data)
if url_matches:
    url = url_matches[-1]
else:
    print("URL 변수를 찾을 수 없습니다.")
    sys.exit(1)

url = f"https://www.neisplus.kr{url}"


# 직접 사용 (Ex. 봉사활동내역)
url = "https://www.neisplus.kr/edi/slf/lh/edi_slf_lh00_001.do"

payload = {}
headers = {
    "accept": "application/json, text/plain, */*",
}

response = session.post(url, json=payload, headers=headers)
data = response.text


print(data)
