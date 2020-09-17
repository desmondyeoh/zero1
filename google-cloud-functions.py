import json
import requests
import flask


# requirements.py
"""
requests>=2.24
"""

def check_data(request):
    
    if request.method == 'OPTIONS':
        # Allows GET requests from any origin with the Content-Type
        # header and caches preflight response for an 3600s
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '3600'
        }
        return ('', 204, headers)

    elif request.method == 'POST':
        try:
            request_json = request.get_json()
            email = request_json['email']
            password = request_json['password']
            phone = request_json['phone']
        
            # Set CORS headers for the main request
            headers = {
                'Content-Type':'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type',
            }

            # END CORS

            c = Zero1Checker()
            login_success = c.login(email=email, password=password)
            if not login_success:
                return ({'msg': 'Wrong email / password'}, 401, headers)
            c.authenticate()
            data_usage_GB = c.get_usage(phone_num=phone)
            print('Data used: %.2f GB' % data_usage_GB)
            return ({'data': data_usage_GB}, 200, headers)
        except:
            return ({'msg': 'Internal Server Error'}, 500, headers)
    
    else:
        return ('Not Found', 404)


class Zero1Checker():
    login_url = 'https://zero1.sg/users/account-login?redirect=%2Fusers%2Fmy-account'
    auth_url = 'https://zero1.sg/users/get-auth'
    usage_url = 'https://zero1.sg/api/usages/index?msisid={}'

    def __init__(self):
        self.s = requests.Session()
        self.jwt_token = None
        self.headers = {
            'accept': 'application/json',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'en-GB,en;q=0.9,en-US;q=0.8,zh-CN;q=0.7,zh;q=0.6,ms;q=0.5',
            'dnt': '1',
            'referer': 'https://zero1.sg/users/my-account',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36',
        }

    def login(self, email, password):
        print('logging in...')
        res = self.s.post(self.login_url, data={'email': email, 'password': password})
        if 'Logout' not in res.text:
            print('Login failed...')
            return False
        print('login success!')
        return True
    
    def authenticate(self):
        print('authenticating...')
        res = self.s.get(self.auth_url, headers=self.headers)
        self.jwt_token = json.loads(res.text)['authUser']['jwt_token']
        self.headers['authorization'] = f'Bearer {self.jwt_token}'
        print('authenticate done!')
    
    def get_usage(self, phone_num):
        print('getting usage...')
        res = self.s.get(self.usage_url.format(phone_num), headers=self.headers)
        usage = json.loads(res.text)
        bucket_id = 'DOMESTIC_DATA_UNLIMITED6GFU_THROTTLE'
        data_used_GB = int(list(filter(lambda x: x['bucketId'] == bucket_id, usage['data']))[0]['used'])/1024**3
        return data_used_GB
