import urllib.request, json, urllib.error

def check(url, payload):
    data = json.dumps(payload).encode('utf-8')
    r = urllib.request.Request(f'http://localhost:5000/api/v1/auth/login/{url}', data=data, headers={'Content-Type': 'application/json'})
    try:
        return urllib.request.urlopen(r).read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return e.read().decode('utf-8')

print("Step 1:", check("step1", {"username": "sentinel_admin", "password": "DemoAdmin123!"}))
print("Step 2:", check("step2", {"username": "sentinel_admin", "otp": "123456"}))
