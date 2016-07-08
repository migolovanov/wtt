# WAF Testing Tool
WAF Testing Tool (WTT) is a small script to send attacks to application firewall and check, which are blocked. Attacks are taken from files in specified folder, transformed to HTTP-requests and sent to specified address (IP, hostname).
Script supports python 2.x/3.x and should work on both windows and *nix hosts.

## Help
```# python wtt.py --help
usage: wtt.py [-h] -f PATH -u URL [-a UA] [-c COOKIE] [-o OUTPUT]
              [-t {status_code,pattern,regex}] [-p PATTERN] [--all]
              [--auth {basic,digest,http}] [--auth-url AUTH_URL]
              [--auth-params AUTH_PARAMS] [--csrf] [--csrf-name CSRF_NAME]
              [--csrf-sendname CSRF_SENDNAME] [--health HEALTH]
              [--report-template REPORT_TEMPLATE] [--threads THREADS]

Waf Testing Tool

optional arguments:
  -h, --help            show this help message and exit
  -f PATH, --folder PATH
                        Path to folder containing attacks samples
  -u URL, --url URL     Set WAF address, e.g.http://127.0.0.1/
  -a UA, --useragent UA
                        Set User-Agent header value
  -c COOKIE, --cookie COOKIE
                        Set Cookies informat key1=value1,key2=value2
  -o OUTPUT, --output OUTPUT
                        Output file (default: report.html)
  -t {status_code,pattern,regex}, --type {status_code,pattern,regex}
                        Detect blocked page based on HTTP response
                        code,pattern or regular expression (default:
                        status_code)
  -p PATTERN, --pattern PATTERN
                        Detect blocked page based on status code or pattern
  --all                 Include passed attack to report
  --auth {basic,digest,http}
                        Enable authentication
  --auth-url AUTH_URL   Set url for authentication
  --auth-params AUTH_PARAMS
                        Set authentication parameters in format
                        key1=value1,key2=value2. E.g. for basic and digest
                        auth username should be set as login, password as
                        password: login=john,password=pwd123
  --auth-success AUTH_SUCCESS
                        Regex pattern to find in response and detect if HTTP
                        auth was successful.
  --csrf                Get CSRF-token from response (body, header or cookie)
  --csrf-name CSRF_NAME
                        Param name, that should be found in response
  --csrf-sendname CSRF_SENDNAME
                        Set param name, that is placed in POST-requests if it
                        deffers with csrf-name
  --health HEALTH       Check server availability frequency (default: 10,
                        disable: 0)
  --report-template REPORT_TEMPLATE
                        Set jinja2 report template
  --threads THREADS     Set threads number (default: 1)```

## Usage examples
Attacks to test OWASP Top10 attacks are located in owasp folder and are ready to use against [BeeBox VM](http://www.itsecgames.com/).
Running script with http authentication and taking csrf tokens from X-Csrf-Token header and adding to POST-requests as "csrftoken" will looke like:
```python wtt.py -u http://protected.app.local/ -f owasp --auth http --auth-params login=bee,password=bug,security_level=0,form=submit --auth-url http://172.16.9.34/bWAPP/login.php --auth-success Welcome.Bee --csrf --csrf-name X-Csrf-Token --csrf-sendname csrftoken -o beebox_report.html --all --threads 5```

### Set blocked attacks criteria
```python wtt.py -u http://protected.app.local/ -f owasp -t status_code```
```python wtt.py -u http://protected.app.local/ -f owasp -t pattern -p Forbidden```
```python wtt.py -u http://protected.app.local/ -f owasp -t regex -p ID:.*```

### Auth by setting Cookie
```python wtt.py -u http://172.16.9.34/ -f owasp -c PHPSESSID=1234abcd5678efgh,some_value=1```

### Basic/Digest auth
```python wtt.py -u http://protected.app.local/ -f owasp --auth basic --auth-params login=John,password=123```
```python wtt.py -u http://protected.app.local/ -f owasp --auth digest --auth-params login=John,password=123```

### HTTP auth
```python wtt.py -u http://protected.app.local/ -f owasp --auth http --auth-url http://protected.app.local/bWAPP/login.php --auth-params login=John,password=123,form=Submit --auth-success Welcome.Bee```

### Get CSRF token for POST-requests
```python wtt.py -u http://protected.app.local/ -f owasp --csrf --csrf-name csrftoken```

## Attack template
Attacks should be provided in JSON format and have following structure:
```{  
   "id": "OWASP_A1_21", # attack ID number
   "description": "SQL Injection (GET/Search)", # 
   "method": "GET", # HTTP-request method
   "url": "/bWAPP/sqli_1.php?title=adsf'%20or%201%3D1%20--%201&action=search", # url for HTTP-request
   "status_code": 403, # expected result (403: blocked, any other - pass)
   "headers":{  
      "Connection": "keep-alive",
      "User-Agent": "Mozilla/5.0 Windows NT 6.3; Win64; x64 AppleWebKit/537.36 KHTML, like Gecko Chrome/44.0.2403.107 Safari/537.36"
   }, # list of used headers (in )
   "body": null, # body for POST-requests
   "payload": "adsf' or 1=1 -- 1" # payload in raw form
}```

## Convert payloads to attack
If you have only payloads and want to convert it into attacks format, use:
```python payload2attacks.py -i folder_with_payloads -o folder_for_ready_attacks```