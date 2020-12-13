# Totoro
Totoro is a simple Python module for sending HTTP(S) requests through Tor network.

It provides a way to create a parallel Tor process or connect to an existing Tor running service, and supports all controller authentication methods (none, socket, cookie and password).

Basically it adds an abstract layer on top of the *stem* module and combines it with *requests*.

**Requirements** :

 - Python 3
 - Python dependencies : [requests](https://requests.readthedocs.io), [stem](https://stem.torproject.org), [fake_useragent](https://pypi.org/project/fake-useragent/)

**Tested on** : Kali 2020.1

**License** : MIT

## Getting started
### Installation
Ensure you have Tor installed on your system :

 - Debian based : `apt install tor`
 - RHEL based : `yum install tor`

Then install Totoro : `pip3 install totororequests`

### Example #1 : run a Tor process
In this example we use Totoro in the easiest way. Totoro will run Tor in a new process and generate a random password to protect the controller from being accessed outside the Python script context.
```python
#!/usr/bin/env python3

from totororequests import Totoro

# Get Totoro
toro = Totoro()

# Start Tor process
if toro.start():
    print('Tor is running')

# Get Tor status (will check both SocksPort and ControlPort/ControlSocket connection)
status = toro.status() # True / False

# Force the use of a VPN when sending requests over Tor
toro.require_vpn()

# Get IP information (real IP and Tor IP)
ipinfo = toro.ipinfo()
# {'vpn': {'ip': '85.124.56.92', ...}, 'tor': {'ip': '199.249.230.82', ...}}

# Send a 'direct' request
sess, resp = toro.dirreq('GET', 'https://google.com')

# Send a request over Tor network
sess, resp = toro.torreq('GET', 'https://google.com')

# Stop Tor
if toro.stop():
    print('Tor is not running anymore')
```

### Example #2 : connect to a running Tor instance
In this example we connect Totoro to a running instance of Tor, potentially not on the same host. If you want to change your public IP address later, you'll need to authenticate to the controller (see the associated section).
```python
#!/usr/bin/env python3

from totororequests import Totoro

toro = Totoro()

# Connect to Tor already-running service
if toro.connect(host='127.0.0.1', port=9050):
    print('Successfully connected')

# Authenticate to the controller
authok = toro.authenticate(method='password', port=9051, password='PASSWORD')
if authok:
    print('Successfully authenticated')

# Send a request over Tor network
sess, resp = toro.torreq('GET', 'https://google.com')

# Request a new identity
if authok:
    change_identity(sync=True)

# Send another request over Tor network (with new identity)
sess, resp = toro.torreq('GET', 'https://google.com')
```

## Send requests
Totoro is just a wrapper around the [requests](https://2.python-requests.org/en/latest/user/quickstart/) library.

To send a request over Tor network, you may use these nice methods :
```python
# toro.get()
# toro.post()
# toro.put()
# toro.delete()
# toro.patch()
# toro.head()
# toro.options()

# Example :
sess, resp = toro.post('https://example.com/login', data={'username':'admin', 'password':'admin'})
```
As you can see, the method returns a tuple with a **Session** object (`sess`) and a **Response** object (`resp`).

The `resp` variable is what you want, it contains the headers of the response and its content.

The `sess` variable is useful because you can reuse it for a later request. A Session object allows you to persist certain parameters across requests ([read more](https://requests.readthedocs.io/en/master/user/advanced/#session-objects)) :
```python
sess, resp2 = toro.get('https://example.com/admin', session=sess)
```
Doing that you will reuse the Cookies (for instance) you got from the previous request on /login.

## Authenticate to the Controller
As a client, it is possible to control Tor's behavior. Totoro lets you request a new identity (= a new IP address), but you must authenticate to the Tor Controller in order to do that.

Two options :

 - You have started a Tor process with the **start()** method (like in Example#1) : in that case you have nothing to do, Totoro is already authenticated to the new controller. It means you can call **change_identity()**.
 - You have connected to an already running instance of Tor using **connect()** (like in Example#2): before requesting a new identity you must follow the steps below.

The controller may be configured in different ways. Totoro supports all the authentication methods.
Depending on your [**torrc** configuration](https://manpages.debian.org/stretch/tor/torrc.5.en.html), follow the appropriate section.

### Auth : None

If your Tor Controller has opened a Control port with no authentication, like this (**torrc**) :
```
ControlPort 9051
```
You can authenticate this way :
```python
toro.authenticate(method=None, port=9051)
```

### Auth : (Safe)Cookie

If your Tor Controller uses (safe)Cookie authentication, when starting Tor a cookie file will be created, generally with 600 rights. This means you should run your Python script with the same user you started Tor, or you'll run into problems. Here is the standard configuration for Cookie auth (**torrc**) :
```
ControlPort 9051
CookieAuthentication 1
CookieAuthFile /home/user/.tor/control.authcookie
```
And you authenticate with Totoro like that :
```python
toro.authenticate(method='cookie', port=9051)
```

### Auth : Password

If you use Password authentication, you must provide a password in order to authenticate to the controller. In the **torrc** configuration, you need the Hash of the password, obtained with the OpenPGP S2K algorithm :
```
ControlPort 9051
CookieAuthentication 0
HashedControlPassword 16:FA9FED70DB6AEDE160DE15E9F1CEAE70DEA72B7D4505DC10782FF21AF3
```
To easily get the hash, use the tor command :
```
$ tor --hash-password EXAMPLE_PASSWORD
```
And in your Python code :
```python
toro.authenticate(method='password', port=9051, password='EXAMPLE_PASSWORD')
```

### Auth : Socket

Another way to communicate with the controller is using a Control socket (**torrc**) :
```
ControlSocket /home/user/.tor/control.socket
```
Totoro can connect this way :
```python
toro.authenticate(method='socket', socket="/home/user/.tor/control.socket")
```

## Documentation

### Totoro(`warnings=False`)
Creates the main object.

By default you'll NOT get warnings on *stdout/stderr* when you perform an HTTPS request with `verify=False`. To make the warnings appear you can pass `warnings=True`. Behind the scene it simply does : `urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)`

### Totoro.connect(`host, port`)
Connects to a Tor service. Call it only if you're connecting to an external instance. If you use the classic approach with **start()**, it creates a Tor process and does everything for you.

Note: You **MUST** use *start()* **OR** *connect()+authenticate()*, **NOT** both.
```python
toro.connect(host='127.0.0.1', port=9050)
```
Returns True or False.

### Totoro.start(`socks_port=9050, control_port=9051, tor_binary=None, password=None`)
Starts a Tor process. That's the traditional way of using Totoro.

Note: You **MUST** use *start()* **OR** *connect()+authenticate()*, **NOT** both.

The start process is as follow :

- Choose a password to limit access to the future controller :
	- If a **password** is provided, use it ;
	- If not, generate a random [a-zA-Z0-9]{25} password.
- Compute the hash of the password :
	- If the **tor_binary** path is provided (`/usr/bin/tor`), use the binary to get the hashed password ;
	- If not, compute the hash with the OpenPGP S2K algorithm.
- Start the Tor process, and use **socks_port** and **control_port** to configure this newly created instance.

```python
# If ports 9050 and 9051 are available, keep it simple :
toro.start()
```
Returns True or False.

### Totoro.status()
Returns the status of Tor service by checking the connectivity with its Control Port/Socket and Socks port.
```python
if toro.status():
    print('Service available')
```
Returns True or False.

### Totoro.stop(`kill=False`)
Stops the previously created Tor process.

By default it sends a *SIGTERM* signal to the process. You can brutally kill it with `kill=True`.
```python
toro.stop()
```

Returns True or False.

### Totoro.require_vpn(`choice=True`)
Enables or disables the "VPN Strict Mode".

When enabled, your requests will fail if you're not connected to a VPN tunnel.
```python
toro.require_vpn()
```
During the script execution you may want to enable/disable this behavior. You can use the parameter to change the setting.
```python
toro.require_vpn(False)
```

### Totoro.vpn_status()
Checks if the system is connected to a VPN.

It basically checks your **tun0** interface and routes associated.
```python
if toro.vpn_status():
    print('VPN connection : OK')
```

Returns True or False.

### Totoro.ipinfo()
Performs a direct and a Tor request and returns your IP information.

It uses the [IP Geolocation](https://ipgeolocation.io/) service.
```python
toro.ipinfo()
# {
#     'direct': {
#         'ip': 'xx.xx.xx.xx',
#         'hostname': 'XXXX.abo.wanadoo.fr',
#         'country_code2': 'FR',
#         'country_code3': 'FRA',
#         'country_name': 'France',
#         'state_prov': 'Ile-de-France',
#         'district': '',
#         'city': 'Montmorency',
#         'zipcode': 'ZZZZZ',
#         'latitude': 'XXX',
#         'longitude': 'XXX',
#         'security': {
#             'threat_score': 0,
#             'is_tor': False,
#             'is_proxy': False,
#             'proxy_type': '',
#             'is_anonymous': False,
#             'is_known_attacker': False,
#             'is_cloud_provider': False
#         }
#     },
#     'tor': {
#         'ip': '199.249.230.82',
#         'hostname': 'tor29.quintex.com',
#         'country_code2': 'US',
#         'country_code3': 'USA',
#         'country_name': 'United States',
#         'state_prov': 'Texas',
#         'district': '',
#         'city': 'San Angelo',
#         'zipcode': 'ZZZZZ',
#         'latitude': 'XXX',
#         'longitude': 'XXX',
#         'security': {
#             'threat_score': 7,
#             'is_tor': True,
#             'is_proxy': False,
#             'proxy_type': ' ',
#             'is_anonymous': True,
#             'is_known_attacker': False,
#             'is_cloud_provider': False
#         }
#     }
# }
```
The returned dictionary is composed by :

 - a `direct` attribute if you're not connected to a VPN ;
 - a `vpn` attribute if you're connected to a VPN ;
 - a `tor` attribute if you're connected to Tor network.

See the [IP Geolocation API](https://ipgeolocation.io/documentation/ip-geolocation-api.html) for information on the returned JSON object.

### Totoro.dirreq(`[...], session=None`)
Performs a direct request (with your official public connection).

Use it exactly as you'd use the [requests.request](https://requests.readthedocs.io/en/master/api/) method. You must pass the `method` parameter to specify the HTTP verb.
```python
sess, resp = toro.dirreq('GET', 'https://google.com')
```
Returns a tuple composed by the Session object and Response.

The `session` parameter may be passed to reuse a Session from a previous request (and persist data like cookies).

Why this method ? Why not using directly requests without Totoro for this purpose? You're right. The only advantage of this method compared to standard *requests.method()* is that you can benefit from the VPN Strict Mode and the fake User-Agent.

### Totoro.torreq(`[...], session=None`)
Performs a request over the Tor network.

The same as above, you may use it like [requests.request](https://requests.readthedocs.io/en/master/api/). It automatically adds the proxies settings to use Tor.
```python
sess, resp = toro.torreq('GET', 'https://google.com')
```
Returns a tuple composed by the Session object and Response.

The `session` parameter may be passed to reuse a Session from a previous request (and persist data like cookies).

In practice you'll use the below helpers...

### get(), post(), put(), patch(), delete(), options(), head()
Helpers to make it more user-friendly. It's the same you can use with *requests*.

All these methods send the request over Tor. They redirect all the parameters to the **torreq()** method.
```python
sess, resp = toro.get('https://example.com/admin', cookies={'PHPSESSID':'XXXXXX'})
sess, resp = toro.post('https://example.com/login', data={'username':'admin', 'password':'admin'})
# [...]
```
Then it also returns a tuple with (Session, Response), and you may pass the `session` parameter as well.

### Totoro.annoy(`url, times=1, threads=10, sync=False`)
Send `times` requests to `url` and immediately drops them (without waiting for response).

Consequences : As HTTP is over the TCP protocol, a TCP handshake needs to be performed. When using this method you'll start the handshake and cancel it instantly. It will just tickle / SYN flood the remote server.

Change `threads` param to control the number of threads used to send the fake requests.

When using `sync=True`, the requests are sent synchronously, and it blocks your script.

```python
toro.annoy('https://example.com', times=100)
```

Note : Do not use it to generate fake logs because it won't work. Use *make_noise()* instead.

### Totoro.make_noise(`urls, times=1, threads=10, shuffle=False, sync=False, timeout=5`)
Sends a series of HTTP requests, `times` times, in parallel threads and without waiting for responses.

Each request is complete (unlike with the *annoy()* method) so it appears in the accesslog of the remote server and you may use it to generate fake logs.

The `urls` parameter must be a list of URL to fetch, in the following formats :

 - Just the URL (default to GET verb) : `https://example.com/admin`
 - Verb + [space] + URL : `POST https://example.com/admin`

When using `shuffle=True` :

 - The total number of sent requests is `times` (it sends `times` times a random request from the list) ;
 - The requests are sent in whatever order, and randomly picked.

When using `shuffle=False` :

 - The total number of sent requests is `times * len(urls)` (it sends `times` times the entire list of requests) ;
 - The requests are sent in the order of the list ;
 - There is no guarantee that they are received in exact same order (and generally won't).

For instance, this instruction :
```python
toro.make_noise([
    'https://example.com/',
    'https://example.com/favicon.ico',
    'GET https://example.com/css/bootstrap.min.css',
    'GET https://example.com/js/jquery.min.js',
    'POST https://example.com/login',
    'DELETE https://example.com/user/15/avatar'
], times=15, shuffle=True)
```
...will send 15 requests, randomly picked from the `urls` list.

When using `sync=True`, the requests are sent synchronously, and it blocks your script.

Change the `timeout` param to set a timeout (in seconds) for each request in the thread pool.

### Totoro.authenticate(`method=None, port=None, socket=None, password=None`)
Sets the authentication parameters and instantiate the connection to the controller. Call it only if you're connecting to an external instance.

Note: You **MUST** use *start()* **OR** *connect()+authenticate()*, **NOT** both.

Parameters :

 - **method** : specify the authentication method (None, `cookie`, `socket`, `password`)
 - **port** : controller port (required **except** if `method="socket"`)
 - **socket** : socket path (required **only** if `method="socket"`)
 - **password** : authentication password (**only** if `method="password"`)

See the section "*Authenticate to the Controller*" for more details.

Returns True or False.

### Totoro.controller()
Returns the controller object. It is an instance of [stem.control.Controller](https://stem.torproject.org/api/control.html).

Totoro just uses it to change the identity, but you may want to do more...
```python
ctrl = toro.controller()

print('Protocol Info :')
print(ctrl.get_protocolinfo())

print('Circuit Status :')
print(ctrl.get_info('circuit-status'))
```

### Totoro.change_identity(`sync=False`)
Requests a new identity (and likely a new IP address).

By default it just sends a NEWNYM signal to Tor controller and don't wait. That means it's not synchronous and it may take a few seconds for the new identity to be effective.
```python
toro.change_identity()
```
You may want to wait until the new identity is OK :
```python
toro.change_identity(sync=True)
```
Caution : it may block the script during several seconds.

### Exceptions
Sometimes an exception can be raised by the Totoro engine.

 - **TotoroException** : different reasons, generally when you provide incorrect parameters to Totoro methods (see the error message for more information) ;
 - **TorNotRunningTotoroException** : you tried to send a request through Tor but Tor is not running ;
 - **VPNNotConnectedTotoroException** : you tried to send a request while VPN Strict Mode is enable, and your VPN connection seems to be broken.

## Changelog

Version history :

 - 1.2.0 - Added dependencies in setup.py, hid SSL warnings by default, improved newnym request behavior, and made Totoro compatible with requests to _.onion_ domains
 - 1.1.3 - Added default User-Agent (fallback) to avoid exceptions when it's not possible to fetch the list from internet
 - 1.1.1 & 1.1.2 - Optimization on thread methods (annoy & make_noise) : proper pool closure, requests timeout, better and more elegant code
 - 1.1.0 - New methods : *annoy()* and *make_noise()*
 - 1.0.0 - Initial version of Totoro
