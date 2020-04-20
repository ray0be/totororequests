# Totoro
Totoro is a simple Python module for sending HTTP(S) requests through Tor network.

It provides a way to create a Tor subprocess or connect to an existing Tor running service, and supports all controller authentication methods (noauth, socket, cookie and password).

**Requirements** :

 - Python 3
 - Python dependencies : [requests](https://requests.readthedocs.io), [stem](https://stem.torproject.org), [fake_useragent](https://pypi.org/project/fake-useragent/)

**Tested on** : Kali 2020.1
**License** : MIT

## Getting started
### Installation
Ensure you have Tor installed on your system :

 - Debian based : `apt install tor`
 - Fedora based : `yum install tor`

Then install Totoro : 

> TODO
`pip install [===>SOON<===]`

### Example #1 : run a Tor subprocess
In this example we use Totoro in the easiest way. Totoro will run Tor in a new subprocess and generate a random password to protect its controller from being accessed outside the Python script context.
```python
#!/usr/bin/env python3

from totororequests import Totoro

# Get Totoro
toro = Totoro(nowarning=True)

# Start Tor subprocess
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
# Todo
```

> TODO

## Authenticate to the Controller
As a client, it is possible to control the Tor's behavior. Totoro let you request a new identity (= a new IP address), but you must authenticate to the Tor Controller in order to do that.

Two options :

 - You have started a Tor subprocess with the **start()** method : in that case you have nothing to do, Totoro has already authenticated to the created controller. It means you can call **change_identity()**.
 - You have connected to an already running instance of Tor using **connect()** : before requesting a new identity you must follow the below steps.

The controller has different authentication methods. Totoro supports all.
Depending on your **torrc** configuration, follow the appropriate section.

### Auth : None

> TODO

### Auth : (Safe)Cookie

> TODO

### Auth : Password

> TODO

### Auth : Socket

> TODO

## Documentation

### Totoro
Main object

> TODO

### Totoro.connect()
Connection to Tor service

> TODO

### Totoro.start()

> TODO

### Totoro.status()

> TODO

### Totoro.stop()

> TODO

### Totoro.require_vpn()

> TODO

### Totoro.vpn_status()

> TODO

### Totoro.ipinfo()

> TODO

### Totoro.dirreq()

> TODO

### Totoro.torreq()

> TODO

### Totoro.authenticate()

> TODO

### Totoro.controller()
The controller object is an instance of [stem.control.Controller](https://stem.torproject.org/api/control.html).

Totoro just uses it to change the identity, but you may want to do more...
```python
ctrl = toro.controller()

print('Protocol Info :')
print(ctrl.get_protocolinfo())

print('Circuit Status :')
print(ctrl.get_info('circuit-status'))
```

### Totoro.change_identity()

> TODO

### Exceptions
Sometimes an exception can be raised by the Totoro engine.

 - **TotoroException** : different reasons, generally when you provide incorrect parameters to Totoro methods (see the error message for more information) ;
 - **TorNotRunningTotoroException** : you tried to send a request through Tor but Tor is not running ;
 - **VPNNotConnectedTotoroException** : you tried to send a request while VPN Strict Mode is enable, and your VPN connection seems to be broken.

