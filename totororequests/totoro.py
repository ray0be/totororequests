#
# TotoroRequests
# Smart Python module for sending HTTP(S) requests through Tor network
#
# Copyright (c) 2020 Victor Paynat-Sautivet <contact@ray0.be>
#


# === Dependencies

import os
import re
import binascii
import hashlib
import random
import time
import subprocess
import socket
import multiprocessing.dummy

import requests
import requests.adapters
import fake_useragent

import stem
import stem.control
import stem.process


# === Helpers

def _strcmd(cmd):
    """Executes a shell command and returns a tuple composed by the exitcode
    and the output of the command.
    """
    return subprocess.getstatusoutput(cmd)


def _generate_tor_hash(password):
    """Python implementation of Tor's password hashing OpenPGP S2K algorithm
    Inspired by : https://gist.github.com/antitree/3962751
    But made compatible with Python3.
    """
    secret = bytes(password, 'ascii')
    indicator = bytes(chr(96), 'ascii')
    salt = b"".join([os.urandom(8), indicator])

    c = 96
    EXPBIAS = 6
    count = (16+(c & 15)) << ((c >> 4) + EXPBIAS)

    d = hashlib.sha1()
    tmp = salt[:8]+secret

    slen = len(tmp)
    while count:
        if count > slen:
            d.update(tmp)
            count -= slen
        else:
            d.update(tmp[:count])
            count = 0

    salt = binascii.b2a_hex(salt[:8]).upper().decode('ascii')
    torhash = d.hexdigest().upper()

    return '16:{}{}{}'.format(salt, '60', torhash)


# === Exceptions

class TotoroException(Exception):
    """Base class for other exceptions"""
    pass


class TorNotRunningTotoroException(TotoroException):
    """The Tor service is not running"""
    pass


class VPNNotConnectedTotoroException(TotoroException):
    """No connection to VPN when performing a request with strict mode"""
    pass


# === Totoro

class Totoro:
    """Used as the main object for sending HTTP requests over Tor network.

    The Totoro object is built and must be configured.
    Then it's possible to use it like you may use the requests module.

    Two modes are available :
        - Send a "direct" HTTP request : using your personal IP or VPN
            connection if set.
        - Send a request over Tor network : using the nodes circuit provided
            by Tor.

    You may force the use of a VPN. In this case, before every request (direct
    or Tor) this will check if you are connected to a VPN, and if not, will
    abort with an exception.

    Totoro can start a "personal" Tor process, this is the recommended way. It
    starts a process that is "attached" to the pid of python script. When your
    script ends, the Tor process terminates as well. It also starts a
    controller with password authentication. The password is randomly
    generated.

    But you may also choose to connect Totoro to an existing Tor service that
    is already running, maybe on another host.
    """

    def __init__(self, nowarning=False):
        # Tor host
        self._host = None        # Tor host

        # Tor service
        self._service = {
            "process": None,     # Started Tor subprocess
            "status": None,      # Status of Tor service/process
            "port": None,        # Socks Port
        }

        # Tor controller
        self._controller = {
            "object": None,      # Stem Controller object
            "authmethod": None,  # Authentication method
            "port": None,        # Control Port
            "socket": None,      # Control Socket
            "password": None,    # Password
        }

        # VPN
        self._vpn_required = False

        # Display https Warnings ?
        if nowarning:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # =======================================================================
    #       TOR SERVICE
    # =======================================================================

    def connect(self, host, port):
        """Sets the connection parameters to make Totoro connect to an existing
        Tor service instead of a created subprocess.
        In practice you must use the start() OR connect() method, not both.
        """
        self._host = host
        self._service['process'] = None
        self._service['port'] = port

        return self.status()

    def status(self):
        """Returns the status of Tor service by checking the connectivity
        with its control port/socket and Socks port.
        """
        try:
            # Test Controller
            if self._controller['object']:
                if self._controller['authmethod'] == 'socket':
                    # Test Control Socket
                    stem.control.Controller.from_socket_file(
                        self._controller['socket']
                    ).close()
                else:
                    # Test Control Port
                    stem.control.Controller.from_port(
                        address=self._host,
                        port=self._controller['port']
                    ).close()

            # Test Service (Socks Port)
            socket.create_connection(
                address=(self._host, self._service['port']),
                timeout=2
            ).close()

            self._service['status'] = True
        except:
            self._service['status'] = False

        return self._service['status']

    def start(self, socks_port=9050, control_port=9051,
              tor_binary=None, password=None):
        """Starts a Tor process locally with given port numbers.
        The controller is protected by randomly chosen password, or by
        given password in parameter.
        In practice you must use the start() OR connect() method, not both.

        If tor_binary is given, this will use this binary to request the hash
        of the password. If not passed, by default, it will compute the hash
        using the OpenPGP S2K algorithm.
        """

        if password is not None and (
                type(password) is not str or not len(password)):
            raise TotoroException('Password must be a non empty string')

        if password is None:
            # Generate a random password for the controller
            chars = 'abcdefghijklmnopqrstuvwxyz'
            chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            chars += '0123456789'
            password = ''.join(random.choice(chars) for i in range(25))

        # Compute the Hash of the password
        hashed = None
        if tor_binary:
            check = re.search('^(/[a-z-]+)+$', tor_binary)
            if not check:
                raise TotoroException('Incorrect tor_binary format')
            if not os.access(tor_binary, os.X_OK):
                raise TotoroException('Tor binary is incorrect')

            excode, tmp = _strcmd(
                '{} --hash-password {}'.format(tor_binary, password)
            )
            if excode == 0:
                hashed = tmp

        if not hashed:
            hashed = _generate_tor_hash(password)

        # Tor config
        torconfig = {
            'SocksPort': str(socks_port),
            'ControlPort': str(control_port),
            'CookieAuthentication': '0',
            'HashedControlPassword': hashed
        }

        # Start Tor process
        try:
            self._service['process'] = stem.process.launch_tor_with_config(
                config=torconfig,
                take_ownership=True
            )
            self._host = '127.0.0.1'
            self._service['port'] = socks_port

            # Automatically authenticate to controller
            self.authenticate(
                method='password',
                port=control_port,
                password=password
            )
        except OSError:
            pass

        time.sleep(0.1)

        return self.status()

    def stop(self, kill=False):
        """Stops the previously created Tor process.
        It's not mandatory to call this method if the script ends because the
        Tor process is linked to your script's pid. But it may be useful if you
        want to stop Tor service during execution.
        """
        if self._controller['object']:
            try:
                self._controller['object'].close()
            except:
                pass

        if self._service['process']:
            try:
                if kill:
                    self._service['process'].kill()
                else:
                    self._service['process'].terminate()
            except:
                pass

        time.sleep(0.1)

        return not self.status()

    # =======================================================================
    #       VPN CHECK
    # =======================================================================

    def require_vpn(self, choice=True):
        """Forces the use (or not) of a VPN when sending requests to Tor.
        When enabled, if the VPN connection is not found the request will be
        aborted and an exception raised.

        Caution : use it only on (recent) Linux systems.
        """
        self._vpn_required = choice
        return choice

    def vpn_status(self):
        """Checks if the system is connected to a VPN.
        Return True or False depending on check result.

        Caution : only works on (recent) Linux systems.
        """
        exc1, __ = _strcmd('ip a show dev tun0')
        exc2, __ = _strcmd('ip link show dev tun0 up')
        exc3, __ = _strcmd('ip ro show default dev tun0')

        return (exc1 == exc2 == exc3 == 0)

    # =======================================================================
    #       IP CHECK
    # =======================================================================

    def ipinfo(self):
        """Performs requests to get IP information.
        Checks the "direct" IP geoinfo and Tor IP geoinfo.
        """
        webdomain = 'https://ipgeolocation.io'
        apidomain = 'https://api.ipgeolocation.io'
        url = apidomain + '/ipgeo?fields=geo&include=hostname,security'
        headers = {
            'Origin': webdomain,
            'Referer': webdomain
        }

        iplist = {}

        # Direct request
        try:
            sess, dirinfo = self.dirreq('GET', url, headers=headers)
            dirinfo = dirinfo.json()
        except:
            dirinfo = {}

        reqtype = 'vpn' if self.vpn_status() else 'direct'
        iplist[reqtype] = dirinfo

        # Tor request
        if self.status():
            try:
                sess, torinfo = self.torreq('GET', url, headers=headers)
                if sess:
                    iplist['tor'] = torinfo.json()
            except:
                pass

        return iplist

    # =======================================================================
    #       REQUESTS
    # =======================================================================

    def _send_request(self, method, url,
                      params=None, data=None, json=None, files=None, headers={},
                      cookies=None, auth=None, timeout=5, allow_redirects=False,
                      stream=False, proxies=None, verify=False, session=None):
        """Performs a HTTP(S) request using the 'requests' module.

        If VPN Strict Mode is enabled, it checks the VPN connection before
        sending the request.

        It uses the Session object from requests, by this way you can reuse a
        previously opened session : in the next request, pass the session
        parameter.

        It selects a random User-Agent to make your request more anonymous.

        Returns a tuple with (requests.Session, requests.Response).
          > See : https://2.python-requests.org/en/latest/api/
        """

        # Check VPN connection
        if self._vpn_required and not self.vpn_status():
            raise VPNNotConnectedTotoroException(
                "Cannot send the request,"
                + "VPN not connected while Strict Mode enabled")

        # Open or reuse session
        if session:
            sess = session
        else:
            sess = requests.Session()
            sess.mount('http://', requests.adapters.HTTPAdapter(max_retries=2))
            sess.mount('https://', requests.adapters.HTTPAdapter(max_retries=2))

        # Select a random User-Agent
        headers['User-Agent'] = fake_useragent.UserAgent().random

        # Send
        resp = sess.request(
            method, url,
            params=params, data=data, json=json, files=files,
            headers=headers, cookies=cookies,
            auth=auth, timeout=timeout,
            allow_redirects=allow_redirects, stream=stream,
            proxies=proxies, verify=verify
        )

        return sess, resp

    def dirreq(self, *args, **kwargs):
        """An alias to _send_request. Performs a direct request."""
        return self._send_request(*args, **kwargs)

    def torreq(self, *args, **kwargs):
        """Performs a request through Tor network."""
        if not self._service['status'] and not self.status():
            raise TorNotRunningTotoroException(
                'Cannot make a request over Tor : service not running')

        # Set Socks proxy
        proxies = {
            'http': 'socks5://' + self._host + ':' + str(self._service['port']),
            'https': 'socks5://' + self._host + ':' + str(self._service['port'])
        }

        return self._send_request(*args, **kwargs, proxies=proxies)

    def get(self, *args, **kwargs):
        """Sends a GET request"""
        return self.torreq('GET', *args, **kwargs)

    def post(self, *args, **kwargs):
        """Sends a POST request"""
        return self.torreq('POST', *args, **kwargs)

    def put(self, *args, **kwargs):
        """Sends a PUT request"""
        return self.torreq('PUT', *args, **kwargs)

    def patch(self, *args, **kwargs):
        """Sends a PATCH request"""
        return self.torreq('PATCH', *args, **kwargs)

    def delete(self, *args, **kwargs):
        """Sends a DELETE request"""
        return self.torreq('DELETE', *args, **kwargs)

    def options(self, *args, **kwargs):
        """Sends an OPTIONS request"""
        return self.torreq('OPTIONS', *args, **kwargs)

    def head(self, *args, **kwargs):
        """Sends a HEAD request"""
        return self.torreq('HEAD', *args, **kwargs)

    # =======================================================================
    #       NOISY REQUESTS
    # =======================================================================

    def annoy(self, url, times=1, threads=10, sync=False):
        """Sends a request and immediatly drops it ({times} times). The purpose
        is to send the requests without waiting for the responses.
        
        Consequences : As HTTP is over the TCP protocol, a TCP handshake needs
        to be performed. Using this method you'll start the handshake and
        cancel it instantly. It will just tickle the remote server.
        
        Caution : Do not use it to generate fake logs because it won't work.
        Use make_noise() instead.
        """

        pool = multiprocessing.dummy.Pool(threads)
        futures = []

        for i in range(times):
            futures.append(
                pool.apply_async(
                    self.get,
                    args=[url],
                    kwds={'timeout':0.0000000001}
                )
            )

        pool.close()

        if sync:
            for future in futures:
                future.wait()

    def make_noise(self, urls, times=1, threads=10,
                   shuffle=False, sync=False, timeout=5):
        """Sends a series of requests, {times} times, in parallel threads and
        without waiting for HTTP responses.

        It may be used to generate fake logs on a web server.

        The 'urls' parameter must be a list of URL to fetch.
        Each element in the list may contain the HTTP verb in front of the URL,
        or only the URL (default is method GET in this case) :
            [
                'https://example.com/',
                'GET https://example.com/main.css',
                'GET https://example.com/jquery.min.js',
                'POST https://example.com/admin.php'
            ]

        When using shuffle=True :
            - total number of requests is {times}
            - requests are sent in whatever order, and randomly picked
        When using shuffle=False :
            - total number of requests is {times}*len(urls)
            - requests are sent in the order of the list
            - there is no assurance that they are received in exact same order
        """

        if type(urls) is not list:
            raise TotoroException('Param urls must be a list of URLs')

        def peelit(full):
            # Extracts the method and url from a string like this:
            # "GET https://example.com/"
            method = 'GET'
            exploded = full.split(' ')

            if len(exploded) == 1:
                url = exploded[0]
            elif len(exploded) == 2:
                method = exploded[0]
                url = exploded[1]
            else:
                raise TotoroException(
                    'Either your URLs list is empty, or one of them contains '
                    + 'whitespaces (please encode them)')

            return method, url

        pool = multiprocessing.dummy.Pool(threads)
        futures = []

        for i in range(times):
            if shuffle:
                method, url = peelit(random.choice(urls))
                futures.append(
                    pool.apply_async(
                        self.torreq,
                        args=[method, url],
                        kwds={'timeout':timeout}
                    )
                )
            else:
                for j in range(len(urls)):
                    method, url = peelit(urls[j])
                    futures.append(
                        pool.apply_async(
                            self.torreq,
                            args=[method, url],
                            kwds={'timeout':timeout}
                        )
                    )

        pool.close()

        if sync:
            for future in futures:
                future.wait()

    # =======================================================================
    #       TOR CONTROLLER
    # =======================================================================

    def authenticate(self, method=None, port=None, socket=None, password=None):
        """Sets the authentication parameters and instantiate the connection
        to the controller.
        """
        if method not in {None, 'socket', 'cookie', 'password'}:
            raise TotoroException('Invalid authentication method')

        if method == 'socket' and not socket:
            raise TotoroException('Missing control socket')

        if method != 'socket' and not port:
            raise TotoroException('Missing control port')

        if method == 'password' and not password:
            raise TotoroException('Missing password')

        self._controller['authmethod'] = method
        self._controller['port'] = port
        self._controller['socket'] = socket
        self._controller['password'] = password

        return self._connect_to_controller()

    def _connect_to_controller(self):
        """Tries a connection to the Tor service controller.
        Returns True if successfully authenticated, False if not.
        """

        # Close eventual previous socket
        if self._controller['object']:
            self._controller['object'].close()
            self._controller['object'] = None

        # Create controller
        if self._controller['authmethod'] == 'socket':
            # Control by socket
            ctrl = stem.control.Controller.from_socket_file(
                self._controller['socket']
            )
        else:
            # Control by port
            ctrl = stem.control.Controller.from_port(
                address=self._host,
                port=self._controller['port']
            )

        # Try to authenticate
        if self._controller['authmethod'] == 'password':
            ctrl.authenticate(password=self._controller['password'])
        else:
            ctrl.authenticate()

        # OK ?
        if ctrl.is_alive() and ctrl.is_authenticated():
            # Store controller
            self._controller['object'] = ctrl
            return True

        return False

    def controller(self):
        """Returns the Tor service controller.
        It's an instance of stem.control.Controller
        (see https://stem.torproject.org/api/control.html)
        """
        ctrl = self._controller['object']
        if ctrl and (not ctrl.is_alive() or not ctrl.is_authenticated()):
            self._connect_to_controller()

        return ctrl

    def change_identity(self, sync=False):
        """Sends a signal to Tor controller to request a new identity.

        Two behaviours :
            - with sync=False : send the signal and continue (it may take few
                seconds to get the new identity)
            - with sync=True : send the signal and wait until you get the new
                identity (will block the script with time.sleep())

        It's recommended to use it asynchronously unless you have a specific
        need.
        """
        ctrl = self.controller()

        if ctrl:
            ctrl.signal(stem.Signal.NEWNYM)
            if sync:
                while not ctrl.is_newnym_available():
                    time.sleep(ctrl.get_newnym_wait())

            return ctrl.get_info('circuit-status')

        return False
