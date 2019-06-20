import hip.udp
import http.client
import json
import logging
import sys
import time
import urllib.parse
import uuid

import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class HipDeviceError(Exception):
    pass

class HipApiError(HipDeviceError):
    pass

class HipAjaxError(HipDeviceError):
    pass

class HipAjaxSyntaxError(HipAjaxError):
    pass

class HipAjaxCommandError(HipAjaxError):
    pass

class HipAjaxInvalidCommandError(HipAjaxCommandError):
    pass

class HipAjaxInvalidPathError(HipAjaxCommandError):
    pass

class HipAjaxInvalidValueError(HipAjaxCommandError):
    pass

class HipAjaxAccessDeniedError(HipAjaxCommandError):
    pass

class HipAjaxInvalidLoginError(HipAjaxCommandError):
    pass

class HipDirUserInvalidDataError(HipApiError):
    pass



class HipDevice:
    """ 
    """

    # keycodes used as parameter in simulate_keypress() method
    
    # numeric keypad
    KEYCODE_NUM_0            = 10
    KEYCODE_NUM_1            = 11
    KEYCODE_NUM_2            = 12
    KEYCODE_NUM_3            = 13
    KEYCODE_NUM_4            = 14
    KEYCODE_NUM_5            = 15
    KEYCODE_NUM_6            = 16
    KEYCODE_NUM_7            = 17
    KEYCODE_NUM_8            = 18
    KEYCODE_NUM_9            = 19
    
    # vario/force star and hash keys
    KEYCODE_NUM_STAR         = 20
    KEYCODE_NUM_HASH         = 21
    
    # verso key and phone buttons
    KEYCODE_NUM_KEY          = 22
    KEYCODE_NUM_PHONE        = 23
                               
    # sipspeaker up/down buttons
    KEYCODE_DOWN             = 30
    KEYCODE_UP               = 31
                               
    # sipspeaker ir remote buttons
    KEYCODE_IR_VOLUME_DOWN   = 40
    KEYCODE_IR_VOLUME_UP     = 41
    KEYCODE_IR_CHANNEL_DOWN  = 42
    KEYCODE_IR_CHANNEL_UP    = 43
    KEYCODE_IR_MUTE          = 44

    # quick dial buttons
    # for dialing quick dial #5 use (KEYCODE_QUICK_DIAL + 5)
    KEYCODE_QUICK_DIAL       = 100


    def __init__(self, devinfo, ssl=False, timeout=120):
        """ Initializes hip device controller
        devinfo -- dict with keys ip-address, http-port a https-port
        """

        if type(devinfo) != dict:
            raise ValueError('devinfo arg must be dictionary')

        self.devinfo = devinfo
        if 'ip-addr' in devinfo:
            self.address = devinfo['ip-addr']
        else:
            raise ValueError('ip-addr key is missing')

        if 'http-port' in devinfo:
            self.http_port = int(devinfo['http-port'])
        else:
            self.http_port = 80

        if 'https-port' in devinfo:
            self.https_port = int(devinfo['https-port'])
        else:
            self.https_port = 443 
        
        try:
            self.version = tuple(map(lambda x:int(x), self.devinfo["sw-version"].split('.')))
        except KeyError :
            pass

        self.session = requests.Session()
        self.session.verify = False
        self.sid = None
        self.ssl = ssl
        self.timeout = timeout
        self.dir_template = None

    def url(self, path):
        """ Builds device url
        """
        url = 'https' if self.ssl else 'http'
        url += '://' + self.address + ':' + (str(self.https_port) if self.ssl else str(self.http_port)) + path
        return url

    #-------------------------------------------------------------------------
    # legacy ajax helpers
    #-------------------------------------------------------------------------

    def send_ajax_request(self, req_json):
        """ Sends ajax command
        request -- array of commands [{'command': 'xxx', 'param1': xxx, ...}, ...]
        returns array of responses to commands [{'status': 'xxx', 'param1': xxx, ...}, ...]
        """    
        # send http request
        rsp = self._make_request("POST", "/ajax", params=self.url_params(), json=req_json)

        # check http response status
        
        #if rsp.status_code != requests.codes.ok:
        if rsp.status_code != 200:
            raise HipDeviceError('HTTP connection error (%d %s)' % (rsp.status_code, rsp.reason) )

        # parse response json
        rsp_json = rsp.json()
        
        if len(req_json) != len(rsp_json):
            raise HipAjaxSyntaxError('Request/response command count mismatch (%d != %d)' %
                                     len(req_json), len(rsp_json))
        return rsp_json

    def check_ajax_status(self, cmd_response):
        """ Checks ajax command response status fields
        Raises exception if status field is not set to 'ok'
        """
        if 'status' in cmd_response:
            status = cmd_response['status']
            if status == 'ok':
                pass
            elif status == 'invalid commmand':
                raise HipAjaxInvalidCommandError(cmd_response['status'])
            elif status == 'invalid path':
                raise HipAjaxInvalidPathError(cmd_response['status'])
            elif status == 'invalid value':
                raise HipAjaxInvalidValueError(cmd_response['status'])
            elif status == 'access denied':
                raise HipAjaxAccessDeniedError(cmd_response['status'])
            elif status == 'invalid login':
                raise HipAjaxInvalidLoginError(cmd_response['status'])
            else:
                raise HipAjaxCommandError(cmd_response['status'])
        else:
            raise HipAjaxSyntaxError('Missing status field')
            

    #-------------------------------------------------------------------------
    # http api helpers
    #-------------------------------------------------------------------------

    def check_api_response(self, rsp, expected_type=None):
        #if rsp.status_code != requests.codes.ok:
        if rsp.status_code != 200:
            raise HipDeviceError('HTTP connection error (%d %s)' 
                                 % (rsp.status_code, rsp.reason) )

        type = rsp.headers.get('content-type')
        if expected_type and type == expected_type:
            pass
        elif type == 'application/json':
            json = rsp.json()
            if json['success'] == False:
                raise HipApiError('{}'.format(json))
        else:
            raise HipDeviceError('Unexpected response content type')

    def check_dir_api_response(self, rsp, expected_type=None):
        if rsp.status_code != 200:
            raise HipDeviceError('HTTP connection error (%d %s)' 
                                 % (rsp.status_code, rsp.reason) )

        content_type = rsp.headers.get('content-type')
        if expected_type and content_type == expected_type:
            pass
        elif content_type == 'application/json':
            json_data = rsp.json()
            success = json_data["success"]
            if not success:
                error = json_data['error']
                code = error['code']
                desc = error['description'] if 'description' in error else ''
                field = error['field'] if 'filed' in error else ''
                param = error['param'] if 'param' in error else ''
                raise HipDirUserInvalidDataError('Error %d: %s %s (%s)' % (code, desc, field, param))
            if "users" in json_data["result"]:
                errors = []
                for i,u in enumerate(json_data["result"]["users"]):
                    if "errors" in u:
                        errors.append({"user":i, "errors":u["errors"]})
                if errors:
                    raise HipDirUserInvalidDataError("Errors when saving users: " + json.dumps(errors))

    def url_params(self, **kwargs):
        params = []
        for key in kwargs:
            if not kwargs[key] is None:
                params.append((key, kwargs[key]))
        if not self.sid is None:
            params.append(('sid', self.sid))
        return params

    def _make_request(self, method, path, json=None, headers=None, params=None, data=None, files=None):
        request = requests.Request(method, self.url(path), json=json, params=params, data=data, files=files)
        self.session.timeout = self.timeout
        request = request.prepare()
        if headers:
            for key, val in headers.items():
                request.headers[key] = val
        logger.debug("Sending {} request {} {}".format(method, request.url, request.body if request.body and len(request.body) < 10000 else ""))
        self._last_response = self.session.send(request, timeout=self.timeout) 
        logger.debug("Response: {} {}".format(self._last_response.reason, self._last_response.text if self._last_response.headers.get("Content-Type") not in ['application/pcap'] and len(self._last_response.text) < 10000 else ""))
        return self._last_response

    def api_get(self, path, params=None, exp_type=None):
        if params is None:
            params = self.url_params()
        rsp = self._make_request("GET", path, params=params)
        self.check_api_response(rsp, exp_type)
        return rsp

    def api_post(self, path, params=None, exp_type=None, json=None, files=None, data=None):
        if params is None:
            params = self.url_params()
        rsp = self._make_request("POST", path, params=params, files=files, json=json, data=data)
        self.check_api_response(rsp, exp_type)
        return rsp
    
    def api_put(self, path, params=None, files=None):
        if params is None:
            params = self.url_params()
        rsp = self._make_request("PUT", path, params=params, files=files)
        self.check_api_response(rsp)
        return rsp

    def api_delete(self, path, params=None, files=None):
        if params is None:
            params = self.url_params()
        rsp = self._make_request("DELETE", path, params=params, files=files)
        self.check_api_response(rsp)
        return rsp


    #-------------------------------------------------------------------------
    # authentication
    #-------------------------------------------------------------------------

    def set_no_auth(self):
        self.session.auth = None

    def set_basic_auth(self, username, password):
        self.session.auth = requests.auth.HTTPBasicAuth(username, password)

    def set_digest_auth(self, username, password):
        self.session.auth = requests.auth.HTTPDigestAuth(username, password)

    #-------------------------------------------------------------------------
    # /api/system
    #-------------------------------------------------------------------------

    def get_system_info(self):
        """ Gets system information (/api/system/info)
        Returns parsed json with response result
        """
        logger.info('get_system_info')
        rsp = self.api_get('/api/system/info')
        return rsp.json()['result']

    def get_system_caps(self):
        """ Gets system capabilities (/api/system/caps)
        Returns parsed json with response result
        """
        logger.info('get_system_caps')
        rsp = self.api_get('/api/system/caps')
        return rsp.json()['result']

    def get_system_status(self):
        """ Gets system status (/api/system/status)
        Returns parsed json with response result
        """
        logger.info('get_system_status')
        rsp = self.api_get('/api/system/status')
        return rsp.json()['result']

    def restart(self):
        """ Restarts device (/api/system/restart)
        Returns None
        """
        logger.info('restart')
        self.api_post('/api/system/restart')

    def restart_vbus(self):
        logger.info('restarting vbus')
        rsp = self.api_get("/api/vbus/restart", {"sid":self.sid})
        return rsp.json()

    #-------------------------------------------------------------------------
    # /api/firmware
    #-------------------------------------------------------------------------

    def upload_firmware(self, file):
        """ Uploads firmware to device (/api/firmware)
        Returns None
        """
        logger.info('upload_firmware')
        self.api_put('/api/firmware', files={'blob-fw': (None, file, 'application/octet-stream')})

    def upload_trusted_cert(self, file, cert_id):
        logger.info('upload_trusted_certificate')
        self.api_put('/api/certificate/trusted',params={"id":cert_id, "sid":self.sid}, files={'blob-cert': (None, open(file, "rb"), 'application/x-x509-ca-cert')})

    def delete_trusted_cert(self, cert_id):
        logger.info('deleting_trusted_certificate_{}'.format(cert_id))
        req = [{"command":"db.deleteblob","blobname":"ca{}.der".format(cert_id)}]
        self.check_ajax_status(self.send_ajax_request(req)[0])

    def delete_user_cert(self, cert_id):
        logger.info('deleting_user_certificate_{}'.format(cert_id))
        req = [{"command":"db.deleteblob","blobname":"cert{}.der".format(cert_id)},{"command":"db.deleteblob","blobname":"pk{}.der".format(cert_id)}]
        self.check_ajax_status(self.send_ajax_request(req)[0])

    def upload_user_cert_key(self, cert_file, key_file, cert_id):
        logger.info('upload_user_certificate')
        self.api_put('/api/certificate/user',params={"id":cert_id, "sid":self.sid, "password":""}, files={'blob-cert': (None, open(cert_file, "rb"), 'application/x-x509-ca-cert'), 'blob-pk':(None, open(key_file), 'application/octet-stream')})

    def apply_firmware(self):
        """ Applies uploaded firmware (/api/firmware/apply)
        Returns None
        """
        logger.info('apply_firmware')
        self.api_post('/api/firmware/apply')

    def call_status(self, session=None):
        logger.info("getting call status")
        rsp = self.api_get("/api/call/status", params=self.url_params(session=session))
        return rsp.json()["result"]
    #-------------------------------------------------------------------------
    # /api/switch
    #-------------------------------------------------------------------------

    def get_switch_caps(self, switch=None):
        """ Get switch(es) capability (/api/switch/ctrl)
        Returns parsed json with response result
        """
        logger.info('get_switch_caps (switch=%s)' % (switch))
        rsp = self.api_get('/api/switch/caps', params=self.url_params(switch=switch))
        return rsp.json()['result']

    def get_switch_status(self, switch=None):
        """ Get switch(es) status (/api/switch/status)
        Returns parsed json with response result
        """
        logger.info('get_switch_status (switch=%s)' % (switch))
        rsp = self.api_get('/api/switch/status', params=self.url_params(switch=switch))
        return rsp.json()['result']

    def control_switch(self, switch, action):
        """ Controls switch (/api/switch/ctrl)
        Returns None
        """
        logger.info('control_switch (switch=%s, action=%s)' % (switch, action))
        self.api_post('/api/switch/ctrl', params=self.url_params(switch=switch, action=action))

    #-------------------------------------------------------------------------
    # /api/camera
    #-------------------------------------------------------------------------

    def get_camera_caps(self):
        """ Gets camera capabilites (/api/camera/caps)
        Returns parsed json with response result
        """ 
        logger.info('get_camera_caps')
        rsp = self.api_get('/api/camera/caps')
        return rsp.json()['result']

    def get_camera_snapshot(self, width, height, source=None, quality=None):
        """ Gets camera snapshot (/api/camera/snapshot)
        Returns jpeg image binary
        """
        rsp = self.api_get('/api/camera/snapshot', 
            params=self.url_params(width=width, height=height, source=source, quality=quality), 
            exp_type='image/jpeg' )
        logger.info('get_camera_snapshot -> %d bytes' % len(rsp.content))
        return rsp.content

    #-------------------------------------------------------------------------
    # /api/config
    #-------------------------------------------------------------------------

    def download_config(self):
        """ Gets device configuration (/api/config)
        Returns xml configuration binary
        """
        rsp = self.api_get('/api/config', exp_type='application/xml')
        logger.info('download_config -> %d bytes' % len(rsp.content))
        return rsp.content;

    def upload_config(self, file):
        """ Sets device configuration (/api/config)
        Returns None
        """
        logger.info('upload_config')
        self.api_put('/api/config', files={'blob-cfg': (None, file, 'application/xml')})

    def reset_config(self):
        """ Sets configuration to factory default (/api/config/factoryreset)
        Returns None
        """
        logger.info('reset_config')
        self.api_post('/api/config/factoryreset')

    #-------------------------------------------------------------------------
    # /api/pcap
    #-------------------------------------------------------------------------

    def download_pcap(self):
        """ Gets device pcap file (/api/pcap)
        Returns pcap file binary
        """
        rsp = self.api_get('/api/pcap', exp_type='application/pcap')
        logger.info('download_pcap -> %d bytes' % len(rsp.content))
        return rsp.content

    def restart_pcap(self):
        """ Restarts packet capture (/api/pcap/restart)
        Returns None
        """
        logger.info('restart_pcap')
        self.api_post('/api/pcap/restart')

    def stop_pcap(self):
        """ Stops packet capture (/api/pcap/stop)
        Returns None
        """
        logger.info('stop_pcap')
        self.api_post('/api/pcap/stop')

    #-------------------------------------------------------------------------
    # /api/io
    #-------------------------------------------------------------------------

    def get_io_caps(self, port=None):
        """ Gets io(s) capability (/api/io/caps)
        Returns parsed json with response result
        """
        rsp = self.api_get('/api/io/caps', params=self.url_params(port=port))
        return rsp.json()['result']

    def get_io_status(self, port=None):
        """ Gets io(s) status (/api/io/status)
        Returns parsed json with response result
        """
        rsp = self.api_get('/api/io/status', params=self.url_params(port=port))
        logger.info('get_io_status (port=%s)' % (port))
        return rsp.json()['result']

    def control_io(self, port, action):
        """ Control output(s) (/api/io/ctrl)
        action may be 'on' or 'off'
        Returns None
        """
        logger.info('control_io (port=%s, action=%s)' % (port, action))
        self.api_post('/api/io/ctrl', params=self.url_params(port=port, action=action))

    #-------------------------------------------------------------------------
    # /api/usersound
    #-------------------------------------------------------------------------

    def upload_usersound(self, id, file):
        """ Uploads user sound into device
        id may be 1..max_user_sounds
        file may be binary or file containt wav data
        Returns None
        """ 
        logger.info('upload_usersound (id=%s)' % (id))
        self.api_put('/api/usersound', params=self.url_params(id=id), 
                     files={'blob-audio': (None, open(file, "rb"), 'audio/wav')})

    def download_usersound(self, id):
        """ Uploads user sound into device
        id may be 1..max_user_sounds
        Returns wav file binary
        """ 
        logger.info('download_usersound (id=%s)' % (id))
        rsp = self.api_get('/api/usersound', params=self.url_params(id=id), exp_type='audio/wav')
        return rsp.content

    def delete_usersound(self, id):
        logger.info('Delete user sound ID=%s)' % (id))
        req = [{"command":"db.deleteblob","blobname":"UserSound{}".format(id-1)}]
        self.check_ajax_status(self.send_ajax_request(req)[0])

    # Resource strings requests

    def upload_rs(self, file):
        logger.info('upload_config')
        self.api_put('/api/rs', files={'blob-xml': (None, open(file, "r"), 'text/xml')}, params=self.url_params(lang="custom"))

    def download_rs(self, lang="custom"):
        rsp = self.api_post('/api/rs', exp_type='application/xml', params={"lang": lang})
        logger.info('download_rs -> %d bytes' % len(rsp.content))
        return rsp.content

    def delete_custom_rs(self):
        logger.info('Delete user sound ID=%s)' % (id))
        req = [{"command": "db.deleteblob", "blobname": "custom-language"}]
        self.check_ajax_status(self.send_ajax_request(req)[0])

    def download_directory(self):
        logger.info('download_directory')
        rsp = self.api_get('/api/directory', exp_type="application/json")
        return rsp.json()

    #audio loop test
    def audio_test(self):
        logger.info('audio test')
        rsp = self.api_get('/api/audio/test', exp_type="application/json")
        return rsp.json()

    #-------------------------------------------------------------------------
    # /api/display
    #-------------------------------------------------------------------------

    def get_display_caps(self):
        """ Gets display(s) capability (/api/display/caps)
        Returns parsed json with response result
        """
        logger.info('get_display_caps')
        rsp = self.api_get('/api/display/caps')
        return rsp.json()['result']


    def upload_display_image(self, display, file):
        """ Uploads gif image to display
        display parameter must be be 'internal'
        file may be binary or file containt gif image data
        Returns None
        """ 
        logger.info('upload_display_image (display=%s)' % (display))
        self.api_put('/api/display/image', params=self.url_params(display=display), 
                     files={'blob-image': (None, file, 'image/gif')})
        

    def delete_display_image(self, display):
        """ Uploads gif image to display
        display parameter must be be 'internal'
        Returns None
        """ 
        logger.info('delete_display_image (display=%s)' % (display))
        self.api_delete('/api/display/image', params=self.url_params(display=display))


    #-------------------------------------------------------------------------
    # /api/sim
    #-------------------------------------------------------------------------

    def simulate_input(self, port, action):
        """ Simulates input port state (/api/sim/input)
        action may be 'on', 'off' or 'restore'
        Returns None
        """
        logger.info('simulate_input (port=%s, action=%s)' % (port, action))
        self.api_post('/api/sim/input', params=self.url_params(port=port, action=action))

    def simulate_keypress(self, keycode):
        """ Simulate keypress (/api/sim/keypress)
        keycode may be one of KEYCODE_xxx constant
        Returns None
        """
        logger.info('simulate_keypress (keycode=%d)' % (keycode))
        self.api_post('/api/sim/keypress', params=self.url_params(keycode=keycode))


    def simulate_keystrokes(self, input, period=0.1):
        """ Simulates numeric keypad input (multiple keypresses)
        keystrokes -- string containing 0..9, *, # characters
        """
        #logger.info('simulate_keystrokes (input=%s)' % (input))
        x=0
        
        for ch in input:
            if ch >= '0' and ch <= '9':
                x=HipDevice.KEYCODE_NUM_0 + (ord(ch) - ord('0'))
       
                self.api_post('/api/sim/keypress',params=self.url_params(keycode=HipDevice.KEYCODE_NUM_0 + (ord(ch) - ord('0'))))
            elif ch == '*':
                self.api_post('/api/sim/keypress',params=self.url_params(keycode=HipDevice.KEYCODE_NUM_STAR))
            elif ch == '#':
                self.api_post('/api/sim/keypress',params=self.url_params(keycode=HipDevice.KEYCODE_NUM_HASH))
            elif ch == 'K':
                self.api_post('/api/sim/keypress',params=self.url_params(keycode=HipDevice.KEYCODE_NUM_KEY))
            elif ch == 'P':
                self.api_post('/api/sim/keypress',params=self.url_params(keycode=HipDevice.KEYCODE_NUM_PHONE))
            time.sleep(period)

        #=======================================================================
        # for ch in input:
        #     if ch >= '0' and ch <= '9':
        #         self.api_post_sim_keypress(HipDevice.KEYCODE_NUM_0 + (ord(ch) - ord('0')))
        #     elif ch == '*':
        #         self.api_post_sim_keypress(HipDevice.KEYCODE_NUM_STAR)
        #     elif ch == '#':
        #         self.api_post_sim_keypress(HipDevice.KEYCODE_NUM_HASH)
        #     elif ch == 'K':
        #         self.api_post_sim_keypress(HipDevice.KEYCODE_NUM_KEY)
        #     elif ch == 'P':
        #         self.api_post_sim_keypress(HipDevice.KEYCODE_NUM_PHONE)
        #     time.sleep(period)
        #=======================================================================

    def get_statistics(self, reset=0, prepare_keys=False):
        logger.info("getting statistics")
        rsp = self.api_get("/api/sim/productstat", params={"reset":reset, "sid":self.sid})
        self.check_api_response(rsp)
        if prepare_keys:
            data = {}
            data["headers"] = rsp.json()["result"]["headers"]
            for kv in rsp.json()["result"]["keyvals"]:
                data[kv["k"]] = kv["v"]
            return data
        else:
            return rsp.json()["result"]

    #-------------------------------------------------------------------------
    # legacy ajax
    #-------------------------------------------------------------------------

    def login(self, username = "admin", password = "2n"):
        """ Logs in user with specified password into device to be able to issue secured commands
        username -- user name (only admin is valid)
        password -- password
        """
        logger.info('login (username=%s, password=%s)' % (username,password))
        req_json = [{'command': 'system.login', 'user': username, 'password': password}]
        rsp_json = self.send_ajax_request(req_json)
        self.check_ajax_status(rsp_json[0])
        # check presence of sid field
        if 'sid' not in rsp_json[0]:
            raise HipAjaxSyntaxError('Missing sid field', rsp_json)
        # store sid for subsequent ajax requests
        self.sid = rsp_json[0]['sid']
        logger.debug('ajax login succedded (sid=%s)' % (self.sid))   
        
  
    
    
    def logout(self):
        """Logs out user
        """ 
        logger.info('logout (sid=%s)' % (self.sid))
        req_json = [{'command': 'system.logout'}]
        rsp_json = self.send_ajax_request(req_json)
        self.check_ajax_status(rsp_json[0])
        self.sid = None

    def set_param(self, path, value):
        """ Sets parameter in device database
        path -- parameter path (eg 'WebServer.DeviceName')
        value -- parameter value (accepts string type only)
        """
        logger.info('set_param (path=%s, value=%s)' % (path, value))
        req_json = [{'command': 'db.set', 'path': path, 'value': str(value)}]
        rsp_json = self.send_ajax_request(req_json)
        self.check_ajax_status(rsp_json[0])

    def get_param(self, path):
        """ Gets parameter from device database
        path -- parameter path (eg 'WebServer.DeviceName')
        returns value of parameter (string)
        """
        req_json = [{'command': 'db.get', 'path': path}]
        rsp_json = self.send_ajax_request(req_json)
        self.check_ajax_status(rsp_json[0])
        
        # check presence of mandatory value field
        if 'value' not in rsp_json[0]:
            raise HipAjaxSyntaxError('Missing value field', rsp_json)
        
        # check presence of mandatory default field
        if 'is_default' not in rsp_json[0]:
            raise HipAjaxSyntaxError('Missing is_default field', rsp_json)
        
        value = rsp_json[0]['value']
        logger.info('get_param (path=%s) -> %s' % (path, value))
        return value
    
    #test skip pri chybne ceste
    def check_params_validity(self,path):
        """ Check validity of parameter from device database
        path -- parameter path (eg 'WebServer.DeviceName')
        returns pass or exception HipAjaxInvalidPathError and id will be skipped
        """
        for actual_path in path:
            self.get_param(actual_path)
            
            
        
        
        
    

    def validate_param(self, path, value):
        """ Validates parameter value
        path -- parameter path (eg 'WebServer.DeviceName')
        value -- parameter value (accepts string type only)
        returns True if value is valid
        """
        req_json = [{'command': 'db.validate', 'path': path, 'value': str(value)}]
        rsp_json = self.send_ajax_request(req_json)

        logger.info('validate_param (path=%s, value=%s) ->%s' % (path, value, rsp_json[0]['status']))
        
        if rsp_json[0]['status'] == 'invalid value':
            return False
        else:
            self.check_ajax_status(rsp_json[0])
            return True

    def get_param_default(self, path):
        """ Gets parameter default value
        path -- parameter path (eg 'WebServer.DeviceName')
        returns default value of parameter (string)
        """
        req_json = [{'command': 'db.getdefault', 'path': path}]
        rsp_json = self.send_ajax_request(req_json)
        self.check_ajax_status(rsp_json[0])
        
        # check presence of mandatory value field
        if 'value' not in rsp_json[0]:
            raise HipAjaxSyntaxError('Missing value field', rsp_json)

        value = rsp_json[0]['value']
        logger.info('get_param_default (path=%s) -> %s' % (path, value))
        return value


    def restart_log(self):
        logger.info('log restart')
        rsp = self._make_request("DELETE", "/api/system/restartlog", params={"sid": self.sid})

    def ble_renew_auth_key(self):
        logger.info('ble - renewing auth key')
        rsp = self.api_get('/api/mobilekey/authkey/renew', params={"sid": self.sid}, exp_type="application/json")
        return rsp.json()

    def ble_delete_auth_key(self, index):
        logger.info('ble - deleting auth key')
        rsp = self.api_delete('/api/mobilekey/authkey', params={"key": index, "sid": self.sid})
        return rsp.json()

    def ble_renew_pairing_key(self):
        logger.info('ble - renewing pairing key')
        rsp = self.api_get('/api/mobilekey/pairing/renew', params={"sid": self.sid}, exp_type="application/json")
        return rsp.json()

    def ble_start_pairing(self, user, timeout=3600):
        logger.info('ble - start pairing')
        rsp = self.api_get('/api/mobilekey/pairing/start', params={"user": user, "timeout":timeout, "sid": self.sid}, exp_type="application/json")
        return rsp.json()

    def ble_stop_pairing(self, user):
        logger.info('ble - stop pairing')
        rsp = self.api_get('/api/mobilekey/pairing/stop', params={"user": user, "sid": self.sid}, exp_type="application/json")
        return rsp.json()

    def ble_get_credentials(self):
        logger.info('ble - get credentials')
        rsp = self.api_get('/api/mobilekey/credentials', exp_type="application/json")
        return rsp.json()

    def ble_get_user_pairing_status(self, user_uuid):
        logger.info('ble - get pairing status {}'.format(user_uuid))
        rsp = self.api_get("/api/mobilekey/pairing/status", params={"sid":self.sid, "user":user_uuid}, exp_type="application/json")
        return rsp.json()["result"]

    def request_inform(self):
        logger.info('requesting inform')
        if int(self.devinfo["sw-version"].split('.')[1]) < 18:
            self.set_param("Cwmp.Enabled", "0")
            time.sleep(1)
            self.set_param("Cwmp.Enabled", "1")
            return
        rsp = self.api_get('/api/system/tr069inform', exp_type="application/json")
        return rsp.json()

    def locate_device(self):
        logger.info('locating device')
        rsp = self.api_get('/api/system/locate', exp_type="application/json")
        return rsp.json()
    
    def simulate_card_swipe(self, cardType, card_id, bitLength=128, device="internal", cardHeld=0):
        card_id = card_id.zfill(int(2*bitLength/8))
        logger.info('simulating card swipe: cardType={}, card_id={}'.format(cardType, card_id))
        rsp = self.api_get('/api/sim/cardswipe', params={"sid": self.sid, "cardType": cardType, "bytes": card_id, "bitLength": bitLength, "cardHeld": cardHeld, "device": device}, exp_type="application/json")
        return rsp.json()   
    
    def create_logging_subscription(self, include="new", filter_string=None, duration=90):
        logger.info('creating logging subscription')
        params = {"sid": self.sid, "include": include, "duration": duration}
        if filter_string:
            params["filter"] = filter_string,
        rsp = self.api_get('/api/log/subscribe', params=params, exp_type="application/json")
        return rsp.json()["result"]
    
    def pull_logging_events(self, subscription_id, timeout=0):
        logger.info('pulling logging events')
        rsp = self.api_get('/api/log/pull', params={"sid": self.sid, "id": subscription_id, "timeout": timeout}, exp_type="application/json")
        return rsp.json()["result"]
        
    def delete_logging_subscription(self, subscription_id):
        logger.info('deleting logging subscription')
        rsp = self.api_get('/api/log/unsubscribe', params={"sid": self.sid, "id": subscription_id}, exp_type="application/json")
        return rsp.json()

    def update_license(self):
        logger.info('updating license')
        rsp = self.api_get('/api/license/update', params={"sid": self.sid}, exp_type="application/json")

    def send_test_email(self, address):
        logger.info('sending test e-mail to {}'.format(address))
        data = [{"command": "smtptest.start", "mailaddress": address}]
        rsp = self.api_post('/ajax', params={"sid": self.sid}, exp_type="application/json", json=data)
        return rsp.json()

    def get_automation_definition(self):
        logger.info('getting automation definition')
        rsp = self.api_get("/api/automation/def", params={"sid":self.sid})
        self.check_api_response(rsp)
        return rsp.json()

    def get_automation_function(self, index):
        logger.info('getting automation function {}'.format(index))
        rsp = self._make_request("GET", "/api/automation/func", params={"index": index, "sid": self.sid})
        
        self.check_api_response(rsp)
        return rsp.json()["result"]

    def upload_automation_function(self, function_num, function_data, idle=False):
        logger.info('uploading automation function number {}'.format(function_num))
        data = {'index' : (None, str(function_num)), 'blob-json' : (None, json.dumps(function_data))}
        if idle:
            data['idle'] = (None, "1")
        rsp = self.api_put("/api/automation/func", params={"sid": self.sid}, files=data)
        self.check_api_response(rsp)
        return rsp.json()

    def delete_automation_function(self, function_num):
        logger.info('deleting automation function number {}'.format(function_num))
        data = {'index' : (None, str(function_num)), 'blob-json' : (None, json.dumps({"title":"","source":[]}))}
        rsp = self.api_put("/api/automation/func", params={"sid": self.sid}, files=data)
        self.check_api_response(rsp)
        return rsp.json()

    def convert_old_automation_function(self, function_data):
        logger.info('converting old automation function')
        data = {'blob-xml' : (None, urllib.parse.quote_plus(function_data))}
        rsp = self._make_request("POST", "/api/automation/convert", params={"sid": self.sid}, files=data)
        self.check_api_response(rsp)
        return rsp.json()

    def get_hardware(self, hw_class=None, hw_id=None):
        logger.info('getting hardware info')
        rsp = self.api_get("/api/system/hardware", params={"sid":self.sid, "class":hw_class, "id":hw_id})
        return rsp.json()["result"]

    def set_lock(self, action, ap_id):
        logger.info('setting global lock of access point {} to {}'.format(ap_id, action))
        rsp = self.api_post("/api/accesspoint/lock", params={"sid":self.sid, "action":action, "id":ap_id})
        self.check_api_response(rsp)
        return rsp.json()

    def simulate_fingerprint(self, user, finger_index, device):
        logger.info('simulating fingerprint of user {}'.format(user))
        rsp = self.api_get("/api/sim/finger", params={"sid":self.sid, "user":user, "finger":finger_index, "device":device})
        self.check_api_response(rsp)
        return rsp.json()

    def dial_number(self, number, account=None):
        logger.info("dialing number {} via account {}".format(number, account))
        rsp = self.api_get("/api/call/dial", params={"sid":self.sid, "number": "{}{}".format(number, "/{}".format(account) if account else "")})
        return rsp.json()["result"]

    def hang_call(self, session):
        logger.info("hanging call session".format(session))
        rsp = self.api_get("/api/call/hangup", params={"sid":self.sid, "session": session})
        return rsp.json()

    def get_version(self):
        v = self.devinfo["sw-version"].split('.')
        return tuple(map(lambda x:int(x), v))

    # new directory
    def dir_get_users(self, users, fields=[]):
        data = {"fields":fields,
                "users":[]}
        for user in users:
            data["users"].append({"uuid":user})
        rsp = self.api_post("/api/dir/get", files={"blob-json":json.dumps(data)})
        self.check_dir_api_response(rsp)
        return rsp.json()["result"]["users"]

    def dir_get_template(self):
        rsp = self.api_get("/api/dir/template", exp_type="application/json")
        return rsp.json()["result"]["users"][0]

    def dir_query(self, timestamp=0, series=None, fields=[]):
        data = {"fields":fields,
                "iterator":{"timestamp":timestamp}}
        if series:
            data["series"] = series
        rsp = self.api_post("/api/dir/query", files={"blob-json":json.dumps(data)})
        self.check_dir_api_response(rsp)
        return rsp.json()["result"]

    def dir_create_single_user_data(self, generate_uuid=False,**kwargs):
        if self.dir_template == None:
            self.dir_template = self.dir_get_template()
        data = {}
        for key, value in kwargs.items():
            data[key] = value
        keys_to_remove = []
        try:
            if data["owner"] == None:
                data.pop("owner")
        except KeyError:
            pass
        try:
            for k, _ in data["access"].items():
                if k not in self.dir_template["access"]:
                    keys_to_remove.append(k)
            for k in keys_to_remove:
                data["access"].pop(k, None)
        except KeyError:
            pass
        if generate_uuid:
            data["uuid"] = str(uuid.uuid4())
        if "email" not in self.dir_template:
            data.pop("email", None)
        return data

    def dir_create_user(self, force=None, **kwargs):
        single_user = self.dir_create_single_user_data(**kwargs)
        data = {}
        if force != None:
            data["force"] = force
        data["users"]=[single_user]
        logger.info("Creating user with data: {}".format(data))
        rsp = self.api_put("/api/dir/create", files={"blob-dir_new":json.dumps(data)})
        self.check_dir_api_response(rsp)
        return rsp.json()["result"]["users"][0]

    def dir_create_users(self, users_data):
        data = {"users":users_data}
        logger.info("Creating users with data: {}".format(data))
        rsp = self.api_put("/api/dir/create", files={"blob-dir_new":json.dumps(data)})
        self.check_dir_api_response(rsp)
        return rsp.json()["result"]

    def dir_update_user(self, user_uuid,**kwargs):
        if self.dir_template == None:
            self.dir_template = self.dir_get_template()
        data = {"users":[{"uuid":user_uuid}]}
        for key, value in kwargs.items():
            data["users"][0][key] = value
        keys_to_remove = []
        try:
            for k, _ in data["users"][0]["access"].items():
                if k not in self.dir_template["access"]:
                    keys_to_remove.append(k)
            for k in keys_to_remove:
                data["users"][0]["access"].pop(k, None)
        except KeyError:
            pass
        logger.info("Updating user with data: {}".format(data))
        rsp = self.api_put("/api/dir/update", files={"blob-dir_new":json.dumps(data)})
        self.check_dir_api_response(rsp)
        return rsp.json()["result"]["users"][0]

    def dir_delete_users(self, users=[], owner=None):
        data = {"users":[]}
        if owner:
            data.pop("users")
            data["owner"] = owner
            logger.info("Deleting al users of owner: {}".format(data["owner"]))
        else:
            for user in users:
                data["users"].append({"uuid":user})
                logger.info("Deleting users: {}".format(data["users"]))
        rsp = self.api_put("/api/dir/delete", files={"blob-dir_new":json.dumps(data)})
        self.check_dir_api_response(rsp)
        return rsp.json()["result"]

    def get_codes_array(self):
        codes = []
        for _ in range(int(self.get_param("State.Limit.SwitchEntries"))):
            codes.append("")
        return codes

    def get_apb_records(self, ap=None):
        rsp = self.api_get("/api/accesspoint/apb/records", params={"sid":self.sid, "id":ap})
        self.check_api_response(rsp)
        return rsp.json()["result"]

    def put_apb_records(self, ap, user_uuid, timeout):
        data = {"accessPoints":[
            { "id" : ap,
             "records":[
                 {"user":user_uuid,
                  "timeout": timeout}
                 ]
             }
            ]
        }
        logger.info("Setting APB record with data: {}".format(data))
        rsp = self.api_put("/api/accesspoint/apb/records", files={"blob-json":json.dumps(data)})
        self.check_api_response(rsp)
        return

    def delete_apb_records(self, ap=None, user_uuid=None):
        data = {"accessPoints":[
            { "id" : ap,
             "records":[
                 {"user":user_uuid}
                 ]
             }
            ]
        }
        logger.info("Deleting APB record with data: {}".format(data))
        rsp = self.api_delete("/api/accesspoint/apb/records", files={"blob-json":json.dumps(data)})
        self.check_api_response(rsp)
        return

    def get_icu_list(self):
        logger.info("Getting ICU list")
        rsp = self.api_get("/api/system/discoverylist")
        self.check_api_response(rsp)
        return rsp.json()["result"]

    def stop_vpn(self):
        logger.info('stopping VPN service')
        self.api_get('/api/system/vpn', params={"action": "stop", "sid": self.sid})

    def restart_vpn(self):
        logger.info('restarting VPN service')
        self.api_get('/api/system/vpn', params={"action": "restart", "sid": self.sid})
                
    def get_holidays(self):
        logger.info("Getting holidays")
        rsp = self.session.get(self.url('/api/config/holidays'), params={"sid":self.sid})
        self.check_api_response(rsp)
        return rsp.json()["result"]

    def put_holidays(self, holiday_dates):
        logger.info("Setting holidays: {}".format(holiday_dates))
        data = {"dates": holiday_dates}
        rsp = self.session.put(self.url("/api/config/holidays"), params={"sid":self.sid}, files={"blob-json":json.dumps(data)})
        self.check_api_response(rsp)
        return rsp.json()
