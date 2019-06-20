
import unittest

class TestUnittest(unittest.TestCase):

    def test_login(self):
        self.req_json = [{'command': 'system.login', 'user': username, 'password': password}]
        self.rsp_json = self.send_ajax_request(req_json)



    def test_First3login(self):
        pass

if __name__ == '__main__':
    unittest.main()
