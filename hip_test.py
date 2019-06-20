from hip.udp import send_echo, scan_network
from hip.device import HipDevice

scan = send_echo("10.27.24.3")
dut = HipDevice(scan)
dut.login(password="Test1234")
dut.simulate_keystrokes("123*")

