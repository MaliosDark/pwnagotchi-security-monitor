import logging
import time
import threading
import subprocess
import os
from scapy.all import ARP, Ether, srp

import pwnagotchi.plugins as plugins
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK  # Corregido aquí
import pwnagotchi.ui.fonts as fonts

class SecurityPlugin(plugins.Plugin):
    __author__ = 'MaliosDark'
    __version__ = '1.8.6'
    __license__ = 'GPL3'
    __description__ = 'Comprehensive security plugin for pwnagotchi.'

    def __init__(self):
        logging.debug("Security plugin created")
        self.detected_pwnagotchi_count = 0
        self.security_action_options = ["Change Wi-Fi Channel", "Alert User", "Do Nothing"]
        self.selected_security_action = self.security_action_options[0]  # Default to changing Wi-Fi channel
        self.ethernet_scan_results = "No scan results yet"
        self.is_scapy_installed = self.check_scapy_installed()
        self.target_ip = "192.168.1.1"  # Default target IP, can be edited through UI
        self.monitoring_interval = 10  # Default monitoring interval in seconds
        self.ethernet_scan_interval = 300  # Default Ethernet scan interval in seconds

    def on_loaded(self):
        logging.info("Security plugin loaded")

        # Check and install scapy if needed
        if not self.is_scapy_installed:
            self.install_scapy()

        # Start a thread to monitor the network
        monitoring_thread = threading.Thread(target=self.monitor_network, args=(ui,))
        monitoring_thread.start()


        # Start a thread for Ethernet scanning
        ethernet_scan_thread = threading.Thread(target=self.ethernet_scan)
        ethernet_scan_thread.start()

        # Start a separate thread for UI updates
        ui_update_thread = threading.Thread(target=self.ui_update_handler)
        ui_update_thread.start()

        # Reboot the pwnagotchi to apply changes
        os.system("pwnagotchi rebootsys")

    def on_ui_setup(self, ui):
        # Add custom UI elements
        ui.add_element('security_status', LabeledValue(color=BLACK, label='Security Status', value='OK',
                                                       position=(ui.width() / 2 - 50, 0), label_font=fonts.Bold,
                                                       text_font=fonts.Medium))

        ui.add_element('detected_pwnagotchi', LabeledValue(color=BLACK, label='Detected Pwnagotchi:',
                                                           value='',
                                                           position=(10, 40),
                                                           label_font=fonts.Medium,
                                                           text_font=fonts.Medium))

        ui.add_element('security_actions', LabeledValue(color=BLACK, label='Security Actions:',
                                                         value='',
                                                         position=(10, 80),
                                                         label_font=fonts.Medium,
                                                         text_font=fonts.Medium))

        # Add a button to access Ethernet scan results
        ui.add_element('scan_button', LabeledValue(color=BLACK, label='Scan Ethernet',
                                                    value='',
                                                    position=(ui.width() / 2 - 25, 120),
                                                    label_font=fonts.Medium,
                                                    text_font=fonts.Medium,
                                                    on_press=self.show_ethernet_scan_results))

        # Add a text input for configuring the target IP
        ui.add_element('target_ip_input', LabeledValue(color=BLACK, label='Target IP:',
                                                        value=str(self.target_ip),
                                                        position=(10, 160),
                                                        label_font=fonts.Medium,
                                                        text_font=fonts.Medium,
                                                        on_change=self.update_target_ip))

        # Add text inputs for configuring monitoring and Ethernet scan intervals
        ui.add_element('monitoring_interval_input', LabeledValue(color=BLACK, label='Monitoring Interval (s):',
                                                                 value=str(self.monitoring_interval),
                                                                 position=(10, 200),
                                                                 label_font=fonts.Medium,
                                                                 text_font=fonts.Medium,
                                                                 on_change=self.update_monitoring_interval))

        ui.add_element('ethernet_scan_interval_input', LabeledValue(color=BLACK, label='Ethernet Scan Interval (s):',
                                                                    value=str(self.ethernet_scan_interval),
                                                                    position=(10, 240),
                                                                    label_font=fonts.Medium,
                                                                    text_font=fonts.Medium,
                                                                    on_change=self.update_ethernet_scan_interval))

    def on_ui_update(self, ui):
        # Update UI elements
        ui.set('security_status', "OK" if self.is_security_ok() else "Alert")

    def check_scapy_installed(self):
        try:
            # Try to import scapy
            import scapy.all
            return True
        except ImportError:
            return False

    def install_scapy(self):
        # Install scapy using pip
        os.system("pwnagotchi plug scapy --install")

    def monitor_network(self, ui):
        while True:
            # Network monitoring logic
            detected_pwnagotchi = self.detect_pwnagotchi_nearby()

            if detected_pwnagotchi:
                # Increment the detected pwnagotchi count
                self.detected_pwnagotchi_count += 1

                # Display detected pwnagotchi information on the UI
                self.display_detected_pwnagotchi(ui, detected_pwnagotchi)

                # Take security actions based on the selected option
                self.take_security_actions(ui)

            time.sleep(self.monitoring_interval)  # Monitoring interval



    def detect_pwnagotchi_nearby(self):
        # Logic for detecting nearby pwnagotchi
        # Use ARP requests to find devices on the network
        request = ARP(pdst=self.target_ip)
        response, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / request, timeout=2, verbose=0)

        if response:
            return True
        else:
            return False

    def display_detected_pwnagotchi(self, ui, detected_pwnagotchi):
        # Display detected pwnagotchi information on the UI
        ui.set('detected_pwnagotchi', f'Detected Pwnagotchi: {detected_pwnagotchi}')
        logging.debug(f'Displaying detected Pwnagotchi: {detected_pwnagotchi}')

    def take_security_actions(self, ui):
        # Take security actions based on the selected option
        if self.selected_security_action == "Change Wi-Fi Channel":
            self.change_wifi_channel()
        elif self.selected_security_action == "Alert User":
            self.alert_user(ui)
            logging.debug('Alerting user')
        elif self.selected_security_action == "Do Nothing":
            # Si la acción seleccionada es "Do Nothing", no hacemos nada.
            pass
        logging.debug(f'Took security actions: {self.selected_security_action}')


    def change_wifi_channel(self):
        # Logic for changing Wi-Fi channel
        # You can use pwnagotchi's API to execute bettercap commands
        os.system("pwnagotchi bettercap 'ble.recon on'")

    def alert_user(self):
        # Logic for alerting the user
        # You can use pwnagotchi's API to display a message on the screen
        ui.set('security_status', "Alert")
        ui.set('security_actions', f'Security Actions: Alert - Detected Pwnagotchi!')
        os.system("pwnagotchi display 'Alert: Detected Pwnagotchi!'")

    def is_security_ok(self):
        # Logic to determine if security is okay
        # For demonstration, security is considered okay if no pwnagotchi is detected
        return not self.detect_pwnagotchi_nearby()

    def ethernet_scan(self):
        while True:
            # Logic for Ethernet scanning
            try:
                # Use subprocess to execute the "arp-scan" command
                result = subprocess.check_output(["arp-scan", "--localnet"], universal_newlines=True)
                self.ethernet_scan_results = result
            except Exception as e:
                logging.error(f"Error during Ethernet scan: {e}")
                self.ethernet_scan_results = "Error during scan."

            time.sleep(self.ethernet_scan_interval)  # Scan interval

    def show_ethernet_scan_results(self):
        # Log the Ethernet scan results
        logging.info(self.ethernet_scan_results)

    def ui_update_handler(self):
        while True:
            # Update UI elements with additional information
            ui.set('security_actions', f'Security Actions: {", ".join(self.security_action_options)}')
            ui.set('detected_pwnagotchi', f'Detected Pwnagotchi Count: {self.detected_pwnagotchi_count}')
            ui.set('ethernet_scan_results', f'Ethernet Scan Results: {self.ethernet_scan_results}')
            time.sleep(60)  # UI update interval

    def update_target_ip(self, value):
        # Update the target IP based on the user input
        self.target_ip = value

    def update_monitoring_interval(self, value):
        # Update the monitoring interval based on the user input
        try:
            self.monitoring_interval = int(value)
        except ValueError:
            logging.warning("Invalid monitoring interval value. Please enter a valid integer.")

    def update_ethernet_scan_interval(self, value):
        # Update the Ethernet scan interval based on the user input
        try:
            self.ethernet_scan_interval = int(value)
        except ValueError:
            logging.warning("Invalid Ethernet scan interval value. Please enter a valid integer.")


