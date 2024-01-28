

## Pwnagotchi Security Plugin

## Overview

The Pwnagotchi Security Plugin is a comprehensive tool designed to enhance network monitoring and security capabilities on the Pwnagotchi platform. With a focus on simplicity and effectiveness, this plugin provides real-time insights into the network environment, allowing users to take proactive security measures.

## Features

- **Pwnagotchi Network Monitoring:** Constantly scans the network for the presence of other Pwnagotchi devices using ARP requests.
- **Customizable Security Actions:** Choose from a set of security actions, such as changing the Wi-Fi channel or displaying alerts, when a Pwnagotchi is detected.
- **Ethernet Scan Integration:** Periodically performs an Ethernet scan using `arp-scan` to provide additional visibility into the connected devices on the network.
- **User-Friendly UI:** Integrates seamlessly with the Pwnagotchi UI, providing an intuitive interface for configuration and monitoring.

## Installation
```markdown
1. Install Flask using:


   pip3 install Flask
   ```

2. Clone the repository or download the `security.py` file.
3. Place the `security.py` file in the Pwnagotchi plugins directory.

   ```bash
   cp security.py /usr/local/share/pwnagotchi/installed-plugins/
   ```

4. Configure the plugin by updating the target IP, monitoring interval, and other settings through the Pwnagotchi UI.
5. There are 3 Modes: ["Do Nothing", "Alert User", "Change Wi-Fi Channel"]
6. Add into the `config.toml` file:

   ```toml
   main.plugins.security.enabled = true
   main.plugins.security.target_ip = "192.168.68.1"
   main.plugins.security.monitoring_interval = 10
   main.plugins.security.ethernet_scan_interval = 300
   main.plugins.security.selected_security_action = "Change Wi-Fi Channel"
   ```

## Usage

1. Access the Pwnagotchi UI.
2. Navigate to the "Plugins" section.
3. Select "Security Plugin" and configure the settings.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

## TODO

- [ ] Implement automatic installation of required dependencies.
- [ ] Enhance user configurability by adding more security action options.
- [ ] Improve UI elements for a better user experience.
- [ ] Support customization of Ethernet scan parameters.

## Possible Improvements

- Explore integration with external security tools.
- Add support for notifications or logging of security events.
- Enhance compatibility with different Pwnagotchi configurations.

Feel free to contribute to the project by submitting issues, feature requests, or pull requests.

Happy Pwnagotchi hacking!
```
