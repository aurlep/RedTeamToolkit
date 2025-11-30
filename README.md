**# RedTeamToolkit**
Red Team Learning Toolkit (v1)

The Red Team Learning Toolkit is an open-source PySide6 desktop application designed to help beginners and students learn offensive security tools in a safe, structured environment.
It introduces 50+ real Red Team utilities, explains their parameters/flags, and allows you to run them on a remote Kali Linux machine via SSH.

⚠️ For educational use only. Use only in labs or systems you own or have explicit permission to test.

**Features**

Categorized list of 50+ Red Team tools

Built-in descriptions, parameters, and usage examples

One-click execution on a Kali host via SSH

Output console with live command results

Covers recon, enumeration, web testing, password attacks, wireless, payloads, MITM, privesc, and more


**Requirements**

Local machine
-pip install PySide6 paramiko
-SSH

Remote Kali machine
-SSH server enabled
-User with sudo rights
-Relevant tools installed (Nmap, Hydra, SQLMap, Gobuster, theHarvester, Bettercap, Metasploit, etc.)

**Run**

git clone https://github.com/aurlep/RedTeamToolkit
cd RedTeamToolkit
python3 frontend.py

**Contribute**

Feedback, ideas, and pull requests are welcome.
This project is open-source and built for the community.
