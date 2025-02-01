# InvokeRogueDC
```

     ___                 _        ____                        ____   ____
    |_ _|_ ____   _____ | | _____|  _ \ ___   __ _ _   _  ___|  _ \ / ___|
     | || '_ \ \ / / _ \| |/ / _ \ |_) / _ \ / _` | | | |/ _ \ | | | |
     | || | | \ V / (_) |   <  __/  _ < (_) | (_| | |_| |  __/ |_| | |___
    |___|_| |_|\_/ \___/|_|\_\___|_| \_\___/ \__, |\__,_|\___|____/ \____|
                                             |___/

    ________________
    |               |
    |  ___________  |
    | |           | |
    | |  ROGUE    | |
    | |    DC     | |
    | |___________| |
    |               |
    |  [|||||||]    |
    |  [|||||||]    |
    |  [|||||||]    |
    |               |
    |    ____       |
    |   |    |      |
    |   '----'      |
    |_______________|

        Made by Wuentin


usage: asciipy [-h] --dc-host DC_HOST [--ldap-encryption {ldaps,ldap-starttls}] --username USERNAME [--password PASSWORD] [--nthash NTHASH] [--aesKey AESKEY] --domain DOMAIN [--kerberos] --computer COMPUTER [--computer-pass COMPUTER_PASS] [--delete]

Create a computer account that will act as a domain controller.

options:
  -h, --help            show this help message and exit
  --dc-host DC_HOST     Domain Controller.
  --ldap-encryption {ldaps,ldap-starttls}
                        LDAP encryption method (Default : ldaps).
  --username USERNAME, -u USERNAME
                        Username for authentication.
  --password PASSWORD, -p PASSWORD
                        Password for authentication.
  --nthash NTHASH, -H NTHASH
                        NT hash for authentication.
  --aesKey AESKEY       AES key to use for Kerberos Authentication.
  --domain DOMAIN, -d DOMAIN
                        Domain name for authentication.
  --kerberos, -k        Use Kerberos authentication instead NTLM.
  --computer COMPUTER   Name of the computer to create in LDAP.
  --computer-pass COMPUTER_PASS
                        Password for the new computer account.
  --delete              Delete an existing computer.

                                                           
```

# Purpose
InvokeRogueDC aims to automate the creation of a machine account functioning as a domain controller. Domain controllers have DCSync rights, enabling persistence within the domain and bypassing certain detection rules.
Use of this tool requires elevated domain privileges.

# Ethical Only
The intended use of InvokeRogueDC is strictly for educational purposes, promoting ethical understanding and responsible learning in the realm of cybersecurity. This tool is not meant for any malicious activities or unauthorized access.
Using this tool against hosts that you do not have explicit permission to test is illegal. You are responsible for any trouble you may cause by using this tool.
