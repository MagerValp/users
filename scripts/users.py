#!/usr/local/munkireport/munkireport-python2
# Written for MunkiReport by tuxudo

import subprocess
import os
import plistlib
import sys
from datetime import datetime
import time

sys.path.insert(0, '/usr/local/munki')
sys.path.insert(0, '/usr/local/munkireport')

from munkilib import FoundationPlist
from Foundation import CFPreferencesCopyAppValue

def get_users_info():

    # Get all users info as plist
    cmd = ['/usr/bin/dscl', '-plist', '.', '-readall', '/Users']
    proc = subprocess.Popen(cmd, shell=False, bufsize=-1,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output, unused_error) = proc.communicate()
    
    try:
        return plistlib.readPlistFromString(output)
    except Exception:
        return {}

def get_group_names():

    # Get all groups info as plist
    cmd = ['/usr/bin/dscl', '-plist', '.', '-readall', '/Groups']
    proc = subprocess.Popen(cmd, shell=False, bufsize=-1,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output, unused_error) = proc.communicate()

    try:
        groups_pl = plistlib.readPlistFromString(output)

        group_names = {}

        # Process all groups to make translate array
        for group in groups_pl:

            # Process each group record name, some of more than one record name
            for record_name in group["dsAttrTypeStandard:RecordName"]:
                group_names.update({record_name: group["dsAttrTypeStandard:RealName"][0].rstrip()})

        return group_names

    except Exception:
        return {}

def process_user_info(all_users,group_names):
    out = []

    for user in all_users:

        # Skip service accounts
        if 'dsAttrTypeStandard:UserShell' not in user.keys() or user['dsAttrTypeStandard:UserShell'][0] == "/usr/bin/false" or 'dsAttrTypeStandard:NFSHomeDirectory' not in user.keys() or user['dsAttrTypeStandard:NFSHomeDirectory'][0] == "/var/setup" or user['dsAttrTypeStandard:NFSHomeDirectory'][0] == "/var/spool/uucp" or user['dsAttrTypeStandard:RecordName'][0] == "root":
            continue

        user_atts = {}

        for user_att in user:             

            if user_att == 'dsAttrTypeStandard:RealName':
                user_atts['real_name'] = user[user_att][0]
            elif user_att == 'dsAttrTypeNative:naprivs':
                user_atts['ard_priv'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:AppleMetaNodeLocation':
                user_atts['node_location'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:AuthenticationHint' and user_account_hints_enabled():
                user_atts['password_hint'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:GeneratedUID':
                user_atts['generated_uuid'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:NFSHomeDirectory':
                user_atts['home_directory'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:PrimaryGroupID':
                user_atts['primary_group_id'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:RecordName':
                user_atts['record_name'] = user[user_att][0]

                # Process user's groups
                try:

                    # Get groups from id command
                    cmd = ['/usr/bin/id', '-Gn', user['dsAttrTypeStandard:RecordName'][0]]
                    proc = subprocess.Popen(cmd, shell=False, bufsize=-1,
                                            stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    (output, unused_error) = proc.communicate()

                    groups_list = []

                    # Translate each group to real name
                    for group in output.split(' '):
                        groups_list.append(group_names[group.rstrip()])

                    user_atts['group_memership'] = ", ".join(sorted(groups_list))

                    # Check for administrator
                    if "Administrators" in user_atts['group_memership']:
                        user_atts['administrator'] = 1
                    else:
                        user_atts['administrator'] = 0

                    # Check for SSH
                    if "SSH Service" in user_atts['group_memership']:
                        user_atts['ssh_access'] = 1
                    else:
                        user_atts['ssh_access'] = 0

                    # Check for Screensharing
                    if "Screensharing Service" in user_atts['group_memership']:
                        user_atts['screenshare_access'] = 1
                    else:
                        user_atts['screenshare_access'] = 0

                except:
                    user_atts['group_memership'] = ""

            elif user_att == 'dsAttrTypeStandard:UniqueID':
                user_atts['unique_id'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:UserShell':
                user_atts['user_shell'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:AppleMetaRecordName':
                user_atts['meta_record_name'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:EMailAddress':
                user_atts['email_address'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:SMBGroupRID':
                user_atts['smb_group_rid'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:SMBHome':
                user_atts['smb_home'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:SMBHomeDrive':
                user_atts['smb_home_drive'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:SMBPrimaryGroupSID':
                user_atts['smb_primary_group_sid'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:SMBSID':
                user_atts['smb_sid'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:SMBScriptPath':
                user_atts['smb_script_path'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:OriginalNodeName':
                user_atts['original_node_name'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:PrimaryNTDomain':
                user_atts['primary_nt_domain'] = user[user_att][0]
            elif user_att == 'dsAttrTypeStandard:CopyTimestamp':
                user_atts['copy_timestamp'] = str(time.mktime(datetime.strptime(user[user_att][0].strip(), "%Y-%m-%dT%H:%M:%SZ").timetuple()))
            elif user_att == 'dsAttrTypeStandard:SMBPasswordLastSet':
                user_atts['smb_password_last_set'] = str((int(user[user_att][0])/10000000)-11644473600)


            elif user_att == 'dsAttrTypeNative:accountPolicyData':

                policy_data = plistlib.readPlistFromString(user[user_att][0])

                for policy_item in policy_data:
                    if policy_item == "creationTime":
                        user_atts['creation_time'] = str(policy_data[policy_item])
                    elif policy_item == "failedLoginCount":
                        user_atts['failed_login_count'] = policy_data[policy_item]
                    elif policy_item == "failedLoginTimestamp":
                        user_atts['failed_login_timestamp'] = str(policy_data[policy_item])
                    elif policy_item == "passwordLastSetTime":
                        user_atts['password_last_set_time'] = str(policy_data[policy_item])
                    elif policy_item == "lastLoginTimestamp":
                        user_atts['last_login_timestamp'] = str(policy_data[policy_item])
                    elif policy_item == "passwordHistoryDepth":
                        user_atts['password_history_depth'] = policy_data[policy_item]

            elif user_att == 'dsAttrTypeNative:LinkedIdentity':

                try:
                    linkid_data = (plistlib.readPlistFromString(user[user_att][0]))["appleid.apple.com"]['linked identities'][0]

                    for linkit_item in linkid_data:
                        if linkit_item == "full name":
                            user_atts['linked_full_name'] = linkid_data[linkit_item]
                        elif linkit_item == "timestamp":
                            user_atts['linked_timestamp'] = str(time.mktime(linkid_data[linkit_item].timetuple()))
                except:
                    user_atts['linked_full_name'] = ""

        out.append(user_atts)
    return out

def user_account_hints_enabled():
    return CFPreferencesCopyAppValue('user_account_hints_enabled', 'MunkiReport')

def main():
    """Main"""

    # Set the encoding
    # The "ugly hack" :P 
    reload(sys)  
    sys.setdefaultencoding('utf8')

    # Get results
    result = dict()
    result = process_user_info(get_users_info(),get_group_names())

    # Write users results to cache
    cachedir = '%s/cache' % os.path.dirname(os.path.realpath(__file__))
    output_plist = os.path.join(cachedir, 'users.plist')
    plistlib.writePlist(result, output_plist)
#    print plistlib.writePlistToString(result)

if __name__ == "__main__":
    main()
