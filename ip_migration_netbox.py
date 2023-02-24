import os
import pynetbox
import requests
import pandas as ps
from slugify import slugify

##Create global variables based in Environmental Variables
NB_API_TOKEN = os.environ.get("netbox_api_token")
NB_URL = os.environ.get("netbox_url")
PHPIPAM_API_TOKEN = os.environ.get("phpipam_api_token")
PHPIPAM_URL = os.environ.get("phpipam_url")

##pynetbox API request variable
nb = pynetbox.api(
    NB_URL,
    token=NB_API_TOKEN
)

##Fill variables for requesting temporary token of PHPIPAM. This is necessary for API interaction
phpipam_appid = "netboxmig"
phpipam_username = "netboxmig"
phpipam_password = PHPIPAM_API_TOKEN
##Request of PHPIPAM temporary token
baseurl = PHPIPAM_URL + "/api/" + phpipam_appid
r_phpipam = requests.post(
    baseurl + '/user/', auth=(phpipam_username, phpipam_password))
response_phpipam_json = r_phpipam.json()
temp_phpipam_token = response_phpipam_json['data']['token']


class ChangesIPAM:
    def __init__(self) -> None:
        pass

##Check if VRF already exists in Netbox
    def check_NewVRF(self, vrf_name):
        resp = requests.get(NB_URL + '/api/ipam/vrfs/', params={
                            'name': vrf_name}, headers={'Authorization': f'token {NB_API_TOKEN}'})
        search_results = resp.json()
        return search_results['results']

##Find the VRF ID in Netbox given the PHPIPAM VRF id
    def check_PHPToNBVRFId(self, phpipam_vrf_id):
        if phpipam_vrf_id == 0 or '0':
            phpipam_vrf_id = '1'
        request_PHPIPAM_vrf_id = requests.get(
            baseurl + '/vrf/'+ phpipam_vrf_id + '/', headers={'token': temp_phpipam_token})
        phpipam_vrf_id_resp = request_PHPIPAM_vrf_id.json()
        request_PHPIPAM_vrf_id_name_formated = phpipam_vrf_id_resp['data']
        request_PHPIPAM_vrf_id_name = request_PHPIPAM_vrf_id_name_formated['name']
        nb_vrf_name_to_id_resp = ChangesIPAM().check_NewVRF(request_PHPIPAM_vrf_id_name)
        nb_vrf_id = nb_vrf_name_to_id_resp[0]['id']
        return nb_vrf_id

##Find a VLAN Group ID given a PHPIPAM L2Domain id        
    def check_VLANGroupName(self, vlan_group_id):
        request_VLAN_Group_id_phpipam = requests.get(
            baseurl + '/l2domains/'+ vlan_group_id + '/', headers={'token': temp_phpipam_token})
        phpipam_vlan_group_resp = request_VLAN_Group_id_phpipam.json()
        phpipam_vlan_group_name_formated = phpipam_vlan_group_resp['data']
        phpipam_vlan_group_name = phpipam_vlan_group_name_formated['name']
        resp_vlan_group_name_nb = requests.get(NB_URL + '/api/ipam/vlan-groups/', params={
                                    'name': phpipam_vlan_group_name}, headers={'Authorization': f'token {NB_API_TOKEN}'})
        vlan_group_name_result = resp_vlan_group_name_nb.json()
        vlan_group_id_nb = vlan_group_name_result['results'][0]['id']
        return vlan_group_id_nb

##Check if VLAN exists in Netbox
    def check_NewVLAN(self, vlan_id, vlan_group_id):
        resp = requests.get(
            NB_URL + '/api/ipam/vlans/', 
            params={
                'vid': vlan_id,
                'group_id': vlan_group_id
                },
            headers={
                'Authorization': f'token {NB_API_TOKEN}'
            }
        )
        search_results = resp.json()
        return search_results['results']

##Check if Prefix exists in a specific Netbox' VRF
    def check_NewPrefix(self, prefix_range, vrf_nb):
        resp = nb.ipam.prefixes.get(prefix=prefix_range, vrf_id=vrf_nb)
        return resp

## Check if VLAN Group exists in Netbox
    def check_NewVLANGroup(self, vlan_group_id):
        resp = nb.ipam.vlan_groups.get(vlan_group_id)
        return resp

##Get the ID of Netbox VRF given the name
    def check_VRFID(self, vrf_name):
        check_vrf_id = requests.get(NB_URL + '/api/ipam/vrfs/', params={
                                    'name': vrf_name}, headers={'Authorization': f'token {NB_API_TOKEN}'})
        vrf_id_result = check_vrf_id.json()
        vrf_id = vrf_id_result['results'][0]['id']
        return vrf_id

##find the Netbox VLAN ID and VLAN Group given a PHPIPAM VLAN ID
    def check_VLANID(self, phpipam_vlan_id):
        phpipam_vlan_id=str(phpipam_vlan_id)
        check_vlan_id = requests.get(
            baseurl + '/vlan/'+ phpipam_vlan_id + '/', headers={'token': temp_phpipam_token})
        phpipam_vlan_id_result = check_vlan_id.json()
        nb_vlan_id = phpipam_vlan_id_result['data']['number']
        phpipam_domain_id = phpipam_vlan_id_result['data']['domainId']
        check_vlan_group_id = ChangesIPAM().check_VLANGroupName(phpipam_domain_id)
        return nb_vlan_id, check_vlan_group_id

##Check if IP Address exist in a specifc VRF of Netbox
    def check_NewIpAddress(self, ip_address, id_vrf):
        resp = nb.ipam.ip_addresses.get(address=ip_address, vrf_id=id_vrf)
        return resp

##Add IP address in a specific VRF of Netbox
    def add_NewIpAddress(self, ip_address, ip_hostname, ip_description, vrf_id):
        print(f'adding IP Address {ip_address}')
        if ip_description and ip_hostname:
            resp = nb.ipam.ip_addresses.create(
                address=ip_address,
                status='active',
                description=ip_description,
                dns_name=ip_hostname, 
                vrf=vrf_id
                )
        elif ip_description:
            resp = nb.ipam.ip_addresses.create(
                address=ip_address,
                status='active',
                description=ip_description,
                vrf=vrf_id
            )
        elif ip_hostname:
            resp = nb.ipam.ip_addresses.create(
                address=ip_address, 
                status='active', 
                dns_name=ip_hostname, 
                vrf=vrf_id
                )
        else:
            resp = nb.ipam.ip_addresses.create(
                address=ip_address, 
                status='active', 
                vrf=vrf_id
                )
        if resp:
            print(f'Added {ip_address}')
        else:
            print(f'Adding {ip_address} FAILED')

## Add VLAN to a specific VLAN Group in Netbox    
    def add_NewVLAN_Group(self, vlan_group_name, vlan_group_description):
        vlan_group_slug = slugify(vlan_group_name)
        if vlan_group_description:
            resp = nb.ipam.vlan_groups.create(name=vlan_group_name, slug=vlan_group_slug, description=vlan_group_description)
        else:
            resp = nb.ipam.vlan_groups.create(name=vlan_group_name, slug=vlan_group_slug)
        if resp:
            print(f'Added VLAN Group {vlan_group_name}')
        else:
            print(f'Adding VLAN Group {vlan_group_name} FAILED')


## Add Prefix to specific VLAN or VRF in Netbox
    def add_NewPrefix(self, prefix_description, prefix_range, new_subnet_vlan, new_is_full, vrf_id):
        print(f'adding prefix {prefix_range}')
        if new_subnet_vlan:
            int_subnet_vlan = int(new_subnet_vlan)
        else:
            int_subnet_vlan = None
        if new_is_full:
            int_is_full = int(new_is_full)
        else:
            int_is_full = None
        if int_subnet_vlan is not None:    
            if int_subnet_vlan > 0:
                vlan_id_and_group_id = ChangesIPAM().check_VLANID(int_subnet_vlan)
                nb_vlan_id_resp = requests.get(NB_URL + '/api/ipam/vlans/', params={
                                            'vid': vlan_id_and_group_id[0], 'group_id': vlan_id_and_group_id[1]}, headers={'Authorization': f'token {NB_API_TOKEN}'})
                nb_vlan_id_json = nb_vlan_id_resp.json()
                nb_vlan_id = nb_vlan_id_json['results'][0]['id']
            else:
                nb_vlan_id = None
        else:
            nb_vlan_id = None
        if int_is_full == 1:
            new_is_full = int_is_full
        else:
            new_is_full = None
        if prefix_description and nb_vlan_id and new_is_full:
            resp = nb.ipam.prefixes.create(
                prefix=prefix_range,
                vrf=vrf_id,
                vlan=nb_vlan_id,
                status='active',
                is_pool=True,
                mark_utilized = True,
                description=prefix_description
            )
        elif prefix_description and nb_vlan_id:
            resp = nb.ipam.prefixes.create(
                prefix=prefix_range,
                vrf=vrf_id,
                vlan=nb_vlan_id,
                status='active',
                mark_utilized = True,
                description=prefix_description
            )
        elif prefix_description and new_is_full:
            resp = nb.ipam.prefixes.create(
                prefix=prefix_range,
                vrf=vrf_id,
                status='active',
                is_pool=True,
                mark_utilized = True,
                description=prefix_description
            )
        elif nb_vlan_id and new_is_full:
            resp = nb.ipam.prefixes.create(
                prefix=prefix_range,
                vrf=vrf_id,
                vlan=nb_vlan_id,
                status='active',
                is_pool=True,
                mark_utilized = True
            )
        elif nb_vlan_id:
            resp = nb.ipam.prefixes.create(
                prefix=prefix_range,
                vrf=vrf_id,
                vlan=nb_vlan_id,
                status='active',
                is_pool=True
            )
        elif new_is_full:
            resp = nb.ipam.prefixes.create(
                prefix=prefix_range,
                vrf=vrf_id,
                status='active',
                is_pool=True,
                mark_utilized = True
            )
        elif prefix_description:
            resp = nb.ipam.prefixes.create(
                prefix=prefix_range,
                vrf=vrf_id,
                status='active',
                is_pool=True,
                description=prefix_description
            )      
        else:
            resp = nb.ipam.prefixes.create(
                prefix=prefix_range,
                status='active',
                vrf=vrf_id,
                is_pool=True
            )
        if resp:
            print(f'Added {prefix_range}')
        else:
            print(f'Adding {prefix_range} FAILED')

## Add VLAN to specific VLAN Group of Netbox
    def add_NewVLAN(self, vlan_name, vlan_id, vlan_description, vlan_group_id):
        print(f'adding {vlan_name}')
        vlan_name = vlan_name[:63]
        if vlan_description:
            resp = requests.post(
                NB_URL + '/api/ipam/vlans/',
                json={
                    'name': vlan_name,
                    'vid': vlan_id,
                    'group': vlan_group_id,
                    'description': vlan_description
                },
                headers={
                    'Authorization': f'token {NB_API_TOKEN}'
                        }
            )
        else:
            resp = requests.post(
                NB_URL + '/api/ipam/vlans/',
                json={
                    'name': vlan_name,
                    'vid': vlan_id,
                    'group': vlan_group_id                },
                headers={
                    'Authorization': f'token {NB_API_TOKEN}'
                        }
            )
        format_resp = resp.json()
        if resp:
            print(f'Added {vlan_name}')
        else:
            if "VLAN with this Group and Name already exists." in format_resp['__all__']:
                resp = requests.post(
                    NB_URL + '/api/ipam/vlans/',
                    json={
                        'name': vlan_name+'-'+vlan_id,
                        'vid': vlan_id,
                        'group': vlan_group_id,
                    },
                    headers={
                        'Authorization': f'token {NB_API_TOKEN}'
                            }
                )
                print(f'Repeated name, adding {vlan_name} as {vlan_name}-{vlan_id}')
            return(resp)
##Add VRF to Netbox
    def add_NewVRF(self, vrf_name, vrf_rd, vrf_description):
        if vrf_description:
            resp = requests.post(
                NB_URL + '/api/ipam/vrfs/',
                 json={
                    'name': vrf_name, 
                    'rd': vrf_rd, 
                    'description': vrf_description
                    }, 
                headers={
                    'Authorization': f'token {NB_API_TOKEN}'
                        }
                )
        else:
            resp = requests.post(NB_URL + '/api/ipam/vrfs/', json={
                                 'name': vrf_name, 'rd': vrf_rd}, headers={'Authorization': f'token {NB_API_TOKEN}'})
        return resp.content

##Read VRFs from PHPIPAM and add them to Netbox
phpipam_vrfs_response = requests.get(
    baseurl + '/vrf/', headers={'token': temp_phpipam_token})
phpipam_vrfs = phpipam_vrfs_response.json()
format_vrfs = phpipam_vrfs['data']
for vrf_item in format_vrfs:
    new_vrf_name = vrf_item['name']
    new_vrf_rd = vrf_item['rd']
    new_vrf_description = vrf_item['description']
    result_check_vrf = ChangesIPAM().check_NewVRF(new_vrf_name)
    if len(result_check_vrf):
        print(f'VRF {new_vrf_name} already exists')
    else:
        add_new_vrf = ChangesIPAM().add_NewVRF(new_vrf_name, new_vrf_rd, new_vrf_description)
        print (f'VRF {new_vrf_name} added')

##Read L2Domains from PHPIPAM and add them as VLAN Groups to Netbox
phpipam_vlan_group_response = requests.get(
    baseurl + '/l2domains/', headers={'token': temp_phpipam_token})
phpipam_vlan_group = phpipam_vlan_group_response.json()
format_vlan_groups = phpipam_vlan_group['data']
for vlan_group in format_vlan_groups:
    new_vlan_group_id = vlan_group['id']
    new_vlan_group_name = vlan_group['name']
    new_vlan_group_description = vlan_group['description']
    result_vlan_group_search = ChangesIPAM().check_NewVLANGroup(new_vlan_group_id)
    if result_vlan_group_search:
        print(f'VLAN Group {new_vlan_group_name} Already added')
    else:
        result_vlan_group_add = ChangesIPAM().add_NewVLAN_Group(new_vlan_group_name, new_vlan_group_description)

##Read PHPIPAM VLANs and add tem to specific VRFs or VLAN Groups in Netbox
phpipam_vlan_response = requests.get(
    baseurl + '/vlan/', headers={'token': temp_phpipam_token})
phpipam_vlan = phpipam_vlan_response.json()
format_vlans = phpipam_vlan['data']
for vlan in format_vlans:
    new_vlan_id = vlan['number']
    new_vlan_description = vlan['description']
    new_vlan_group_id = vlan['domainId']
    new_vlan_name = vlan['name']
    result_check_vlan_group = ChangesIPAM().check_VLANGroupName(new_vlan_group_id)
    result_check_vlan = ChangesIPAM().check_NewVLAN(new_vlan_id, result_check_vlan_group)
    if len(result_check_vlan):
        print(f'VLAN {new_vlan_name} already exists!')
    else:
        result_add_vlan = ChangesIPAM().add_NewVLAN(new_vlan_name, new_vlan_id, new_vlan_description, result_check_vlan_group)

##Read IP Addresses from PHPIPAM and add them to specific VRFs or VLANs in Netbox
phpipam_sections_response = requests.get(
    baseurl + '/sections/', headers={'token': temp_phpipam_token})
phpipam_sections = phpipam_sections_response.json()
for loop in phpipam_sections['data']:
    sections_id = loop['id']
    sections_name = loop['name']
    print(f'getting addresses from section {sections_id} - {sections_name}')
    phpipam_response = requests.get(
        baseurl + '/sections/'+sections_id+'/subnets/addresses/', headers={'token': temp_phpipam_token})
    print(f'result of query is {phpipam_response.status_code}')
    ip_addresses_per_section = phpipam_response.json()
    if ip_addresses_per_section['success'] == 0:
        print('No Addresses for this section')
    else:
        sections_phpipam = ip_addresses_per_section['data']
    for sections_loop in sections_phpipam:
        new_subnet_range = sections_loop['subnet']+'/'+sections_loop['mask']
        new_subnet_description = sections_loop['description']
        new_subnet_full = sections_loop['isFull']
        new_subnet_vrf = sections_loop['vrfId']
        new_subnet_vlan = sections_loop['vlanId']
        if new_subnet_vrf:
            nb_vrf = ChangesIPAM().check_PHPToNBVRFId(new_subnet_vrf)
        else:
            nb_vrf = 1
        result_check_prefix = ChangesIPAM().check_NewPrefix(new_subnet_range, nb_vrf)
        if result_check_prefix:
            print(f'Prefix {new_subnet_range} already exists!')
        else:
            result_add_prefix = ChangesIPAM().add_NewPrefix(
                new_subnet_description, new_subnet_range, new_subnet_vlan, new_subnet_full, nb_vrf)
        if len(sections_loop['addresses']) > 0:
            for sections_ips in sections_loop['addresses']:
                if sections_ips['hostname']:
                    new_ip_hostname = sections_ips['hostname']
                    special_characters=[']','*','[', '+', ';', '(',')','{','}',',','<','>','%','$','!','?', ' ', '/', '&', '|', '~', '`', '#', '=']
                    normal_string = new_ip_hostname
                    for i in special_characters:
                        normal_string=normal_string.replace(i,"")
                        new_ip_hostname=normal_string
                else:
                    new_ip_hostname = None
                if sections_ips['description']:
                    new_ip_description = sections_ips['description']
                else:
                    new_ip_description = None
                new_ip = sections_ips['ip']+'/'+sections_loop['mask']
                result_check_ip = ChangesIPAM().check_NewIpAddress(new_ip, nb_vrf)
                if result_check_ip:
                    print(f' IP Address {new_ip} already exists!')
                else:
                    result_add_ip = ChangesIPAM().add_NewIpAddress(
                        new_ip, new_ip_hostname, new_ip_description, nb_vrf)
