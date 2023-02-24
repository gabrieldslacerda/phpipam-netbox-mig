# Python Migrator of PHPIPAM to Netbox

This script was made to read IPAM information of PHPIPAM, check if it exists in Netbox, and push it if don't.

## Requirements

You need the following Python packages:
 - os
 - pynetbox
 - requests
 - pandas
 - slugify

You can install them all via pip:

*pip install pynetbox requests pandas slugify*

You also need to create a **PHPIPAM API APP**. That's how PHPIPAM programs its API interaction. I created the "netboxmig" app, and a PHPIPAM username with the same name. In this case, the password of the user is the same as the API KEY.

One last requirement is the **Environment Variables**. To avoid stuffing credentials in our code, I'm getting this info from Environment Variables of our system. You need to create 4 variables:
 - netbox_api_token
 - netbox_url
 - phpipam_api_token
 - phpipam_url
 
Make sure to add the URLs **without / at the end**. 

Afterwards, the script is ready to roll. Today, it supports the migration of VRFs, VLANs, L2 Domains (as VLAN Groups), Prefixes and IP Addresses. 

## Contribution

I believe the script can be more efficient, but i'm no Python Ninja, so feel free to suggest changes, fork it, whatever.
