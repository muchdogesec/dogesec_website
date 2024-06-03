---
date: 2024-07-01
title: "A Beginners Guide to TAXII Clients and Servers"
description: "Want to consume and/or share cyber threat intelligence easily? TAXII is what you need. Let me show you."
categories:
  - DIY
  - TUTORIAL
tags: [
    STIX,
    TAXII
]
products:
    - arango_taxii_server
author_staff_member: david-greenwood
image: /assets/images/blog/2024-07-01/header.jpeg
featured_image: /assets/images/blog/2024-07-01/header.jpeg
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

TAXII, or Trusted Automated Exchange of Intelligence Information, is a protocol designed specifically to share and consume cyber threat intelligence. 

TAXII enables organisations to share CTI by defining a single API that all upstream and downstream technology can be built to support, removing the issues of trying to support many individual API designs.

TAXII Clients connect to said API endpoints.

## STIX vs TAXII

Before I kick off, it's important to make the distinction between STIX and TAXII. Many often confuse the two, myself included only a few month ago.

[STIX is a representation of threat intelligence -- the content](/blog/beginners_guide_stix_objects).

TAXII is a standard way to consume and share that content -- the protocol.

So how are they related? A TAXII Server must be able to handle STIX content (print it in responses, and receive it from producer).

A TAXII server can also handle other intelligence formats, in addition to STIX. However, in the following tutorial posts, I will only focus on TAXII servers and clients that use STIX 2.1 structured data. Why? Almost all of the cyber threat intelligence world that supports TAXII uses STIX data with it.

Just one final note for the avoidance of doubt... one of the reasons that leads to confusion is this versioning of the standards. STIX is currently on version 2.1. TAXII, also currently on 2.1. However the versioning is completely independent and there is no coupling of the two based on version.

## An introduction to TAXII

Now that's clear (hopefully), at its core; TAXII has two main concepts...

1. TAXII Servers: store created intelligence from and disseminate it to consumers (the TAXII Clients) via the API
  * [see our post on the TAXII server we built for a comprehensive overview on what servers can do](/blog/ten_minute_taxii_server/)
2. TAXII Clients: that publish intelligence and/or consume intelligence from TAXII Servers
  * I will cover these in this post, showing you how to interact with our TAXII Server

Note, a TAXII Server and Client can be the same machine (the code supports both Server and Client functionality).

For example, a Threat Intelligence platform acts as a TAXII Client and consumes intelligence feeds from remote TAXII Servers. The TIP also acts a TAXII server for downstream security tools connecting to the TIP to poll for curated intel.

[The TAXII 2.1 specification](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html) defines two primary services to support a variety of common intelligence sharing models:

<img class="img-fluid" src="/assets/images/blog/2024-07-01/taxii-architecture.png" alt="TAXII architecture" title="TAXII architecture" />

* Collections: An interface to a server-provided repository of objects that allows a producer to serve consumers in a request-response template.
* Channels: Allows the exchange of information according to a publish-subscribe model.

For the more technically inclined, a good equivalent is to think of Collections as a REST API and Channels as webhooks.

In reality, the Channels don't exist. I am not really sure why OASIS decided to include it in the published specification. As such, Channels will be totally ignored in this write up.

Collections and Channels can be organized in different ways.

The search for information on a TAXII server depends on what you are looking for and how you want to receive it. Generally the design of Collections and Channels on a TAXII Server will look something like this:

<img class="img-fluid" src="/assets/images/blog/2024-07-01/taxii-architecture-2.png" alt="TAXII architecture" title="TAXII architecture" />

TAXII Clients contain the logic to consume data from and publish data to Collections (request/response) or Channels (streamed) via the TAXII Servers API.

A TAXII Client might just be a script making API calls to the TAXII Server to retrieve data, though a few fully fledged TAXII Clients with more advanced logic (and a nice user interface) to interact with TAXII APIs exist, some of which I will show you in this tutorial.

Before I get into those, I will demonstrate these concepts by going through the TAXII APIs.

To do this, lets jump right in and install a TAXII Server.

## cti-taxii-client

A growing number of cyber security products are introducing native TAXII 2.1 Client functionality to consume cyber threat intelligence from TAXII 2.1 Servers (you should check the docs of products in your security stack).

However, before you decide to build out all the logic required for a TAXII 2.1 Client into your own product, there are some existing open-source options you might want to consider, or at least to use for inspiration.

The vendor agnostic option is cti-taxii-client. [cti-taxii-client is a client developed by Oasis](https://github.com/oasis-open/cti-taxii-client/), and it is probably the best template to use if you plan to build your own TAXII 2.1 Client.

cti-taxii-client is a minimal client implementation for the TAXII 2.X server. It supports the following TAXII 2.0 and 2.1 API services:

* Server Discovery
* Get API Root Information
* Get Status
* Get Collections
* Get a Collection
* Get Objects
* Add Objects
* Get an Object
* Delete an Object (2.1 only)
* Get Object Manifests
* Get Object Versions (2.1 only)

The easiest way to install the TAXII client is with pip:

```shell
git clone https://github.com/oasis-open/cti-taxii-client/
cd cti-taxii-client
python3 -m venv cti-taxii-client_env
source cti-taxii-client_env/bin/activate
pip3 install taxii2-client
```

To test out the TAXII 2.1 Client, you will need a running TAXII 2.1 Server. For this post I will use our TAXII server implementaion, [arango_taxii_server](https://github.com/muchdogesec/arango_taxii_server/).

[Unlike in this post](/blog/ten_minute_taxii_server) when I was manually creating `curl` requests that required me to add the full logic in each request to interact with the TAXII 2.1 Server, a TAXII Client automates all this logic.

cti-taxii-client supports both [TAXII 2.0](https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v20.html) and [TAXII 2.1](https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v21.html) in two distinct sub-modules. For this tutorial I will use TAXII 2.1 as most people are using this version (it has been around for 4 years).

To begin with I have written a simple Python script that uses the cti-taxii-client module functions to query the discovery endpoint to find out what is on the server.

```python
## python3 server-discovery.py
### import requirements https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v21.html#taxii2client.v21.Server
from taxii2client.v21 import Server

server = Server('http://localhost:8000/taxii2/', user='USER', password='PASS')

print('server.title : ', server.title)
print('server.description : ', server.description)
print('server.contact : ', server.contact)
print('server.default.url :', server.default.url)
print('server.custom_properties :', server.custom_properties)

roots = []
for api in server.api_roots:
    roots.append(api.url)

print('server.api_roots : ',roots)
```

Which prints;

```txt
server.title :  Arango TAXII Server
server.description :  https://github.com/muchdogesec/arango_taxii_server/
server.contact :  noreply@dogesec.com
server.default.url : {}
server.custom_properties : {}
server.api_roots :  ['http://127.0.0.1:8000/api/taxii2/test_db_1_database/','http://127.0.0.1:8000/api/taxii2/cti_database/','http://127.0.0.1:8000/api/taxii2/_system/','http://127.0.0.1:8000/api/taxii2/taxii_root_demo_database/','http://127.0.0.1:8000/api/taxii2/test_db_13_database/']
```

Three `server.api_roots` are printed (thus accessible to this user). I can now identify what Collections exist in one of the API Roots (I will use `http://127.0.0.1:8000/api/taxii2/cti_database/`).

```python
## python3 get-collections.py
### import requirements https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v21.html#taxii2client.v21.ApiRoot
from taxii2client.v21 import ApiRoot

default = ApiRoot(url='http://127.0.0.1:8000/api/taxii2/cti_database/', user='USER', password='PASS')

collection_no = 1

for collections in default.collections:

    print()
    print('Collection {}'.format(collection_no))
    print()
    print("collection.title: ", collections.title)
    print("collection.description: ", collections.description)
    print("collection.id: ", collections.id)
    print('collection.custom_properties: ',collections.custom_properties)
    print('collection.can_read: ',collections.can_read)
    print('collection.can_write: ',collections.can_write)
    print('collection.media_types: ',collections.media_types)
    print()

    collection_no += 1
```

Which prints;

```txt
Collection 1

collection.title:  mitre_attack_enterprise
collection.description:  vertex+edge
collection.id:  mitre_attack_enterprise
collection.custom_properties:  {}
collection.can_read:  True
collection.can_write:  True
collection.media_types:  ['application/stix+json;version=2.1']


Collection 2

collection.title:  mitre_attack_ics
collection.description:  vertex+edge
collection.id:  mitre_attack_ics
collection.custom_properties:  {}
collection.can_read:  True
collection.can_write:  True
collection.media_types:  ['application/stix+json;version=2.1']


Collection 3

collection.title:  mitre_attack_mobile
collection.description:  vertex+edge
collection.id:  mitre_attack_mobile
collection.custom_properties:  {}
collection.can_read:  True
collection.can_write:  True
collection.media_types:  ['application/stix+json;version=2.1']


Collection 4

collection.title:  nvd_cve
collection.description:  vertex+edge
collection.id:  nvd_cve
collection.custom_properties:  {}
collection.can_read:  True
collection.can_write:  True
collection.media_types:  ['application/stix+json;version=2.1']


Collection 5

collection.title:  sigmahq_rules
collection.description:  vertex+edge
collection.id:  sigmahq_rules
collection.custom_properties:  {}
collection.can_read:  True
collection.can_write:  True
collection.media_types:  ['application/stix+json;version=2.1']
```

Now I can start to discover the Objects held by each of these Collections. I will use `mitre_attack_enterprise` to demonstrate.

```python
## python3 get_objects.py
### import requirements https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v21.html#taxii2client.v21.Server
from taxii2client.v21 import Server
import json

server = Server('http://localhost:8000/taxii2/', user='USER', password='PASS')

col = {}

for api_roots in server.api_roots:
    api_root = api_roots.collections
    try:
        for collections in api_roots.collections:
            col[collections.id] = collections 

    except:
        print('')
        continue

collection3 =  col['mitre_attack_enterprise']

response = collection3.get_objects()
# Parse the response body as JSON
stix_objects = json.loads(response.text)

# Print the STIX objects
print(json.dumps(stix_objects, indent=4))
```

```json
{
    "more": true,
    "next": 34617997,
    "objects": [
        {
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "id": "course-of-action--797312d4-8a84-4daf-9c56-57da4133c322",
            "type": "course-of-action",
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/mitigations/T1199",
                    "external_id": "T1199"
                }
            ],
            "modified": "2019-07-25T12:30:35.417Z",
            "name": "Trusted Relationship Mitigation",
            "description": "Network segmentation can be used to isolate infrastructure components that do not require broad network access. Properly manage accounts and permissions used by parties in trusted relationships to minimize potential abuse by the party and if the party is compromised by an adversary. Vet the security policies and procedures of organizations that are contracted for work that require privileged access to network resources.",
            "x_mitre_deprecated": true,
            "x_mitre_version": "1.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "spec_version": "2.1",
            "x_mitre_attack_spec_version": "2.1.0"
        },
        {
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "id": "course-of-action--7a14d974-f3d9-4e4e-9b7d-980385762908",
            "type": "course-of-action",
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/mitigations/T1073",
                    "external_id": "T1073"
                }
            ],
            "modified": "2019-07-24T14:24:44.818Z",
            "name": "DLL Side-Loading Mitigation",
            "description": "Update software regularly. Install software in write-protected locations. Use the program sxstrace.exe that is included with Windows along with manual inspection to check manifest files for side-loading vulnerabilities in software.",
            "x_mitre_deprecated": true,
            "x_mitre_version": "1.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "spec_version": "2.1",
            "x_mitre_attack_spec_version": "2.1.0"
        },
        {
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "id": "course-of-action--7a4d0054-53cd-476f-88af-955dddc80ee0",
            "type": "course-of-action",
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/mitigations/T1189",
                    "external_id": "T1189"
                },
                {
                    "url": "https://blogs.windows.com/msedgedev/2017/03/23/strengthening-microsoft-edge-sandbox/",
                    "description": "Cowan, C. (2017, March 23). Strengthening the Microsoft Edge Sandbox. Retrieved March 12, 2018.",
                    "source_name": "Windows Blogs Microsoft Edge Sandbox"
                },
                {
                    "url": "https://arstechnica.com/information-technology/2017/03/hack-that-escapes-vm-by-exploiting-edge-browser-fetches-105000-at-pwn2own/",
                    "description": "Goodin, D. (2017, March 17). Virtual machine escape fetches $105,000 at Pwn2Own hacking contest - updated. Retrieved March 12, 2018.",
                    "source_name": "Ars Technica Pwn2Own 2017 VM Escape"
                },
                {
                    "url": "https://blogs.technet.microsoft.com/srd/2017/08/09/moving-beyond-emet-ii-windows-defender-exploit-guard/",
                    "description": "Nunez, N. (2017, August 9). Moving Beyond EMET II \u2013 Windows Defender Exploit Guard. Retrieved March 12, 2018.",
                    "source_name": "TechNet Moving Beyond EMET"
                },
                {
                    "url": "https://en.wikipedia.org/wiki/Control-flow_integrity",
                    "description": "Wikipedia. (2018, January 11). Control-flow integrity. Retrieved March 12, 2018.",
                    "source_name": "Wikipedia Control Flow Integrity"
                }
            ],
            "modified": "2019-07-24T19:14:33.952Z",
            "name": "Drive-by Compromise Mitigation",
            "description": "Drive-by compromise relies on there being a vulnerable piece of software on the client end systems. Use modern browsers with security features turned on. Ensure all browsers and plugins kept updated can help prevent the exploit phase of this technique.\n\nFor malicious code served up through ads, adblockers can help prevent that code from executing in the first place. Script blocking extensions can help prevent the execution of JavaScript that may commonly be used during the exploitation process.\n\nBrowser sandboxes can be used to mitigate some of the impact of exploitation, but sandbox escapes may still exist. (Citation: Windows Blogs Microsoft Edge Sandbox) (Citation: Ars Technica Pwn2Own 2017 VM Escape)\n\nOther types of virtualization and application microsegmentation may also mitigate the impact of client-side exploitation. The risks of additional exploits and weaknesses in implementation may still exist. (Citation: Ars Technica Pwn2Own 2017 VM Escape)\n\nSecurity applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. (Citation: TechNet Moving Beyond EMET) Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. (Citation: Wikipedia Control Flow Integrity) Many of these protections depend on the architecture and target application binary for compatibility.",
            "x_mitre_deprecated": true,
            "x_mitre_version": "1.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "spec_version": "2.1",
            "x_mitre_attack_spec_version": "2.1.0"
        },
        {
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "id": "course-of-action--7a6e5ca3-562f-4185-a323-f3b62b5b2e6b",
            "type": "course-of-action",
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/mitigations/T1177",
                    "external_id": "T1177"
                },
                {
                    "source_name": "Microsoft LSA Protection Mar 2014",
                    "description": "Microsoft. (2014, March 12). Configuring Additional LSA Protection. Retrieved November 27, 2017.",
                    "url": "https://technet.microsoft.com/library/dn408187.aspx"
                },
                {
                    "url": "https://docs.microsoft.com/windows/access-protection/credential-guard/credential-guard-manage",
                    "description": "Lich, B., Tobin, J., Hall, J. (2017, April 5). Manage Windows Defender Credential Guard. Retrieved November 27, 2017.",
                    "source_name": "Microsoft Enable Cred Guard April 2017"
                },
                {
                    "url": "https://docs.microsoft.com/windows/access-protection/credential-guard/credential-guard-how-it-works",
                    "description": "Lich, B., Tobin, J. (2017, April 5). How Windows Defender Credential Guard works. Retrieved November 27, 2017.",
                    "source_name": "Microsoft Credential Guard April 2017"
                },
                {
                    "source_name": "Microsoft DLL Security",
                    "description": "Microsoft. (n.d.). Dynamic-Link Library Security. Retrieved November 27, 2017.",
                    "url": "https://msdn.microsoft.com/library/windows/desktop/ff919712.aspx"
                }
            ],
            "modified": "2019-07-24T19:47:23.978Z",
            "name": "LSASS Driver Mitigation",
            "description": "On Windows 8.1 and Server 2012 R2, enable LSA Protection by setting the Registry key <code>HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL</code> to <code>dword:00000001</code>. (Citation: Microsoft LSA Protection Mar 2014) LSA Protection ensures that LSA plug-ins and drivers are only loaded if they are digitally signed with a Microsoft signature and adhere to the Microsoft Security Development Lifecycle (SDL) process guidance.\n\nOn Windows 10 and Server 2016, enable Windows Defender Credential Guard (Citation: Microsoft Enable Cred Guard April 2017) to run lsass.exe in an isolated virtualized environment without any device drivers. (Citation: Microsoft Credential Guard April 2017)\n\nEnsure safe DLL search mode is enabled <code>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\SafeDllSearchMode</code> to mitigate risk that lsass.exe loads a malicious code library. (Citation: Microsoft DLL Security)",
            "x_mitre_deprecated": true,
            "x_mitre_version": "1.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "spec_version": "2.1",
            "x_mitre_attack_spec_version": "2.1.0"
        },
        {
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "id": "course-of-action--7aee8ea0-0baa-4232-b379-5d9ce98352cf",
            "type": "course-of-action",
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/mitigations/T1179",
                    "external_id": "T1179"
                }
            ],
            "modified": "2019-07-24T19:37:27.850Z",
            "name": "Hooking Mitigation",
            "description": "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of operating system design features. For example, mitigating all hooking will likely have unintended side effects, such as preventing legitimate software (i.e., security products) from operating properly. Efforts should be focused on preventing adversary tools from running earlier in the chain of activity and on identifying subsequent malicious behavior.",
            "x_mitre_deprecated": true,
            "x_mitre_version": "1.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "spec_version": "2.1",
            "x_mitre_attack_spec_version": "2.1.0"
        },
        {
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "id": "course-of-action--7bb5fae9-53ad-4424-866b-f0ea2a8b731d",
            "type": "course-of-action",
            "created": "2019-06-06T20:15:34.146Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "M1020",
                    "url": "https://attack.mitre.org/mitigations/M1020"
                }
            ],
            "modified": "2019-06-06T20:15:34.146Z",
            "name": "SSL/TLS Inspection",
            "description": "Break and inspect SSL/TLS sessions to look at encrypted web traffic for adversary activity.",
            "x_mitre_version": "1.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "spec_version": "2.1",
            "x_mitre_attack_spec_version": "2.1.0"
        },
        {
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "id": "course-of-action--7c1796c7-9fc3-4c3e-9416-527295bf5d95",
            "type": "course-of-action",
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/mitigations/T1043",
                    "external_id": "T1043"
                },
                {
                    "source_name": "University of Birmingham C2",
                    "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
                    "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf"
                }
            ],
            "modified": "2019-07-24T14:17:58.966Z",
            "name": "Commonly Used Port Mitigation",
            "description": "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific protocol used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools. (Citation: University of Birmingham C2)",
            "x_mitre_deprecated": true,
            "x_mitre_version": "1.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "spec_version": "2.1",
            "x_mitre_attack_spec_version": "2.1.0"
        }
    ]
}
```

I've cut down the response for brevity in this post because it contains 50 responses per page. 

You will also see that I need to introduce some pagination logic into the script if I want to obtain all the objects. [The TAXII Client ships with a Class (`as_pages`) for TAXII 2.1 endpoints that support pagination](https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v21.html#taxii2client.v21.as_pages).

```python
## python3 get_objects_paginated.py
### import requirements https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v21.html#taxii2client.v21.Server
### https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v21.html#taxii2client.v21.as_pages
from taxii2client.v21 import as_pages, Server
import json

server = Server('http://localhost:8000/taxii2/', user='USER', password='PASS')

col = {}

for api_roots in server.api_roots:
    try:
        for collections in api_roots.collections:
            col[collections.id] = collections 
    except:
        print('')
        continue

collection3 = col['mitre_attack_enterprise']

page_no = 1
for envelope in as_pages(collection3.get_objects, per_request=50):
    print('\nPage # {}'.format(page_no))
    
    # Parse the envelope as JSON
    stix_objects = json.loads(envelope.text)

    # Pretty-print the STIX objects
    print(json.dumps(stix_objects, indent=4))

    page_no += 1
```

Of course one of the other key functions is filtering -- I don't always want all objects returned. This is very easy to do...

```python
## python3 get_objects_filtered.py
### import requirements https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v21.html#taxii2client.v21.Server
from taxii2client.v21 import Server
import json

server = Server('http://localhost:8000/taxii2/', user='USER', password='PASS')

col = {}

for api_roots in server.api_roots:
    try:
        for collections in api_roots.collections:
            col[collections.id] = collections 
    except:
        print('')
        continue

collection3 = col['mitre_attack_enterprise']

# Retrieve a specific object by ID
response = collection3.get_object(obj_id='course-of-action--7c1796c7-9fc3-4c3e-9416-527295bf5d95')

# Parse the response body as JSON
stix_object = json.loads(response.text)

# Print the STIX object
print(json.dumps(stix_object, indent=4))
```

```json
{
    "more": false,
    "objects": [
        {
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "id": "course-of-action--7c1796c7-9fc3-4c3e-9416-527295bf5d95",
            "type": "course-of-action",
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/mitigations/T1043",
                    "external_id": "T1043"
                },
                {
                    "source_name": "University of Birmingham C2",
                    "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
                    "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf"
                }
            ],
            "modified": "2019-07-24T14:17:58.966Z",
            "name": "Commonly Used Port Mitigation",
            "description": "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific protocol used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools. (Citation: University of Birmingham C2)",
            "x_mitre_deprecated": true,
            "x_mitre_version": "1.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "spec_version": "2.1",
            "x_mitre_attack_spec_version": "2.1.0"
        }
    ]
}
```

You can see `'more': False` indicating no more pages of objects. However, it is entirely possible there are more than one version of the same Object might exist.

To demonstrate this, I'll first publish an object (`attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5`) with multiple versions...

cti-taxii-client also supports the [publishing of Objects (add_objects)](https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v21.html#taxii2client.v21.Collection.add_objects). You can pass the STIX Objects using `.add_objects` in a JSON escaped STIX 2.1 Object, as follows...

```python
## python3 add_objects.py
### import requirements https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v21.html#taxii2client.v21.Collection.add_objects
from taxii2client.v21 import Server 

server = Server('http://localhost:8000/taxii2/', user='USER', password='PASS')

col = {}

for api_roots in server.api_roots:
    api_root = api_roots.collections
    try:
        for collections in api_roots.collections:
            col[collections.id] = collections 

    except:
        print('')
        continue

collection3 = col['mitre_attack_enterprise']

x = collection3.add_objects("{\"objects\":[{\"type\":\"attack-pattern\",\"spec_version\":\"2.1\",\"id\":\"attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5\",\"created_by_ref\":\"identity--d2916708-57b9-5636-8689-62f049e9f727\",\"created\":\"2020-01-01T11:21:07.478851Z\",\"modified\":\"2020-01-01T11:21:07.478851Z\",\"name\":\"Spear Phishing\",\"description\":\"Used for tutorial content\",\"object_marking_refs\":[\"marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da\"]},{\"type\":\"attack-pattern\",\"spec_version\":\"2.1\",\"id\":\"attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5\",\"created_by_ref\":\"identity--d2916708-57b9-5636-8689-62f049e9f727\",\"created\":\"2020-01-02T11:21:07.478851Z\",\"modified\":\"2020-01-02T11:21:07.478851Z\",\"name\":\"Spear Phishing Updated ONCE\",\"description\":\"Used for tutorial content\",\"object_marking_refs\":[\"marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da\"]},{\"type\":\"attack-pattern\",\"spec_version\":\"2.1\",\"id\":\"attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5\",\"created_by_ref\":\"identity--d2916708-57b9-5636-8689-62f049e9f727\",\"created\":\"2020-01-03T11:21:07.478851Z\",\"modified\":\"2020-01-03T11:21:07.478851Z\",\"name\":\"Spear Phishing Updated TWICE\",\"description\":\"Used for tutorial content\",\"object_marking_refs\":[\"marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da\"]}]}")

print('status: ', x.status)
print('id: ', x.id)
print('failure_count: ', x.failure_count)
print('pending_count: ', x.pending_count)
print('success_count: ', x.success_count)
```

Remember, you must have `can_write` permissions to the collection to add / delete objects from it using TAXII.

This script responds as follows;

```txt
status:  complete
id:  2571f72a-520a-485c-8239-c64ef24cc4c4
failure_count:  0
pending_count:  0
success_count:  3
```

Now, if I just request the object via the Attack Pattern object we'll get one result...

```python
## python3 get_objects_filtered_2.py
### import requirements https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v21.html#taxii2client.v21.Server
from taxii2client.v21 import Server
import json

server = Server('http://localhost:8000/taxii2/', user='USER', password='PASS')

col = {}

for api_roots in server.api_roots:
    try:
        for collections in api_roots.collections:
            col[collections.id] = collections 
    except:
        print('')
        continue

collection3 = col['mitre_attack_enterprise']

# Retrieve a specific object by ID
response = collection3.get_object(obj_id='attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5')

# Parse the response body as JSON
stix_object = json.loads(response.text)

# Print the STIX object
print(json.dumps(stix_object, indent=4))
```

```json
{
    "more": false,
    "objects": [
        {
            "created": "2020-01-03T11:21:07.478851Z",
            "created_by_ref": "identity--d2916708-57b9-5636-8689-62f049e9f727",
            "description": "Used for tutorial content",
            "id": "attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5",
            "modified": "2020-01-03T11:21:07.478851Z",
            "name": "Spear Phishing Updated TWICE",
            "object_marking_refs": [
                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
            ],
            "spec_version": "2.1",
            "type": "attack-pattern"
        }
    ]
}
```

By default, the latest version of the object will always be printed.

So now I need to find the object versions;

```python
## python3 get_object_versions.py
### import requirements https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v21.html#taxii2client.v21.Server

from taxii2client.v21 import Server, as_pages
import json

server = Server('http://localhost:8000/taxii2/', user='USER', password='PASS')

col = {}

try:
    for api_roots in server.api_roots:
        for collection in api_roots.collections:
            col[collection.id] = collection
except Exception as e:
    print('Error while retrieving collections:', e)
    exit()

collection_id = 'mitre_attack_enterprise'
obj_id = 'attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5'

if collection_id in col:
    collection3 = col[collection_id]

    page_no = 1
    try:
        for envelope in as_pages(collection3.object_versions, obj_id=obj_id, per_request=50):
            print(f'\nPage # {page_no}')

            # Parse the envelope as JSON
            versions = json.loads(envelope.text)

            # Pretty-print the STIX object versions
            print(json.dumps(versions, indent=4))

            page_no += 1
    except Exception as e:
        print('Error retrieving or processing object versions:', e)
else:
    print(f'Collection with ID {collection_id} not found.')
```

```json
Page # 1
{
    "more": false,
    "versions": [
        "2020-01-03T11:21:07.478851Z",
        "2020-01-02T11:21:07.478851Z",
        "2020-01-01T11:21:07.478851Z"
    ]
}
```

Now I can use multiple filters, to include version, to get a specific version of the object.

```python
## python3 get_specific_object_version.py
### import requirements https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v21.html#taxii2client.v21.Server
from taxii2client.v21 import Server
import json

server = Server('http://localhost:8000/taxii2/', user='USER', password='PASS')

col = {}

for api_roots in server.api_roots:
    api_root = api_roots.collections
    try:
        for collections in api_roots.collections:
            col[collections.id] = collections 

    except:
        print('')
        continue

collection_id = 'mitre_attack_enterprise'

def filter(object_id, object_version, collection=collection3):
    x =  collection.get_object(obj_id=object_id, modified=object_version)
    return x

get_version = filter('attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5','2020-01-01T11:21:07.478851Z' )

# Parse the response body as JSON
stix_object = json.loads(get_version.text)

# Print the STIX object
print(json.dumps(stix_object, indent=4))
```

```json
{
    "more": false,
    "objects": [
        {
            "created": "2020-01-01T11:21:07.478851Z",
            "created_by_ref": "identity--d2916708-57b9-5636-8689-62f049e9f727",
            "description": "Used for tutorial content",
            "id": "attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5",
            "modified": "2020-01-01T11:21:07.478851Z",
            "name": "Spear Phishing",
            "object_marking_refs": [
                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
            ],
            "spec_version": "2.1",
            "type": "attack-pattern"
        }
    ]
}
```

Finally, delete operations are also covered by cti-taxii-client.

```python
## python3 delete_object.py
### import requirements https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v21.html#taxii2client.v21.Server
from taxii2client.v21 import Server 

server = Server('http://localhost:8000/taxii2/', user='USER', password='PASS')

col = {}

for api_roots in server.api_roots:
    api_root = api_roots.collections
    try:
        for collections in api_roots.collections:
            col[collections.id] = collections 

    except:
        print('')
        continue

collection_id = 'mitre_attack_enterprise'

collection3.delete_object(obj_id='attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5')
print('Successfully deleted')
```

Which prints;

```
Successfully deleted
```

The delete behaviour when used like this only deletes the latest version of the object. I can see this by rerunning `get_object_versions.py`;

```json
Page # 1
{
    "more": false,
    "versions": [
        "2020-01-02T11:21:07.478851Z",
        "2020-01-01T11:21:07.478851Z"
    ]
}
```

## In summary

Hopefully some of these demo scripts have given you a brief overview of how a TAXII client works under the hood. The scripts are far from perfect, nor have I covered all its features.

As cti-taxii-client is a minimal implementation, there are some functions missing. That said, it is still a great starting point to build off or to use for testing the responses from a TAXII Server.

[CYTAXII2](https://github.com/cyware-labs/cytaxii2) is an Open Source offering from Cyware that provides developers with the support for interacting with the TAXII server using a Python library. It implements all TAXII services according to TAXII 2.X specifications.

Many commercial products come with built in TAXII Client functionality too.

Whatever TAXII Client you choose, all will work with our open-source TAXII server, [arango_taxii_server](https://github.com/muchdogesec/arango_taxii_server/).