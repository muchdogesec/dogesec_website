---
date: 2024-07-01
last_modified: 2024-07-01
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
image: /assets/images/blog/2024-07-01/header.png
featured_image: /assets/images/blog/2024-07-01/header.png
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

Install cti-taxii-client. Install Arango TAXII Server. Learn from example code about how TAXII clients work.

## Overview

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

In this post I'll create an `example_scripts` directory with the contents of these scripts shown in this post. One note, I use the `user=read_write_user` / `password=testing123`, you will need to modify these to match your ArangoDB user.

```shell
mkdir example_scripts
```

To begin with I have written a simple Python script that uses the cti-taxii-client library to query the discovery endpoint to find out what is on the server.

```python
# example_scripts/server_discovery.py
import json
import base64
from taxii2client.v21 import Server

# Function to encode user and password in base64
def encode_credentials(user, password):
    credentials = f"{user}:{password}"
    return base64.b64encode(credentials.encode()).decode()

# Base64 encoded user and password (not needed with taxii2-client)
# encoded_credentials = encode_credentials('read_write_user', 'testing123')

# URL for the TAXII 2.1 server
url = 'http://127.0.0.1:8000/api/taxii2/'

# Create a Server instance
server = Server(url, user='read_write_user', password='testing123')

# Collect server information
server_info = {
    'title': server.title,
    'description': server.description,
    'contact': server.contact,
    'custom_properties': server.custom_properties,
    'api_roots': [api.url for api in server.api_roots]
}

# Print server information in JSON format
print("Request URL:", url)
print(json.dumps(server_info, indent=4))
```

```shell
python3 example_scripts/server_discovery.py
```

Which prints;

```json
{
    "title": "Arango TAXII Server",
    "description": "https://github.com/muchdogesec/arango_taxii_server/",
    "contact": "noreply@dogesec.com",
    "api_roots": [
        "http://127.0.0.1:8000/api/taxii2/cti_database/",
        "http://127.0.0.1:8000/api/taxii2/demo_database/"
    ]
}
```

Two `api_roots` are printed (thus accessible to this user). I can now identify what Collections exist in one of the API Roots (I will use `http://127.0.0.1:8000/api/taxii2/cti_database/`).

```python
# example_scripts/get_collections.py
import json
import base64
from taxii2client.v21 import ApiRoot

# Function to encode user and password in base64
def encode_credentials(user, password):
    credentials = f"{user}:{password}"
    return base64.b64encode(credentials.encode()).decode()

# Base64 encoded user and password
encoded_credentials = encode_credentials('read_write_user', 'testing123')

# Set the API root URL
api_root_url = 'http://127.0.0.1:8000/api/taxii2/cti_database/'

# Create an ApiRoot instance with encoded credentials
api_root = ApiRoot(api_root_url, user='read_write_user', password='testing123')

# Collect and print the collection details in JSON format
collections_info = {
    'collections': []
}

for collection in api_root.collections:
    collection_info = {
        'title': collection.title,
        'description': collection.description,
        'id': collection.id,
        'custom_properties': collection.custom_properties,
        'can_read': collection.can_read,
        'can_write': collection.can_write,
        'media_types': collection.media_types,
    }
    collections_info['collections'].append(collection_info)

# Print the collections information in JSON format
print(json.dumps(collections_info, indent=4))

```

```shell
python3 example_scripts/get_collections.py
```

```json
{
    "collections": [
        {
            "id": "yara_rules",
            "title": "yara_rules",
            "description": "vertex+edge",
            "can_read": true,
            "can_write": true,
            "media_types": [
                "application/stix+json;version=2.1"
            ]
        },
        {
            "id": "mitre_attack_enterprise",
            "title": "mitre_attack_enterprise",
            "description": "vertex+edge",
            "can_read": true,
            "can_write": true,
            "media_types": [
                "application/stix+json;version=2.1"
            ]
        },
        {
            "id": "mitre_attack_mobile",
            "title": "mitre_attack_mobile",
            "description": "vertex+edge",
            "can_read": true,
            "can_write": true,
            "media_types": [
                "application/stix+json;version=2.1"
            ]
        },
        {
            "id": "mitre_attack_ics",
            "title": "mitre_attack_ics",
            "description": "vertex+edge",
            "can_read": true,
            "can_write": true,
            "media_types": [
                "application/stix+json;version=2.1"
            ]
        }
```

Now I can start to discover the Objects held by each of these Collections. I will use `mitre_attack_enterprise` to demonstrate.

```python
# example_scripts/get_objects.py
import json
from taxii2client.v21 import ApiRoot

# Create an ApiRoot instance with correct URL and credentials
api_root_url = 'http://127.0.0.1:8000/api/taxii2/cti_database/'
api_root = ApiRoot(api_root_url, user='read_write_user', password='testing123')

# Dictionary to hold collections
collections_dict = {}

# Iterate over collections in the specified API root
try:
    for collection in api_root.collections:
        collections_dict[collection.id] = collection
except Exception as e:
    print(f"Error processing API root {api_root.url}: {e}")

# Get the specific collection by ID
collection_id = 'mitre_attack_enterprise'
collection = collections_dict.get(collection_id)

if collection:
    # Retrieve objects from the collection
    stix_objects = collection.get_objects()

    # Print the STIX objects in JSON format
    print(json.dumps(stix_objects, indent=4))
else:
    print(f"Collection with ID {collection_id} not found.")

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
```

I've cut down the response for brevity in this post because it contains 50 responses per page. 

You will also see that I need to introduce some pagination logic into the script if I want to obtain all the objects. [The TAXII Client ships with a Class (`as_pages`) for TAXII 2.1 endpoints that support pagination](https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v21.html#taxii2client.v21.as_pages).

In this script I also use the `limit` URL parameter (set to `1`) to only return one result per page, to show what pagination looks like. The following script prints the response from the first two pages.

```python
# example_scripts/get_objects_paginated.py
from taxii2client.v21 import as_pages, Server
import json

# Create a Server instance with correct URL and credentials
server = Server('http://127.0.0.1:8000/api/taxii2/', user='read_write_user', password='testing123')

# Dictionary to hold collections
collections_dict = {}

# Iterate over API roots and collections
for api_root in server.api_roots:
    try:
        for collection in api_root.collections:
            collections_dict[collection.id] = collection
    except Exception as e:
        print(f"Error processing API root {api_root.url}: {e}")
        continue

# Get the specific collection by ID
collection_id = 'mitre_attack_enterprise'
collection = collections_dict.get(collection_id)

if collection:
    page_no = 1
    for envelope in as_pages(collection.get_objects, per_request=1):  # Limit set to 1
        print(f'\nPage # {page_no}')

        # Parse the envelope as JSON
        stix_objects = envelope

        # Pretty-print the STIX objects
        print(json.dumps(stix_objects, indent=4))

        if page_no >= 2:  # Show only the first 2 pages
            break

        page_no += 1
else:
    print(f"Collection with ID {collection_id} not found.")

```

```shell
python3 example_scripts/get_objects_paginated.py
```

```json
Page # 1
{
    "more": true,
    "next": "46984006_undef+0.22373385850816663",
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
        }
    ]
}

Page # 2
{
    "more": true,
    "next": "46984006_undef+0.19274094492717542",
    "objects": [
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
        }
    ]
}
```

You can see the more pages exist each time because `more` is set to `true`. The next page id, which the TAXII client (`as_pages`) uses to move to the next page, is defined in the `next` property.

Of course one of the other key functions is filtering -- I don't always want all objects returned. This script filters by the `match[id]` URL parameter for the object `course-of-action--7c1796c7-9fc3-4c3e-9416-527295bf5d95`:

```python
# example_scripts/get_objects_filtered.py
from taxii2client.v21 import Server
import json

# Create a Server instance with correct URL and credentials
server = Server('http://127.0.0.1:8000/api/taxii2/', user='read_write_user', password='testing123')

# Dictionary to hold collections
collections_dict = {}

# Iterate over API roots and collections
for api_root in server.api_roots:
    try:
        for collection in api_root.collections:
            collections_dict[collection.id] = collection
    except Exception as e:
        print(f"Error processing API root {api_root.url}: {e}")
        continue

# Get the specific collection by ID
collection_id = 'mitre_attack_enterprise'
collection = collections_dict.get(collection_id)

if collection:
    try:
        # Retrieve a specific object by ID
        stix_object = collection.get_object(obj_id='course-of-action--7c1796c7-9fc3-4c3e-9416-527295bf5d95')

        # Print the STIX object in JSON format
        print(json.dumps(stix_object, indent=4))
    except Exception as e:
        print(f"Error retrieving object from collection: {e}")
else:
    print(f"Collection with ID {collection_id} not found.")
```

```shell
python3 example_scripts/get_objects_filtered.py
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

You can see `'more': False` indicating no more pages of objects.

By default, the latest version of the object will always be printed unless you ask for specific versions. So lets write a script that checks for versions of this object.

```python
# example_scripts/get_object_versions.py
from taxii2client.v21 import Server, as_pages
import json

# Create a Server instance with correct URL and credentials
server = Server('http://127.0.0.1:8000/api/taxii2/', user='read_write_user', password='testing123')

# Dictionary to hold collections
collections_dict = {}

# Iterate over API roots and collections
try:
    for api_root in server.api_roots:
        for collection in api_root.collections:
            collections_dict[collection.id] = collection
except Exception as e:
    print(f"Error while retrieving collections: {e}")
    exit()

# Define the collection ID and object ID
collection_id = 'mitre_attack_enterprise'
obj_id = 'course-of-action--7c1796c7-9fc3-4c3e-9416-527295bf5d95'

# Retrieve the specific collection by ID
collection = collections_dict.get(collection_id)

if collection:
    page_no = 1
    try:
        for envelope in as_pages(collection.object_versions, obj_id=obj_id, per_request=50):
            print(f'\nPage # {page_no}')

            # Parse the envelope as JSON
            versions = envelope  # `envelope` is already in JSON format

            # Pretty-print the STIX object versions
            print(json.dumps(versions, indent=4))

            page_no += 1
    except Exception as e:
        print(f"Error retrieving or processing object versions: {e}")
else:
    print(f"Collection with ID {collection_id} not found.")

```

```shell
python3 example_scripts/get_object_version.py
```

```json
{
    "more": false,
    "next": null,
    "versions": [
        "2018-01-17T12:56:55.080Z",
        "2018-04-18T17:59:24.739Z",
        "2018-10-17T00:14:20.652Z",
        "2019-07-24T14:17:58.966Z"
    ]
}
```

The version returned earlier was the latest `2019-07-24T14:17:58.966Z`. Lets instead request the earliest `2018-01-17T12:56:55.080Z`.

```python
# example_scripts/get_object_version_oldest.py
from taxii2client.v21 import Server
import json

# Create a Server instance with correct URL and credentials
server = Server('http://127.0.0.1:8000/api/taxii2/', user='read_write_user', password='testing123')

# Dictionary to hold collections
collections_dict = {}

# Iterate over API roots and collections
for api_root in server.api_roots:
    try:
        for collection in api_root.collections:
            collections_dict[collection.id] = collection
    except Exception as e:
        print(f"Error processing API root {api_root.url}: {e}")
        continue

# Get the specific collection by ID
collection_id = 'mitre_attack_enterprise'
collection = collections_dict.get(collection_id)

if collection:
    try:
        # Retrieve a specific version of an object by ID and version
        object_id = 'course-of-action--7c1796c7-9fc3-4c3e-9416-527295bf5d95'
        version = '2018-01-17T12:56:55.080Z'
        stix_object = collection.get_object(obj_id=object_id, version=version)

        # Print the STIX object in JSON format
        print(json.dumps(stix_object, indent=4))
    except Exception as e:
        print(f"Error retrieving object from collection: {e}")
else:
    print(f"Collection with ID {collection_id} not found.")
```


```json
{
    "more": false,
    "next": null,
    "objects": [
        {
            "created": "2018-01-17T12:56:55.080Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "description": "Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific protocol used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools. (Citation: University of Birmingham C2)",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/wiki/Technique/T1043",
                    "external_id": "T1043"
                },
                {
                    "source_name": "University of Birmingham C2",
                    "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
                    "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf"
                }
            ],
            "id": "course-of-action--7c1796c7-9fc3-4c3e-9416-527295bf5d95",
            "modified": "2018-01-17T12:56:55.080Z",
            "name": "Commonly Used Port Mitigation",
            "spec_version": "2.1",
            "type": "course-of-action",
            "x_mitre_attack_spec_version": "2.1.0",
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_version": "1.0"
        }
    ]
}
```

cti-taxii-client also supports the [publishing of Objects (add_objects)](https://taxii2client.readthedocs.io/en/latest/api/taxii2client.v21.html#taxii2client.v21.Collection.add_objects). You can pass the STIX Objects using `.add_objects`.

I use a new API root and collection for this request. You'll also see I post the same object (by `id`) three times. This demonstrates how versioning works as three versions of this object will be created as the `modified` time increases between the objects.

```python
# example_scripts/add_objects.py
from taxii2client.v21 import Server
import json
import requests
from requests.auth import HTTPBasicAuth

# Create a Server instance with correct URL and credentials
server = Server('http://127.0.0.1:8000/api/taxii2/', user='read_write_user', password='testing123')

# Dictionary to hold collections
collections_dict = {}

# Iterate over API roots and collections
for api_root in server.api_roots:
    try:
        for collection in api_root.collections:
            collections_dict[collection.id] = collection
    except Exception as e:
        print(f"Error processing API root {api_root.url}: {e}")
        continue

# Get the specific collection by ID
collection_id = 'blog'
collection = collections_dict.get(collection_id)

if collection:
    try:
        # JSON object to be added to the collection
        objects_to_add = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": "attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5",
                    "created_by_ref": "identity--d2916708-57b9-5636-8689-62f049e9f727",
                    "created": "2020-01-01T11:21:07.478851Z",
                    "modified": "2020-01-01T11:21:07.478851Z",
                    "name": "Spear Phishing",
                    "description": "Used for tutorial content",
                    "object_marking_refs": ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"]
                },
                {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": "attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5",
                    "created_by_ref": "identity--d2916708-57b9-5636-8689-62f049e9f727",
                    "created": "2020-01-02T11:21:07.478851Z",
                    "modified": "2020-01-02T11:21:07.478851Z",
                    "name": "Spear Phishing Updated ONCE",
                    "description": "Used for tutorial content",
                    "object_marking_refs": ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"]
                },
                {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": "attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5",
                    "created_by_ref": "identity--d2916708-57b9-5636-8689-62f049e9f727",
                    "created": "2020-01-03T11:21:07.478851Z",
                    "modified": "2020-01-03T11:21:07.478851Z",
                    "name": "Spear Phishing Updated TWICE",
                    "description": "Used for tutorial content",
                    "object_marking_refs": ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"]
                }
            ]
        }

        # Prepare the headers
        headers = {
            'Content-Type': 'application/taxii+json;version=2.1',
            'Accept': 'application/taxii+json;version=2.1'
        }

        # Print the request URL and headers
        request_url = collection.url + 'objects/'
        print(f"Request URL: {request_url}")
        print("Request Headers:", json.dumps(headers, indent=4))

        # Make the request using requests library
        response = requests.post(
            request_url,
            headers=headers,
            auth=HTTPBasicAuth('read_write_user', 'testing123'),
            json=objects_to_add
        )

        # Print the response in JSON format
        print(json.dumps(response.json(), indent=4))
    except Exception as e:
        print(f"Error adding objects to the collection: {e}")
else:
    print(f"Collection with ID {collection_id} not found.")
```

Remember, you must have `can_write` permissions to the collection to add / delete objects from it using TAXII.

This script responds as follows;

```json
{
  "id": "da62e209-cf48-40f3-a687-b89b0cde5546",
  "status": "pending",
  "total_count": 3,
  "success_count": 0,
  "successes": [],
  "failure_count": 0,
  "failures": [],
  "pending_count": 3,
  "pendings": [
    {
      "message": null,
      "version": "2020-01-01T11:21:07.478Z",
      "id": "attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5"
    },
    {
      "message": null,
      "version": "2020-01-02T11:21:07.478Z",
      "id": "attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5"
    },
    {
      "message": null,
      "version": "2020-01-03T11:21:07.478Z",
      "id": "attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5"
    }
  ],
  "request_timestamp": "2024-06-18T09:48:30.879800Z"
}
```

If I use the `get_object_versions.py` script but use the id `attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5` (in place of `course-of-action--7c1796c7-9fc3-4c3e-9416-527295bf5d95`) I get the following;


```json
{
    "more": false,
    "next": null,
    "versions": [
        "2020-01-01T11:21:07.478Z",
        "2020-01-02T11:21:07.478Z",
        "2020-01-03T11:21:07.478Z"
    ]
}
```

Finally, delete operations are also covered by cti-taxii-client. Here I delete the object I just created, and all versions of it (`attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5`);

```python
# example_scripts/delete_object.py
from taxii2client.v21 import Server, Collection
import requests
from requests.auth import HTTPBasicAuth

# Create a Server instance with correct URL and credentials
server = Server('http://127.0.0.1:8000/api/taxii2/', user='read_write_user', password='testing123')

# Dictionary to hold collections
collections_dict = {}

# Iterate over API roots and collections
for api_root in server.api_roots:
    try:
        for collection in api_root.collections:
            collections_dict[collection.id] = collection
    except Exception as e:
        print(f"Error processing API root {api_root.url}: {e}")
        continue

# Get the specific collection by ID
collection_id = 'blog'
collection = collections_dict.get(collection_id)

if collection:
    try:
        # Prepare the headers
        headers = {
            'Content-Type': 'application/taxii+json;version=2.1',
            'Accept': 'application/taxii+json;version=2.1'
        }

        # Define the object ID to be deleted
        object_id = 'attack-pattern--6b948b5a-3c09-5365-b48a-da95c3964cb5'

        # Print the request URL and headers
        request_url = f"{collection.url}objects/{object_id}/"
        print(f"Request URL: {request_url}")
        print("Request Headers:", json.dumps(headers, indent=4))

        # Make the DELETE request using requests library
        response = requests.delete(
            request_url,
            headers=headers,
            auth=HTTPBasicAuth('read_write_user', 'testing123')
        )

        # Check for successful deletion
        if response.status_code == 200:
            print('Successfully deleted')
        else:
            print(f"Failed to delete. Status code: {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"Error deleting object from the collection: {e}")
else:
    print(f"Collection with ID {collection_id} not found.")
```

Which prints;

```
Successfully deleted
```

## In summary

Hopefully some of these demo scripts have given you a brief overview of how a TAXII client works under the hood. The scripts are far from perfect, nor have I covered all its features.

As cti-taxii-client is a minimal implementation, there are some functions missing. That said, it is still a great starting point to build off or to use for testing the responses from a TAXII Server.

[CYTAXII2](https://github.com/cyware-labs/cytaxii2) is an Open Source offering from Cyware that provides developers with the support for interacting with the TAXII server using a Python library. It implements all TAXII services according to TAXII 2.X specifications.

Many commercial products come with built in TAXII Client functionality too.

Whatever TAXII Client you choose, all will work with our open-source TAXII server, [arango_taxii_server](https://github.com/muchdogesec/arango_taxii_server/).