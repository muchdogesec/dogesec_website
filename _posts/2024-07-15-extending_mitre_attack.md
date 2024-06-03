---
date: 2024-07-15
title: "Extending MITRE ATT&CK"
description: "Add new objects, edit existing ones or create an entierly new framework. Anything is possible."
categories:
  - DIY
  - TUTORIAL
tags: [
    MITRE,
    ATT&CK,
    STIX
]
products:
    - 
author_staff_member: david-greenwood
image: /assets/images/blog/2024-07-15/header.jpeg
featured_image: /assets/images/blog/2024-07-15/header.jpeg
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

Some time ago, [MITRE Engenuity announced the ATT&CK Workbench](https://medium.com/mitre-engenuity/).

The workbench can perform a lot of functions, though arguably its most useful is the ability to create new objects or extend existing objects with new content. Matrices, techniques, tactics, mitigations, groups, and software can all be created and edited.

Think of it as an extension of core ATT&CK.

## Overview

Using the ATT&CK Workbench you can extend the knowledge base according to your own needs, or even an entirely new dataset aligned with ATT&CK terminology so that it's usable with other ATT&CK tools.

For example, [as I described in another blog post](/blog/getting_started_mitre_attack_navigator), we built DISARM (a disinformation framework) STIX objects in line with the MITRE ATT&CK object structure so that it could be used with ATT&CK Navigator.

By sticking to the ATT&CK format (built on STIX 2.1 Objects) for customisation it also facilitates a greater level of collaboration within the community.

In this post I will walk-through some use-cases for creating objects using the ATT&CK Workbench.

Lets first start by installing it...

## Install and run

I use Docker on my local machine, so will proceed with the [Docker installation steps](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend#installing-using-docker). [You can also install manually from source by following the steps linked here](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend#manual-installation).

```shell
mkdir attack-workbench
cd attack-workbench
git clone https://github.com/center-for-threat-informed-defense/attack-workbench-frontend.git
git clone https://github.com/center-for-threat-informed-defense/attack-workbench-collection-manager.git
git clone https://github.com/center-for-threat-informed-defense/attack-workbench-rest-api.git
cd attack-workbench-frontend
docker-compose up
```

Now open up a browser and navigate to `http://localhost`.

## Setting the organisation

On the first run you will be prompted to create an Organization Identity;

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-doge-demo-identity.png" alt="ATT&CK Workbench Identity" title="ATT&CK Workbench Identity" />

Your organization identity is used for attribution of edits you make to objects in the knowledge base. Essentially what this does is create a STIX 2.1 Identity Object with the organization details you enter, which is then referenced in STIX Objects you create or update.

Objects you create will be marked with your organization as the creator, new major versions of existing objects will likewise be marked with your organization as the modifier (this is especially useful when multiple groups are working on the knowledgebase)

## Importing MITRE's version of ATT&CK

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-techniques.png" alt="ATT&CK Workbench Techniques" title="ATT&CK Workbench Techniques" />

Out-of-the-box, the ATT&CK Workbench will contain no Objects. Clicking any of the options in the Navigation bar will show no data.

The first thing you will probably want to do is add an existing version of ATT&CK. 

You can also import a custom ATT&CK dataset created in another ATT&CK workbench, perhaps by another organisation you collaborate with.

For this tutorial I will start by importing MITRE's core ATT&CK data as a Collection, although the process is the same wherever you gather your ATT&CK data from.

A Collection is a set of related ATT&CK Objects; Collections may be used represent specific releases of a dataset such as a specific version of ATT&CK. Collections can be created by anyone, not just MITRE.

Data providers (like MITRE) can publish their Collections using a Collection Index wrapper (note this is not STIX object). A Collection Index contains a list of collections represented as custom STIX Objects `x-mitre-collection`.

For example this Collection Index contains two collections (MITRE ATT&CK Enterprise version 15.1 and MITRE ATT&CK Enterprise version 15.0);

```json
{
    "id": "10296991-439b-4202-90a3-e38812613ad4",
    "name": "MITRE ATT&CK",
    "description": "MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.",
    "created": "2018-01-17T12:56:55.080000+00:00",
    "modified": "2022-05-24T14:00:00.188000+00:00",
    "collections": [
        {
            "id": "x-mitre-collection--402e24b4-436e-4936-b19b-2038648f489",
            "created": "2018-01-17T12:56:55.080Z",
            "versions": [
                {
                    "version": "15.1",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-15.1.json",
                    "modified": "2024-05-02T14:00:00.188Z"
                },
                {
                    "version": "15.0",
                    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-15.0.json",
                    "modified": "2024-04-23T14:00:00.188Z"
                }
            ]
        }
    ]
}
```

Each domain of MITRE's official ATT&CK (Enterprise, Mobile and ICS) is represented as a `x-mitre-collection` Object with the individual releases as a series of STIX 2.1 Bundles inside it.

MITRE publish their ATT&CK versions as Collection Index via the ATT&CK STIX data GitHub repository. [Here is the current Collection Index listing all historic ATT&CK versions](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json).

The ATT&CK Workbench can be configured to subscribe to Collection Indexes so that it automatically receives updates when they are available, or to allow the user to easily browse the new Collections added to the index.

I will go ahead and import the core MITRE ATT&CK Collection Bundle.

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-import.png" alt="ATT&CK Workbench Import" title="ATT&CK Workbench Import" />

To do this go to `Collections` > `Imported Collections` > `Add a Collection Index` and enter the Collection Bundle URL: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json`.

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-imported.png" alt="ATT&CK Workbench Imported" title="ATT&CK Workbench Imported" />

Clicking preview will show you all the Collections in the Collection Bundle. In the case of MITRE's version of ATT&CK that is Enterprise, Mobile and ICS (and each published version).

All that is left to do is to click `Add`.

Once the Collection Index is added I then have choose the Domain and version to import. To do this go to `Collections` > `MITRE ATT&CK`. I can then choose the Collection (e.g. Enterprise) and the version I want.

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-collections.png" alt="ATT&CK Workbench Collections" title="ATT&CK Workbench Collections" />

To import, click the download icon.

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-import-collection.png" alt="ATT&CK Workbench Import Collection" title="ATT&CK Workbench Import Collection" />

In some cases, you might only want to sync certain Objects from the core ATT&CK repository, for example, only downloading Group Objects.

For this exercise I will download the entire Enterprise ATT&CK version 11 Collection (17,671 Objects in total -- most of which are Relationship Objects).

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-imported-techniques.png" alt="ATT&CK Workbench Imported Workbench Technique" title="ATT&CK Workbench Imported Workbench Technique" />

Once the import completes, you will now see the MITRE ATT&CK core data populated for each Object type as you browse around the Workbench.

## Creating new Objects

You might be tempted to create your own Matrix and adding existing (or custom) Tactics and Techniques to it.

You probably do not want to do that. Here's why...

In most cases, you will be wanting to extend the knowledge in the core ATT&CK Domains with new Data Sources, Software, Mitigations and Groups linked to Techniques already captured in the three default Matrices.

Going back to the Unit 42 report used previously in this tutorial; [Popping Eagle: How We Leveraged Global Analytics to Discover a Sophisticated Threat Actor](https://unit42.paloaltonetworks.com/popping-eagle-malware/).

It reports:

> It also includes a second stage malicious tool written in Go dubbed "Going Eagle."

> This attacker-controlled IP used the first-stage malware to load a second stage DLL that we call “Going Eagle.”

> This tool was created for one task only – to create a reverse SOCKS proxy to get the attacker control over the machine (as described in the “Lateral Movement” section later on).

"Going Eagle" appears to be a new Tool specific to this campaign, [and is not captured in MITRE's own version of ATT&CK](https://attack.mitre.org/software).

It is the perfect opportunity for us to create a custom ATT&CK Software Object.

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-create-software.png" alt="ATT&CK Workbench Create Software" title="ATT&CK Workbench Create Software" />

When creating a new tool, you will be prompted to select either Software (Malware) or Software (Tool).

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-malware-or-tool.png" alt="ATT&CK Workbench Malware or Tool" title="ATT&CK Workbench Malware or Tool" />

The descriptions shown are not particularly clear.

I find the specification descriptions of the STIX 2.1 Domain Objects easier to determine the distinction, versus the distinctions shown in the description above.

> Tools are legitimate software that can be used by threat actors to perform attacks. Unlike malware, these tools or software packages are often found on a system and have legitimate purposes for power users, system administrators, network administrators, or even normal users.

Source: [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_z4voa9ndw8v)

> Malware is a type of TTP that represents malicious code. It generally refers to a program that is inserted into a system, usually covertly.

Source: [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_s5l7katgbp09)

Using these characterisations and after studying the report, I would classify Going Eagle as a Malware.

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-adding-going-eagle-malware.png" alt="ATT&CK Workbench Adding Malware" title="ATT&CK Workbench Adding Malware" />

I can now fill in the required and optional fields for the object:

* type: Software (Malware)
    * STIX Property: `type` 
    * Note: already set as a result of creation
* name: name of the Object
    * STIX Property: `name`
* ID
    * STIX Property: `external_references.external_id`
    * Note: must follow ATT&CK Object ID structure (must start with `S`)
* version
    * STIX Property: `x_mitre_version`
* platforms
    * STIX Property: `x_mitre_platforms`
* contributors
    * STIX Property: `x_mitre_contributors`
    * Note: A list of strings detailing contributors, e.g. David G (is not a reference to an Identity Object)
* associated software
    * STIX Property: `x_mitre_aliases` (software name), `external_references.source_name` (software name) and `external_references.description` (software description)
* description
    * STIX Property: `description`
* domains
    * STIX Property: `x_mitre_domains`

Here is the STIX Malware SDO generated by the Workbench;

```json
{
    "labels": [],
    "x_mitre_platforms": [
        "Windows"
    ],
    "x_mitre_domains": [
        "enterprise-attack"
    ],
    "x_mitre_contributors": [
        "david",
        "greenwood"
    ],
    "x_mitre_aliases": [
        "my software"
    ],
    "object_marking_refs": [],
    "type": "malware",
    "id": "malware--ee25ab98-d40c-46c1-8fbe-eed63ca48f7b",
    "created": "2022-02-11T08:53:40.731Z",
    "modified": "2022-02-28T18:52:19.031Z",
    "x_mitre_version": "0.1",
    "external_references": [
        {
            "source_name": "mitre-attack",
            "external_id": "S9001",
            "url": "https://attack.mitre.org/software/S9001"
        },
        {
            "source_name": "my software",
            "description": "just some software"
        }
    ],
    "x_mitre_deprecated": false,
    "revoked": false,
    "description": "* Original package name Eagle2.5-Client-Dll (outlined in red in Figure 6).\n* Original function names (like main.StartEagle).\n* Packages from Go standard and extended library (like bufio, log, x/net).\n* Packages from other resources like GitHub repositories (outlined in yellow and green in Figure 6).",
    "spec_version": "2.1",
    "created_by_ref": "identity--d1dd6b52-23b7-490c-b54f-810fb1136752",
    "name": "Going Eagle",
    "is_family": true,
    "x_mitre_attack_spec_version": "2.1.0",
    "x_mitre_modified_by_ref": "identity--d1dd6b52-23b7-490c-b54f-810fb1136752"
}
```

Once you have added the Object information, it is now time to link it to other Objects to ensure it shows up in the right places.

For example, I know from the Popping Eagle report some of the MITRE ATT&CK Techniques the Malware leverages. 

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-popping-eagle-technique.png" alt="ATT&CK Workbench Popping Eagle Technique" title="ATT&CK Workbench Popping Eagle Technique" />

When editing the Software Object, after it has been created, I can create the supported Relationships for the STIX 2.1 Object type, in this case, Malware.

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-create-relationship.png" alt="ATT&CK Workbench Join Objects with Relationship" title="ATT&CK Workbench Join Objects with Relationship" />

Here is the STIX SRO generated by the Workbench; 

```json
{
    "x_mitre_domains": [],
    "object_marking_refs": [],
    "type": "relationship",
    "id": "relationship--25624dc3-abfc-4186-b242-16d37742bf68",
    "created": "2022-06-28T13:09:39.457Z",
    "modified": "2022-06-28T13:09:39.457Z",
    "x_mitre_version": "0.1",
    "external_references": [],
    "x_mitre_deprecated": false,
    "revoked": false,
    "description": "Here's how Going Eagle uses it",
    "spec_version": "2.1",
    "relationship_type": "uses",
    "source_ref": "malware--ee25ab98-d40c-46c1-8fbe-eed63ca48f7b",
    "target_ref": "attack-pattern--707399d6-ab3e-4963-9315-d9d3818cd6a0",
    "x_mitre_attack_spec_version": "2.1.0",
    "created_by_ref": "identity--d1dd6b52-23b7-490c-b54f-810fb1136752",
    "x_mitre_modified_by_ref": "identity--d1dd6b52-23b7-490c-b54f-810fb1136752"
}
```

Now that you can create and link Objects it is always a good ideas to have some sort of review process to validate them.

All Objects move through a workflow starting life as "work in progress" in the Workbench.

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-object-status.png" alt="ATT&CK Workbench Object status" title="ATT&CK Workbench Object status" />

You can change the state of the workflow too "awaiting review", or "reviewed". Objects can also be revoked or deprecated.

## Sharing and Collaborating with Workbench

When creating or updating ATT&CK Objects, whether for internal or external sharing and collaboration, you will eventually get to a point where you need to share and disseminate your work.

There are a few ways in which this can be done, depending on your objectives. I will show you them all and let you decide that for yourself.

### Custom Collections

As you have already seen it is possible to import Collections to Workbench.

It is also possible to create your own that can be used to share and collaborate from.

Here I create a new Collection by navigating to; Collections > My Collections > Create New Collection;

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-create-collection.png" alt="ATT&CK Workbench custom collection" title="ATT&CK Workbench custom collection" />

Inside this new Collection I will add the one Object I created earlier, the Software Object;

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-add-object-to-collection.png" alt="ATT&CK Workbench add object to custom collection" title="ATT&CK Workbench add object to custom collection" />

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-collection-save.png" alt="ATT&CK Workbench add object to custom collection" title="ATT&CK Workbench add object to custom collection" />

Once it is successfully created, the Workbench will show the new Collection (and the API endpoint to grab the STIX 2.1 Bundle for the Collection from).

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-my-first-collection.png" alt="ATT&CK Workbench custom collection" title="ATT&CK Workbench custom collection" />

To share this with the community (and offer the opportunity for others to submit updates and changes), I can use accessible place on the internet for others to grab it. 

In order to make the Collection importable to another Workbench, you also need to create a Collection Index, pointing to the STIX 2.1 Bundle .json, and again store it somewhere accessible to downstream workbenches.

Now all that is left to do is share my Collection Index URL (the GitHub link) so that others can import and work on it.

### The Workbench API

The Workbench ships with an API that covers all the functions to work with data; view (GET), create (POST), update (PUT), and delete (DELETE actions).

This is the option with most functionality with regards to integrations.

You can access the docs when the Workbench is running at; `localhost/api-docs/`.

<img class="img-fluid" src="/assets/images/blog/2024-07-15/attack-workbench-api.png" alt="ATT&CK Workbench API" title="ATT&CK Workbench API" />

I can use the `GET /api/software` Endpoint to retrieve the Software Object (Tool) I created, Going Eagle, using the `search` Parameter;

```shell
curl -X GET "http://localhost/api/software?search=Going%20Eagle"
```

```json
[
    {
        "_id": "62bb4de385026a00132c0772",
        "stix": {
            "labels": [],
            "x_mitre_platforms": [
                "Windows"
            ],
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_contributors": [
                "david",
                "greenwood"
            ],
            "x_mitre_aliases": [
                "my software"
            ],
            "object_marking_refs": [],
            "type": "malware",
            "id": "malware--ee25ab98-d40c-46c1-8fbe-eed63ca48f7b",
            "created": "2022-06-11T08:53:40.731Z",
            "modified": "2022-06-28T18:52:19.031Z",
            "x_mitre_version": "0.1",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "S9001",
                    "url": "https://attack.mitre.org/software/S9001"
                },
                {
                    "source_name": "my software",
                    "description": "just some software"
                }
            ],
            "x_mitre_deprecated": false,
            "revoked": false,
            "description": "* Original package name Eagle2.5-Client-Dll (outlined in red in Figure 6).\n* Original function names (like main.StartEagle).\n* Packages from Go standard and extended library (like bufio, log, x/net).\n* Packages from other resources like GitHub repositories (outlined in yellow and green in Figure 6).",
            "spec_version": "2.1",
            "created_by_ref": "identity--d1dd6b52-23b7-490c-b54f-810fb1136752",
            "name": "Going Eagle",
            "is_family": true,
            "x_mitre_attack_spec_version": "2.1.0",
            "x_mitre_modified_by_ref": "identity--d1dd6b52-23b7-490c-b54f-810fb1136752"
        },
        "workspace": {
            "workflow": {
                "state": "reviewed"
            },
            "collections": [],
            "attack_id": "S9001"
        },
        "__t": "Software",
        "__v": 0,
        "created_by_identity": {
            "_id": "62a43d112c4a830013645834",
            "stix": {
                "roles": [],
                "sectors": [],
                "object_marking_refs": [],
                "type": "identity",
                "id": "identity--d1dd6b52-23b7-490c-b54f-810fb1136752",
                "created": "2022-06-10T19:50:07.959Z",
                "modified": "2022-06-11T06:58:25.072Z",
                "x_mitre_version": "0.1",
                "external_references": [],
                "x_mitre_deprecated": false,
                "revoked": false,
                "description": "We build powerful threat intelligence tools",
                "spec_version": "2.1",
                "name": "DOGESEC DEMOS",
                "identity_class": "organization",
                "x_mitre_attack_spec_version": "2.1.0"
            },
            "workspace": {
                "workflow": {
                    "state": "awaiting-review"
                },
                "collections": []
            },
            "__t": "IdentityModel",
            "__v": 0
        },
        "modified_by_identity": {
            "_id": "62a43d112c4a830013645834",
            "stix": {
                "roles": [],
                "sectors": [],
                "object_marking_refs": [],
                "type": "identity",
                "id": "identity--d1dd6b52-23b7-490c-b54f-810fb1136752",
                "created": "2022-06-10T19:50:07.959Z",
                "modified": "2022-06-11T06:58:25.072Z",
                "x_mitre_version": "0.1",
                "external_references": [],
                "x_mitre_deprecated": false,
                "revoked": false,
                "description": "We build powerful threat intelligence tools",
                "spec_version": "2.1",
                "name": "DOGESEC DEMOS",
                "identity_class": "organization",
                "x_mitre_attack_spec_version": "2.1.0"
            },
            "workspace": {
                "workflow": {
                    "state": "awaiting-review"
                },
                "collections": []
            },
            "__t": "IdentityModel",
            "__v": 0
        }
    }
]
```

The response is returned in JSON structured into various sections;

* `stix`: contains the full STIX 2.1 Object for the Software (STIX `malware` Object).
* `workspace`: this contains Workbench information, including workflow status
* `created_by_identity`: contains a nested `stix` Identity Object (for creator)
* `modified_by_identity`: in case Objects are modified by another user (and thus new major STIX version created) a nested `stix` object which contains the STIX Identity Object of editor

I can also GET the Relationship I created, using the `sourceRef` parameter now that I know the STIX `id` of the `malware` Object.

```shell
curl -X GET "http://localhost/api/relationships?sourceRef=malware--ee25ab98-d40c-46c1-8fbe-eed63ca48f7b"
```

```json
[
    {
        "_id": "62bafd93866b00001a4d9aff",
        "stix": {
            "x_mitre_domains": [],
            "object_marking_refs": [],
            "type": "relationship",
            "id": "relationship--25624dc3-abfc-4186-b242-16d37742bf68",
            "created": "2022-06-28T13:09:39.457Z",
            "modified": "2022-06-28T13:09:39.457Z",
            "x_mitre_version": "0.1",
            "external_references": [],
            "x_mitre_deprecated": false,
            "revoked": false,
            "description": "Here's how Going Eagle uses it",
            "spec_version": "2.1",
            "relationship_type": "uses",
            "source_ref": "malware--ee25ab98-d40c-46c1-8fbe-eed63ca48f7b",
            "target_ref": "attack-pattern--707399d6-ab3e-4963-9315-d9d3818cd6a0",
            "x_mitre_attack_spec_version": "2.1.0",
            "created_by_ref": "identity--d1dd6b52-23b7-490c-b54f-810fb1136752",
            "x_mitre_modified_by_ref": "identity--d1dd6b52-23b7-490c-b54f-810fb1136752"
        },
        "workspace": {
            "workflow": {
                "state": "work-in-progress"
            },
            "collections": []
        },
        "__t": "RelationshipModel",
        "__v": 0,
        "source_object": {
            "_id": "62bb4de385026a00132c0772",
            "stix": {
                "labels": [],
                "x_mitre_platforms": [
                    "Windows"
                ],
                "x_mitre_domains": [
                    "enterprise-attack"
                ],
                "x_mitre_contributors": [
                    "david",
                    "greenwood"
                ],
                "x_mitre_aliases": [
                    "my software"
                ],
                "object_marking_refs": [],
                "type": "malware",
                "id": "malware--ee25ab98-d40c-46c1-8fbe-eed63ca48f7b",
                "created": "2022-06-11T08:53:40.731Z",
                "modified": "2022-06-28T18:52:19.031Z",
                "x_mitre_version": "0.1",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "S9001",
                        "url": "https://attack.mitre.org/software/S9001"
                    },
                    {
                        "source_name": "my software",
                        "description": "just some software"
                    }
                ],
                "x_mitre_deprecated": false,
                "revoked": false,
                "description": "* Original package name Eagle2.5-Client-Dll (outlined in red in Figure 6).\n* Original function names (like main.StartEagle).\n* Packages from Go standard and extended library (like bufio, log, x/net).\n* Packages from other resources like GitHub repositories (outlined in yellow and green in Figure 6).",
                "spec_version": "2.1",
                "created_by_ref": "identity--d1dd6b52-23b7-490c-b54f-810fb1136752",
                "name": "Going Eagle",
                "is_family": true,
                "x_mitre_attack_spec_version": "2.1.0",
                "x_mitre_modified_by_ref": "identity--d1dd6b52-23b7-490c-b54f-810fb1136752"
            },
            "workspace": {
                "workflow": {
                    "state": "reviewed"
                },
                "collections": [],
                "attack_id": "S9001"
            },
            "__t": "Software",
            "__v": 0
        },
        "target_object": {
            "_id": "62a4591e2c4a83001364a460",
            "stix": {
                "x_mitre_platforms": [
                    "Linux",
                    "macOS",
                    "Windows",
                    "Network"
                ],
                "x_mitre_domains": [
                    "enterprise-attack"
                ],
                "x_mitre_contributors": [
                    "Austin Clark, @c2defense"
                ],
                "object_marking_refs": [
                    "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
                ],
                "type": "attack-pattern",
                "id": "attack-pattern--707399d6-ab3e-4963-9315-d9d3818cd6a0",
                "created": "2017-05-31T21:30:27.342Z",
                "x_mitre_version": "1.4",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1016",
                        "url": "https://attack.mitre.org/techniques/T1016"
                    },
                    {
                        "source_name": "Mandiant APT41 Global Intrusion ",
                        "url": "https://www.mandiant.com/resources/apt41-initiates-global-intrusion-campaign-using-multiple-exploits",
                        "description": "Gyler, C.,Perez D.,Jones, S.,Miller, S.. (2021, February 25). This is Not a Test: APT41 Initiates Global Intrusion Campaign Using Multiple Exploits. Retrieved February 17, 2022."
                    },
                    {
                        "source_name": "US-CERT-TA18-106A",
                        "url": "https://www.us-cert.gov/ncas/alerts/TA18-106A",
                        "description": "US-CERT. (2018, April 20). Alert (TA18-106A) Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020."
                    },
                    {
                        "url": "https://capec.mitre.org/data/definitions/309.html",
                        "source_name": "capec",
                        "external_id": "CAPEC-309"
                    }
                ],
                "x_mitre_deprecated": false,
                "revoked": false,
                "description": "Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include [Arp](https://attack.mitre.org/software/S0099), [ipconfig](https://attack.mitre.org/software/S0100)/[ifconfig](https://attack.mitre.org/software/S0101), [nbtstat](https://attack.mitre.org/software/S0102), and [route](https://attack.mitre.org/software/S0103).\n\nAdversaries may also leverage a [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) on network devices to gather information about configurations and settings, such as IP addresses of configured interfaces and static/dynamic routes.(Citation: US-CERT-TA18-106A)(Citation: Mandiant APT41 Global Intrusion )\n\nAdversaries may use the information from [System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016) during automated discovery to shape follow-on behaviors, including determining certain access within the target network and what actions to do next. ",
                "modified": "2022-05-20T17:34:15.406Z",
                "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                "name": "System Network Configuration Discovery",
                "x_mitre_detection": "System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Lateral Movement, based on the information obtained.\n\nMonitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Further, LinkById|T1059.008 commands may also be used to gather system and network information with built-in features native to the network device platform.  Monitor CLI activity for unexpected or unauthorized use  commands being run by non-standard users from non-standard locations.  Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).",
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "discovery"
                    }
                ],
                "x_mitre_is_subtechnique": false,
                "x_mitre_data_sources": [
                    "Process: OS API Execution",
                    "Command: Command Execution",
                    "Process: Process Creation",
                    "Script: Script Execution"
                ],
                "x_mitre_attack_spec_version": "2.1.0",
                "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                "spec_version": "2.1"
            },
            "workspace": {
                "collections": [
                    {
                        "collection_ref": "x-mitre-collection--402e24b4-436e-4936-b19b-2038648f489",
                        "collection_modified": "2022-05-24T14:00:00.188Z"
                    }
                ],
                "attack_id": "T1016"
            },
            "__t": "Technique",
            "__v": 0
        },
        "created_by_identity": {
            "_id": "62a43d112c4a830013645834",
            "stix": {
                "roles": [],
                "sectors": [],
                "object_marking_refs": [],
                "type": "identity",
                "id": "identity--d1dd6b52-23b7-490c-b54f-810fb1136752",
                "created": "2022-06-10T19:50:07.959Z",
                "modified": "2022-06-11T06:58:25.072Z",
                "x_mitre_version": "0.1",
                "external_references": [],
                "x_mitre_deprecated": false,
                "revoked": false,
                "description": "We build powerful threat intelligence tools",
                "spec_version": "2.1",
                "name": "DOGESEC DEMOS",
                "identity_class": "organization",
                "x_mitre_attack_spec_version": "2.1.0"
            },
            "workspace": {
                "workflow": {
                    "state": "awaiting-review"
                },
                "collections": []
            },
            "__t": "IdentityModel",
            "__v": 0
        },
        "modified_by_identity": {
            "_id": "62a43d112c4a830013645834",
            "stix": {
                "roles": [],
                "sectors": [],
                "object_marking_refs": [],
                "type": "identity",
                "id": "identity--d1dd6b52-23b7-490c-b54f-810fb1136752",
                "created": "2022-06-10T19:50:07.959Z",
                "modified": "2022-06-11T06:58:25.072Z",
                "x_mitre_version": "0.1",
                "external_references": [],
                "x_mitre_deprecated": false,
                "revoked": false,
                "description": "We build powerful threat intelligence tools",
                "spec_version": "2.1",
                "name": "DOGESEC DEMOS",
                "identity_class": "organization",
                "x_mitre_attack_spec_version": "2.1.0"
            },
            "workspace": {
                "workflow": {
                    "state": "awaiting-review"
                },
                "collections": []
            },
            "__t": "IdentityModel",
            "__v": 0
        }
    }
]
```

You can also start creating some Objects. Here is an example request using a dummy Technique to demonstrate...

```shell
curl -X POST "http://localhost/api/techniques" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d '{\"workspace\":{\"workflow\":{\"state\":\"awaiting-review\"},\"attackId\":\"TZ998\",\"collections\":[]},\"stix\":{\"type\":\"attack-pattern\",\"spec_version\":\"2.1\",\"created\":\"2022-06-29T06:58:09.436Z\",\"modified\":\"2022-06-29T06:58:09.436Z\",\"created_by_ref\":\"identity--d1dd6b52-23b7-490c-b54f-810fb1136752\",\"revoked\":false,\"external_references\":[{\"source_name\":\"mitre-attack\",\"description\":\"This is a technique external references description\",\"url\":\"string\",\"external_id\":\"TZ998\"}],\"name\":\"A new technique\",\"description\":\"This is a technique description.\",\"x_mitre_modified_by_ref\":\"identity--d1dd6b52-23b7-490c-b54f-810fb1136752\",\"x_mitre_contributors\":[\"DOGESEC DEMO\"],\"x_mitre_platforms\":[\"Windows\"],\"x_mitre_deprecated\":false,\"x_mitre_domains\":[\"enterprise-attack\"],\"x_mitre_detection\":\"Here is how to find it\",\"x_mitre_version\":\"1.0\",\"x_mitre_attack_spec_version\":\"2.1.0\"}}'
```

Finally to update an Object, I can use the PUT endpoints.

As an example, I will update the Technique I just created. The structure of the URL for a PUT request on an Object is as follows

```shell
curl -X PUT "http://localhost/api/techniques/<STIX_ID>/modified/<MODIFIED_DATE>"
```

Note, `<STIX_ID>` is the entire STIX ID (e.g. `attack-pattern--92081b2d-bb81-47f0-9714-a06a5d60e461`) and `<MODIFIED_DATE>` is the `modified_time` currently assigned to the STIX Object you want to changes (in my case, what I received in the response when creating the Object) -- it is not the modified_time you want to set (you must set this in the request body under the `modified_time` field).

For example,

```shell
curl -X PUT "http://localhost/api/techniques/attack-pattern--92081b2d-bb81-47f0-9714-a06a5d60e461/modified/2022-06-29T06:58:09.436Z"
```

If you do not know the `modified_time` of the Object, you can obtain it by making a GET request for the latest version of it which will print the STIX Object with the `modified_time` Property:

```shell
curl -X GET "http://localhost/api/techniques/attack-pattern--92081b2d-bb81-47f0-9714-a06a5d60e461?versions=latest"
```

In the body of the request you need to pass all Object Properties (whether you want to update them or not), this includes the `id` Property. If you do not want to make changes to a Property you must pass it as it currently exists. If you want to change it, simply change the Property value.

To remove optional Properties you can simply omit them from the body of the request. Be careful, all `x_mitre` custom Properties are optional, but deleting them (omitting them from the body) will cause issues with ATT&CK integration.

In this example request body I am updating only updating the `name` and `modified_time` Properties of my Technique Object;

```shell
curl -X PUT "http://localhost/api/techniques/attack-pattern--92081b2d-bb81-47f0-9714-a06a5d60e461/modified/2022-06-29T06:58:09.436Z" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d '{"workspace":{"workflow":{"state":"awaiting-review"},"attackId":"TZ998","collections":[]},"stix":{"type":"attack-pattern","spec_version":"2.1","created":"2022-06-29T06:58:09.436Z","modified":"2022-06-29T07:58:09.436Z","id":"attack-pattern--92081b2d-bb81-47f0-9714-a06a5d60e461","created_by_ref":"identity--d1dd6b52-23b7-490c-b54f-810fb1136752","revoked":false,"external_references":[{"source_name":"mitre-attack","description":"This is a technique external references description","url":"string","external_id":"TZ998"}],"name":"A new name for this technique","description":"This is a technique description.","x_mitre_modified_by_ref":"identity--d1dd6b52-23b7-490c-b54f-810fb1136752","x_mitre_contributors":["DOGESEC DEMO"],"x_mitre_platforms":["Windows"],"x_mitre_deprecated":false,"x_mitre_domains":["enterprise-attack"],"x_mitre_detection":"Here is how to find it","x_mitre_version":"1.0","x_mitre_attack_spec_version":"2.1.0"}}'
```

```json
{
    "stix": {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "created": "2022-06-29T06:58:09.436Z",
        "modified": "2022-06-29T07:58:09.436Z",
        "id": "attack-pattern--92081b2d-bb81-47f0-9714-a06a5d60e461",
        "created_by_ref": "identity--d1dd6b52-23b7-490c-b54f-810fb1136752",
        "revoked": false,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "description": "This is a technique external references description",
                "url": "string",
                "external_id": "TZ998"
            }
        ],
        "name": "A new name for this technique",
        "description": "This is a technique description.",
        "x_mitre_modified_by_ref": "identity--d1dd6b52-23b7-490c-b54f-810fb1136752",
        "x_mitre_contributors": [
            "DOGESEC DEMO"
        ],
        "x_mitre_platforms": [
            "Windows"
        ],
        "x_mitre_deprecated": false,
        "x_mitre_domains": [
            "enterprise-attack"
        ],
        "x_mitre_detection": "Here is how to find it",
        "x_mitre_version": "1.0",
        "x_mitre_attack_spec_version": "2.1.0"
    },
    "workspace": {
        "workflow": {
            "state": "awaiting-review"
        },
        "collections": [],
        "attack_id": "TZ998"
    },
    "__t": "Technique",
    "_id": "62bc6454a5125b001378c10b",
    "__v": 0
}
```

The API also exposes GET, PUT, POST, and DELETE endpoints for other Objects, and for Workbench management. I will let you discover those for yourself.

### ATT&CK Navigator Integration

The [ATT&CK Navigator](/blog/getting_started_mitre_attack_navigator/) can be configured to display the contents of your local knowledge base.

For this, you will need a local copy of the Navigator installed on a machine you have access to.

Go to your local install and open the file;

```shell
vi NAVIGATOR_ROOT/nav-app/src/assets/config.json
```

Here is what the default looks like: https://github.com/mitre-attack/attack-navigator/blob/master/nav-app/src/assets/config.json.

Now add the following to the file, nested under the `version` object;

```json
        {
            "name": "ATT&CK Workbench",
            "version": "0.1",
            "domains": [
                {   
                    "name": "Enterprise",
                    "identifier": "enterprise-attack",
                    "data": ["http://localhost/api/stix-bundles/?domain=enterprise-attack"]
                }
            ]
        }
```

It should look something like this;

<img class="img-fluid" src="/assets/images/blog/2024-07-15/navigator-versions.png" alt="Navigator version file" title="Navigator version file" />

Note, the data URLs pointing to the STIX Bundles will differ depending on your Workbench setup and the data you want to use inside the ATT&CK Navigator.

<img class="img-fluid" src="/assets/images/blog/2024-07-15/navigator-select-custom-attack.png" alt="Select custom ATT&CK" title="Select custom ATT&CK" />

When creating new layers, you will now be able to select the custom ATT&CK version from the Workbench in Navigator. Any changes you make inside the Workbench will also automatically be available in the Navigator layers using it.

### A custom ATT&CK Website

The code for MITRE's ATT&CK website, [attack.mitre.org](https://attack.mitre.org/), is available on [GitHub](https://github.com/mitre-attack/attack-website).

Now you are making changes to ATT&CK, you can integrate it on your own custom ATT&CK website allowing consumers to easily browse your content.

First clone a copy of the website;

```shell
git clone https://github.com/mitre-attack/attack-website.git
```

Now open the following file;

```shell
vi modules/site_config.py
```

Here is what the default looks like: https://github.com/mitre-attack/attack-website/blob/master/modules/site_config.py.

Now replace the domain URLs with the relevant Workbench API endpoints (you can also add your own domains).

Here is an example where I am replacing MITREs latest ATT&CK version with my own from the Navigator;

```python
domains = [
    {
        "name" : "enterprise-attack",
        "location" : "http://localhost/api/stix-bundles/?domain=enterprise-attack",
        "alias" : "Enterprise",
        "deprecated" : False
    },
    {
        "name" : "mobile-attack",
        "location" : "STIX_LOCATION_MOBILE",
        "alias" : "Mobile",
        "deprecated" : False
    },
    {
        "name" : "ics-attack",
        "location" : "STIX_LOCATION_ICS",
        "alias" : "ICS",
        "deprecated" : False
    },
    {
        "name" : "pre-attack",
        "location" : "STIX_LOCATION_PRE,",
        "alias": "PRE-ATT&CK",
        "deprecated" : True
    }
]
```