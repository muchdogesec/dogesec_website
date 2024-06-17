---
date: 2024-07-04
last_modified: 2024-07-04
title: "MITRE ATT&CK is More Than Tactics and Techniques"
description: "Software, Data Sources, Data Components, Campaigns etc., make the MITRE ATT&CK data set even more powerful than you might realise."
categories:
  - TUTORIAL
  - PRODUCTS
tags: [
    MITRE,
    ATT&CK,
    STIX
]
products:
    - arango_cti_processor
    - CTI Butler
author_staff_member: david-greenwood
image: /assets/images/blog/2024-07-04/header.png
featured_image: /assets/images/blog/2024-07-04/header.png
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

If you're only using ATT&CK Tactics and Techniques then you're missing a lot of the value ATT&CK offers. In this post I'll explain all the ATT&CK Objects to show how they all interlink (and show you a few [CTI Butler](https://www.ctibutler.com/) queries so you can dig deeper).

## ATT&CK STIX objects

### ATT&CK object `Matrix` = STIX object `x-mitre-matrix`

The Matrix (`x-mitre-matrix`) object captures specific information about the Matrix for the Domain being covered either Enterprise, ICS, or Mobile.

Here's the one for Enterprise:

```json
        {
            "tactic_refs": [
                "x-mitre-tactic--daa4cbb1-b4f4-4723-a824-7f1efd6e0592",
                "x-mitre-tactic--d679bca2-e57d-4935-8650-8031c87a4400",
                "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca",
                "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5",
                "x-mitre-tactic--5bc1d813-693e-4823-9961-abf9af4b0e92",
                "x-mitre-tactic--5e29b093-294e-49e9-a803-dab3d73b77dd",
                "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
                "x-mitre-tactic--2558fd61-8c75-4730-94c4-11926db2a263",
                "x-mitre-tactic--c17c5845-175e-4421-9713-829d0573dbc9",
                "x-mitre-tactic--7141578b-e50b-4dcc-bfa4-08a8dd689e9e",
                "x-mitre-tactic--d108ce10-2419-4cf9-a774-46161d6c6cfe",
                "x-mitre-tactic--f72804c5-f15a-449e-a5da-2eecd181f813",
                "x-mitre-tactic--9a4e74ab-5008-408c-84bf-a10dfbc53462",
                "x-mitre-tactic--5569339b-94c2-49ee-afb3-2222936582c8"
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "id": "x-mitre-matrix--eafc1b4c-5e56-4965-bd4e-66a6a89c88cc",
            "type": "x-mitre-matrix",
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "external_id": "enterprise-attack",
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/matrices/enterprise"
                }
            ],
            "modified": "2022-04-01T20:43:55.937Z",
            "name": "Enterprise ATT&CK",
            "description": "Below are the tactics and technique representing the MITRE ATT&CK Matrix for Enterprise. The Matrix contains information for the following platforms: Windows, macOS, Linux, AWS, GCP, Azure, Azure AD, Office 365, SaaS.",
            "x_mitre_version": "1.0",
            "x_mitre_attack_spec_version": "2.1.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "spec_version": "2.1",
            "x_mitre_domains": [
                "enterprise-attack"
            ]
        }
```

The main purpose of this object is to group the Tactic objects (`x-mitre-tactic`) associated with the domain.

To search for these objects in the Enterprise domain using CTI Butler:

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc.type == "x-mitre-matrix"
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 1 Object in v15.1.

Also found in `mitre_attack_mobile_vertex_collection` and `mitre_attack_ics_vertex_collection`

### ATT&CK object `Collection` = STIX object `x-mitre-collection`

These are similar to `x-mitre-matrix` objects (1 per domain), but include a list of all objects in the domain under the `x_mitre_contents` property.

```json
        {
            "type": "x-mitre-collection",
            "id": "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019",
            "spec_version": "2.1",
            "x_mitre_attack_spec_version": "2.1.0",
            "name": "Enterprise ATT&CK",
            "x_mitre_version": "15.1",
            "description": "ATT&CK for Enterprise provides a knowledge base of real-world adversary behavior targeting traditional enterprise networks. ATT&CK for Enterprise covers the following platforms: Windows, macOS, Linux, PRE, Office 365, Google Workspace, IaaS, Network, and Containers.",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "created": "2018-01-17T12:56:55.080Z",
            "modified": "2024-05-02T14:00:00.188Z",
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "x_mitre_contents": [
                {
                    "object_ref": "attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298",
                    "object_modified": "2022-04-25T14:00:00.188Z"
                }
```

The `x_mitre_contents` for Enterprise ATT&CK has 1000's of objects that I've cut from the object printed above.

I suspect this object is used for the MITRE ATT&CK TAXII Server to define all the objects in a TAXII Collection (clarification needed).

To search for these objects in the Enterprise domain using CTI Butler:

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  FILTERdoc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc.type == "x-mitre-collection"
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 1 Object in v15.1.

Also found in `mitre_attack_mobile_vertex_collection` and `mitre_attack_ics_vertex_collection`

### ATT&CK object `Tactic` = STIX object `x-mitre-tactic`

Tactics (`x-mitre-tactic--`) represent the "why" of an ATT&CK technique or sub-technique. It is the adversary's tactical goal: the reason for performing an action. For example, an adversary may want to achieve credential access.

https://attack.mitre.org/tactics/

Tactics have IDs in format: TANNNN

For example, Tactic TA0043 Reconnaissance: https://attack.mitre.org/tactics/TA0043/

```json
        {
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "id": "x-mitre-tactic--2558fd61-8c75-4730-94c4-11926db2a263",
            "type": "x-mitre-tactic",
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "external_id": "TA0006",
                    "url": "https://attack.mitre.org/tactics/TA0006",
                    "source_name": "mitre-attack"
                }
            ],
            "modified": "2022-04-25T14:00:00.188Z",
            "name": "Credential Access",
            "description": "The adversary is trying to steal account names and passwords.\n\nCredential Access consists of techniques for stealing credentials like account names and passwords. Techniques used to get credentials include keylogging or credential dumping. Using legitimate credentials can give adversaries access to systems, make them harder to detect, and provide the opportunity to create more accounts to help achieve their goals.",
            "x_mitre_version": "1.0",
            "x_mitre_attack_spec_version": "2.1.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_shortname": "credential-access",
            "spec_version": "2.1"
        }
```

To search for these objects in the Enterprise domain using CTI Butler:

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc.type == "x-mitre-tactic"
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 14 Objects in v15.1.

Also found in `mitre_attack_mobile_vertex_collection` and `mitre_attack_ics_vertex_collection`

### ATT&CK object `Technique` = STIX object `attack-pattern`

Techniques (`attack-pattern` with Custom Property `"x_mitre_is_subtechnique": false`) represent 'how' an adversary achieves a tactical goal by performing an action. For example, an adversary may dump credentials to achieve credential access.

https://attack.mitre.org/techniques/

Techniques have IDs in format: TNNNN 

For example, Technique T1595 Active Scanning: https://attack.mitre.org/techniques/T1595/

```json
        {
            "x_mitre_platforms": [
                "PRE"
            ],
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "id": "attack-pattern--67073dde-d720-45ae-83da-b12d5e73ca3b",
            "type": "attack-pattern",
            "created": "2020-10-02T16:53:16.526Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1595",
                    "url": "https://attack.mitre.org/techniques/T1595"
                },
                {
                    "source_name": "Botnet Scan",
                    "url": "https://www.caida.org/publications/papers/2012/analysis_slash_zero/analysis_slash_zero.pdf",
                    "description": "Dainotti, A. et al. (2012). Analysis of a \u201c/0\u201d Stealth Scan from a Botnet. Retrieved October 20, 2020."
                },
                {
                    "source_name": "OWASP Fingerprinting",
                    "url": "https://wiki.owasp.org/index.php/OAT-004_Fingerprinting",
                    "description": "OWASP Wiki. (2018, February 16). OAT-004 Fingerprinting. Retrieved October 20, 2020."
                }
            ],
            "modified": "2022-05-11T14:00:00.188Z",
            "name": "Active Scanning",
            "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting. Active scans are those where the adversary probes victim infrastructure via network traffic, as opposed to other forms of reconnaissance that do not involve direct interaction.\n\nAdversaries may perform different forms of active scanning depending on what information they seek to gather. These scans can also be performed in various ways, including using native features of network protocols such as ICMP.(Citation: Botnet Scan)(Citation: OWASP Fingerprinting) Information from these scans may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)).",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "reconnaissance"
                }
            ],
            "x_mitre_detection": "Monitor for suspicious network traffic that could be indicative of scanning, such as large quantities originating from a single source (especially if the source is known to be associated with an adversary/botnet). Analyzing web metadata may also reveal artifacts that can be attributed to potentially malicious activity, such as referer or user-agent string HTTP/S fields.\n\nMuch of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.\n\nDetection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.",
            "x_mitre_version": "1.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_data_sources": [
                "Network Traffic: Network Traffic Flow",
                "Network Traffic: Network Traffic Content"
            ],
            "x_mitre_is_subtechnique": false,
            "spec_version": "2.1",
            "x_mitre_attack_spec_version": "2.1.0"
        }
```

Note, how `x_mitre_is_subtechnique` = `false` indicating this is not a sub-technique.

To search for these objects in the Enterprise domain using CTI Butler:

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc.type == "attack-pattern"
  AND doc.x_mitre_is_subtechnique == false
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 342 Objects in v15.1.

Also found in `mitre_attack_mobile_vertex_collection` and `mitre_attack_ics_vertex_collection`

### ATT&CK object `Sub-Technique` = STIX object `attack-pattern`

Sub-Techniques (`attack-pattern` with Custom Property `"x_mitre_is_subtechnique": true`) are a more specific implementation of a Technique (they are children to a parent).

For example, T1595.001 Scanning IP Blocks is a Sub-Technique of Technique T1595 Active Scanning.

Techniques have IDs in format: TNNNN.NNN

For example, Sub-Technique T1595.001 Scanning IP Blocks: https://attack.mitre.org/techniques/T1595/001/

```json
        {
            "x_mitre_platforms": [
                "PRE"
            ],
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "id": "attack-pattern--db8f5003-3b20-48f0-9b76-123e44208120",
            "type": "attack-pattern",
            "created": "2020-10-02T16:54:23.193Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1595.001",
                    "url": "https://attack.mitre.org/techniques/T1595/001"
                },
                {
                    "source_name": "Botnet Scan",
                    "url": "https://www.caida.org/publications/papers/2012/analysis_slash_zero/analysis_slash_zero.pdf",
                    "description": "Dainotti, A. et al. (2012). Analysis of a \u201c/0\u201d Stealth Scan from a Botnet. Retrieved October 20, 2020."
                }
            ],
            "modified": "2022-04-25T14:00:00.188Z",
            "name": "Scanning IP Blocks",
            "description": "Adversaries may scan victim IP blocks to gather information that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses.\n\nAdversaries may scan IP blocks in order to [Gather Victim Network Information](https://attack.mitre.org/techniques/T1590), such as which IP addresses are actively in use as well as more detailed information about hosts assigned these addresses. Scans may range from simple pings (ICMP requests and responses) to more nuanced scans that may reveal host software/versions via server banners or other network artifacts.(Citation: Botnet Scan) Information from these scans may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133)).",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "reconnaissance"
                }
            ],
            "x_mitre_detection": "Monitor for suspicious network traffic that could be indicative of scanning, such as large quantities originating from a single source (especially if the source is known to be associated with an adversary/botnet).\n\nMuch of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.\n\nDetection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.",
            "x_mitre_is_subtechnique": true,
            "x_mitre_version": "1.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_data_sources": [
                "Network Traffic: Network Traffic Flow"
            ],
            "spec_version": "2.1",
            "x_mitre_attack_spec_version": "2.1.0"
        }
```

This time note how `x_mitre_is_subtechnique` = `true`. This is how Techniques and Sub-Techniques can be most easily differentiated.

To search for these objects in the Enterprise domain using CTI Butler:

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc.type == "attack-pattern"
  AND doc.x_mitre_is_subtechnique == true
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 438 Objects in v15.1.

Also found in `mitre_attack_mobile_vertex_collection` and `mitre_attack_ics_vertex_collection`

### ATT&CK object `Mitigation` = STIX object `course-of-action`

A Course of Action (`course-of-action`) represents ATT&CK Mitigations.

https://attack.mitre.org/mitigations/

Mitigations represent security concepts and classes of technologies that can be used to prevent a technique or sub-technique from being successfully executed.

Mitigations have IDs in format: MNNNN (and TNNNN)

For example, Mitigation M1049 - Antivirus/Antimalware: https://attack.mitre.org/mitigations/M1049/

```json
        {
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "id": "course-of-action--a6a47a06-08fc-4ec4-bdc3-20373375ebb9",
            "type": "course-of-action",
            "created": "2019-06-11T17:08:33.055Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "M1049",
                    "url": "https://attack.mitre.org/mitigations/M1049"
                }
            ],
            "modified": "2020-03-31T13:07:15.684Z",
            "name": "Antivirus/Antimalware",
            "description": "Use signatures or heuristics to detect malicious software.",
            "x_mitre_version": "1.1",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "spec_version": "2.1",
            "x_mitre_attack_spec_version": "2.1.0"
        }
```

To search for these objects in the Enterprise domain using CTI Butler:

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc.type == "course-of-action"
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 284 Objects in v15.1.

Also found in `mitre_attack_mobile_vertex_collection` and `mitre_attack_ics_vertex_collection`

As noted, some Mitigations have the IDs in the format TNNNN.

These Mitigations have a direct link to a Techniqiue with the same ID. e.g. T1005

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc.external_references != null AND IS_ARRAY(doc.external_references)
  FOR extRef IN doc.external_references
    FILTER extRef.external_id == "T1005"
    AND extRef.source_name == "mitre-attack"
    RETURN {
        name: doc.name,
        id: doc.id,
        attack_id: extRef.external_id
        }
```

```json
[
  {
    "name": "Data from Local System",
    "id": "attack-pattern--3c4a2599-71ee-4405-ba1e-0e28414b4bc5",
    "attack_id": "T1005"
  },
  {
    "name": "Data from Local System Mitigation",
    "id": "course-of-action--7ee0879d-ce4f-4f54-a96b-c532dfb98ffd",
    "attack_id": "T1005"
  }
]
```

### ATT&CK object `Groups` = STIX object `intrusion-set`

Intrusion Sets (`intrusion-set`) represent ATT&CK Groups.

https://attack.mitre.org/groups/

Groups are sets of related intrusion activity that are tracked by a common name in the security community.

Groups have IDs in format: GNNNN

For example, Group G0016 - APT29: https://attack.mitre.org/groups/G0016/

```json
        {
            "modified": "2024-04-12T21:15:41.833Z",
            "name": "APT29",
            "description": "[APT29](https://attack.mitre.org/groups/G0016) is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Costs RU Gov April 2021)(Citation: UK Gov Malign RIS Activity April 2021) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. [APT29](https://attack.mitre.org/groups/G0016) reportedly compromised the Democratic National Committee starting in the summer of 2015.(Citation: F-Secure The Dukes)(Citation: GRIZZLY STEPPE JAR)(Citation: Crowdstrike DNC June 2016)(Citation: UK Gov UK Exposes Russia SolarWinds April 2021)\n\nIn April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to the SVR; public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes.(Citation: NSA Joint Advisory SVR SolarWinds April 2021)(Citation: UK NSCS Russia SolarWinds April 2021) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Unit 42 SolarStorm December 2020)",
            "aliases": [
                "APT29",
                "IRON RITUAL",
                "IRON HEMLOCK",
                "NobleBaron",
                "Dark Halo",
                "StellarParticle",
                "NOBELIUM",
                "UNC2452",
                "YTTRIUM",
                "The Dukes",
                "Cozy Bear",
                "CozyDuke",
                "SolarStorm",
                "Blue Kitsune",
                "UNC3524",
                "Midnight Blizzard"
            ],
            "x_mitre_deprecated": false,
            "x_mitre_version": "6.0",
            "x_mitre_contributors": [
                "Daniyal Naeem, BT Security",
                "Matt Brenton, Zurich Insurance Group",
                "Katie Nickels, Red Canary",
                "Joe Gumke, U.S. Bank",
                "Liran Ravich, CardinalOps"
            ],
            "type": "intrusion-set",
            "id": "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542",
            "created": "2017-05-31T21:31:52.748Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "revoked": false,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/groups/G0016",
                    "external_id": "G0016"
                }
                ...
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_attack_spec_version": "3.2.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "spec_version": "2.1"
        }
```

Note, the full list of `external_references` has been cut from the object above for brevity.

To search for these objects in the Enterprise domain using CTI Butler:

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc.type == "intrusion-set"
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 165 Objects in v15.1.

Also found in `mitre_attack_mobile_vertex_collection` and `mitre_attack_ics_vertex_collection`

### ATT&CK object `Software` = STIX object `malware`

Malware (`malware`) represents ATT&CK Software that is malicious.

https://attack.mitre.org/software/

Software have IDs in format: SNNNN

For example, Software S0331 - Agent Tesla: https://attack.mitre.org/software/S0331/

```json
        {
            "modified": "2023-09-11T20:13:18.738Z",
            "name": "Agent Tesla",
            "description": "[Agent Tesla](https://attack.mitre.org/software/S0331) is a spyware Trojan written for the .NET framework that has been observed since at least 2014.(Citation: Fortinet Agent Tesla April 2018)(Citation: Bitdefender Agent Tesla April 2020)(Citation: Malwarebytes Agent Tesla April 2020)",
            "x_mitre_platforms": [
                "Windows"
            ],
            "x_mitre_deprecated": false,
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_version": "1.3",
            "x_mitre_aliases": [
                "Agent Tesla"
            ],
            "type": "malware",
            "id": "malware--e7a5229f-05eb-440e-b982-9a6d2b2b87c8",
            "created": "2019-01-29T18:44:04.748Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "revoked": false,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/software/S0331",
                    "external_id": "S0331"
                },
                {
                    "source_name": "Agent Tesla",
                    "description": "(Citation: Fortinet Agent Tesla April 2018)(Citation: Talos Agent Tesla Oct 2018)(Citation: DigiTrust Agent Tesla Jan 2017)"
                },
                {
                    "source_name": "Bitdefender Agent Tesla April 2020",
                    "description": "Arsene, L. (2020, April 21). Oil & Gas Spearphishing Campaigns Drop Agent Tesla Spyware in Advance of Historic OPEC+ Deal. Retrieved May 19, 2020.",
                    "url": "https://labs.bitdefender.com/2020/04/oil-gas-spearphishing-campaigns-drop-agent-tesla-spyware-in-advance-of-historic-opec-deal/"
                },
                {
                    "source_name": "Talos Agent Tesla Oct 2018",
                    "description": "Brumaghin, E., et al. (2018, October 15). Old dog, new tricks - Analysing new RTF-based campaign distributing Agent Tesla, Loki with PyREbox. Retrieved November 5, 2018.",
                    "url": "https://blog.talosintelligence.com/2018/10/old-dog-new-tricks-analysing-new-rtf_15.html"
                },
                {
                    "source_name": "Malwarebytes Agent Tesla April 2020",
                    "description": "Jazi, H. (2020, April 16). New AgentTesla variant steals WiFi credentials. Retrieved May 19, 2020.",
                    "url": "https://blog.malwarebytes.com/threat-analysis/2020/04/new-agenttesla-variant-steals-wifi-credentials/"
                },
                {
                    "source_name": "DigiTrust Agent Tesla Jan 2017",
                    "description": "The DigiTrust Group. (2017, January 12). The Rise of Agent Tesla. Retrieved November 5, 2018.",
                    "url": "https://www.digitrustgroup.com/agent-tesla-keylogger/"
                },
                {
                    "source_name": "Fortinet Agent Tesla April 2018",
                    "description": "Zhang, X. (2018, April 05). Analysis of New Agent Tesla Spyware Variant. Retrieved November 5, 2018.",
                    "url": "https://www.fortinet.com/blog/threat-research/analysis-of-new-agent-tesla-spyware-variant.html"
                }
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "x_mitre_attack_spec_version": "3.1.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "spec_version": "2.1",
            "is_family": true
        }
```

To search for these objects in the Enterprise domain using CTI Butler:

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc.type == "malware"
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 596 Objects in v15.1.

Also found in `mitre_attack_mobile_vertex_collection` and `mitre_attack_ics_vertex_collection`

### ATT&CK object `Software` = STIX object `tool`

Tools (`tool`) also represents a type of software, but unlike Malware, they represent objects that are that is benign.

https://attack.mitre.org/software/

Tools also have IDs in format: SNNNN

For example, Software S0104 - netstat: https://attack.mitre.org/software/S0104/

```json
        {
            "modified": "2024-01-23T19:57:39.135Z",
            "name": "netstat",
            "description": "[netstat](https://attack.mitre.org/software/S0104) is an operating system utility that displays active TCP connections, listening ports, and network statistics. (Citation: TechNet Netstat)",
            "x_mitre_deprecated": false,
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "x_mitre_version": "1.3",
            "x_mitre_aliases": [
                "netstat"
            ],
            "type": "tool",
            "id": "tool--4664b683-f578-434f-919b-1c1aad2a1111",
            "created": "2017-05-31T21:33:04.545Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "revoked": false,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/software/S0104",
                    "external_id": "S0104"
                },
                {
                    "source_name": "TechNet Netstat",
                    "description": "Microsoft. (n.d.). Netstat. Retrieved April 17, 2016.",
                    "url": "https://technet.microsoft.com/en-us/library/bb490947.aspx"
                }
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "x_mitre_attack_spec_version": "3.2.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "spec_version": "2.1"
        }
```

To search for these objects in the Enterprise domain using CTI Butler:

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc.type == "tool"
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 86 Objects in v15.1.

Also found in `mitre_attack_mobile_vertex_collection`

### ATT&CK object `Campaign` = STIX object `campaign`

Campaign (`campaign`) represents an security operations to achieve some objective.

https://attack.mitre.org/campaigns/

Campaigns have IDs in format: CNNNN

For example, Campaign C0022 - Operation Dream Job: https://attack.mitre.org/campaigns/C0022/

```json
        {
            "modified": "2024-04-11T00:31:21.576Z",
            "name": "Operation Dream Job",
            "description": "[Operation Dream Job](https://attack.mitre.org/campaigns/C0022) was a cyber espionage operation likely conducted by [Lazarus Group](https://attack.mitre.org/groups/G0032) that targeted the defense, aerospace, government, and other sectors in the United States, Israel, Australia, Russia, and India. In at least one case, the cyber actors tried to monetize their network access to conduct a business email compromise (BEC) operation. In 2020, security researchers noted overlapping TTPs, to include fake job lures and code similarities, between [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), Operation North Star, and Operation Interception; by 2022 security researchers described [Operation Dream Job](https://attack.mitre.org/campaigns/C0022) as an umbrella term covering both Operation Interception and Operation North Star.(Citation: ClearSky Lazarus Aug 2020)(Citation: McAfee Lazarus Jul 2020)(Citation: ESET Lazarus Jun 2020)(Citation: The Hacker News Lazarus Aug 2022)",
            "aliases": [
                "Operation Dream Job",
                "Operation North Star",
                "Operation Interception"
            ],
            "first_seen": "2019-09-01T04:00:00.000Z",
            "last_seen": "2020-08-01T04:00:00.000Z",
            "x_mitre_first_seen_citation": "(Citation: ESET Lazarus Jun 2020)",
            "x_mitre_last_seen_citation": "(Citation: ClearSky Lazarus Aug 2020)",
            "x_mitre_deprecated": false,
            "x_mitre_version": "1.2",
            "type": "campaign",
            "id": "campaign--0257b35b-93ef-4a70-80dd-ad5258e6045b",
            "created": "2023-03-17T13:37:42.596Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "revoked": false,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/campaigns/C0022",
                    "external_id": "C0022"
                },
                {
                    "source_name": "Operation Interception",
                    "description": "(Citation: ESET Lazarus Jun 2020)"
                },
                {
                    "source_name": "Operation North Star",
                    "description": "(Citation: McAfee Lazarus Jul 2020)(Citation: McAfee Lazarus Nov 2020)"
                },
                {
                    "source_name": "McAfee Lazarus Nov 2020",
                    "description": "Beek, C. (2020, November 5). Operation North Star: Behind The Scenes. Retrieved December 20, 2021.",
                    "url": "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/operation-north-star-behind-the-scenes/"
                },
                {
                    "source_name": "ESET Lazarus Jun 2020",
                    "description": "Breitenbacher, D and Osis, K. (2020, June 17). OPERATION IN(TER)CEPTION: Targeted Attacks Against European Aerospace and Military Companies. Retrieved December 20, 2021.",
                    "url": "https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_Operation_Interception.pdf"
                },
                {
                    "source_name": "McAfee Lazarus Jul 2020",
                    "description": "Cashman, M. (2020, July 29). Operation North Star Campaign. Retrieved December 20, 2021.",
                    "url": "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/operation-north-star-a-job-offer-thats-too-good-to-be-true/?hilite=%27Operation%27%2C%27North%27%2C%27Star%27"
                },
                {
                    "source_name": "ClearSky Lazarus Aug 2020",
                    "description": "ClearSky Research Team. (2020, August 13). Operation 'Dream Job' Widespread North Korean Espionage Campaign. Retrieved December 20, 2021.",
                    "url": "https://www.clearskysec.com/wp-content/uploads/2020/08/Dream-Job-Campaign.pdf"
                },
                {
                    "source_name": "The Hacker News Lazarus Aug 2022",
                    "description": "Lakshmanan, R. (2022, August 17). North Korea Hackers Spotted Targeting Job Seekers with macOS Malware. Retrieved April 10, 2023.",
                    "url": "https://thehackernews.com/2022/08/north-korea-hackers-spotted-targeting.html"
                }
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "x_mitre_attack_spec_version": "3.2.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "x_mitre_domains": [
                "enterprise-attack"
            ],
            "spec_version": "2.1"
        }
```

To search for these objects in the Enterprise domain using CTI Butler:

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc.type == "campaign"
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 28 Objects in v15.1.

Also found in `mitre_attack_mobile_vertex_collection` and `mitre_attack_ics_vertex_collection`

### ATT&CK object `Data Source` = STIX object `x-mitre-data-source`

Data Sources (`x-mitre-data-source`) represent the various subjects/topics of information that can be collected by sensors/logs.

https://attack.mitre.org/datasources/

Data Sources have IDs in format: DSNNNN

For example, Data Source DS0029 - Network Traffic: https://attack.mitre.org/datasources/DS0029/

```json
        {
            "modified": "2023-04-20T18:38:13.356Z",
            "name": "Network Traffic",
            "description": "Data transmitted across a network (ex: Web, DNS, Mail, File, etc.), that is either summarized (ex: Netflow) and/or captured as raw data in an analyzable format (ex: PCAP)",
            "x_mitre_platforms": [
                "IaaS",
                "Linux",
                "Windows",
                "macOS",
                "Android",
                "iOS"
            ],
            "x_mitre_deprecated": false,
            "x_mitre_domains": [
                "enterprise-attack",
                "mobile-attack"
            ],
            "x_mitre_version": "1.1",
            "x_mitre_contributors": [
                "Center for Threat-Informed Defense (CTID)",
                "ExtraHop"
            ],
            "x_mitre_collection_layers": [
                "Cloud Control Plane",
                "Host",
                "Network"
            ],
            "type": "x-mitre-data-source",
            "id": "x-mitre-data-source--c000cd5c-bbb3-4606-af6f-6c6d9de0bbe3",
            "created": "2021-10-20T15:05:19.274Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "revoked": false,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/datasources/DS0029",
                    "external_id": "DS0029"
                }
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "x_mitre_attack_spec_version": "3.1.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "spec_version": "2.1"
        }
```

To search for these objects in the Enterprise domain using CTI Butler:

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc.type == "x-mitre-data-source"
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 38 Objects in v15.1.

Also found in `mitre_attack_mobile_vertex_collection` and `mitre_attack_ics_vertex_collection`

### ATT&CK object `Data Component` = STIX object `x-mitre-data-component`

Data components are children of Data Sources.

Data Components identify specific properties/values of a data source relevant to detecting a given ATT&CK technique or sub-technique. For example, Network Traffic is the Data Source and Network Traffic Flow is one of the Data Components linked to it.

Data Components don't have any ATT&CK specific ID's.

```json
        {
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "id": "x-mitre-data-component--a7f22107-02e5-4982-9067-6625d4a1765a",
            "type": "x-mitre-data-component",
            "created": "2021-10-20T15:05:19.274Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "modified": "2022-04-25T14:00:00.188Z",
            "name": "Network Traffic Flow",
            "description": "Summarized network packet data, with metrics, such as protocol headers and volume (ex: Netflow or Zeek http.log)",
            "x_mitre_data_source_ref": "x-mitre-data-source--c000cd5c-bbb3-4606-af6f-6c6d9de0bbe3",
            "x_mitre_version": "1.0",
            "x_mitre_attack_spec_version": "2.1.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "spec_version": "2.1",
            "x_mitre_domains": [
                "enterprise-attack"
            ]
        }
```

You can see the relationship to the Data Source in the `x_mitre_data_source_ref` property (in this case `x-mitre-data-source--c000cd5c-bbb3-4606-af6f-6c6d9de0bbe3`, DS0029 - Network Traffic).

To search for these objects in the Enterprise domain using CTI Butler:

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc.type == "x-mitre-data-component"
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 109 Objects in v15.1.

Also found in `mitre_attack_mobile_vertex_collection` and `mitre_attack_ics_vertex_collection`

### ATT&CK object `Asset` = STIX object `x-mitre-asset`

Assets are unique to the ICS domain.

Assets represent the devices and systems commonly found within Industrial Control System environments. Each asset object includes a mapping of technique relationships that represent the adversary actions that may target the device based on its capability and function.

https://attack.mitre.org/assets/

Assets have IDs in format: ANNNN

For example, Asset A0011 - Virtual Private Network (VPN) Server: https://attack.mitre.org/assets/A0011/

```json
        {
            "modified": "2023-10-04T18:07:59.333Z",
            "name": "Virtual Private Network (VPN) Server",
            "description": "A VPN server is a device that is used to establish a secure network tunnel between itself and other remote VPN devices, including field VPNs. VPN servers can be used to establish a secure connection with a single remote device, or to securely bridge all traffic between two separate networks together by encapsulating all data between those networks. VPN servers typically support remote network services that are used by field VPNs to initiate the establishment of the secure VPN tunnel between the field device and server.",
            "x_mitre_sectors": [
                "General"
            ],
            "x_mitre_related_assets": [
                {
                    "name": "Virtual Private Network (VPN) terminator",
                    "related_asset_sectors": [
                        "General"
                    ],
                    "description": "A VPN terminator is a device performs the role of either a VPN client or server to support the establishment of VPN connection. (Citation: IEC February 2019)"
                },
                {
                    "name": "Field VPN",
                    "related_asset_sectors": [
                        "General"
                    ],
                    "description": "Field VPN are typically deployed at remote outstations and are used to create secure connections to VPN servers within data/control center environments.  "
                }
            ],
            "x_mitre_platforms": [
                "Windows",
                "Linux",
                "Embedded"
            ],
            "x_mitre_deprecated": false,
            "x_mitre_domains": [
                "ics-attack"
            ],
            "x_mitre_version": "1.0",
            "type": "x-mitre-asset",
            "id": "x-mitre-asset--0804f037-a3b9-4715-98e1-9f73d19d6945",
            "created": "2023-09-28T15:13:07.950Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "revoked": false,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/assets/A0011",
                    "external_id": "A0011"
                },
                {
                    "source_name": "IEC February 2019",
                    "description": "IEC 2019, February Security for industrial automation and control systems - Part 4-2: Technical security requirements for IACS components Retrieved. 2020/09/25 ",
                    "url": "https://webstore.iec.ch/publication/34421"
                }
            ],
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "x_mitre_attack_spec_version": "3.2.0",
            "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "spec_version": "2.1"
        }
```

To search for these objects in the ICS domain using CTI Butler:

```sql
FOR doc IN mitre_attack_ics_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc.type == "x-mitre-asset"
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 14 Objects in v15.1.

### Relationships between object types

STIX Relationship Objects are also used to link Object types that have a connection, e.g. a Malware to a Technique (to describe the technique a malware uses), Technique to Sub-Technique (to describe the hierarchy), etc.

Note, as shown earlier, STIX embedded relationships (under `*_ref` or `*_refs` properties) are also used in some cases (e.g. as shown to link a data component to a data source).

Here's an example SRO linking a Data Component to a Technique (Data Component detects the Technique)...

```json
{
    "type": "relationship",
    "id": "relationship--00b98fa6-4913-40a4-8920-befed8621c41",
    "created": "2022-05-11T16:22:58.806Z",
    "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
    "revoked": false,
    "object_marking_refs": [
        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
    ],
    "modified": "2022-09-26T15:15:33.180Z",
    "description": "Monitor ICS asset application logs that indicate alarm settings have changed, although not all assets will produce such logs.",
    "relationship_type": "detects",
    "source_ref": "x-mitre-data-component--9c2fa0ae-7abc-485a-97f6-699e3b6cf9fa",
    "target_ref": "attack-pattern--e5de767e-f513-41cd-aa15-33f6ce5fbf92",
    "x_mitre_deprecated": false,
    "x_mitre_version": "1.0",
    "x_mitre_attack_spec_version": "2.1.0",
    "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
}
```

There are lots of different relationship types in each ATT&CK domain.

Using CTI Butler...

```sql
FOR doc IN mitre_attack_enterprise_edge_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc._is_ref == false
  COLLECT WITH COUNT INTO length
  RETURN length
```

I can see there are 19438 `relationships` Objects in ATT&CK Enterprise v15.1

I can also easily write a query to identify the different relationships types that exist between objects in the Enterprise domain;

```sql
FOR doc IN mitre_attack_enterprise_edge_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._is_ref == false
  AND doc.relationship_type != "revoked-by"
  LET source = DOCUMENT(doc._from)
  LET target = DOCUMENT(doc._to)
  COLLECT relationshipType = doc.relationship_type, sourceType = source.type, targetType = target.type
  RETURN {
    relationship_type: relationshipType,
    source_ref_type: sourceType,
    target_ref_type: targetType
  }
```

I can also search all the embedded relationships (`*_ref`, `*_refs`) using CTI Butler (ignoring ones that don't join ATT&CK objects):

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  LET refKeys = ATTRIBUTES(doc)
  FOR key IN refKeys
    FILTER (key LIKE "%_ref" OR key LIKE "%_refs") AND key != "created_by_ref" AND key != "object_marking_refs" AND key != "x_capec_can_follow_refs" AND key != "x_capec_child_of_refs" AND key != "x_mitre_modified_by_ref"
    COLLECT uniqueKey = key INTO grouped
    LET refValues = FLATTEN(
      FOR d IN grouped[*].doc
        RETURN d[uniqueKey]
    )
    LET refTypes = UNIQUE(
      FLATTEN(
        FOR refValue IN refValues
          FILTER refValue != NULL
          LET refDoc = FIRST(FOR rdoc IN mitre_attack_enterprise_vertex_collection FILTER rdoc.id == refValue RETURN rdoc)
          RETURN refDoc.type
      )
    )
    RETURN {
      reference: uniqueKey,
      types: refTypes
    }
```

```json
[
  {
    "reference": "tactic_refs",
    "types": [
      "x-mitre-tactic"
    ]
  },
  {
    "reference": "x_mitre_data_source_ref",
    "types": [
      "x-mitre-data-source"
    ]
  }
]
```

Which on a graph looks like this:

<iframe width="768" height="432" src="https://miro.com/app/live-embed/uXjVKBgHZ2I=/?moveToViewport=-1075,-483,1713,911&embedId=788698668005" frameborder="0" scrolling="no" allow="fullscreen; clipboard-read; clipboard-write" allowfullscreen></iframe>

## MITRE ATT&CK Custom objects and properties

If you are new to STIX, [I would recommend first jumping back into my STIX tutorial to really understand the concept of STIX customisation before continuing](/blog/create_custom_stix_objects).

You might have also noticed that many Custom STIX Properties are being used in addition the default STIX 2.1 Properties for each ATT&CK STIX Object.

Custom Properties are easily identifiable in STIX 2.1 as the Property names should always start with `x_`. In the case of ATT&CK, MITRE always use the prefix `x_mitre_`, for example, `x_mitre_version`.

To find them (and the object types they are found in) using CTI Butler:

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  LET keys = ATTRIBUTES(doc)
  FOR key IN keys
    FILTER key LIKE "x_%"
    COLLECT docType = doc.type INTO grouped
    LET uniqueKeys = UNIQUE(grouped[*].key)
    RETURN {
      type: docType,
      keys: uniqueKeys
    }
```

```json
[
  {
    "type": "attack-pattern",
    "keys": [
      "x_mitre_is_subtechnique",
      "x_mitre_modified_by_ref",
      "x_mitre_domains",
      "x_mitre_attack_spec_version",
      "x_mitre_detection",
      "x_mitre_version",
      "x_mitre_defense_bypassed",
      "x_mitre_platforms",
      "x_mitre_data_sources",
      "x_mitre_contributors",
      "x_mitre_deprecated",
      "x_mitre_remote_support",
      "x_mitre_permissions_required",
      "x_mitre_system_requirements",
      "x_mitre_impact_type",
      "x_mitre_effective_permissions",
      "x_mitre_network_requirements"
    ]
  },
  {
    "type": "campaign",
    "keys": [
      "x_mitre_first_seen_citation",
      "x_mitre_modified_by_ref",
      "x_mitre_domains",
      "x_mitre_attack_spec_version",
      "x_mitre_deprecated",
      "x_mitre_version",
      "x_mitre_last_seen_citation",
      "x_mitre_contributors"
    ]
  },
  {
    "type": "course-of-action",
    "keys": [
      "x_mitre_attack_spec_version",
      "x_mitre_version",
      "x_mitre_deprecated",
      "x_mitre_modified_by_ref",
      "x_mitre_domains"
    ]
  },
  {
    "type": "identity",
    "keys": [
      "x_mitre_attack_spec_version",
      "x_mitre_version",
      "x_mitre_domains"
    ]
  },
  {
    "type": "intrusion-set",
    "keys": [
      "x_mitre_modified_by_ref",
      "x_mitre_domains",
      "x_mitre_attack_spec_version",
      "x_mitre_deprecated",
      "x_mitre_version",
      "x_mitre_contributors"
    ]
  },
  {
    "type": "malware",
    "keys": [
      "x_mitre_modified_by_ref",
      "x_mitre_domains",
      "x_mitre_attack_spec_version",
      "x_mitre_deprecated",
      "x_mitre_version",
      "x_mitre_platforms",
      "x_mitre_aliases",
      "x_mitre_contributors"
    ]
  },
  {
    "type": "marking-definition",
    "keys": [
      "x_mitre_attack_spec_version",
      "x_mitre_domains"
    ]
  },
  {
    "type": "tool",
    "keys": [
      "x_mitre_modified_by_ref",
      "x_mitre_domains",
      "x_mitre_contributors",
      "x_mitre_attack_spec_version",
      "x_mitre_deprecated",
      "x_mitre_version",
      "x_mitre_platforms",
      "x_mitre_aliases"
    ]
  },
  {
    "type": "x-mitre-collection",
    "keys": [
      "x_mitre_attack_spec_version",
      "x_mitre_version",
      "x_mitre_contents"
    ]
  },
  {
    "type": "x-mitre-data-component",
    "keys": [
      "x_mitre_attack_spec_version",
      "x_mitre_version",
      "x_mitre_domains",
      "x_mitre_modified_by_ref",
      "x_mitre_data_source_ref",
      "x_mitre_deprecated"
    ]
  },
  {
    "type": "x-mitre-data-source",
    "keys": [
      "x_mitre_modified_by_ref",
      "x_mitre_domains",
      "x_mitre_contributors",
      "x_mitre_collection_layers",
      "x_mitre_attack_spec_version",
      "x_mitre_version",
      "x_mitre_platforms",
      "x_mitre_deprecated"
    ]
  },
  {
    "type": "x-mitre-matrix",
    "keys": [
      "x_mitre_attack_spec_version",
      "x_mitre_version",
      "x_mitre_modified_by_ref",
      "x_mitre_domains"
    ]
  },
  {
    "type": "x-mitre-tactic",
    "keys": [
      "x_mitre_shortname",
      "x_mitre_attack_spec_version",
      "x_mitre_version",
      "x_mitre_domains",
      "x_mitre_modified_by_ref"
    ]
  }
]
```

In addition to custom properties, ATT&CK is also represented using a mix of core STIX 2.1 Domain Objects and some Custom SDOs (as shown earlier in this post). These custom objects can be identified where their type starts with `x-`. For reference, here are the custom SDOs created by MITRE for ATT&CK,

* Matrix (`x-mitre-matrix`)
* Data Sources (`x-mitre-data-source`)
* Data Component (`x-mitre-data-component`)
* Tactic (`x-mitre-tactic`)

A list of all STIX Objects and custom properties they contain used by ATT&CK [can be viewed here](https://github.com/mitre/cti/blob/master/USAGE.md) too.

## Explore ATT&CK in more detail...

...including how it references other knowledge-bases, check out [CTI Butler](https://www.ctibutler.com/). I've shown you some simple queries in this post, but the beauty of the query language is that is can also satisfy much more advanced use-cases too!