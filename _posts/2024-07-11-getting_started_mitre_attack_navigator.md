---
date: 2024-07-11
last_modified: 2024-07-11
title: "Getting Started with MITRE ATT&CK Navigator"
description: "The MITRE ATT&CK Navigator is a very useful tool to explore the MITRE ATT&CK framework. Here is how I've used it."
categories:
  - TUTORIAL
  - PRODUCTS
tags: [
    MITRE,
    ATT&CK,
    STIX,
    Navigator
]
products:
    - disarm2stix
    - CTI Butler
    - sigma2stix
author_staff_member: david-greenwood
image: /assets/images/blog/2024-07-11/header.png
featured_image: /assets/images/blog/2024-07-11/header.png
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

The MITRE ATT&CK Navigator is a web-based tool for annotating and exploring the MITRE ATT&CK framework. It is very useful for both offensive and defensive activities.

Here is a nice overview of the ATT&CK Navigator presented by MITRE:

<iframe width="560" height="315" src="https://www.youtube.com/embed/pcclNdwG8Vs?si=SpR9LdvqNp6JHXf7" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

### Install ATT&CK Navigator

To make it easy to get started, [there is a public instance running here that you can use](https://mitre-attack.github.io/attack-navigator/).

You can also install the ATT&CK Navigator on your own machine.

To do this you will need Node and Angular installed to run. Once installed...

```shell
git clone https://github.com/mitre-attack/attack-navigator
cd attack-navigator/nav-app
npm install
ng serve
```

Now open up a browser and navigate to `localhost:4200`, you should see the index page.

### Model an intelligence report

For this first walkthrough I will use this post from the brilliant UNIT-42; [Popping Eagle: How We Leveraged Global Analytics to Discover a Sophisticated Threat Actor](https://unit42.paloaltonetworks.com/popping-eagle-malware/) to model the information against ATT&CK Tactics and Techniques.

The Unit 42 team have made it easy for us by detailing the ATT&CK Techniques and Sub-Techniques about the Popping Eagle Malware at the bottom of the post.

<img class="img-fluid" src="/assets/images/blog/2024-07-11/unit42-annotated-report.png" alt="Unit42 report with ATT&CK" title="Unit42 report with ATT&CK" />

For reference, they are:

* [T1568: Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)
* [T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
* [T1218: System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
* [T1090: Proxy](https://attack.mitre.org/techniques/T1090/)
* [T1046: Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
* [T1021: Remote Services](https://attack.mitre.org/techniques/T1021/)
    * [T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
* [T1016: System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)
* [T1087: Account Discovery](https://attack.mitre.org/techniques/T1087/)
* [T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)
    * [T1003.001: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
    * [T1003.003: NTDS](https://attack.mitre.org/techniques/T1003/003/)

I will use a layer in ATT&CK Navigator to represent this report.

To do this I first, create a new layer choosing the appropriate ATT&CK Matrix. In this case that is the Enterprise domain (because the report does not mention mobile or ICS infrastructure).

<img class="img-fluid" src="/assets/images/blog/2024-07-11/navigator-new-layer.jpeg" alt="Navigator new layer" title="Navigator new layer" />

When on the Matrix view, shown above, click the `layer controls` > `layer information` button and give the layer some contextual information including a title, description, and link back to the blog post (this very is useful to others viewing your layer in the future).

Now I can start adding the Techniques to the layer. This can be done in two ways; 1) by finding the Technique in the matrix, right clicking it, and select `Add to Selection`.

However, there is a much easier way...

<img class="img-fluid" src="/assets/images/blog/2024-07-11/navigator-multiselect.png" alt="Navigator multiselect" title="Navigator multiselect" />

Select; `selection controls` > `search & multiselect`.

Now it is possible to search and select from the results (under Techniques) to find the Techniques needed.

<img class="img-fluid" src="/assets/images/blog/2024-07-11/navigator-colour-techniques.png" alt="Navigator colour techniques" title="Navigator colour techniques" />

Once all the Techniques have been selected, you can make them more visible on the Matrix by selecting; `technique controls` > `fill bucket`. In the screenshot above, I have coloured the selected Techniques green.

<img class="img-fluid" src="/assets/images/blog/2024-07-11/navigator-export-layer.png" alt="Navigator export layer" title="Navigator export layer" />

It is now possible to export your layer as a `.json` doc by selecting; `layer controls` > `download layer as .json`.

<img class="img-fluid" src="/assets/images/blog/2024-07-11/navigator-import-layer.png" alt="Navigator import layer" title="Navigator import layer" />

The exported `.json` can then be shared and imported to other instances of the ATT&CK Navigator (or other products that support the structure of the exported `.json`).

### Comparing intelligence reports

In many cases, you will want to compare Techniques between reports. For example to identify similarities between malware.

For this I will compare the Popping Eagle layer, with APT 39.

[As you know from previous posts](/blog/mitre_attack_data_structure), ATT&CK contains information about widely known Groups as STIX 2.1 Intrusion Set objects.

<img class="img-fluid" src="/assets/images/blog/2024-07-11/navigator-search-groups.png" alt="Navigator search groups" title="Navigator search groups" />

Therefore all that is needed is to create a new layer, click `selection controls` > `search & multiselect`, and search for APT 39 under "Threat Groups". Clicking `select` will select all Techniques related to APT 39 which can then be coloured in the same way as before.

Now I have two layers. Before being able to compare the layers, I first need to [assign each layer a score](https://github.com/mitre-attack/attack-navigator/blob/master/USAGE.md#scoring-techniques).

> A score is a numeric value assigned to a Technique. The meaning or interpretation of scores is completely up to the user user - the Navigator simply visualizes the matrix based on any scores you have assigned.

As you can see there are a few ways scoring can be used. For this use-case I will assign a score of 1 to the Popping Eagle layer and a score of 2 for the APT 39 layer. The actual value of the score is irrelevant (in this scenario, but can be very useful for others) as long as they are different and within the supported range of `0` - `100`.

<img class="img-fluid" src="/assets/images/blog/2024-07-11/navigator-score-layer.png" alt="Navigator score layer" title="Navigator score layer" />

Now I have assigned a score to each layer, I can create a new layer from the two layers. 

<img class="img-fluid" src="/assets/images/blog/2024-07-11/navigator-create-layer-from-layer.png" alt="Navigator create layer from layer" title="Navigator create layer from layer" />

Looking at the top tabs in the screenshot above you can see Popping Eagle has been assigned ID `a` and APT 39 `b`. Therefore the score expression needed is `a + b`. Now click create.

<img class="img-fluid" src="/assets/images/blog/2024-07-11/navigator-combined-layers.png" alt="Navigator combined layers" title="Navigator combined layers" />

I have added a legend in the bottom right of my newly created layer; Popping Eagle vs APT 39.

* Yellow shows Techniques unique to APT 39,
* Red shows Techniques unique to Popping Eagle,
* and Green shows Techniques used by both.

In this case, there is quite a difference between the Techniques Popping Eagle and APT39... so we might infer APT39 don't use Popping Eagle as it is not aligned with their known behaviours.

There are many other uses for comparing layers, including;

* tracking the evolution of an actor over time as new Techniques are discovered or the actor changes their approach
* comparing known intelligence collected on the same campaign from different sources so that you can have the most comprehensive information available in one place
* identifying gaps between Techniques that you have intelligence about and Techniques you are detecting for in your SIEM (or whatever) to identify blindspots in your defenses, which brings me on to...

### Mapping to internal logs

One of the largest reasons for collecting intelligence is to ensure you are defending against it.

As covered in the last post in this tutorial, the ATT&CK data model contains the following Object types;

> Data Sources (STIX 2.1 object: `x-mitre-data-source`): [Data sources](https://attack.mitre.org/datasources/) represent the various subjects/topics of information that can be collected by sensors/logs. Tracked using ID in format: DSNNNN (e.g. [DS0029 - Network Traffic](https://attack.mitre.org/datasources/DS0029/))

> Data Component (STIX 2.1 object: `x-mitre-data-component`): Data components are children of Data Sources. Data Components identify specific properties/values of a data source relevant to detecting a given ATT&CK technique or sub-technique. For example, Network Traffic is the Data Source and Remote Services is one of the Data Components linked to it.

Each Data Component Object has a Relationship to one or more Technique.

For example the Data Source [DS0026: Active Directory](https://attack.mitre.org/datasources/DS0026/) has a Data component [Active Directory Credential Request](https://attack.mitre.org/datasources/DS0026/#Active%20Directory%20Credential%20Request) which is linked to the following Techniques;

* [T1558: Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558)
    * [T1558.001: Golden Ticket](https://attack.mitre.org/techniques/T1558/001)
    * [T1558.003: Kerberoasting](https://attack.mitre.org/techniques/T1558/003)
    * [T1558.004: AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004)

This is very useful information to have.

For example, if an organisation is using Active Directory, it is very likely their SIEM is ingesting Active Directory logs for detection.

Assuming the logs cover Active Directory Credential Requests, with the right detection rules, the organisation would be able to detect the Techniques shown above.

To better document this coverage of Data Sources flowing into the SIEM, the Organisation could create a new layer covering all the Techniques associated to the Data Sources being monitored.

<img class="img-fluid" src="/assets/images/blog/2024-07-11/navigator-data-sources.png" alt="Navigator data sources" title="Navigator data sources" />

To create a new layer for Techniques associated with Data Sources; search for the Data Source, find the correct Data Source(s), and click select.

### Mapping Intelligence Reports to Data Sources being monitored

Continuing with the example, now imagine the organisation is analysing APT 39 and wants to ensure they are prepared.

<img class="img-fluid" src="/assets/images/blog/2024-07-11/navigator-data-source-visibility.png" alt="Navigator data source visibility" title="Navigator data source visibility" />

Above, I've overlaid a layer containing APT 39 Techniques against the Techniques linked to Data Source being monitored by the organisation.

As you can see in the legend:

* green: represents Techniques related to Data Sources being monitored and leveraged by APT 39
* red: represents Techniques being leveraged by APT 39 but not Techniques related to Data Sources being monitored, and finally,
* orange: represents Techniques related to Data Sources being monitored but not leveraged by APT 39.

In short, the Techniques in red indicate those used by APT 39 the organisation will not be able to detect.

If my organisation suspects we might be a target of this group, we might want to consider our detection rules.

Of course, the ability to detect the Techniques depends on whether the right detection rules are in place for the specific way the threat is exploiting the Technique (more on that in a bit).

However, before I get into that, let us take a Technique in red (related to Data Sources that I am not monitoring) and see what Data Sources are linked to it (so that the organisation can start ingesting them, should they be relevant to their network);

<img class="img-fluid" src="/assets/images/blog/2024-07-11/navigator-view-technique-external.png" alt="Navigator data source lookup" title="Navigator data source lookup" />

To uncover the Data Sources where there are blindspots, right click on the Techniques in red, and select view Technique.

<img class="img-fluid" src="/assets/images/blog/2024-07-11/detection-attack-website.png" alt="Navigator data source lookup" title="Navigator data source lookup" />

This opens up the MITRE ATT&CK website on the Technique where the associated Data Sources are listed.

Take for example the Technique [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/) highlighted in red. One of the related Data Sources is [DS0028: Logon Session](https://attack.mitre.org/datasources/DS0028/).

It's also possible to do this in [CTI Butler](https://www.ctibutler.com/) too:

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc.type == "attack-pattern"
  LET ext_refs = doc.external_references != null ? doc.external_references : []
  FILTER IS_ARRAY(ext_refs)
  AND LENGTH(
    FOR ref IN ext_refs
      FILTER ref.external_id == "T1078"
      RETURN ref
  ) > 0
  RETURN [doc]
```

Therefore, it is important the organisation considers monitoring logs that contain Logon Sessions. In some cases, the Data Sources might not always be applicable, for example, if you are not using Active Directory (in which case cannot be exploited).

### Detection Coverage in ATT&CK Navigator

Once you are collecting the necessary Data Sources to detect an attack, the next step is to ensure that detection rules exist for the Techniques.

In a similar way to before, this is just a process of taking a live detection rule, mapping it the relevant ATT&CK Techniques, and then modelling these on the ATT&CK Navigator.

Take this Sigma Rule:

https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/activity_logs/azure_ad_user_added_to_admin_role.yml

It monitors `azure` `activitylogs` for `Add member to role.` operations, where the properties are upgraded to `Administrator` or `Admins`.

In the `tags` section of the rule the associated ATT&CK Tactic is [TA003: Persistence](https://attack.mitre.org/tactics/TA0003/) and Sub-Technique [T1098.003: Account Manipulation.Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/).

This Sigma data is also represented as STIX using our [sigma2stix](https://github.com/muchdogesec/sigma2stix/) conversion utility.

The data is also available in CTI Butler;

```sql
FOR doc IN sigma_rules_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "r2024-05-13"
  AND doc.name == "User Added to an Administrator's Azure AD Role"
  LET keys_to_remove = (
    FOR key IN ATTRIBUTES(doc, true)
    FILTER STARTS_WITH(key, "_")
    RETURN key
  )
  RETURN UNSET(doc, keys_to_remove)

```

```json
[
  {
    "_bundle_id": "bundle--c524d1c9-1f7e-5cc9-8ad3-7ac3f9444e94",
    "_file_name": "sigma-rule-bundle-r2024-05-13.json",
    "_id": "sigma_rules_vertex_collection/indicator--b64185c6-d32c-56a0-a139-04b41da0f1d3",
    "_is_latest": false,
    "_key": "indicator--b64185c6-d32c-56a0-a139-04b41da0f1d3",
    "_record_created": "2024-05-29T19:36:19.244993",
    "_record_md5_hash": "c139d4d7414bc6e2b730d96b05e68330",
    "_record_modified": "2024-05-29T19:36:19.244993",
    "_rev": "_h6UhkZa--N",
    "_stix2arango_note": "r2024-05-13",
    "created": "2021-10-04T00:00:00.000Z",
    "created_by_ref": "identity--860f4c0f-8c26-5889-b39d-ce94368bc416",
    "description": "User Added to an Administrator's Azure AD Role. The following false positives can result from this detection; PIM (Privileged Identity Management) generates this event each time 'eligible role' is enabled.",
    "external_references": [
      {
        "source_name": "sigma-rule",
        "url": "https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/activity_logs/azure_ad_user_added_to_admin_role.yml",
        "external_id": "rule"
      },
      {
        "source_name": "sigma-rule",
        "description": "ebbeb024-5b1d-4e16-9c0c-917f86c708a7",
        "external_id": "id"
      },
      {
        "source_name": "sigma-rule",
        "description": "medium",
        "external_id": "level"
      },
      {
        "source_name": "sigma-rule",
        "description": "test",
        "external_id": "status"
      },
      {
        "source_name": "sigma-rule",
        "description": "Raphaël CALVET, @MetallicHack",
        "external_id": "author"
      },
      {
        "source_name": "ATTACK",
        "description": "tactic",
        "external_id": "persistence"
      },
      {
        "source_name": "ATTACK",
        "description": "tactic",
        "external_id": "privilege_escalation"
      },
      {
        "source_name": "mitre-attack",
        "url": "https://attack.mitre.org/techniques/T1098.003",
        "external_id": "T1098.003"
      },
      {
        "source_name": "mitre-attack",
        "url": "https://attack.mitre.org/techniques/T1078",
        "external_id": "T1078"
      },
      {
        "source_name": "sigma-rule",
        "description": "https://m365internals.com/2021/07/13/what-ive-learned-from-doing-a-year-of-cloud-forensics-in-azure-ad/",
        "external_id": "reference"
      }
    ],
    "id": "indicator--b64185c6-d32c-56a0-a139-04b41da0f1d3",
    "indicator_types": [
      "malicious-activity",
      "anomalous-activity"
    ],
    "modified": "2022-10-09T00:00:00.000Z",
    "name": "User Added to an Administrator's Azure AD Role",
    "object_marking_refs": [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--860f4c0f-8c26-5889-b39d-ce94368bc416"
    ],
    "pattern": "{'title': \"User Added to an Administrator's Azure AD Role\", 'id': 'ebbeb024-5b1d-4e16-9c0c-917f86c708a7', 'status': 'test', 'description': \"User Added to an Administrator's Azure AD Role\", 'references': ['https://m365internals.com/2021/07/13/what-ive-learned-from-doing-a-year-of-cloud-forensics-in-azure-ad/'], 'author': 'Raphaël CALVET, @MetallicHack', 'date': '2021/10/04', 'modified': '2022/10/09', 'tags': ['attack.persistence', 'attack.privilege_escalation', 'attack.t1098.003', 'attack.t1078'], 'logsource': {'product': 'azure', 'service': 'activitylogs'}, 'detection': {'selection': {'Operation': 'Add member to role.', 'Workload': 'AzureActiveDirectory', 'ModifiedProperties{}.NewValue|endswith': ['Admins', 'Administrator']}, 'condition': 'selection'}, 'falsepositives': [\"PIM (Privileged Identity Management) generates this event each time 'eligible role' is enabled.\"], 'level': 'medium'}",
    "pattern_type": "sigma",
    "spec_version": "2.1",
    "type": "indicator",
    "valid_from": "2021-10-04T00:00:00Z"
  }
]
```

Adding ATT&CK data to your rules makes it easy to create layers for each of them in the Navigator.

The `logsource` part of this Sigma detection rule can also be directly tied to ATT&CK Data Source Objects which helps to perform the initial task of linking ATT&CK Techniques to a rule.

In this example the relevant Data Source is [DS0026: Active Directory](https://attack.mitre.org/datasources/DS0026/) > Active Directory Object Modification (which is linked to [T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098/)). In this case, the creator of this rule might therefore want to add the `tags` `attack.ds0026`.

Once complete, the layers for each rule can then be combined into a single layer displaying a complete picture of your defensive posture. 

To help me keep track of all the rules I have added, I make sure the rule ID is added to each layer (under layer metadata fields).

And by associating ATT&CK Techniques to detection rules, you can also take advantage of ATT&CK Mitigations:

> Course of Action (`course-of-action`): represent ATT&CK [Mitigations](https://attack.mitre.org/mitigations/enterprise/). Mitigations represent security concepts and classes of technologies that can be used to prevent a technique or sub-technique from being successfully executed.

Mitigations provide defenders with ways in which they can take action during an incident when a detection rule linked to an associate Technique is triggered.

For example, if I right click the Sub-Technique [T1098.003: Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/) in Navigator I can see that is has the following ATT&CK Mitigations:

<img class="img-fluid" src="/assets/images/blog/2024-07-11/mitigations-attack-website.png" alt="Navigator mitigations" title="Navigator mitigations" />

* [M1032: Multi-factor Authentication](https://attack.mitre.org/mitigations/M1032/)
* [M1026: Privileged Account Management](https://attack.mitre.org/mitigations/M1026/)

In this case [M1026: Privileged Account Management](https://attack.mitre.org/mitigations/M1026/) is most relevant to the detection.

Assuming this rule was triggered I could use some of this information to help with remediation and improving defenses.

## Navigator beyond ATT&CK

We spent some time recently looking at [DISARM](https://www.disarm.foundation/framework) which aims to provide a single knowledge-base for disinformation classifications.

In the way MITRE ATT&CK has provided a standard for contextual information about adversary tactics and techniques based on real-world observations, DISARM aims to do the same for disinformation.

Part of what we worked on was a tool, [disarm2stix](https://github.com/muchdogesec/disarm2stix/), that converted the DISARM Framework into STIX 2.1 objects.

In modelling those objects, we wanted to ensure they were compliant with the ATT&CK structure so we could work with it in existing ATT&CK tools, like Navigator.

To do this we needed to create the following STIX objects, with the MITRE custom properties.

* `x-mitre-matrix`: for the Matrix
* `x-mitre-tactic`: for each Tactic
* `attack-pattern`: for Techniques or Sub-Techniques

If you're new to MITRE ATT&CK, [read this post that details more about the structure of each object](/blog/mitre_attack_data_structure).

To demonstrate, here is an example of each object type with the required MITRE custom properties.

Matrix:

```json
        {
            "type": "x-mitre-matrix",
            "spec_version": "2.1",
            "id": "x-mitre-matrix--03e1a731-175d-5181-ba28-8be2e2159da9",
            "created_by_ref": "identity--8700e156-6ce9-5090-8589-f9d0aef7bdb7",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2024-03-13T00:00:00.000Z",
            "name": "DISARM Red Framework",
            "description": "Incident creator TTPs.",
            "tactic_refs": [
                "x-mitre-tactic--b977ad29-eb0c-5f09-bb2f-6d3f23e2a175",
                "x-mitre-tactic--82beb3f6-7be5-502d-9511-b6264777171e",
                "x-mitre-tactic--10ccaa61-bf44-56ec-b1a7-3fc01942ec6d",
                "x-mitre-tactic--5991cba0-faaf-51ee-9928-4deba0ca83b6",
                "x-mitre-tactic--2c0826a4-1598-5909-810a-792dda66651d",
                "x-mitre-tactic--787a1b03-3797-5ccb-bc2e-049332bd3c94",
                "x-mitre-tactic--fdbba12c-028c-5707-8d12-83cddfd0b9e8",
                "x-mitre-tactic--c8de9ad5-0d1d-5ece-b18b-e474b6162104",
                "x-mitre-tactic--7ebacd41-0ee5-5628-9d85-a7d52db80821",
                "x-mitre-tactic--8a30baff-0b0c-5bab-8066-26655d672640",
                "x-mitre-tactic--2bb32a6b-0893-5d9c-a362-d41cb2a4a6ae",
                "x-mitre-tactic--ec5943c5-cf40-59dd-a7ed-c2175fc9727a",
                "x-mitre-tactic--c597dc51-891f-5fe0-a2ab-dd2c245ed0f4",
                "x-mitre-tactic--a17f30bf-131f-5f29-bd3b-16b801bf4084",
                "x-mitre-tactic--cc6cd844-a777-5265-9216-e439b16b339b",
                "x-mitre-tactic--92928c79-f2cc-5cd3-aaf8-27254fdd79da"
            ],
            "external_references": [
                {
                    "source_name": "DISARM",
                    "url": "https://www.disarm.foundation/",
                    "external_id": "DISARM"
                }
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--8700e156-6ce9-5090-8589-f9d0aef7bdb7"
            ]
        }
```

Tactic:

```json
        {
            "type": "x-mitre-tactic",
            "spec_version": "2.1",
            "id": "x-mitre-tactic--b977ad29-eb0c-5f09-bb2f-6d3f23e2a175",
            "created_by_ref": "identity--8700e156-6ce9-5090-8589-f9d0aef7bdb7",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2024-03-13T00:00:00.000Z",
            "name": "Plan Strategy",
            "description": "Define the desired end state, i.e. the set of required conditions that defines achievement of all objectives.",
            "external_references": [
                {
                    "source_name": "DISARM",
                    "url": "https://raw.githubusercontent.com/DISARMFoundation/DISARMframeworks/main/generated_pages/tactics/TA01.md",
                    "external_id": "TA01"
                }
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--8700e156-6ce9-5090-8589-f9d0aef7bdb7"
            ],
            "x_mitre_shortname": "plan-strategy"
        }
```

Technique:

```json
        {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--6697e4c7-d4b1-509b-a906-f1251bafed53",
            "created_by_ref": "identity--8700e156-6ce9-5090-8589-f9d0aef7bdb7",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2024-03-13T00:00:00.000Z",
            "name": "Create Inauthentic Social Media Pages and Groups",
            "description": "Create key social engineering assets needed to amplify content, manipulate algorithms, fool public and/or specific incident/campaign targets. Computational propaganda depends substantially on false perceptions of credibility and acceptance. By creating fake users and groups with a variety of interests and commitments, attackers can ensure that their messages both come from trusted sources and appear more widely adopted than they actually are.",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "disarm",
                    "phase_name": "establish-assets"
                }
            ],
            "external_references": [
                {
                    "source_name": "DISARM",
                    "url": "https://raw.githubusercontent.com/DISARMFoundation/DISARMframeworks/main/generated_pages/techniques/T0007.md",
                    "external_id": "T0007"
                }
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--8700e156-6ce9-5090-8589-f9d0aef7bdb7"
            ],
            "x_mitre_is_subtechnique": false,
            "x_mitre_platforms": [
                "Windows",
                "Linux",
                "Mac"
            ],
            "x_mitre_version": "2.1"
        }
```

Sub-Technique

```json
        {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--b4fa73b9-327b-58e1-9a44-637e9d045d46",
            "created_by_ref": "identity--8700e156-6ce9-5090-8589-f9d0aef7bdb7",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2024-03-13T00:00:00.000Z",
            "name": "Conduct Crowdfunding Campaigns",
            "description": "An influence operation may Conduct Crowdfunding Campaigns on platforms such as GoFundMe, GiveSendGo, Tipeee, Patreon, etc.",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "disarm",
                    "phase_name": "drive-offline-activity"
                }
            ],
            "external_references": [
                {
                    "source_name": "DISARM",
                    "url": "https://raw.githubusercontent.com/DISARMFoundation/DISARMframeworks/main/generated_pages/techniques/T0017.001.md",
                    "external_id": "T0017.001"
                }
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--8700e156-6ce9-5090-8589-f9d0aef7bdb7"
            ],
            "x_mitre_is_subtechnique": true,
            "x_mitre_platforms": [
                "Windows",
                "Linux",
                "Mac"
            ],
            "x_mitre_version": "2.1"
        }
```

[Here is a full bundle file of objects produced by disarm2stix](https://raw.githubusercontent.com/muchdogesec/cti_knowledge_base_store/main/disarm/disarm-bundle-v1_4.json).

Which once imported to Navigator looks as follows;

<img class="img-fluid" src="/assets/images/blog/2024-07-11/navigator-using-disarm.png" alt="Navigator using DISARM" title="Navigator using DISARM" />