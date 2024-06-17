---
date: 2024-07-25
last_modified: 2024-07-25
title: "Mapping CVE to MITRE ATT&CK"
description: "Being able to link CVEs not only allows for you to filter them on the Tactic and Techniques being used, but also deeper information like the tools being used. Here's a basic proof-of-concept you can implement."
categories:
  - PRODUCTS
tags: [
    STIX
]
products:
    - stix2arango
    - CTI Butler
author_staff_member: david-greenwood
image: /assets/images/blog/2024-07-23/header.png
featured_image: /assets/images/blog/2024-07-23/header.png
layout: post
published: false
redirect_from:
  - 
---


[I have described previously about how CTI Butler joins data from different knowledgebase](/blog/cti_knowledge_base_graph).

One of the features I've recently being working on is linking the 200k+ CVE objects in CTI Butler to ATT&CK (it already links them to Sigma Rules, CWEs and CPEs).

Imagine being able to begin a hunt by asking; which CVEs published in the last month are using the ATT&CK Enterprise Technique, Content Injection (T1659)? Which CVEs are using PACEMAKER (S1109)? [Or any of the other object types reported by ATT&CK](/blog/mitre_attack_data_structure).

Of course this not only allows you to pivot on CVEs using ATT&CK, but also any other information you might hold that is linked into MITRE ATT&CK (e.g. you might be tracking actors using ATT&CK tools, etc.).

The problem is, how do you take a CVE and link it ATT&CK.

## Planning a proof-of-concept

[CTI Butler](https://www.ctibutler.com/) already holds all published CVEs in STIX 2.1 format.

For this use-case we only case about the Vulnerability object (because these contain the most descriptive information about each CVE).

For example to get all CVEs published in 2018

```sql
FOR doc IN nvd_cve_vertex_collection
    FILTER doc.type == "vulnerability"
    AND doc.revoked != true
    AND doc.created >= "2020-01-01T00:00:00.000Z" AND doc.created <= "2020-12-31T23:59:59.999Z"
    COLLECT WITH COUNT INTO length
    RETURN length
```

For demo purposes, lets look at a smaller subset of `description` for CVEs published in January 2020.

```sql
FOR doc IN nvd_cve_vertex_collection
    FILTER doc.type == "vulnerability"
    AND doc.revoked != true
    AND doc.created >= "2020-01-01T00:00:00.000Z" AND doc.created <= "2020-01-31T23:59:59.999Z"
    RETURN {
        id: doc.id,
        cve: doc.name,
        published: doc.created,
        modified: doc.modified,
        description: doc.description
        }
```

```json
[
  {
    "id": "vulnerability--7256211c-e7f8-521b-af2e-9575690af8f1",
    "cve": "CVE-2019-15985",
    "published": "2020-01-06T08:15:11.503Z",
    "modified": "2020-01-08T20:55:54.203Z",
    "description": "Multiple vulnerabilities in the REST and SOAP API endpoints of Cisco Data Center Network Manager (DCNM) could allow an authenticated, remote attacker to execute arbitrary SQL commands on an affected device. To exploit these vulnerabilities, an attacker would need administrative privileges on the DCNM application. For more information about these vulnerabilities, see the Details section of this advisory. Note: The severity of these vulnerabilities is aggravated by the vulnerabilities described in the Cisco Data Center Network Manager Authentication Bypass Vulnerabilities advisory, published simultaneously with this one."
  },
  {
    "id": "vulnerability--620f4cb1-67db-57bb-b7b0-81f6c1b45519",
    "cve": "CVE-2016-6587",
    "published": "2020-01-08T18:15:10.213Z",
    "modified": "2020-01-13T19:50:15.777Z",
    "description": "An Information Disclosure vulnerability exists in the mid.dat file stored on the SD card in Symantec Norton Mobile Security for Android before 3.16, which could let a local malicious user obtain sensitive information."
  },
  {
    "id": "vulnerability--a68f7180-2a48-520c-b027-19a4404e3eaa",
    "cve": "CVE-2015-5952",
    "published": "2020-01-15T17:15:13.537Z",
    "modified": "2020-01-22T15:28:32.637Z",
    "description": "Directory traversal vulnerability in Thomson Reuters for FATCA before 5.2 allows remote attackers to execute arbitrary files via the item parameter."
  },
```

Side note, you might be wondering why a CVE with ID `CVE-2015-5952` was publushed in 2020. I am not to sure either, but this is the date being reported as the `created` time by the NVD CVE API that cve2stix uses to assign `published` value

```shell
curl --location 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-5952'
```

```json
{
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2024-06-15T15:07:46.420",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2015-5952",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2020-01-15T17:15:13.537",
                "lastModified": "2020-01-22T15:28:32.637",
```

Back to the subject at hand...

Most `description` values are very short.

Though I am still confident a well trained AI model will be more than capable.

As a POC I'll start with a generic model, GPT-4o;

```
<CVE ID>
<CVE DESCRIPTION>

What MITRE ATT&CK concepts are being described in this text?

For each ATT&CK concept identified, print your response as only JSON in the following structure:

{
    "CVE_ID": {
        "detected_objects": [
        {
            attack_id: "ID",
            attack_name: "NAME",
            confidence_score: "SCORE"
        },
        {
            attack_id: "ID",
            attack_name: "NAME",
            confidence_score: "SCORE"
        }
    ]
}

Where confidence score defines how sure you are this technique or subtechnique is being described in the text (between 0 [lowest] and 1 [highest])`
```

Lets try the above command with the description of CVE-2016-6587:

> An Information Disclosure vulnerability exists in the mid.dat file stored on the SD card in Symantec Norton Mobile Security for Android before 3.16, which could let a local malicious user obtain sensitive information.

```json
{
    "CVE-2016-6587": {
        "detected_objects": [
        {
            "attack_id": "T1005",
            "attack_name": "Data from Local System",
            "confidence_score": 0.9
        },
        {
            "attack_id": "T1586",
            "attack_name": "Compromise Accounts",
            "confidence_score": 0.7
        },
        {
            "attack_id": "T1589",
            "attack_name": "Gather Victim Identity Information",
            "confidence_score": 0.7
        }
    ]
}
```

At this point I'm not looking for model accuracy because the model can be swapped out easily as required -- we have some much better locally trained models, plus there are also off-the-shelf models, e.g. [those that ship with TRAM](/blog/getting_started_mitre_tram).

The point being is the general concept here works, and also allows me to set a confidence threshold in my code for allowing only high confidence ATT&CK matches.

So, to continue my proof of concept, lets assume my confidence threshold is >= 0.7 (so all the entries returned above match). Using this information I can now link the detected ATT&CK object IDs.

I can use a CTI Butler query to do this;

```sql
LET ATTACK_IDS = [
    "T1005",
    "T1586",
    "T1589"
]

LET enterprise_results = (
    FOR doc IN mitre_attack_enterprise_vertex_collection
        FILTER doc._stix2arango_note != "automatically imported on collection creation"
        AND doc._stix2arango_note == "v15.1"
        AND (doc.type != "x-mitre-collection" AND doc.type != "marking-definition" AND doc.type != "identity" AND doc.type != "x-mitre-matrix" AND doc.type != "x-mitre-data-component")
        AND doc.external_references != null AND IS_ARRAY(doc.external_references)
        FOR extRef IN doc.external_references
            FILTER extRef.external_id IN ATTACK_IDS
            AND extRef.source_name == "mitre-attack"
            RETURN {
                id: doc.id,
                attack_id: extRef.external_id,
                type: doc.type,
                collection: "enterprise"
            }
)

LET ics_results = (
    FOR doc IN mitre_attack_ics_vertex_collection
        FILTER doc._stix2arango_note != "automatically imported on collection creation"
        AND doc._stix2arango_note == "v15.1"
        AND (doc.type != "x-mitre-collection" AND doc.type != "marking-definition" AND doc.type != "identity" AND doc.type != "x-mitre-matrix" AND doc.type != "x-mitre-data-component")
        AND doc.external_references != null AND IS_ARRAY(doc.external_references)
        FOR extRef IN doc.external_references
            FILTER extRef.external_id IN ATTACK_IDS
            AND extRef.source_name == "mitre-attack"
            RETURN {
                id: doc.id,
                attack_id: extRef.external_id,
                type: doc.type,
                collection: "ics"
            }
)

LET mobile_results = (
    FOR doc IN mitre_attack_mobile_vertex_collection
        FILTER doc._stix2arango_note != "automatically imported on collection creation"
        AND doc._stix2arango_note == "v15.1"
        AND (doc.type != "x-mitre-collection" AND doc.type != "marking-definition" AND doc.type != "identity" AND doc.type != "x-mitre-matrix" AND doc.type != "x-mitre-data-component")
        AND doc.external_references != null AND IS_ARRAY(doc.external_references)
        FOR extRef IN doc.external_references
            FILTER extRef.external_id IN ATTACK_IDS
            AND extRef.source_name == "mitre-attack"
            RETURN {
                id: doc.id,
                attack_id: extRef.external_id,
                type: doc.type,
                collection: "mobile"
            }
)

RETURN UNION_DISTINCT(
    enterprise_results,
    ics_results,
    mobile_results
)
```

```json
[
  [
    {
      "id": "attack-pattern--81033c3b-16a4-46e4-8fed-9b030dd03c4a",
      "attack_id": "T1586",
      "type": "attack-pattern",
      "collection": "enterprise"
    },
    {
      "id": "attack-pattern--3c4a2599-71ee-4405-ba1e-0e28414b4bc5",
      "attack_id": "T1005",
      "type": "attack-pattern",
      "collection": "enterprise"
    },
    {
      "id": "attack-pattern--5282dd9a-d26d-4e16-88b7-7c0f4553daf4",
      "attack_id": "T1589",
      "type": "attack-pattern",
      "collection": "enterprise"
    },
    {
      "id": "course-of-action--7ee0879d-ce4f-4f54-a96b-c532dfb98ffd",
      "attack_id": "T1005",
      "type": "course-of-action",
      "collection": "enterprise"
    }
  ]
]
```

I've included all ATT&CK objects, so you can see a Course of Action returned above. 


FOR doc IN mitre_attack_enterprise_vertex_collection
        FILTER doc._stix2arango_note != "automatically imported on collection creation"
        AND doc._stix2arango_note == "v15.1"
        AND (doc.type != "x-mitre-collection" OR doc.type != "marking-definition" OR doc.type != "identity" OR doc.type != "x-mitre-collection" OR doc.type != "x-mitre-matrix" OR doc.type !="x-mitre-data-component")
        FOR extRef IN doc.external_references
           FILTER extRef.external_id == "T1005"
            AND extRef.source_name == "mitre-attack"
            RETURN {
                id: doc.id,
                type: doc.type,
                collection: "enterprise"
            }


FILTER extRef.external_id == "T1113"
    AND extRef.source_name == "mitre-attack"


vulnerability--620f4cb1-67db-57bb-b7b0-81f6c1b45519
Note, I do not filter by object type, because ATT&CK trained AI models will also return software, data sources, etc. in the response.



I knew that the `description` field inside the Vulnerability object would likely hold the best source of data to use when trying to infer what ATT&CK object are being use


This would then give you immediate insight into all intel linked to T1659 like th

### 9. CVE (`vulnerability`) -> ATT&CK (`attack-pattern`)

At the time of writing, this is my favourite relationship in CTI Butler. It makes it possible to search for CVEs using MITRE ATT&CK Techniques.

To do this, arango_cti_processor uses the latest OpenAI models to generate mappings.

Using `description` inside each Vulnerability object inside the `nvd_cpe_vertex_collection`, the following prompt is used;

```
[CVE DESCRIPTION]

What MITRE ATT&CK techniques and subtechniques are being described in this text?

For each ATT&CK technique or sub-technique identified, print your response as only JSON in the following structure:

{
    attack_id: "ID",
    attack_name: "NAME",
    confidence_score: "SCORE"
}

Where confidence score defines how sure you are this technique or subtechnique is being described in the text (between 0 [lowest] and 1 [highest])
```

This will return response that looks as follows;

```json
[
    {
        "attack_id": "T1078",
        "attack_name": "Valid Accounts",
        "confidence_score": "0.9"
    },
    {
        "attack_id": "T1110.001",
        "attack_name": "Password Guessing",
        "confidence_score": "0.6"
    }
]
```

Anything with a confidence greater than 0.4 (e.g. Active Scanning above) is considered that the CVE is referencing an ATT&CK technique in CTI Butler (this threshold can be manually set in your own install of stix2arango if you disagree).

The ATT&CK STIX object can be identified in the three MITRE ATT&CK ArangoDB Collections:

1. `mitre_attack_enterprise_vertex_collection`
2. `mitre_attack_mobile_vertex_collection`
3. `mitre_attack_ics_vertex_collection`

The `attack_id` returned by the AI can be searched against the STIX `attack-pattern` object `external_references.external_id` property values (where `external_references.source_name=mitre-attack`).

Therefore, in the above example, T1078 and T1110.001 would be searched, which would return `attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81` (T1078) and `attack-pattern--09c4c11e-4fa1-4f8c-8dad-3cf8e69ad119` (T1110.001) both in the `mitre_attack_enterprise_vertex_collection`

So in this case, two relationship objects would be generated with the following values:

* relationship 1
  * `"source_ref": "vulnerability--0078c56a-6545-53cd-ace6-695a775e8fd4"` (CVE-2023-49355)
  * `"target_ref": "attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81"` (MITRE ATT&CK Enterprise T1078)
  * `"relationship_type": "exploited-using"`
* relationship 2
  * `"source_ref": "vulnerability--0078c56a-6545-53cd-ace6-695a775e8fd4"` (CVE-2023-49355)
  * `"target_ref": "attack-pattern--09c4c11e-4fa1-4f8c-8dad-3cf8e69ad119"` (MITRE ATT&CK Enterprise T1110.001)
  * `"relationship_type": "exploited-using"`


Here is the full SRO for relationship 1:

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--72f25d31-ca82-5ccc-99d8-8949428c87a2",
    "created_by_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "relationship_type": "exploited-using",
    "source_ref": "vulnerability--0078c56a-6545-53cd-ace6-695a775e8fd4",
    "target_ref": "attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
}
```

To generate the ID of SRO;

* namespace: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3`
* value `exploited-using+nvd_cve_vertex_collection+vulnerability--0078c56a-6545-53cd-ace6-695a775e8fd4+mitre_attack_enterprise_vertex_collection+attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81`

Gives a UUID v5 of `4e781b39-2b09-5bf7-a292-7f7466070688`.