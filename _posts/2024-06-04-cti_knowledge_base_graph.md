---
date: 2024-06-04
last_modified: 2024-06-04
title: "Creating a Cyber Threat Intelligence Graph"
description: "Joining the data held in knowledge-bases like MITRE ATT&CK allows for rich classification of cyber threat intelligence. Here is how we do that, so you can too."
categories:
  - PRODUCTS
  - DIY
tags: [
	MITRE,
    ATT&CK,
    CWE,
    NVD,
    CPE,
    CWE,
    CVE,
    CAPEC,
    Sigma Rules,
    YARA,
    DISARM,
    STIX,
    ArangoDB,
    STIX
]
products:
    - CTI Butler
    - stix2arango
    - arango_cti_processor
author_staff_member: david-greenwood
image: /assets/images/blog/2024-06-04/header.png
featured_image: /assets/images/blog/2024-06-04/header.png
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

CTI Butler ingests STIX structured data from popular CTI knowledge-bases.

Here is a diagram that shows where data comes from, how it is stored, and finally, how it is joined.

<iframe width="768" height="432" src="https://miro.com/app/live-embed/uXjVKQPtpEk=/?moveToViewport=-2094,-1337,3988,1782&embedId=331762124208" frameborder="0" scrolling="no" allow="fullscreen; clipboard-read; clipboard-write" allowfullscreen></iframe>

[Here is where you can find CTI Butler](https://www.ctibutler.com/).

Want to know more? Read on...

## Does this not already exist?

Surprisingly, no.

Many TIPs have custom implementations of a few of the knowledge-bases we support but don't store the data as pure STIX. Those that do are more focused on joining the objects to intelligence research than other knowledge-bases.

We wanted to write search queries like; what Sigma Rules are affected by CVE-XXXX, and what ATT&CK techniques are used when exploiting said vulnerability?

Our team could find nothing that existed with such rich relationships between knowledge-bases allowing us to do this, so we set out to build CTI Butler.

## Where does the data that powers CTI Butler come from?

CTI Butler uses the following CTI knowledge-bases:

1. MITRE ATT&CK Enterprise
    * [data taken directly from the MITRE repository](https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack)
2. MITRE ATT&CK ICS
    * [data taken directly from the MITRE repository](https://github.com/mitre-attack/attack-stix-data/tree/master/ics-attack)
3. MITRE ATT&CK Mobile
    * [data taken directly from the MITRE repository](https://github.com/mitre-attack/attack-stix-data/tree/master/mobile-attack)
4. MITRE CAPEC
    * [data taken directly from the MITRE repository](https://github.com/mitre/cti/tree/master/capec/2.1)
5. MITRE CWE
    * [data converted to STIX using cwe2stix](https://github.com/muchdogesec/cwe2stix/issues)
6. NVD CVE
    * [data converted to STIX using cve2stix (run by cxe2stix_helper)](https://github.com/muchdogesec/cxe2stix_helper/)
7. NVD CPE
    * [data converted to STIX using cpe2stix (run by cxe2stix_helper)](https://github.com/muchdogesec/cxe2stix_helper/)
8. Sigma Rules
    * [data converted to STIX using sigma2stix](https://github.com/muchdogesec/sigma2stix)
9. YARA Rules
    * [data converted to STIX using yara2stix](https://github.com/muchdogesec/yara2stix)
10. DISARM Red Framework
    * [data converted to STIX using disarm2stix](https://github.com/muchdogesec/disarm2stix)

All ten sources provide STIX 2.1 Bundles of the data.

## Where is all this data stored by CTI Butler?

If you have used any of our tools you will know we use ArangoDB to store STIX objects.

I will not explain why we use ArangoDB here, [this post from Sekoia explains it much better than I ever could](https://medium.com/@OWN_team/threat-intelligence-data-storage-make-it-easy-with-arangodb-11e29dd4de45).

To get the Bundles into ArangoDB we use a small utility our team built called [stix2arango](https://github.com/muchdogesec/stix2arango). In short stix2arango;

1. takes a STIX bundle (from one of the aforementioned sources)
2. creates an ArangoDB Database / Collections to store the knowledge-base data (if they do not already exist)
3. inserts the data

To elaborate on step 2, all data is stored in an ArangoDB database called "CTI".

The collections for each knowledge-base source are named as follows;

1. MITRE ATT&CK Enterprise (`mitre_attack_enterprise_vertex_collection` / `mitre_attack_enterprise_edge_collection`)
2. MITRE ATT&CK ICS (`mitre_attack_ics_vertex_collection` / `mitre_attack_ics_edge_collection`)
3. MITRE ATT&CK Mobile (`mitre_attack_mobile_vertex_collection` / `mitre_attack_mobile_edge_collection`)
4. MITRE CAPEC (`mitre_capec_vertex_collection` / `mitre_capec_edge_collection`)
5. MITRE CWE (`mitre_cwe_vertex_collection` / `mitre_cwe_edge_collection`)
6. NVD CVE (`nvd_cve_vertex_collection` / `nvd_cve_edge_collection`)
7. NVD CPE (`nvd_cpe_vertex_collection` / `nvd_cpe_edge_collection`)
8. Sigma Rules (`sigma_rules_vertex_collection` / `sigma_rules_edge_collection`)
9. YARA Rules (`yara_rules_vertex_collection` / `yara_rules_edge_collection`)
10. DISARM Red Framework (`disarm_vertex_collection` / `disarm_edge_collection`)

Note, the `*_edge` collections hold STIX Relationship objects from the knowledge-base bundles (in addition to the ones created by stix2arango, as described in this post), and the `*_vertex` collections hold all the other STIX objects present in the bundles.

## Versioning of Objects

Most knowledge-bases supported by CTI Butler are versioned.

Take ATT&CK as an example, [you can see in the ATT&CK repository the various versions of the Enterprise Matrix](https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack).

The only exceptions to this is for the NVD data, whereby the STIX Bundles are grouped (by cve2stix and cpe2stix) by the time of the last update for the CVE or CPE respectively. The reason for this is simple, the CVE and CPE dataset is HUGE. A single bundle of all CVE STIX objects would easily exceed 2GB.

stix2arango also takes care of versioning of each knowledge-base, allowing users to retrieve objects by a specific version of a knowledge-base.

If an object with a non-unique STIX `id` is inserted, but a different `modified` time value, stix2arango will ensure the latest version (highest `modified` time) is marked with the hidden property `_is_latest==true` (all other versions of the same object will be market `_is_latest==false`).

This allows for the latest version of each knowledge-base to be easily retrieve the latest version of each object.

For example, to always get the latest version of MITRE ATT&CK in CTI Butler I can use the query:

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
    FILTER _is_latest == true
    RETURN [doc]
```

CTI Butler also uses another feature of stix2arango to track versioning. When passing a STIX Bundle to stix2arango the `--stix2arango_note` flag is used to add the version of the knowledgebase the Object was inserted from. 

Take each ATT&CK Bundle for example, CTI Butler currently uses the flags; `--stix2arango_note 15.0`, `--stix2arango_note 14.1`, `--stix2arango_note 14.0`, and so on (for each available ATT&CK version).

Here is an example of a full stix2arango command used by CTI Butler for inserting version 14.0 of the ATT&CK Enterprise STIX Bundle:

```shell
python3 stix2arango.py \
    --file enterprise-attack-14.0.json \
    --database cti-butler \
    --collection mitre_attack_enterprise \
    --stix2arango_note v14.0
```

This allows you to write queries to get specific versions of each knowledge.

Here is how I would then request all software objects in ATT&CK version 14;

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
    FILTER doc.type == "tool"
    AND doc._stix2arango_note == "v14.0"
    RETURN [doc]
```

## How (and why) the knowledge-bases in CTI Butler are joined

One of my favourite features of CTI Butler is the relationships it creates between different knowledge-bases it holds once they're imported.

At a high-level the data in CTI Butler is joined follows:

1. CAPEC (`attack-pattern`) -> ATT&CK (`attack-pattern`) [`technique`]
2. CAPEC (`attack-pattern`) -> CWE (`weakness`) [`exploits`]
3. CWE (`weakness`) -> CAPEC (`attack-pattern`) [`exploited-using`]
4. ATT&CK (`attack-pattern`) -> CAPEC (`attack-pattern`) [`relies-on`]
5. Sigma Rule (`indicator`) -> ATT&CK (`attack-pattern`) [`detects`]
6. Sigma Rule (`indicator`) -> CVE (`vulnerability`) [`detects`]
7. CVE (`vulnerability`) -> CWE (`weakness`) [`exploited-using`]
8. CVE (`indicator`) -> CPE (`software`) [`pattern-contains`]

The parenthesis (`()`) in the list above denote the STIX Object types in each knowledge-base that are used as the `source_ref` and `target_ref` used to create the joins. The square brackets (`[]`) define the STIX `relationship_type` used in the relationship object used to link them.

You can see all this visually here:

<iframe width="768" height="432" src="https://miro.com/app/live-embed/uXjVKQPtpEk=/?moveToViewport=-2094,-1337,3988,1782&embedId=331762124208" frameborder="0" scrolling="no" allow="fullscreen; clipboard-read; clipboard-write" allowfullscreen></iframe>

By linking the data in a graph structure like this allows for the traversal of the knowledge graph, or put in plain English; allows for the enrichment of knowledge-bases.

Take the example of a CVE being linked to a CPE. If an SBOM contained a specific CPE, it is easy to traverse the graph and find out what CVEs it is linked to.

Similarly CVEs being linked to ATT&CK Techniques. By classifying CVEs by ATT&CK Technique, it becomes simpler to understand how something is vulnerable and more-so, whether the appropriate controls are in place to either detect or remediate it.

Like most security products, the way the data is joined is fairly simplistic (although there are no smoke-and-mirrors here!).

CTI Butler is not directly responsible for these joins. That is done by another utility of ours called, [arango_cti_processor](https://github.com/muchdogesec/arango_cti_processor).

Let me show you...

### 1. CAPEC (`attack-pattern`) -> ATT&CK (`attack-pattern`)

All CAPEC objects are stored by stix2arango in an ArangoDB Collection called `mitre_capec_vertex_collection`.

CAPEC `attack-pattern` STIX Objects in this collection can contain one of more `external_references.source_name=ATTACK`.

Take [CAPEC-112](https://github.com/mitre/cti/blob/master/capec/2.1/attack-pattern/attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1.json) (`attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1`) as an example:

```json
            "external_references": [
                {
                    "external_id": "CAPEC-112",
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/112.html"
                },
                {
                    "external_id": "CWE-330",
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/330.html"
                },
                {
                    "external_id": "CWE-326",
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/326.html"
                },
                {
                    "external_id": "CWE-521",
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/521.html"
                },
                {
                    "description": "Brute Force",
                    "external_id": "T1110",
                    "source_name": "ATTACK",
                    "url": "https://attack.mitre.org/wiki/Technique/T1110"
                },
                {
                    "description": "Brute Force",
                    "external_id": "11",
                    "source_name": "WASC",
                    "url": "http://projects.webappsec.org/Brute-Force"
                },
                {
                    "description": "Brute force attack",
                    "source_name": "OWASP Attacks",
                    "url": "https://owasp.org/www-community/attacks/Brute_force_attack"
                }
```

See how one `external_references.source_name=ATTACK` is shown, with `external_references.external_id=T1110` (this is an ATT&CK Technique ID).

arango_cti_processor uses these references to create a STIX `relationship` Objects with the CAPEC object as the `source_ref` and the ATT&CK object as the `target_ref`.

ATT&CK technique objects (always `attack-pattern`s) are stored in one of three ArangoDB Collections by stix2arango:

1. `mitre_attack_enterprise_vertex_collection`
2. `mitre_attack_mobile_vertex_collection`
3. `mitre_attack_ics_vertex_collection`

The objects can looked up in these collections by searching for `external_references.source_name=mitre-attack` and the corresponding ATT&CK ID (e.g. `T1110`).

For example, here is a snippet of [ATT&CK T1110 found in the the `mitre_attack_enterprise_vertex_collection`](https://github.com/mitre/cti/blob/master/enterprise-attack/attack-pattern/attack-pattern--a93494bb-4b80-4ea1-8695-3236a49916fd.json) (`attack-pattern--a93494bb-4b80-4ea1-8695-3236a49916fd`) that would be linked to from CAPEC-112:

```json
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1110",
                    "external_id": "T1110"
                },
                {
                    "source_name": "TrendMicro Pawn Storm Dec 2020",
                    "description": "Hacquebord, F., Remorin, L. (2020, December 17). Pawn Storm\u2019s Lack of Sophistication as a Strategy. Retrieved January 13, 2021.",
                    "url": "https://www.trendmicro.com/en_us/research/20/l/pawn-storm-lack-of-sophistication-as-a-strategy.html"
                },
                {
                    "source_name": "Dragos Crashoverride 2018",
                    "description": "Joe Slowik. (2018, October 12). Anatomy of an Attack: Detecting and Defeating CRASHOVERRIDE. Retrieved December 18, 2020.",
                    "url": "https://www.dragos.com/wp-content/uploads/CRASHOVERRIDE2018.pdf"
                }
            ],
```

So in this case, one relationship object would be generated by arango_cti_processor with the following values:

* relationship 1
  * `"source_ref": "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"` (CAPEC-112)
  * `"target_ref": "attack-pattern--a93494bb-4b80-4ea1-8695-3236a49916fd"` (ATT&CK Enterprise T1110)
  * `"relationship_type": "technique"`

Here is the full SRO that would be created:

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--4a1b2d43-6d6d-5b3b-a7c8-b66ec17ce3d0",
    "created_by_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "relationship_type": "technique",
    "source_ref": "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1",
    "target_ref": "attack-pattern--a93494bb-4b80-4ea1-8695-3236a49916fd",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
}
```

To generate the ID of SROs, a UUIDv5 is generated using the namespace `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` and the `relationship_type+source_collection_name/source_ref+target_collection_name/target_ref` values.

Using the example above this would be:

* namespace: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3`
* value `technique+mitre_capec_vertex_collection+attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1+mitre_attack_enterprise_vertex_collection+attack-pattern--a93494bb-4b80-4ea1-8695-3236a49916fd`

Gives a UUID v5 of `4a1b2d43-6d6d-5b3b-a7c8-b66ec17ce3d0`.

All generated objects are stored in the source edge collection, `mitre_capec_edge_collection`.

### 2. CAPEC (`attack-pattern`) -> CWE (`weakness`)

This relationship is created in much the same way as CAPEC (`attack-pattern`) -> ATT&CK (`attack-pattern`) relationships.

You will see in the previous snippet of the [CAPEC-112](https://github.com/mitre/cti/blob/master/capec/2.1/attack-pattern/attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1.json) STIX object (`attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1`) there are also  `external_references.source_name=cwe` references.

The `external_references.external_id` defines the CWEs linked to this CAPEC, in this example; `CWE-330`, `CWE-326`, `CWE-521`.

CWE objects (`weakness`) are stored in an ArangoDB Collection by stix2arango called `mitre_cwe_vertex_collection`.

And again, in a similar way, CWE `weakness` objects can be identified . Here is a snippet of the STIX object for CWE-330 (`weakness--5c1cf10b-dc31-5536-a1b5-dc5094e7f4b2`):

```json
            "external_references": [
                {
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/330.html",
                    "external_id": "CWE-330"
                },
                {
                    "source_name": "Information Technology Laboratory, National Institute of Standards and Technology",
                    "description": "SECURITY REQUIREMENTS FOR CRYPTOGRAPHIC MODULES",
                    "url": "https://csrc.nist.gov/csrc/media/publications/fips/140/2/final/documents/fips1402.pdf",
                    "external_id": "REF-267"
                },
                {
                    "source_name": "John Viega, Gary McGraw",
                    "description": "Building Secure Software: How to Avoid Security Problems the Right Way",
                    "external_id": "REF-207"
                },
                {
                    "source_name": "Michael Howard, David LeBlanc",
                    "description": "Writing Secure Code",
                    "url": "https://www.microsoftpressstore.com/store/writing-secure-code-9780735617223",
                    "external_id": "REF-7"
                },
```

So in this case, three relationship objects would be generated by arango_cti_processor with the following values:

* relationship 1
  * `"source_ref": "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"` (CAPEC-112)
  * `"target_ref": "weakness--5c1cf10b-dc31-5536-a1b5-dc5094e7f4b2"` (CWE-330)
  * `"relationship_type": "exploits"`
* relationship 2
  * `"source_ref": "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"` (CAPEC-112)
  * `"target_ref": "weakness--3f87bca2-8785-543e-906e-cf2adb753c31"` (CWE-326)
  * `"relationship_type": "exploits"`
* relationship 3
  * `"source_ref": "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"` (CAPEC-112)
  * `"target_ref": "weakness--de02e88c-42c5-5ddf-b5d1-1c8aeac79926"` (CWE-521)
  * `"relationship_type": "exploits"`

Here is the full SRO that would be created for relationship 1:

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--a17c9525-c535-5ad9-b431-20f6568fef71",
    "created_by_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "relationship_type": "exploits",
    "source_ref": "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1",
    "target_ref": "weakness--5c1cf10b-dc31-5536-a1b5-dc5094e7f4b2",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
}
```

To generate the ID of SRO;

* namespace: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3`
* value `exploits+mitre_capec_vertex_collection+attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1+mitre_cwe_vertex_collection+weakness--5c1cf10b-dc31-5536-a1b5-dc5094e7f4b2`

Gives a UUID v5 of `a17c9525-c535-5ad9-b431-20f6568fef71`.

### 3. CWE (`weakness`) -> CAPEC (`attack-pattern`)

The joins happen in a similar way to the previous two examples, using data found in the `external_references` of both STIX objects.

As noted earlier CWE objects are stored by stix2arango in the `mitre_cwe_vertex_collection` and CAPEC objects in the `mitre_capec_vertex_collection`.

Taking an example CWE from the `mitre_cwe_vertex_collection`, this time CWE-1007 (`weakness--94110a45-2221-5fb5-aa09-322b8dfc4b6a`).

```json
            ],
            "external_references": [
                {
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/1007.html",
                    "external_id": "CWE-1007"
                },
                {
                    "source_name": "Michael Howard, David LeBlanc",
                    "description": "Writing Secure Code",
                    "url": "https://www.microsoftpressstore.com/store/writing-secure-code-9780735617223",
                    "external_id": "REF-7"
                },
                {
                    "source_name": "Gregory Baatard, Peter Hannay",
                    "description": "The 2011 IDN Homograph Attack Mitigation Survey",
                    "url": "http://ro.ecu.edu.au/cgi/viewcontent.cgi?article=1174&context=ecuworks2012",
                    "external_id": "REF-8"
                },
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/632.html",
                    "external_id": "CAPEC-632"
                }
            ],
```

Here joins to CAPEC from CWEs can be found where `external_references.source_name=capec`, where the actual CAPEC ID is found under the `external_references.external_id` property, in this case CAPEC-632 (`attack-pattern--c4e18b3f-0445-49e8-9bf1-d47a23082501`)

So in this case, one relationship object would be generated by arango_cti_processor with the following values:

* relationship 1
  * `"source_ref": "weakness--94110a45-2221-5fb5-aa09-322b8dfc4b6a"` (CWE-1007)
  * `"target_ref": "attack-pattern--c4e18b3f-0445-49e8-9bf1-d47a23082501"` (CAPEC-632)
  * `"relationship_type": "exploited-using"`

Here is the full SRO:

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--1f7a0bef-e81c-5535-94e8-93ba418c861a",
    "created_by_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "relationship_type": "exploited-using",
    "source_ref": "weakness--94110a45-2221-5fb5-aa09-322b8dfc4b6a",
    "target_ref": "attack-pattern--c4e18b3f-0445-49e8-9bf1-d47a23082501",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
}
```

To generate the ID of SRO;

* namespace: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3`
* value `exploited-using+mitre_cwe_vertex_collection+weakness--94110a45-2221-5fb5-aa09-322b8dfc4b6a+mitre_capec_vertex_collection+attack-pattern--c4e18b3f-0445-49e8-9bf1-d47a23082501`

Gives a UUID v5 of `1f7a0bef-e81c-5535-94e8-93ba418c861a`.

### 4. ATT&CK (`attack-pattern`) -> CAPEC (`attack-pattern`)

Again, `external_references` are used to generate the joins.

The source ATT&CK collections are:

1. `mitre_attack_enterprise_vertex_collection`
2. `mitre_attack_mobile_vertex_collection` (note, no current CAPECs referenced in the matrix (version 15.0))
3. `mitre_attack_ics_vertex_collection` (note, no current CAPECs referenced in the matrix (version 15.0))

And the target CAPEC collection:

1. `mitre_capec_vertex_collection`

As an example I will use T1044: File System Permissions Weakness (`attack-pattern--0ca7beef-9bbc-4e35-97cf-437384ddce6a`)

```json
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1044",
                    "url": "https://attack.mitre.org/techniques/T1044"
                },
                {
                    "external_id": "CAPEC-17",
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/17.html"
                },
```

Here we have a reference to CAPEC-17 (`attack-pattern--9ad2c2eb-9939-4590-9683-2e789692d262`).

So in this case, one relationship object would be generated by arango_cti_processor with the following values:

* relationship 1
  * `"source_ref": "attack-pattern--0ca7beef-9bbc-4e35-97cf-437384ddce6a"` (ATT&CK Enterprise T1044)
  * `"target_ref": "attack-pattern--9ad2c2eb-9939-4590-9683-2e789692d262"` (CAPEC-17)
  * `"relationship_type": "relies-on"`

Here is the full SRO:

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--71516b78-02a9-5cc6-9079-5142f49b39f8",
    "created_by_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "relationship_type": "relies-on",
    "source_ref": "attack-pattern--0ca7beef-9bbc-4e35-97cf-437384ddce6a",
    "target_ref": "attack-pattern--9ad2c2eb-9939-4590-9683-2e789692d262",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
}
```

To generate the ID of SRO;

* namespace: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3`
* value `relies-on+mitre_attack_enterprise_vertex_collection+attack-pattern--0ca7beef-9bbc-4e35-97cf-437384ddce6a+mitre_capec_vertex_collection+attack-pattern--9ad2c2eb-9939-4590-9683-2e789692d262`

Gives a UUID v5 of `71516b78-02a9-5cc6-9079-5142f49b39f8`.

### 5. Sigma Rule (`indicator`) -> ATT&CK (`attack-pattern` or `x-mitre-tactic`)

I am sure you're following along by now, Sigma Rules to ATT&CK object joins use the same logic as the last four examples.

Sigma Rules are stored by stix2arango in the collection `sigma_rules_vertex_collection`.

The ATT&CK target collections are:

1. `mitre_attack_enterprise_vertex_collection`
2. `mitre_attack_mobile_vertex_collection`
3. `mitre_attack_ics_vertex_collection`

Here's an example of Potential Compromised 3CXDesktopApp Update Activity (`indicator--e7581747-1e44-4d4b-85a6-0db0b4a00f2a`):

```json
    "external_references": [
        {
            "source_name": "sigma-rule",
            "external_id": "url",
            "url": "https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2023/TA/3CX-Supply-Chain/proc_creation_win_malware_3cx_compromise_susp_update.yml"
        },
        {
            "source_name": "sigma-rule",
            "external_id": "id",
            "description": "e7581747-1e44-4d4b-85a6-0db0b4a00f2a"
        },
        {
            "source_name": "sigma-rule",
            "external_id": "reference",
            "description": "https://www.linkedin.com/feed/update/urn:li:activity:7047435754834198529/"
        },
        {
            "source_name": "sigma-rule",
            "external_id": "author",
            "description": "Nasreddine Bencherchali (Nextron Systems)"
        },
        {
            "source_name": "sigma-rule",
            "external_id": "license",
            "description": "None"
        },
        {
            "source_name": "sigma-rule",
            "external_id": "detection",
            "description": "emerging_threats"
        },
        {
            "source_name": "sigma-rule",
            "external_id": "status",
            "description": "test"
        },
        {
            "source_name": "sigma-rule",
            "external_id": "level",
            "description": "high"
        },
        {
            "source_name": "ATTACK",
            "external_id": "technique",
            "description": "t1218"
        },
        {
            "source_name": "ATTACK",
            "external_id": "tactic",
            "description": "defense_evasion"
        },
        {
            "source_name": "ATTACK",
            "external_id": "tactic",
            "description": "execution"
        }
    ],
```

Sigma objects contain ATT&CK Technique objects (`attack-pattern`), as per other examples. However, unlike other examples they also contain ATT&CK Tactics (`x-mitre-tactic`).

The way ATT&CK data is referenced in Sigma Rule Indicators is slightly different to the other examples, as is the way the STIX objects are searched.

For Techniques, that is where the objects is as follows:

```json
            "source_name": "ATTACK",
            "external_id": "technique",
```

The `description` value in the object, e.g. `t1218` above, is used to search ATT&CK objects in each ATT&CK collection using the `external_references.external_id` property.

So in this case, one relationship object would be generated with the following values:

* relationship 1
  * `"source_ref": "indicator--e7581747-1e44-4d4b-85a6-0db0b4a00f2a"` (Sigma Rule: Potential Compromised 3CXDesktopApp Update Activity)
  * `"target_ref": "attack-pattern--457c7820-d331-465a-915e-42f85500ccc4"` (ATT&CK T1218)
  * `"relationship_type": "relies-on"`

For Tactics, that is where the objects is as follows:

```json
            "source_name": "ATTACK",
            "external_id": "tactic",
```

The `description` value in the object, e.g. `defense_evasion` and `execution` above, is used to search ATT&CK objects in each ATT&CK collection using the `name` property.

However, before doing so any `_` characters are replaces with a white-space. For example, in this example `defense_evasion` would become `defense evasion`.

So in this case, two relationship objects would be generated by arango_cti_processor with the following values:

* relationship 1
  * `"source_ref": "indicator--e7581747-1e44-4d4b-85a6-0db0b4a00f2a"` (Sigma Rule: Potential Compromised 3CXDesktopApp Update Activity)
  * `"target_ref": "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a"` (ATT&CK Enterprise TA0005)
  * `"relationship_type": "detects"`
* relationship 2
  * `"source_ref": "indicator--e7581747-1e44-4d4b-85a6-0db0b4a00f2a"` (Sigma Rule: Potential Compromised 3CXDesktopApp Update Activity)
  * `"target_ref": "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5"` (ATT&CK Enterprise TA0002)
  * `"relationship_type": "detects"`

Here is the full SRO for relationship 1:

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--38124280-c03e-5e59-8ed9-1585573d9d42",
    "created_by_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "relationship_type": "detects",
    "source_ref": "indicator--e7581747-1e44-4d4b-85a6-0db0b4a00f2a",
    "target_ref": "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
}
```

To generate the ID of SRO;

* namespace: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3`
* value `detects+sigma+rules_vertex_collection+indicator--e7581747-1e44-4d4b-85a6-0db0b4a00f2a+mitre_attack_enterprise_vertex_collection+x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a`

Gives a UUID v5 of `38124280-c03e-5e59-8ed9-1585573d9d42`.

### 6. Sigma Rule (`indicator`) -> CVE (`vulnerability`)

Sigma Rules are stored by stix2arango in the collection `sigma_rules_vertex_collection`.

CVEs are stored by stix2arango in the collection `nvd_cve_vertex_collection`.

Some Sigma Rules contain references to CVEs. Here is an example using the rule CVE-2020-0688 Exchange Exploitation via Web Log (`indicator--fce2c2e2-0fb5-41ab-a14c-5391e1fd70a5`):

```json
    "external_references": [
        {
            "source_name": "sigma-rule",
            "external_id": "url",
            "url": "https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2020/Exploits/CVE-2020-0688/web_cve_2020_0688_msexchange.yml"
        },
        {
            "source_name": "sigma-rule",
            "external_id": "id",
            "description": "fce2c2e2-0fb5-41ab-a14c-5391e1fd70a5"
        },
        {
            "source_name": "sigma-rule",
            "external_id": "author",
            "description": "Florian Roth (Nextron Systems)"
        },
        {
            "source_name": "sigma-rule",
            "external_id": "license",
            "description": "None"
        },
        {
            "source_name": "sigma-rule",
            "external_id": "detection",
            "description": "emerging_threats"
        },
        {
            "source_name": "sigma-rule",
            "external_id": "status",
            "description": "test"
        },
        {
            "source_name": "sigma-rule",
            "external_id": "level",
            "description": "critical"
        },
        {
            "source_name": "ATTACK",
            "external_id": "technique",
            "description": "t1190"
        },
        {
            "source_name": "ATTACK",
            "external_id": "tactic",
            "description": "initial_access"
        },
        {
            "source_name": "CVE",
            "external_id": "CVE-2020-0688",
            "url": "https://nvd.nist.gov/vuln/detail/cve-2020-0688"
        }
    ],
```

Here where `"source_name": "CVE",` you can get the ID of the CVE under the `external_id` property (`CVE-2020-0688`, above).

Using this ID the name property of Vulnerability objects in the `nvd_cve_vertex_collection` can be searched. In this case CVE-2020-0688 matches to `vulnerability--8b316cd4-34d2-5921-aa5b-9174d3fc1724`.

So in this case, one relationship object would be generated with the following values:

* relationship 1
  * `"source_ref": "indicator--fce2c2e2-0fb5-41ab-a14c-5391e1fd70a5"` (Sigma Rule CVE-2020-0688 Exchange Exploitation via Web Log)
  * `"target_ref": "vulnerability--8b316cd4-34d2-5921-aa5b-9174d3fc1724"` (CVE-2020-0688)
  * `"relationship_type": "detects"`

Here is the full SRO:

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--cec97877-ac13-5f34-90a3-56e7066ed2ed",
    "created_by_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "relationship_type": "detects",
    "source_ref": "indicator--fce2c2e2-0fb5-41ab-a14c-5391e1fd70a5",
    "target_ref": "vulnerability--8b316cd4-34d2-5921-aa5b-9174d3fc1724",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
}
```

To generate the ID of SRO;

* namespace: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3`
* value `detects+sigma+rules_vertex_collection+indicator--fce2c2e2-0fb5-41ab-a14c-5391e1fd70a5+nvd_cve_vertex_collection+vulnerability--8b316cd4-34d2-5921-aa5b-9174d3fc1724`

Gives a UUID v5 of `cec97877-ac13-5f34-90a3-56e7066ed2ed`.

### 7. CVE (`vulnerability`) -> CWE (`weakness`)

This time the source objects (CVEs) are stored by stix2arango in the collection `nvd_cve_vertex_collection`, and the target objects (CWEs) taken from the collection `mitre_cwe_vertex_collection`.

As an example, CVE-2023-49355 (`vulnerability--0078c56a-6545-53cd-ace6-695a775e8fd4`):

            "external_references": [
                {
                    "source_name": "cve",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-49355",
                    "external_id": "CVE-2023-49355"
                },
                {
                    "source_name": "cwe",
                    "url": "https://cwe.mitre.org/data/definitions/CWE-787.html",
                    "external_id": "CWE-787"
                },

Contains an `external_references` to CWE-787 (`weakness--5d0a9fae-053c-5312-a13f-64c6d6fa763d`).

So in this case, one relationship object would be generated with the following values:

* relationship 1
  * `"source_ref": "vulnerability--0078c56a-6545-53cd-ace6-695a775e8fd4"` (ATT&CK T1044)
  * `"target_ref": "attack-pattern--9ad2c2eb-9939-4590-9683-2e789692d262"` (CAPEC-17)
  * `"relationship_type": "exploited-using"`

Here is the full SRO:

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--ffe7fcc0-17a5-5da7-8a89-4c56fef63717",
    "created_by_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "relationship_type": "exploited-using",
    "source_ref": "vulnerability--0078c56a-6545-53cd-ace6-695a775e8fd4",
    "target_ref": "attack-pattern--9ad2c2eb-9939-4590-9683-2e789692d262",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
}
```

To generate the ID of SRO;

* namespace: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3`
* value `exploited-using+nvd_cve_vertex_collection+vulnerability--0078c56a-6545-53cd-ace6-695a775e8fd4+mitre_capec_vertex_collection+attack-pattern--9ad2c2eb-9939-4590-9683-2e789692d262`

Gives a UUID v5 of `ffe7fcc0-17a5-5da7-8a89-4c56fef63717`.

### 8. CVE (`indicator`) -> CPE (`software`)

STOP HERE IF YOUR SKIMMING -- here the way joins are generated is different to the previous examples.

(CVEs) are stored by stix2arango in the collection `nvd_cve_vertex_collection`, and the target objects (CPEs) taken from the collection `nvd_cpe_vertex_collection`.

However, CVE STIX Indicator objects list CPEs in the `pattern` property. Take CVE-2023-48662 (`indicator--f98fd4d1-af26-5dd2-b26c-3fde56527193`) as an example:

```json
"pattern": "([((software:cpe='cpe:2.3:a:dell:solutions_enabler_virtual_appliance:-:*:*:*:*:*:*:*') OR (software:cpe='cpe:2.3:a:dell:solutions_enabler_virtual_appliance:-:*:*:*:eem:*:*:*') OR (software:cpe='cpe:2.3:a:dell:solutions_enabler_virtual_appliance:9.2.3.6:*:*:*:*:*:*:*')) OR ((software:cpe='cpe:2.3:a:dell:unisphere_for_powermax_virtual_appliance:-:*:*:*:*:*:*:*') OR (software:cpe='cpe:2.3:a:dell:unisphere_for_powermax_virtual_appliance:9.2.3.22:*:*:*:*:*:*:*')) OR ((software:cpe='cpe:2.3:o:dell:powermax_os:5978:*:*:*:eem:*:*:*'))])",
```

Here six CPE IDs are found in the pattern.

Using these CPEs IDs, the Software objects in the `nvd_cpe_vertex_collection` are searched (using the `cpe` property) for matches.

For the above we get the following:

* CPE ID: `cpe:2.3:a:dell:solutions_enabler_virtual_appliance:-:*:*:*:*:*:*:*`
    * STIX ID:`software--ba1f35c0-0fdb-50e4-8e46-53fe85708e8c`
* `cpe:2.3:a:dell:solutions_enabler_virtual_appliance:-:*:*:*:eem:*:*:*`
    * STIX ID: `software--544e6013-9bf4-5d56-a2d3-7f4cfaae1b27`
* `cpe:2.3:a:dell:solutions_enabler_virtual_appliance:9.2.3.6:*:*:*:*:*:*:*`
    * STIX ID: `software--de9297a8-fb3c-528a-ad83-1f94107c7d28`
* `cpe:2.3:a:dell:unisphere_for_powermax_virtual_appliance:-:*:*:*:*:*:*:*`
    * STIX ID: `software--51c6df16-dbe6-5005-88d6-0d1bdacf01c0`
* `cpe:2.3:a:dell:unisphere_for_powermax_virtual_appliance:9.2.3.22:*:*:*:*:*:*:*`
    * STIX ID: `software--b46d4cde-8baf-5819-a94f-7eb7fd68f99f`
* `cpe:2.3:o:dell:powermax_os:5978:*:*:*:eem:*:*:*`
    * STIX ID: `software--41d6de91-e0da-54a0-bc0f-3d8393a4cb56`

Thus the following six relationships are created:

* relationship 1
  * `"source_ref": "indicator--f98fd4d1-af26-5dd2-b26c-3fde56527193"` (CVE-2023-48662)
  * `"target_ref": "software--ba1f35c0-0fdb-50e4-8e46-53fe85708e8c"`
  * `"relationship_type": "pattern-contains"`
* relationship 2
  * `"source_ref": "indicator--f98fd4d1-af26-5dd2-b26c-3fde56527193"` (CVE-2023-48662)
  * `"target_ref": "software--544e6013-9bf4-5d56-a2d3-7f4cfaae1b27"`
  * `"relationship_type": "pattern-contains"`
* relationship 3
  * `"source_ref": "indicator--f98fd4d1-af26-5dd2-b26c-3fde56527193"` (CVE-2023-48662)
  * `"target_ref": "software--de9297a8-fb3c-528a-ad83-1f94107c7d28"`
  * `"relationship_type": "pattern-contains"`
* relationship 4
  * `"source_ref": "indicator--f98fd4d1-af26-5dd2-b26c-3fde56527193"` (CVE-2023-48662)
  * `"target_ref": "software--51c6df16-dbe6-5005-88d6-0d1bdacf01c0"`
  * `"relationship_type": "pattern-contains"`
* relationship 5
  * `"source_ref": "indicator--f98fd4d1-af26-5dd2-b26c-3fde56527193"` (CVE-2023-48662)
  * `"target_ref": "software--b46d4cde-8baf-5819-a94f-7eb7fd68f99f"`
  * `"relationship_type": "pattern-contains"`
* relationship 6
  * `"source_ref": "indicator--f98fd4d1-af26-5dd2-b26c-3fde56527193"` (CVE-2023-48662)
  * `"target_ref": "software--41d6de91-e0da-54a0-bc0f-3d8393a4cb56"`
  * `"relationship_type": "pattern-contains"`

Here is the full SRO for relationship 1:

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--4e801b5e-28e5-5cbd-b21d-6e76aab3801a",
    "created_by_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "relationship_type": "pattern-contains",
    "source_ref": "indicator--f98fd4d1-af26-5dd2-b26c-3fde56527193",
    "target_ref": "software--ba1f35c0-0fdb-50e4-8e46-53fe85708e8c",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]
}
```

To generate the ID of SRO;

* namespace: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3`
* value `pattern-contains+nvd_cve_vertex_collection+indicator--f98fd4d1-af26-5dd2-b26c-3fde56527193+nvd_cpe_vertex_collection+software--ba1f35c0-0fdb-50e4-8e46-53fe85708e8c`

Gives a UUID v5 of `4e801b5e-28e5-5cbd-b21d-6e76aab3801a`.

## Get started...

Now you know how it works, start exploring the data...

### The easy way

[Sign up for CTI Butler for immediate access](https://www.ctibutler.com/). Our team have curated quick-start queries to help you get up-and-running. There is also a TAXII API allowing you to easily integrate the intelligence with your other security tooling.

### The hard way

Install, run, and maintain the underlying software that powers CTI Butler yourself:

* [stix2arango](https://github.com/muchdogesec/stix2arango)
* [arango_cti_processor](https://github.com/muchdogesec/arango_cti_processor/)