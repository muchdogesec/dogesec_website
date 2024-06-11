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