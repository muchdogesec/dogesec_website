---
date: 2024-07-23
last_modified: 2024-07-23
title: "Graphing of Ransomware Payments"
description: "Modelling ransomwhe.re data as STIX 2.1 object so that it can be explored as a graph."
categories:
  - POC
tags: [
    STIX,
    cryptocurrency,
    bitcoin
]
products:
    - ransomwhere2stix
    - stix2arango
author_staff_member: david-greenwood
image: /assets/images/blog/2024-07-23/header.png
featured_image: /assets/images/blog/2024-07-23/header.png
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

Take [ransomwhe.re](https://ransomwhe.re/) data. Turn it into STIX 2.1 objects. Explore ransom payments by malware on a graph.

## How it started

A lot of the report writing I do is focused around Ransomware, given its prevalence.

However, much of the work has been around how to prevent falling victim by analysing the malware itself and the methods of distribution.

I have never really "followed the money" in my research to see how many victims are actually paying for decryption keys.

This information alone is very useful. Tracking the amount of payments being made, and their value, gives a good indication of how successful a particular campaign has been.

### Problem 1: representing the data

I wanted to represent the data as STIX, as you might have guessed from the other posts on this blog.

However, STIX has no current SCOs to represent cryptocurrency concepts in [its core specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html).

So I set out to create some custom extensions. If you're new to creating custom STIX objects, [read this first](/blog/create_custom_stix_objects).

In short I created two new objects:

1. `cryptocurrency-wallet`: represents the actual wallet where crypto is stored
  * [see my Extension Definition with schema](https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/extension-definition/cryptocurrency-wallet.json)
2. `cryptocurrency-transactions`: represents the transactions of crypto between one or more wallets
  * [see my Extension Definition with schema](https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/extension-definition/cryptocurrency-transaction.json)

### Problem 2: accessing ransom payment data

A ton of businesses make their money off researching blockchain transactions and then selling their research.

However, I wanted to try and keep this work open for the benefit of the community.

At this point I started to research open-databases tracking wallet hashes used in ransom requests so that I could then start searching the blockchain for inbound transactions to said wallet.

Though as is usually the case, someone else had done it before me (and much better than I could have).

Then I discovered;

> Ransomwhere is the open, crowdsourced ransomware payment tracker. Browse and download ransomware payment data or help build our dataset by reporting ransomware demands you have received.

[Ransomwhe.re](https://ransomwhe.re/)

Ransomwhere also has an open API to access the data which was all I needed.

### Problem 3: modelling Ransomwhere data in STIX

With the data structure and data sources decided, I could then start to model the data.

The detailed logic for this is described in the docs for a tool we created for this job, [ransomwhere2stix](https://github.com/muchdogesec/pocs/tree/main/ransomwhere2stix).

Here's the structure of the objects generated;

<iframe width="768" height="432" src="https://miro.com/app/live-embed/uXjVK7NkJ9A=/?moveToViewport=-576,-274,1152,548&embedId=81782626451" frameborder="0" scrolling="no" allow="fullscreen; clipboard-read; clipboard-write" allowfullscreen></iframe>

## Where we're at

ransomwhere2stix produces a STIX bundle [you can see an example of this data here](https://raw.githubusercontent.com/muchdogesec/ransomwhere2stix/main/examples/ransomwhere-bundle.json).

Using [stix2arango](https://github.com/muchdogesec/stix2arango/) I can import this into ArangoDB as follows;

```shell
git clone https://github.com/muchdogesec/stix2arango/
git clone https://github.com/muchdogesec/pocs/ransomwhere2stix/
mkdir -p stix2arango/cti_knowledge_base_store/ransomwhere
cp pocs/ransomwhere2stix/examples/ransomwhere-bundle.json stix2arango/cti_knowledge_base_store/ransomwhere/ransomwhere-bundle.json
cd stix2arango
# set up stix2arango
python3 stix2arango.py \
  --file cti_knowledge_base_store/ransomwhere/ransomwhere-bundle.json \
  --database ransomware \
  --collection ransomwhere \
  --stix2arango_note blog_poc \
  --ignore_embedded_relationships false
```

We can now start to explore the objects...

This search will return all objects...

```sql
FOR doc IN ransomwhere_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    LET keys = ATTRIBUTES(doc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
        RETURN KEEP(doc, filteredKeys)
```

You can filter by each type;

```sql
FOR doc IN ransomwhere_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc.type == "indicator"
    LET keys = ATTRIBUTES(doc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
        RETURN KEEP(doc, filteredKeys)
```

Currently returns 105 objects, here is the first in the response...

```json
  {
    "created": "2020-01-09T17:36:50.000Z",
    "created_by_ref": "identity--904ac99b-7539-5de7-9ffa-23186f0e07b6",
    "description": "Known Cryptocurrency Wallets associated with REvil / Sodinokibi",
    "id": "indicator--7186c016-334c-5955-89d2-658e4a4d3756",
    "indicator_types": [
      "malicious-activity"
    ],
    "modified": "2020-01-09T17:36:50.000Z",
    "name": "REvil / Sodinokibi Cryptocurrency Wallets",
    "object_marking_refs": [
      "marking-definition--904ac99b-7539-5de7-9ffa-23186f0e07b6",
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
    ],
    "pattern": "[cryptocurrency-wallet:address = '3BeQ9H5tByJK9CeeZftDsBFhgt1i5Q7AQK' OR cryptocurrency-wallet:address = '3L7ECcRBCypxrS5U9Kw9WexcsHmX4wKYz6' OR cryptocurrency-wallet:address = '34mMCqo83wc8GeLWjSPeQE8QiY9LKnkNuj' OR cryptocurrency-wallet:address = '3JYLAk26kZPw62W6UD2Jyk5i9jhCAPJjg4' OR cryptocurrency-wallet:address = '3Jxwt3fmXhUwDNDQ4sWYCgahLGDVjy1SQm' OR cryptocurrency-wallet:address = '3HTHHMm2YwNdwEDkGc6dRyxxKvByymeVqV' OR cryptocurrency-wallet:address = '3E9F7gE3upQ8rgsPjwiKH7ugfdneypPjqj']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
    "spec_version": "2.1",
    "type": "indicator",
    "valid_from": "2020-01-09T17:36:50Z"
  }
```

If you want to search for Indicators you could use a search like:

```sql
FOR doc IN ransomwhere_vertex_collection
    FILTER doc._stix2arango_note != "automatically imported on collection creation"
    AND doc.name LIKE "%WannaCry%"
    LET keys = ATTRIBUTES(doc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
    RETURN KEEP(doc, filteredKeys)
```

```json
[
  {
    "created": "2020-11-14T07:08:23.000Z",
    "created_by_ref": "identity--904ac99b-7539-5de7-9ffa-23186f0e07b6",
    "id": "malware--4ac72b77-fc6d-5aba-b37c-39d3dd27b3ff",
    "is_family": true,
    "malware_types": [
      "ransomware"
    ],
    "modified": "2020-11-14T07:08:23.000Z",
    "name": "WannaCry",
    "object_marking_refs": [
      "marking-definition--904ac99b-7539-5de7-9ffa-23186f0e07b6",
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
    ],
    "spec_version": "2.1",
    "type": "malware"
  },
  {
    "created": "2020-11-14T07:08:23.000Z",
    "created_by_ref": "identity--904ac99b-7539-5de7-9ffa-23186f0e07b6",
    "description": "Known Cryptocurrency Wallets associated with WannaCry",
    "id": "indicator--4ac72b77-fc6d-5aba-b37c-39d3dd27b3ff",
    "indicator_types": [
      "malicious-activity"
    ],
    "modified": "2020-11-14T07:08:23.000Z",
    "name": "WannaCry Cryptocurrency Wallets",
    "object_marking_refs": [
      "marking-definition--904ac99b-7539-5de7-9ffa-23186f0e07b6",
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
    ],
    "pattern": "[cryptocurrency-wallet:address = '115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn' OR cryptocurrency-wallet:address = '13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94' OR cryptocurrency-wallet:address = '12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw' OR cryptocurrency-wallet:address = '1QAc9S5EmycqjzzWDc1yiWzr9jJLC8sLiY' OR cryptocurrency-wallet:address = '15zGqZCTcys6eCjDkE3DypCjXi6QWRV6V1']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
    "spec_version": "2.1",
    "type": "indicator",
    "valid_from": "2020-11-14T07:08:23Z"
  }
]
```

stix2arango creates a graph of objects using the STIX relationship objects and embedded relationships inside STIX objects.

That means I can traverse the graph to find out what objects are related to what others. I'll use the REvil / Sodinokibi Cryptocurrency Wallets Indicator...

```sql
// First, get all the ids from ransomwhere_vertex_collection that match the criteria
LET vertex_ids = (
    FOR doc IN ransomwhere_vertex_collection
        FILTER doc._stix2arango_note != "automatically imported on collection creation"
        AND doc.type == "indicator"
        AND doc.id == "indicator--7186c016-334c-5955-89d2-658e4a4d3756"
        LET keys = ATTRIBUTES(doc)
        LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
        RETURN doc.id
)

// Next, find all relationships that have source_ref or target_ref in the list of vertex_ids
FOR rel IN ransomwhere_edge_collection
    FILTER rel.source_ref IN vertex_ids OR rel.target_ref IN vertex_ids
    RETURN {
        relationship_id: rel.id,
        source_ref: rel.source_ref,
        target_ref: rel.target_ref,
        relationship_type: rel.relationship_type
    }
```

We get the Malware object the Indicator belongs to, and all the Cryptocurrency Wallets listed inside the Indicator pattern.

```json
[
  {
    "relationship_id": "relationship--7e1b770d-c8b6-5691-872c-9f6cbef5a3bf",
    "source_ref": "indicator--7186c016-334c-5955-89d2-658e4a4d3756",
    "target_ref": "malware--7186c016-334c-5955-89d2-658e4a4d3756",
    "relationship_type": "indicates"
  },
  {
    "relationship_id": "relationship--c56fe058-6cdb-57a9-bb23-8f56efba4ce8",
    "source_ref": "indicator--7186c016-334c-5955-89d2-658e4a4d3756",
    "target_ref": "cryptocurrency-wallet--40b020eb-43a5-55a8-acd1-62a3aae761bc",
    "relationship_type": "pattern-contains"
  },
  {
    "relationship_id": "relationship--2da4674c-bcef-5095-8336-15ebec6b63ad",
    "source_ref": "indicator--7186c016-334c-5955-89d2-658e4a4d3756",
    "target_ref": "cryptocurrency-wallet--8e4221d4-48b9-5fd7-be9b-45fba3c545b6",
    "relationship_type": "pattern-contains"
  },
  {
    "relationship_id": "relationship--2f54948e-cdee-5844-8df2-a2584822e5f7",
    "source_ref": "indicator--7186c016-334c-5955-89d2-658e4a4d3756",
    "target_ref": "cryptocurrency-wallet--c5bb4016-b780-5d8b-8503-2fa8e1b5460b",
    "relationship_type": "pattern-contains"
  },
  {
    "relationship_id": "relationship--77dfe8ea-bcd1-577f-829f-c43e51a06290",
    "source_ref": "indicator--7186c016-334c-5955-89d2-658e4a4d3756",
    "target_ref": "cryptocurrency-wallet--2418b59a-20a7-5c75-801b-449c3dc8c00b",
    "relationship_type": "pattern-contains"
  },
  {
    "relationship_id": "relationship--12fc35d2-e8c8-5e92-98e6-840851118d5c",
    "source_ref": "indicator--7186c016-334c-5955-89d2-658e4a4d3756",
    "target_ref": "cryptocurrency-wallet--4619d607-041b-5c79-a98d-2fef07cac3da",
    "relationship_type": "pattern-contains"
  },
  {
    "relationship_id": "relationship--b85386a3-19c1-5d6b-8781-6176a49ccd2f",
    "source_ref": "indicator--7186c016-334c-5955-89d2-658e4a4d3756",
    "target_ref": "cryptocurrency-wallet--131063b3-04c4-5c14-8669-6db0ac11314f",
    "relationship_type": "pattern-contains"
  },
  {
    "relationship_id": "relationship--e841fe7d-6b46-5442-a7da-9100389e5c33",
    "source_ref": "indicator--7186c016-334c-5955-89d2-658e4a4d3756",
    "target_ref": "cryptocurrency-wallet--aecb8fb0-57a3-5310-beb7-d7af80dd2968",
    "relationship_type": "pattern-contains"
  },
  {
    "relationship_id": "relationship--e5e4b608-e2ad-5bd0-a0af-5391f4d574d8",
    "source_ref": "indicator--7186c016-334c-5955-89d2-658e4a4d3756",
    "target_ref": "identity--904ac99b-7539-5de7-9ffa-23186f0e07b6",
    "relationship_type": "created-by"
  },
  {
    "relationship_id": "relationship--4ab7e4fe-ab39-535f-a3fc-1dd941884cb6",
    "source_ref": "indicator--7186c016-334c-5955-89d2-658e4a4d3756",
    "target_ref": "marking-definition--904ac99b-7539-5de7-9ffa-23186f0e07b6",
    "relationship_type": "object-marking"
  },
  {
    "relationship_id": "relationship--08576437-b2e1-586f-802a-dbb84c964145",
    "source_ref": "indicator--7186c016-334c-5955-89d2-658e4a4d3756",
    "target_ref": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "relationship_type": "object-marking"
  }
]
```

Often you will want to know how much a malware string has netted for the actors using it to extort organisations.

```sql
// Step 1: Get all cryptocurrency-wallet ids related to the indicator
LET wallet_ids = (
    LET vertex_ids = (
        FOR doc IN ransomwhere_vertex_collection
            FILTER doc._stix2arango_note != "automatically imported on collection creation"
            AND doc.type == "indicator"
            AND doc.id == "indicator--7186c016-334c-5955-89d2-658e4a4d3756"
            LET keys = ATTRIBUTES(doc)
            LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
            RETURN doc.id
    )
    FOR rel IN ransomwhere_edge_collection
        FILTER rel.source_ref IN vertex_ids OR rel.target_ref IN vertex_ids
        FILTER rel.relationship_type == "pattern-contains"
        RETURN DISTINCT rel.target_ref
)

// Step 2: Get all cryptocurrency-transactions related to the cryptocurrency-wallets
LET transactions = (
    FOR rel IN ransomwhere_edge_collection
        FILTER rel.relationship_type == "address"
        AND rel.target_ref IN wallet_ids
        RETURN rel.source_ref
)

// Step 3: Sum all the amounts linked to the indicator id and divide by 100000000
LET total_amount = (
    FOR transaction IN ransomwhere_vertex_collection
        FILTER transaction.type == "cryptocurrency-transaction"
        AND transaction.id IN transactions
        FOR output IN transaction.output
            FILTER output.address_ref IN wallet_ids
            COLLECT AGGREGATE total = SUM(output.amount)
        RETURN total / 100000000
)

RETURN { 
    indicator_id: "indicator--7186c016-334c-5955-89d2-658e4a4d3756", 
    total_amount: total_amount[0] 
}
```

```json
[
  {
    "indicator_id": "indicator--7186c016-334c-5955-89d2-658e4a4d3756",
    "total_amount": 327.41854732
  }
]
```

Note, the `total_amount` shows total Bitcoins received by all wallets linked to this malware.

To work out an accurate USD amount you need to convert each transaction amount into USD first using the exchange rate on the `execution_time` datetime reported in the transaction.

Here's an example of doing that for one transaction...

```sql
FOR doc IN ransomwhere_vertex_collection
    FILTER doc.id == "cryptocurrency-transaction--2b8233e1-7ec8-50bc-a567-0a17da8427b9"
    LET keys = ATTRIBUTES(doc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
    RETURN KEEP(doc, filteredKeys)
```

```json
[
  {
    "execution_time": "2020-04-04T15:44:42Z",
    "extensions": {
      "extension-definition--151d042d-4dcf-5e44-843f-1024440318e5": {
        "extension_type": "new-sco"
      }
    },
    "hash": "7377f834e1697c44fb3a39aca71548f36911ac3bd05f2f4c4b5f86c59cb9b860",
    "id": "cryptocurrency-transaction--2b8233e1-7ec8-50bc-a567-0a17da8427b9",
    "object_marking_refs": [
      "marking-definition--904ac99b-7539-5de7-9ffa-23186f0e07b6",
      "marking-definition--27557362-b745-4161-96e8-ccd62ce4cb26",
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
    ],
    "output": [
      {
        "address_ref": "cryptocurrency-wallet--6b5c9429-9ca0-5f75-9fad-73fa07e719bc",
        "amount": 74110745
      }
    ],
    "spec_version": "2.1",
    "symbol": "BTC",
    "type": "cryptocurrency-transaction"
  }
]
```

On April 4, 2020, the closing price of Bitcoin was approximately $6,789.36 USD. Thus this transaction was worth (0.74110745BTC x 6,789.36) 5,032.34USD.

Often you'll start from the bottom up, that is asking; is this transaction linked to a malware family?

Here I start with `cryptocurrency-transaction--f437c493-b651-5cbb-845a-3dd231a39ec6`;

```sql
// Step 1: Find cryptocurrency-wallets associated with the given cryptocurrency-transaction
LET transaction_id = "cryptocurrency-transaction--f437c493-b651-5cbb-845a-3dd231a39ec6"

LET wallet_ids = (
    FOR rel IN ransomwhere_edge_collection
        FILTER rel.relationship_type == "address"
        AND rel.source_ref == transaction_id
        RETURN rel.target_ref
)

// Step 2: Find indicators associated with these cryptocurrency-wallets
LET indicator_ids = (
    FOR rel IN ransomwhere_edge_collection
        FILTER rel.relationship_type == "pattern-contains"
        AND rel.target_ref IN wallet_ids
        RETURN DISTINCT rel.source_ref
)

// Step 3: Find malware associated with these indicators
LET malware_ids = (
    FOR rel IN ransomwhere_edge_collection
        FILTER rel.relationship_type == "indicates"
        AND rel.source_ref IN indicator_ids
        RETURN DISTINCT rel.target_ref
)

// Step 4: Retrieve malware details
FOR malware IN ransomwhere_vertex_collection
    FILTER malware.id IN malware_ids
    RETURN malware.name
```

```json
[
  "Netwalker (Mailto)"
]
```

## In summary

It is important to stress here that this work should be considered a proof-of-concept to show how our new STIX crypto objects can be used to model criminal transactions related to Ransomware (or any crime really).

You can do better than me!

Once you have a cryptocurrency transaction or wallet represented as STIX objects you can use them, across your research. Link them to new malware strings, actors, reports, etc. to build your graph of intelligence.

If this post has given you enough inspiration to start using STIX to represent crypto in your research, then I've achieved my objective.