---
date: 2024-07-23
last_modified: 2024-07-23
title: "A STIX Graph of Ransomware Payments"
description: "Modelling ransomwhe.re data as STIX 2.1 object so that is can be explored in a graph."
categories:
  - PRODUCTS
tags: [
    STIX
]
products:
    - ransomwhere2stix
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

## tl;dr

Take [ransomwhe.re](https://ransomwhe.re/) data. Turn it into STIX 2.1 objects. Explore ransom payments by malware on a graph.

## How the story started

A lot of the report writing I do is focused around Ransomware, given its prevalence.

However, much of the work has been around how to prevent falling victim by analysing the malware itself and the methods of distribition.

I have never really "followed the money" in my research to see how many victims are actually paying for decryption keys.

This information alone is very useful. Tracking the amount of payments being made, and their value, gives a good indication of how successful a paticular campaign has been.

## Problem 1: representing the data

I wanted to represent the data as STIX, as you might have guessed from the other posts on this blog.

However, STIX has no current SCOs to represent cryptocurrency concepts in [its core specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html).

So I set out to create some custom extensions. If you're new to creating custom STIX objects, [read this first](create_custom_stix_objects).

In short I created two new objects:

1. `cryptocurrency-wallet`: represents the actual wallet where crypto is stored
  * [see my Extension Definition with schema](https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/extension-definition/cryptocurrency-wallet.json)
2. `cryptocurrency-transactions`: represents the transactions of crypto between one or more wallets
  * [see my Extension Definition with schema](https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/extension-definition/cryptocurrency-transaction.json)

## Problem 2: accessing ransom payment data

A ton of businesses make their money off researching blockchain transactions and then selling their research.

However, I wanted to try and keep this work open for the benefit of the community.

At this point I started to research open-databases tracking wallet hashes used in ransom requests so that I could then start searching the blockchain for inbound transactions to said wallet.

Though as is usually the case, someone else had done it before me (and much better than I could have).

Then I discovered;

> Ransomwhere is the open, crowdsourced ransomware payment tracker. Browse and download ransomware payment data or help build our dataset by reporting ransomware demands you have received.

[Ransomwhe.re](https://ransomwhe.re/)

Ransomwhere also has an open API to access the data which was all I needed.

## Problem 3: modelling Ransomwhere data in STIX

With the data structure and data sources decided, I could then start to model the data.

I won't explain too much here.

The logic for this is described in the docs for a tool we created for this job, [ransomwhere2stix](https://github.com/muchdogesec/ransomwhere2stix).

## Where we are in this story

ransomwhere2stix produces a STIX bundle [you can see an example of this data here](https://raw.githubusercontent.com/muchdogesec/ransomwhere2stix/main/examples/ransomwhere-bundle.json).

Using [stix2arango](https://github.com/muchdogesec/stix2arango/) I can import this into ArangoDB as follows;

```shell
git clone https://github.com/muchdogesec/stix2arango/
# set up stix2arango
python3 stix2arango.py \
  --file cti_knowledge_base_store/ransomwhere-bundle.json \
  --database ransomware \
  --collection ransomwhere \
  --ignore_embedded_relationships false
```

## Where the story is heading



