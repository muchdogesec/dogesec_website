---
date: 2024-07-29
last_modified: 2024-07-29
title: "A Graph of Credit Card Fraud using STIX"
description: "Using STIX 2.1 to track fraudulent credit card transactions so that they can be traversed on a graph."
categories:
  - PRODUCTS
tags: [
    STIX,
    credit card
]
products:
    - creditcard2stix
    - stix2arango
author_staff_member: david-greenwood
image: /assets/images/blog/2024-07-29/header.png
featured_image: /assets/images/blog/2024-07-29/header.png
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

Turn bank card numbers into STIX 2.1 objects. Explore the credit card data in the graph. Link the cards to other STIX objects in your research (Actors, Incidents, etc.).

## Overview

As you might expect, a lot of the users of our tools work for financial service companies.

One of the biggest problems these organisations face is fraud. The number of fraudulent transactions continues to increase, despite more advance methods to detect them.

As a starting point to combat this problem, many companies are tracking stolen card data sold on online card forums.

The problem is, this is often just a list of card numbers, expiry dates, card security codes, and card holder names in a huge csv format. Many organisations simply grab these numbers (from an intel feed), store them in relational databases (or a TIP), which they then cross-reference against their card numbers. This is not only time consuming, but it also incredibly inefficient -- it needs to be done by every single banking organisation each time

What if each card in a breach could easily be enriched with the issuer data, and more?...

## The anatomy of a bank card

The first 6 or 8 digits of a payment card number  cards, debit cards, etc.) are known as the Issuer Identification Numbers (IIN), previously known as Bank Identification Number (BIN). These identify the institution that issued the card to the card holder.

For example, `531903` identifies the card as a Mastercard issued in the United States by the bank, Jack Henry & Associates.

[binlist.net](https://binlist.net/) offer a lookup service where you can enter the IIN number and get the result

You can do this programmatically using their API as follows;

```shell
curl --request POST \
    --url 'https://bin-ip-checker.p.rapidapi.com/?bin=5<CARD_NUMBER>' \
    --header 'Content-Type: application/json' \
    --header 'x-rapidapi-host: bin-ip-checker.p.rapidapi.com' \
    --header 'x-rapidapi-key: <API_KEY>' \
    --data '{"bin":"<CARD_NUMBER>"}'
```

e.g. for `531903`;

```json
{
  "success": true,
  "code": 200,
  "BIN": {
    "valid": true,
    "number": 531903,
    "length": 6,
    "scheme": "MASTERCARD",
    "brand": "MASTERCARD",
    "type": "DEBIT",
    "level": "STANDARD",
    "currency": "USD",
    "issuer": {
      "name": "JACK HENRY & ASSOCIATES",
      "website": "http://www.jackhenry.com",
      "phone": "+14172356652"
    },
    "country": {
      "name": "UNITED STATES",
      "native": "United States",
      "flag": "🇺🇸",
      "numeric": "840",
      "capital": "Washington, D.C.",
      "currency": "USD",
      "currency_symbol": "$",
      "region": "Americas",
      "subregion": "Northern America",
      "idd": "1",
      "alpha2": "US",
      "alpha3": "USA",
      "language": "English",
      "language_code": "EN",
      "latitude": 34.05223,
      "longitude": -118.24368
    }
  }
}
```

## Credit card leaks

With credit card data sales, the seller usually provides a CSV with all the required data to allow for fraudulent transactions to be made with it.

This usually includes a minimum of;

* `card_number`
* `card_security_code`
* `card_expiry_date`
* `card_holder_name`

However, as security increases, usually this data includes the card holders address and other identifying information that might be requested during a transaction.

STIX has no current SCOs to represent cards concepts in [its core specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html).

So I set out to create some custom extensions. If you're new to creating custom STIX objects, [read this first](/blog/create_custom_stix_objects).

In short I created a new `credit-card` object. [See my Extension Definition with schema for the object here](https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/extension-definition/credit-card.json).

I wanted to also separate the card from the issuer. I don't have any bank details in the `credit-card` object. Instead I link `credit-card` objects to `identity` objects representing the issuer using a STIX relationship.

The logic and mapping can be seen in the tool we built to perform this workflow, [creditcard2stix](https://github.com/muchdogesec/creditcard2stix).

## Using leaked data and BIN List to create STIX objects

At a high-level my intended workflow during research is;

1. receive credit card dump
2. turn to STIX 2.1 enriched with BIN List data
3. use objects in my research (e.g. searching for other references of the credit card, attaching to known criminal identities, etc.).

Using some sample credit card data I generated, (not actual leaked cards), here you can see what the objects look like and how they are related;

<div class="stixview" data-stix-url="/assets/images/blog/2024-07-29/credit-card-bundle.json" data-stix-allow-dragdrop="false" data-show-idrefs="false" data-show-markings="true" data-show-sidebar="true" data-graph-layout="cise" data-caption="Example credit card bundle" data-disable-mouse-zoom="false" data-graph-width="100%" data-graph-height="85vh" data-show-footer="true"></div>

I could then start to use this data in my research, for example, linking cards in a dump to a report I've written about said dump, e.g.

<div class="stixview" data-stix-url="/assets/images/blog/2024-07-29/credit-card-bundle-with-report.json" data-stix-allow-dragdrop="false" data-show-idrefs="false" data-show-markings="true" data-show-sidebar="true" data-graph-layout="cise" data-caption="Dummy credit card leak" data-disable-mouse-zoom="false" data-graph-width="100%" data-graph-height="85vh" data-show-footer="true"></div>

## Automating this workflow

[txt2stix](https://github.com/muchdogesec/txt2stix) will take a text file and extract observables and TTPs from it, outputting the data as a STIX 2.1 bundle of detected objects.

[You can see the available card extractions here](https://github.com/muchdogesec/txt2stix/blob/main/extractions/pattern/config.yaml#L523).

By using txt2stix, you not only get the conversion to STIX as described above, but txt2stix will also extract relationships.

For example, lets imagine you have a report that contained the text along the following lines:

> The carding group Card Runners used the following cards obtained from the Fake Real Plastic (http://igvmwp3544wpnd6u.onion) to withdraw cash from ATMs across the world: 
>
> * 5507211322378981
> * 4571717066493601

Running this through txt2stix;

```shell
python3 txt2stix.py \
  --relationship_mode ai \
  --input_file card-runners.txt \
  --name "Card Runners Report" \
  --tlp_level clear \
  --confidence 80 \
  --label blog \
  --use_extractions pattern_bank_card_mastercard,pattern_bank_card_visa,pattern_bank_card_amex,pattern_bank_card_union_pay,pattern_bank_card_diners,pattern_bank_card_jcb,pattern_bank_card_discover,lookup_threat_actor,pattern_url
```

Which gives;

<div class="stixview" data-stix-url="/assets/images/blog/2024-07-29/bundle--a9a39207-3176-4ef5-b8a1-c38267ff8197.json" data-stix-allow-dragdrop="false" data-show-idrefs="false" data-show-markings="true" data-show-sidebar="true" data-graph-layout="cise" data-caption="txt2stix Card Runners Report" data-disable-mouse-zoom="false" data-graph-width="100%" data-graph-height="85vh" data-show-footer="true"></div>