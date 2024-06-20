---
date: 2024-07-17
last_modified: 2024-07-17
title: "The Problems with Modelling Countries as STIX Objects"
description: "And why we built a small utility to solve them for you."
categories:
  - PRODUCTS
tags: [
    STIX
]
products:
    - location2stix
    - CTI Butler
author_staff_member: david-greenwood
image: /assets/images/blog/2024-07-17/header.png
featured_image: /assets/images/blog/2024-07-17/header.png
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

Take the list of recognised countries and regions. Map them as normalised STIX objects. Make them available to everyone so that the CTI world has a single way of representing them.

## Overview

When intelligence producers talk about countries in their reports, there is no standard framework to represent them. This makes it incredibly hard to link reports talking about the same location. For example, on provider might set location as North Korea, another as NK, another as DPRK... you get the idea.

Referring to a country or region in a standardised way is not a problem that the CTI world suffers from.

[ISO 3166](https://www.iso.org/iso-3166-country-codes.html) is an international standard which defines codes representing names of countries and their subdivisions.

It means if I am referring to the United Kingdom, or should that be the United Kingdom of Great Britain and Northern Ireland?, or Grande Bretagne?, I can use a standardised two digit code GB that anyone, including machines, can easily interpret.

This is not the problem that needs to be solved here.

All of our cyber threat intelligence is reported as STIX 2.1 Objects.

STIX 2.1 has a [Location](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_th8nitr8jb4k) Domain object for representing data from Continent level, all the way down to specific co-ordinates.

So it sounds like the obvious choice to represent a location... BUT...

## SDO vs. SCO

If you're unsure of the difference between SDOs and SCOs, [please go back and read this post first](/blog/beginners_guide_stix_objects).

With this in mind, I'd assume countries should be modelled as SCOs. The United Kingdom of Great Britain and Northern Ireland, or GB I should say, is a country recognised by the UN.

However, there are no location specific SCOs in the STIX specification.

Of course, [I could create some custom SDOs](/blog/create_custom_stix_objects). The problem with this approach is interoperability. Many downstream products will not understand custom STIX objects out-of-the-box.

So this means the Location SDO is the best compromise here.

Location SDOs are great for many use-cases.

Lets say I'm reporting some intelligence on where a USB drive was found. Such information is both specific to an event and descriptive of what that event was.

```json
{
    "type": "location",
    "spec_version": "2.1",
    "id": "location--e63bd3fc-03dd-4a93-93f9-af9cddefc8d1",
    "created": "2016-04-06T20:03:00.000Z",
    "modified": "2016-04-06T20:03:00.000Z",
    "name": "Where USB drive was found",
    "latitude": "64.75111",
    "longitude": "-147.34944"
}
```

However, a country is not specific to an event, nor is paticularly descriptive. Everyone who mentions a Country is describing the same thing.

The problem here is the way UUIDs are produced for SDOs -- they are random UUIDv4s.

A lot of intelligence producers naturally use for Location SDOs for country level information (because SCOs don't exist), but what that means is you get many producers, creating location objects, talking about the same thing, but with different IDs (random UUIDv4s each time) and times.

e.g. producer one makes;

```json
{
    "type": "location",
    "spec_version": "2.1",
    "id": "location--cc27479a-fbd8-4283-ab6c-efa5d76ab45d",
    "created": "2018-01-01T00:00:00.000Z",
    "modified": "2018-01-01T00:00:00.000Z",
    "name": "Belize",
    "country": "BZ"
}
```

and producer two makes...

```json
{
    "type": "location",
    "spec_version": "2.1",
    "id": "location--a80b0e66-0de6-49c7-ba52-1106fc7cdd4d",
    "created": "2023-01-01T00:00:00.000Z",
    "modified": "2023-01-01T00:00:00.000Z",
    "name": "Belize",
    "country": "BZ"
}
```

Normalisation is slightly easier if the `country` property is passed (ISO 3166-1 ALPHA-2 Code), but this is completely optional. [You can see in this example](https://gist.github.com/rjsmitre/79775df68b0d1c7c0985b4fe7f115586) which is representative of most cases, no `country` value is printed;

```json
    {
      "type": "location",
      "id": "location--07608992-927e-434c-9cbd-bf45274290a0",
      "created": "2017-07-18T22:00:30.405Z",
      "modified": "2017-07-18T22:00:30.405Z",
      "country": "China"
    },
```

It also means extra processing is required to normalise objects into yet another object for the location in the consuming tools.

## The solution

A central set of STIX 2.1 Location objects all tools can use, modelled as follows;

```json
{
  "type": "location",
  "spec_version": "2.1",
  "id": "location--<UUID V5>",
  "created_by_ref": "identity--<IDENTITY>",
  "created": "2020-01-01T00:00:00.000Z",
  "modified": "2020-01-01T00:00:00.000Z",
  "name": "<name>",
  "region": "<sub-region>",
  "country": "<alpha-2>",
  "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION>"
    ],
    "external_references": [
        {
            "source_name": "alpha-3",
            "external_id": "<alpha-3>"
        },
        {
            "source_name": "iso_3166-2",
            "external_id": "<iso_3166-2>"
        },
        {
            "source_name": "country-code",
            "external_id": "<country-code>"
        }
    ]
}
```

The logic to generate these objects can be found in [location2stix, including the ISO-3166 values used to generate them](https://github.com/muchdogesec/location2stix).

location2stix also models Regions (e.g. Americas), Sub-Regions (e.g. Latin America and the Caribbean), and Intermediate Regions (e.g. Caribbean), and links them together.

## Creating a centralised store of objects

The output of location2stix is available to [download here](https://pub-ce0133952c6947428e077da707513ff5.r2.dev/locations%2Flocations-bundle.json).

This location data is also stored in CTI Butler for remote lookup.

For example, if I was an intelligence producer who wanted to use the STIX 2.1 objects for North Korea, and I know the two digit ISO code (`KP`), I could find it using the CTI Butler query...

```sql
FOR doc IN locations_vertex_collection
FILTER doc.country == "KP"
LET keysToRemove = (
  FOR key IN ATTRIBUTES(doc)
  FILTER STARTS_WITH(key, "_")
  RETURN key
)
RETURN UNSET(doc, keysToRemove)
```

```json
[
  {
    "country": "KP",
    "created": "2020-01-01T00:00:00.000Z",
    "created_by_ref": "identity--674a16c1-8b43-5c3e-8692-b3d8935e4903",
    "external_references": [
      {
        "source_name": "alpha-3",
        "external_id": "PRK"
      },
      {
        "source_name": "iso_3166-2",
        "external_id": "ISO 3166-2:KP"
      },
      {
        "source_name": "country-code",
        "external_id": "408"
      }
    ],
    "id": "location--d5c93aa7-eaa5-5dc8-8dfa-c15f1f51fbaa",
    "modified": "2020-01-01T00:00:00.000Z",
    "name": "Korea (Democratic People's Republic of)",
    "object_marking_refs": [
      "marking-definition--674a16c1-8b43-5c3e-8692-b3d8935e4903",
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
    ],
    "region": "eastern-asia",
    "spec_version": "2.1",
    "type": "location"
  }
]
```

I could also search for `Korea` like so, if I didn't know the two digit ISO code;

```sql
FOR doc IN locations_vertex_collection
FILTER CONTAINS(doc.name, "Korea")
LET keysToRemove = (
  FOR key IN ATTRIBUTES(doc)
  FILTER STARTS_WITH(key, "_")
  RETURN key
)
RETURN UNSET(doc, keysToRemove)
```

```json
[
  {
    "country": "KR",
    "created": "2020-01-01T00:00:00.000Z",
    "created_by_ref": "identity--674a16c1-8b43-5c3e-8692-b3d8935e4903",
    "external_references": [
      {
        "source_name": "alpha-3",
        "external_id": "KOR"
      },
      {
        "source_name": "iso_3166-2",
        "external_id": "ISO 3166-2:KR"
      },
      {
        "source_name": "country-code",
        "external_id": "410"
      }
    ],
    "id": "location--a090c7b9-1f8c-51c7-9d4c-f26bce6a4519",
    "modified": "2020-01-01T00:00:00.000Z",
    "name": "Korea, Republic of",
    "object_marking_refs": [
      "marking-definition--674a16c1-8b43-5c3e-8692-b3d8935e4903",
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
    ],
    "region": "eastern-asia",
    "spec_version": "2.1",
    "type": "location"
  },
  {
    "country": "KP",
    "created": "2020-01-01T00:00:00.000Z",
    "created_by_ref": "identity--674a16c1-8b43-5c3e-8692-b3d8935e4903",
    "external_references": [
      {
        "source_name": "alpha-3",
        "external_id": "PRK"
      },
      {
        "source_name": "iso_3166-2",
        "external_id": "ISO 3166-2:KP"
      },
      {
        "source_name": "country-code",
        "external_id": "408"
      }
    ],
    "id": "location--d5c93aa7-eaa5-5dc8-8dfa-c15f1f51fbaa",
    "modified": "2020-01-01T00:00:00.000Z",
    "name": "Korea (Democratic People's Republic of)",
    "object_marking_refs": [
      "marking-definition--674a16c1-8b43-5c3e-8692-b3d8935e4903",
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
    ],
    "region": "eastern-asia",
    "spec_version": "2.1",
    "type": "location"
  }
]
```

I could also ask the question; what countries are in Europe?

To do this I need to first find the location object representing the European region;

```sql
FOR doc IN locations_vertex_collection
FILTER doc.name == "Europe"
LET keysToRemove = (
  FOR key IN ATTRIBUTES(doc)
  FILTER STARTS_WITH(key, "_")
  RETURN key
)
RETURN UNSET(doc, keysToRemove)
```

```json
[
  {
    "created": "2020-01-01T00:00:00.000Z",
    "created_by_ref": "identity--674a16c1-8b43-5c3e-8692-b3d8935e4903",
    "external_references": [
      {
        "source_name": "region-code",
        "external_id": "Europe"
      }
    ],
    "id": "location--82b2b1a9-5f88-55ab-877e-812017e26fca",
    "modified": "2020-01-01T00:00:00.000Z",
    "name": "Europe",
    "object_marking_refs": [
      "marking-definition--674a16c1-8b43-5c3e-8692-b3d8935e4903",
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
    ],
    "region": "europe",
    "spec_version": "2.1",
    "type": "location"
  }
]
```

Now I can see all objects that link to Europe

```sql
FOR edge IN locations_edge_collection
FILTER edge.target_ref == "location--82b2b1a9-5f88-55ab-877e-812017e26fca"
RETURN edge.source_ref
```

Which returns a list of location IDs.

I can then use this list to find the countries, note, I filter by 

```json
LET idList = [
  "<LIST OF IDS FROM LAST QUERY>"
]

FOR vertex IN locations_vertex_collection
FILTER vertex.id IN idList AND HAS(vertex, "country") AND vertex.country != null
RETURN vertex.name
```

Putting these all together...

```sql
// Step 1: Find the location object representing Europe
LET europeLocation = (
    FOR doc IN locations_vertex_collection
    FILTER doc.name == "Europe"
    LET keysToRemove = (
        FOR key IN ATTRIBUTES(doc)
        FILTER STARTS_WITH(key, "_")
        RETURN key
    )
    RETURN UNSET(doc, keysToRemove)
)[0]

// Step 2: Get the ID of the Europe location
LET europeLocationId = europeLocation.id

// Step 3: Find all edges linked to Europe
LET linkedEdges = (
    FOR edge IN locations_edge_collection
    FILTER edge.target_ref == europeLocationId
    RETURN edge.source_ref
)

// Step 4: Filter and return the countries from the vertex collection
FOR vertex IN locations_vertex_collection
FILTER vertex.id IN linkedEdges AND HAS(vertex, "country") AND vertex.country != null
SORT vertex.name
RETURN vertex.name
```

```json
[
  "Åland Islands",
  "Albania",
  "Andorra",
  "Austria",
  "Belarus",
  "Belgium",
  "Bosnia and Herzegovina",
  "Bulgaria",
  "Croatia",
  "Czechia",
  "Denmark",
  "Estonia",
  "Faroe Islands",
  "Finland",
  "France",
  "Germany",
```

## Get started...

Now you know how it works, start exploring the data yourself...

### The easy way

[Sign up for CTI Butler for immediate access](https://www.ctibutler.com/). Our team have curated quick-start queries to help you get up-and-running. There is also a TAXII API allowing you to easily integrate the intelligence with your other security tooling.

### The hard way

Install, run, and maintain the underlying software that powers CTI Butler yourself:

* [stix2arango](https://github.com/muchdogesec/stix2arango)
* [arango_cti_processor](https://github.com/muchdogesec/arango_cti_processor/)