---
date: 2024-06-12
title: "Spin Up Your Own TAXII Server in 10 Minutes"
description: "We built an open-source TAXII server. This post describes how you can use it to start sharing your threat intelligence. Minimal technical knowledge required."
categories:
  - PRODUCTS
  - DIY
tags: [
    TAXII,
    STIX
]
products:
    - stix2arango
    - arango_taxii_server
author_staff_member: david-greenwood
image: /assets/images/blog/2024-06-12/header.jpeg
featured_image: /assets/images/blog/2024-06-12/header.jpeg
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

We wanted to distribute STIX 2.1 objects to our community using TAXII. We built a TAXII server coupled with a storage layer to do this. It is called Arango TAXII Server. This post describes how you can get started with it.

[If you just want to start using Arango TAXII Server, go here](https://github.com/muchdogesec/arango_taxii_server/).

## Optional pre-reading

If you're new to TAXII, start by reading these tutorials in our community forum, they will make this post much easier to read:

* [TAXII 2.1 Server Core Concepts (using the Medallion TAXII server)](https://community.dogesec.com/t/taxii-2-1-server-core-concepts-using-the-medallion-taxii-server/44)
* [TAXII 2.1 Client Core Concepts (using the OASIS TAXII client)](https://community.dogesec.com/t/taxii-2-1-client-core-concepts-using-the-oasis-taxii-client/45)

## Install Arango TAXII Server

[Follow the instructions here](https://github.com/muchdogesec/arango_taxii_server).

If you're following along with this post I am going to assume you've installed an ArangoDB instance locally and your Arango TAXII Server `.env` file looks like this;

```txt
# ARANGO
ARANGODB='http://127.0.0.1:8529/'
# CELERY
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP=1
# POSTGRES
POSTGRES_DB=postgres
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
# TAXII SERVER
SERVER_BASE_URL='http://127.0.0.1:8000/'
SERVER_TITLE='Arango TAXII Server'
SERVER_DESCRIPTION='https://github.com/muchdogesec/arango_taxii_server/'
SERVER_MAX_CONTENT_LENGTH=10485760
SERVER_EMAIL='noreply@dogesec.com'
SERVER_SUPPORT='https://community.dogesec.com/'
```

Once you've started the Docker container, as per the documentation linked above, you can access the Swagger UI for the API in a browser at: http://127.0.0.1:8000/api/schema/swagger-ui/

<img class="img-fluid" src="/assets/images/blog/2024-06-12/Arango-TAXII-Server.png" alt="Arango TAXII Server" title="Arango TAXII Server" />

Now, before I walk through using Arango TAXII Server, let me start by seeding our server with a Database and some Collections.

## Seeding

Arango TAXII Server considers every database in ArangoDB as a TAXII root.

To create a new Database in ArangoDB:

<video controls class="img-fluid">
    <source src="/assets/images/blog/2024-06-12/create-arango-db.webm" type="video/webm" />
</video>

* Log in to the web interface (http://127.0.0.1:8529/), as root
* Select `_system`
* Select `Databases`
* Select `Add new Database`
* Create your Database making sure the name ends in `_database` (e.g. I used `taxii_root_demo_database` in the video)

Now for the Collections...

ArangoDB uses stix2arango as middle-ware.

As such Arango TAXII Server expects a pair of Collections (one vertex, one edge), named with the suffixes `*_vertex_collection` and `*_edge_collection`.

You can use stix2arango to create these collections (recommended).

Alternatively you can create them in the ArangoDB UI (make sure to create them in the correct database):

<video controls class="img-fluid">
    <source src="/assets/images/blog/2024-06-12/create-arango-collection.webm" type="video/webm" />
</video>

* Log in to the web interface (http://127.0.0.1:8529/), as root
* Select the Database you want to add the collections to (e.g. `taxii_root_demo_database`)
* Select `Collections`
* Select `Add new Collection`
* Create your Document Collection making sure the name ends in `_vertex_collection` (e.g. I used `demo_vertex_collection` in the video)
* Create your Edge Collection making sure the name ends in `_edge_collection` (e.g. I used `demo_edge_collection` in the video)

## User and authentication

Arango TAXII Server uses the ArangoDB user and permissions models.

Arango TAXII Server will only show Databases and Collections a user has either Read or Read/Write permissions to.

In order to use POST and DELETE TAXII endpoints, a user must have Read/Write permissions for the relevant Collection.

Here is a quick demonstration on how to manage user permissions in ArangoDB;

<video controls class="img-fluid">
    <source src="/assets/images/blog/2024-06-12/manage-arango-user-permissions.webm" type="video/webm" />
</video>

* Log in to the web interface (http://127.0.0.1:8529/), as root
* Select `_system`
* Select `Users`
* Select the user you want to change permissions for
* Select `Permissions`
* Assign correct permissions to Databases and/or Collections for selected user

## Using Arango TAXII Server

Now I have created a Database, some Collections, and have assigned user permissions I can start using the Arango TAXII Server.

To authenticate against the API, a user must pass their ArangoDB user credentials (base64 encoded) in the header of each request using basic auth as follows;

```
Authorization: Basic <credentials in base64>
```

If you want to use the Swagger UI, you can enter your credentials as follows;

<img class="img-fluid" src="/assets/images/blog/2024-06-12/swagger-ui-authorise.png" alt="Swagger UI authorise" title="Swagger UI authorise" />

To get all TAXII API Roots (aka ArangoDB Databases) my user is authorised to see:

```shell
curl -X 'GET' \
  'http://127.0.0.1:8000/api/taxii2/' \
  -H 'accept: application/json' \
  -H 'Authorization: Basic REVOKED'
```

```json
{
  "title": "Arango TAXII Server",
  "description": "https://github.com/muchdogesec/arango_taxii_server/",
  "contact": "noreply@dogesec.com",
  "api_roots": [
    "http://127.0.0.1:8000/api/taxii2/_system/",
    "http://127.0.0.1:8000/api/taxii2/cti_database/",
    "http://127.0.0.1:8000/api/taxii2/test_db_13_database/",
    "http://127.0.0.1:8000/api/taxii2/test_db_1_database/",
    "http://127.0.0.1:8000/api/taxii2/taxii_root_demo_database/"
  ]
}
```

You can see the `taxii_root_demo_database` API Root I created in the video above, along with some other Collections already on my server.

I can get info about this API Root as follows

```shell
curl -X 'GET' \
  'http://127.0.0.1:8000/api/taxii2/taxii_root_demo_database/' \
  -H 'accept: application/json' \
  -H 'Authorization: Basic REVOKED'
```

```json
{
  "max_content_length": 10485760,
  "title": "taxii_root_demo_database",
  "versions": [
    "application/stix+json;version=2.1"
  ]
}
```

Note, Arango TAXII Server only supports STIX 2.1 Objects.

Let's see what Collections this API Root holds:

```shell
curl -X 'GET' \
  'http://127.0.0.1:8000/api/taxii2/taxii_root_demo_database/collections/' \
  -H 'accept: application/json' \
  -H 'Authorization: Basic REVOKED'
```

```json
{
  "collections": [
    {
      "id": "demo",
      "title": "demo",
      "description": "vertex+edge",
      "can_read": true,
      "can_write": true,
      "media_types": [
        "application/stix+json;version=2.1"
      ]
    }
  ]
}
```

You can see only one collection is returned, even though I created two. Remember, that's because Arango TAXII Server will consider pairs of edge and vertex collections will first be joined before being exposed to the user. So above, `demo` considers the ArangoDB Collections `demo_vertex_collection` and `demo_edge_collection`.

You'll see my user can both read and write to this Collection. As noted, wether as user can read/write, read or even see a Collection is defined under the permissions of the ArangoDB user.

If there were more collection pairs, and the authenticated user could read them, you'd see them listed in this response too.

To see the objects this Collection holds...

```shell
curl -X 'GET' \
  'http://127.0.0.1:8000/api/taxii2/taxii_root_demo_database/collections/demo/objects/' \
  -H 'accept: application/json' \
  -H 'Authorization: Basic REVOKED'
```

```json
{
  "more": false,
  "next": null,
  "objects": []
}
```

The response is empty because I have not added any Objects to this Collection yet.

Let me do that now.

Here I am adding a Threat Actor ([taken from the STIX 2.1 examples](https://oasis-open.github.io/cti-documentation/examples/identifying-a-threat-actor-profile)):

```shell
curl -X 'POST' \
  'http://127.0.0.1:8000/api/taxii2/taxii_root_demo_database/collections/demo/objects/' \
  -H 'accept: application/json' \
  -H 'Authorization: Basic REVOKED' \
  -H 'Content-Type: application/json' \
  -d '{
  "objects": [{"type":"threat-actor","spec_version":"2.1","id":"threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428","created":"2014-11-19T23:39:03.893Z","modified":"2014-11-19T23:39:03.893Z","name":"Disco Team Threat Actor Group","description":"This organized threat actor group operates to create profit from all types of crime.","threat_actor_types":["crime-syndicate"],"aliases":["Equipo del Discoteca"],"roles":["agent"],"goals":["Steal Credit Card Information"],"sophistication":"expert","resource_level":"organization","primary_motivation":"personal-gain"}]
}'
```

```json
{
  "id": "c3c73600-2dd4-4dc1-aece-0b73eb959094",
  "status": "pending",
  "total_count": 1,
  "success_count": 0,
  "successes": [],
  "failure_count": 0,
  "failures": [],
  "pending_count": 1,
  "pendings": [
    {
      "message": null,
      "version": "2024-05-22 13:44:29.664616+00:00",
      "id": "threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428"
    }
  ],
  "request_timestamp": "2024-05-22T13:44:29.664616Z"
}
```

This request returns a status response for the POST request to add objects.

We can check the status of the request at any time as follows;

```shell
curl -X 'GET' \
  'http://127.0.0.1:8000/api/taxii2/taxii_root_demo_database/status/c3c73600-2dd4-4dc1-aece-0b73eb959094/' \
  -H 'accept: application/json' \
  -H 'Authorization: Basic REVOKED'
```

```json
{
  "id": "c3c73600-2dd4-4dc1-aece-0b73eb959094",
  "status": "complete",
  "total_count": 1,
  "success_count": 1,
  "successes": [
    {
      "message": null,
      "version": "2024-05-22 13:54:15.089657+00:00",
      "id": "threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428"
    }
  ],
  "failure_count": 0,
  "failures": [],
  "pending_count": 0,
  "pendings": [],
  "request_timestamp": "2024-05-22T13:54:15.089657Z"
}
```

The object has now moved from `pending` to `complete`.

If we now retrieve it:

```shell
curl -X 'GET' \
  'http://127.0.0.1:8000/api/taxii2/taxii_root_demo_database/collections/demo/objects/threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428/?limit=10' \
  -H 'accept: application/json' \
  -H 'Authorization: Basic REVOKED'
```

```json
{
  "more": false,
  "next": null,
  "objects": [
    {
      "aliases": [
        "Equipo del Discoteca"
      ],
      "created": "2014-11-19T23:39:03.893Z",
      "description": "This organized threat actor group operates to create profit from all types of crime.",
      "goals": [
        "Steal Credit Card Information"
      ],
      "id": "threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428",
      "modified": "2014-11-19T23:39:03.893Z",
      "name": "Disco Team Threat Actor Group",
      "primary_motivation": "personal-gain",
      "resource_level": "organization",
      "roles": [
        "agent"
      ],
      "sophistication": "expert",
      "spec_version": "2.1",
      "threat_actor_types": [
        "crime-syndicate"
      ],
      "type": "threat-actor"
    },
    {
      "aliases": [
        "Equipo del Discoteca"
      ],
      "created": "2014-11-19T23:39:03.893Z",
      "description": "This organized threat actor group operates to create profit from all types of crime.",
      "goals": [
        "Steal Credit Card Information"
      ],
      "id": "threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428",
      "modified": "2014-11-19T23:39:03.893Z",
      "name": "Disco Team Threat Actor Group",
      "primary_motivation": "personal-gain",
      "resource_level": "organization",
      "roles": [
        "agent"
      ],
      "sophistication": "expert",
      "spec_version": "2.1",
      "threat_actor_types": [
        "crime-syndicate"
      ],
      "type": "threat-actor"
    }
  ]
}
```

Because Arango TAXII Server uses stix2arango as middleware, it can also handle updates of objects.

Lets add the same object, with an updated `title` (`NEW TITLE`) and `modified` time (`2020-01-01T00:00:00.000Z`)

```shell
curl -X 'POST' \
  'http://127.0.0.1:8000/api/taxii2/taxii_root_demo_database/collections/demo/objects/' \
  -H 'accept: application/json' \
  -H 'Authorization: Basic REVOKED' \
  -H 'Content-Type: application/json' \
  -d '{
  "objects": [{"type":"threat-actor","spec_version":"2.1","id":"threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428","created":"2014-11-19T23:39:03.893Z","modified":"2020-01-01T00:00:00.000Z","name":"NEW TITLE","description":"This organized threat actor group operates to create profit from all types of crime.","threat_actor_types":["crime-syndicate"],"aliases":["Equipo del Discoteca"],"roles":["agent"],"goals":["Steal Credit Card Information"],"sophistication":"expert","resource_level":"organization","primary_motivation":"personal-gain"}]
}'
```

```json
{
  "id": "59684531-e636-4b6e-b209-453b0c68df47",
  "status": "pending",
  "total_count": 1,
  "success_count": 0,
  "successes": [],
  "failure_count": 0,
  "failures": [],
  "pending_count": 1,
  "pendings": [
    {
      "message": null,
      "version": "2024-05-22 13:59:31.898585+00:00",
      "id": "threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428"
    }
  ],
  "request_timestamp": "2024-05-22T13:59:31.898585Z"
}
```

If I now check the version endpoint;

```shell
curl -X 'GET' \
  'http://127.0.0.1:8000/api/taxii2/taxii_root_demo_database/collections/demo/objects/threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428/versions/' \
  -H 'accept: application/json' \
  -H 'Authorization: Basic REVOKED'
```

```json
{
  "more": false,
  "next": null,
  "versions": [
    "2014-11-19T23:39:03.893Z",
    "2020-01-01T00:00:00.000Z"
  ]
}
```

We can see both versions in the database.

Using the parameters available on the object endpoint, I can select the desired version of this object. By default, the TAXII server will always return the latest version of the object (in this case `2020-01-01T00:00:00.000Z`).

## And that's 10 minutes!

Our Arango TAXII Server implements the entire [TAXII specification](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html).

In this post I have only covered some of the TAXII endpoints and have not shown you how to use the filtering and paging parameters available on them.

My suggestion would be to keep playing with Arango TAXII Server using the Swagger UI interface. You'll quickly get familiar with how it works and what you can do.

Of course, if you just want to connect a TAXII Client to your Arango TAXII Server install you don't need to worry about any of this -- the Client will handle it all for you!