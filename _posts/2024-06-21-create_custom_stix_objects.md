---
date: 2024-06-21
last_modified: 2024-06-21
title: "Creating Your Own Custom STIX Objects"
description: "Sometimes the default STIX 2.1 objects will not be broad enough for your needs. This post describes how you can extend STIX. Python code included."
categories:
  - DIY
  - TUTORIAL
tags: [
    STIX
]
products:
    - stix4doge
    - txt2stix
author_staff_member: david-greenwood
image: /assets/images/blog/2024-06-21/header.png
featured_image: /assets/images/blog/2024-06-21/header.png
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

[The STIX 2.1 Specification covers many of the most common cyber threat intelligence concepts](/blog/beginners-guide-stix-objects/).

However, there are times when the default STIX 2.1 objects will not be broad enough for your needs.

For these cases, you can use [STIX Extensions](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_32j232tfvtly) which allow you to define new STIX Objects and Properties by creating an Extension Definition that defines a schema for them.

## Overview

There are two ways to extend STIX using STIX Extensions, depending on what you want to achieve.

1. A brand-new STIX Object
	* this is needed when the current STIX objects do not closely match the type of "thing" you are trying to describe.
2. Additional properties for an existing STIX Object 
	* this is typically done to represent a sub-component or module of one or more STIX Object types.

Note, at the end of this post I also describe the legacy ways STIX objects can be created or extended with new properties. In almost all cases you should use the current way of extending STIX.

## 1. Create a brand-new STIX Object

Whilst STIX 2.1 has a broad range of Objects, there are times when an existing one does not quite meet need existing needs.

For example, our tool [cwe2stix](https://github.com/muchdogesec/cwe2stix) turns CWEs into STIX objects. CWEs are weaknesses in software. There is no STIX SDO that really covers the concept of a weakness, thus it makes sense to create a custom STIX SDO to represent it.

### The Extension Definition

The first part of the process to do this is to create an Extension Definition STIX object. Here's an example;

```json
{
    "type": "extension-definition",
    "spec_version": "2.1",
    "id": "extension-definition--31725edc-7d81-5db7-908a-9134f322284a",
    "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "name": "Weakness",
    "description": "This extension creates a new SDO that can be used to represent weaknesses (for CWEs).",
    "schema": "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/schemas/sdos/weakness.json",
    "version": "1.0",
    "extension_types": [
        "new-sdo"
    ],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
    ]
}
```

The main job of the Extension Definition is to link to the schema of the new object you will create (in this example, a Weakness object). This makes it possible for those reading the custom object to understand how each property is constructed. It also gives publishers enough information to use your custom object.

Here is a simple bit of code as an example to generate the above Extension Definition;

```python
import stix2
from stix2 import ExtensionDefinition

WeaknessExtensionDefinition = ExtensionDefinition(
    id="extension-definition--31725edc-7d81-5db7-908a-9134f322284a",
    created_by_ref="identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="Weakness",
    description="This extension creates a new SDO that can be used to represent weaknesses (for CWEs).",
    schema="https://raw.githubusercontent.com/muchdogesec/stix4doge/main/schemas/sdos/weakness.json",
    version="1.0",
    extension_types=[
    	"new-sdo"
    ],
    object_marking_refs=[
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
    ]
)

print(WeaknessExtensionDefinition)
```

The `extension_types` can be either `new-sdo` for SDOs (as above), `new-sco` for SCOs, or `new-sro` for SROs. If you're not sure about when to use each of these options, [read my STIX 2.1 guide that will explain all](/blog/beginners_guide_stix_objects/).

I use a UUIDv5 for the `id` of the object to ensure it persists during updates.

#### A side note on schemas

[The OASIS core STIX 2.1 schemas will help provide some guidance on how to define your `schema`](https://github.com/oasis-open/cti-stix2-json-schemas/).

A well defined schema is vital for creators of STIX objects wanting to use your schema to understand the properties and data types available for them to use. It's equally important for consumers to understand the type of values that can be returned.

When getting started with defining a schema is to take a look at some existing examples -- [the schemas for native STIX objects created by OASIS are perfect for this](https://github.com/oasis-open/cti-stix2-json-schemas). For example, the [Vulnerability SDO schema](https://github.com/oasis-open/cti-stix2-json-schemas/blob/master/schemas/sdos/vulnerability.json).

This guide, [Understanding JSON Schema](https://json-schema.org/understanding-json-schema/index.html), is also a helpful resource for newbies too.

Here's the schema for my custom Weakness SDO;

```json
{
	"$id": "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/schemas/sdos/weakness.json",
	"$schema": "https://json-schema.org/draft/2020-12/schema",
	"title": "weakness",
	"description": "This extension creates a new SDO that can be used to represent weaknesses (for CWEs).",
	"type": "object",
	"allOf": [
		{
			"$ref": "https://github.com/oasis-open/cti-stix2-json-schemas/blob/master/schemas/common/core.json"
		},
		{
			"properties": {
				"type": {
					"type": "string",
					"description": "The value of this property MUST be `weakness`.",
					"enum": [
						"weakness"
					]
				},
				"id": {
					"title": "id",
					"pattern": "^weakness--"
				},
				"name": {
					"type": "string",
					"description": "The CWE ID used to identify the Weakness."
				},
				"description": {
				  "type": "string",
				  "description": "A description about the Weakness."
				},
				"modes_of_introduction": {
					"type": "array",
					"items": {
						"type": "string"
					}
				},
				"likelihood_of_exploit": {
					"type": "array",
					"items": {
						"type": "string"
					}
				},
				"common_consequences": {
					"type": "array",
					"items": {
						"type": "string"
					}
				},
				"detection_methods": {
					"type": "array",
					"items": {
						"type": "string"
					}
				},
				"extensions": {
					"type": "object",
					"properties": {
						"extension-definition--31725edc-7d81-5db7-908a-9134f322284a": {
							"type": "object",
							"properties": {
            					"extension_type": {
									"enum": [
										"new-sdo"
									]
            					}
							},
							"required": ["new-sdo"]
						},
					"required": ["extension-definition--31725edc-7d81-5db7-908a-9134f322284a"]
					}
				}
			}
		}
	],
	"required": [
		"type",
		"id",
		"name",
		"extensions"
  	]
}
```

You'll see I don't actually define all the properties (e.g. `spec_version`, as I can import these from the core STIX schema `"$ref": "../common/core.json"`.

### The Custom Object

Now all the ground-work has been laid, here is an example of a custom STIX Weakness object:

```json
{
    "type": "weakness",
    "spec_version": "2.1",
    "id": "weakness--c8feb14a-270e-50cb-8470-ecf91ef90e06",
    "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "name": "CWE Demo",
    "description": "A demo weakness",
    "modes_of_introduction": [
        "Implementation"
    ],
    "likelihood_of_exploit": [
        "Medium"
    ],
    "common_consequences": [
        "Confidentiality",
        "Integrity"
    ],
    "detection_methods": [
        "Automated Static Analysis"
    ],
    "external_references": [
        {
            "source_name": "cwe",
            "url": "http://cwe.mitre.org/data/definitions/117.html",
            "external_id": "CWE-117"
        }
    ],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
    ],
    "extensions": {
        "extension-definition--31725edc-7d81-5db7-908a-9134f322284a": {
            "extension_type": "new-sdo"
        }
    }
}
```

See how the `extensions` section links to my Extension Definition object previously shown as a reference.

Here is some basic code that can be used used to generate the above Weakness object:

```python
import stix2
from stix2 import CustomObject
from stix2.properties import (
    BooleanProperty, ExtensionsProperty, ReferenceProperty,
    IDProperty, IntegerProperty, ListProperty, StringProperty,
    TimestampProperty, TypeProperty,
)
from stix2.v21.common import (
    ExternalReference,
)
from stix2.utils import NOW

_type = 'weakness'
@CustomObject('weakness', [
    ('type', TypeProperty(_type, spec_version='2.1')),
    ('spec_version', StringProperty(fixed='2.1')),
    ('id', IDProperty(_type, spec_version='2.1')),
    ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
    ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
    ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
    ('name', StringProperty(required=True)),
    ('description', StringProperty()),
    ('modes_of_introduction', ListProperty(StringProperty)),
    ('common_consequences', ListProperty(StringProperty)),
    ('detection_methods', ListProperty(StringProperty)),
    ('likelihood_of_exploit', ListProperty(StringProperty)),
    ('external_references', ListProperty(ExternalReference)),
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
    ('extensions', ExtensionsProperty(spec_version='2.1'))
])
class Weakness(object):
    def __init__(self, **kwargs):
        pass

WeaknessSDO = Weakness(
    id="weakness--c8feb14a-270e-50cb-8470-ecf91ef90e06",
    created_by_ref="identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="CWE Demo",
    description="A demo weakness",
    modes_of_introduction=[
        "Implementation"
    ],
    likelihood_of_exploit=[
        "Medium"
    ],
    common_consequences=[
        "Confidentiality",
        "Integrity"
    ],
    detection_methods=[
        "Automated Static Analysis"
    ],
    external_references=[
        {
            "source_name": "cwe",
            "url": "http://cwe.mitre.org/data/definitions/117.html",
            "external_id": "CWE-117"
        }
    ],
    object_marking_refs=[
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
   	],
    extensions= {
        "extension-definition--31725edc-7d81-5db7-908a-9134f322284a": {
            "extension_type": "new-sdo"
        }
    }
)

print(WeaknessSDO)
```

This code creates a custom Weakness class with the help of the STIX2 library, and then uses it to create the object.

A very helpful source of more examples for creating STIX classes can be seen for the core [SDOs here](https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/v21/sdo.py), [SROs here](https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/v21/sro.py), and [SCOs here](https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/v21/observables.py).

## 2. Custom Properties defined using an Extension Definition

Sometimes an entirely new object is not required. Perhaps you want to add an extra property to a core STIX object to represent something custom to your dataset (perhaps some sort of custom scoring).

Custom properties are defined in a similar way to custom objects (using an Extension Definition) but instead of creating an entirely new object, they just define the addition of a new custom property.

For custom properties two types of Extension Definition `extension_types` can be used;

1. `property-extension`: custom properties are nested in the extensions field
2. `toplevel-property-extension`: custom properties are nested at the top level of the object

Generally I strongly recommend using `property-extension`s as these are better understood by downstream tools that enforce strict STIX validation.

### Using property-extension

To compare the two, here is an example `property-extension`. First the Extension Definition:

```json
{
    "id": "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e",
    "type": "extension-definition",
    "spec_version": "2.1",
    "name": "Adding demo scoring properties to Indicator",
    "description": "This schema adds two custom properties to a STIX object",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    "schema": "https://raw.githubusercontent.com/example.json",
    "version": "1.0",
    "extension_types": [
        "property-extension"
    ],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
    ],
}
```

Created using the code;

```python
import stix2
from stix2 import ExtensionDefinition

PropertyExtensionDefinition = ExtensionDefinition(
    id="extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e",
    created_by_ref="identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="Adding demo scoring properties to Indicator",
    description="This schema adds two custom properties to a STIX Indicator object",
    schema="https://raw.githubusercontent.com/example.json",
    version="1.0",
    extension_types=[
    	"property-extension"
    ],
    object_marking_refs=[
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
    ]
)

print(PropertyExtensionDefinition)
```

The schema is not published at the URL shown in the `schema` field, but it would look as follows;

```json
{
	"$id": "https://raw.githubusercontent.com/example.json",
	"$schema": "https://json-schema.org/draft/2020-12/schema",
	"title": "Adding demo scoring properties to Indicator",
	"description": "This schema adds two custom properties to a STIX Indicator object",
	"type": "object",
	"allOf": [
		{
			"$ref": "https://github.com/oasis-open/cti-stix2-json-schemas/blob/master/schemas/common/core.json"
		},
		{
			"properties": {
				"extensions": {
					"type": "object",
					"properties": {
						"extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
							"type": "object",
							"properties": {
            					"extension_type": {
									"enum": [
										"property-extension"
									]
            					},
								"impact": {
								  "type": "number",
								  "description": "The impact of the Indicator on a scale between 1-10"
								},
								"maliciousness": {
								  "type": "number",
								  "description": "The maliciousness of the Indicator is on a scale between 1-10"
								},
							},
							"required": ["property-extension"]
						},
					"required": ["extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e"]
					}
				}
			}
		}
	],
	"required": [
		"extensions"
  	]
}
```

And the Indicator that uses the two custom properties I've defined.

```json
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--e97bfccf-8970-4a3c-9cd1-5b5b97ed5d0c",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    "name": "File hash for Poison Ivy variant",
    "description": "This file hash indicates that a sample of Poison Ivy is present.",
    "labels": [
       "malicious-activity"
    ],
    "pattern": "[file:hashes.'SHA-256' = 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c']",
    "pattern_type": "stix",
    "valid_from": "2020-01-01T00:00:00.000Z",
    "extensions": {
        "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e" : {
            "extension_type": "property-extension",
            "impact": 5,
            "maliciousness": 8
        }
    },
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
    ]
}
```

As you can see the custom properties `impact` and `maliciousness` are nested inside the extension definition (`extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e`)property.

For reference, here is the code I used to generate the Indicator printed above;

```python
import stix2
from stix2 import Indicator

IndicatorPropertyExtension = Indicator(
    id="indicator--e97bfccf-8970-4a3c-9cd1-5b5b97ed5d0c",
    created_by_ref="identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="File hash for Poison Ivy variant",
    description="This file hash indicates that a sample of Poison Ivy is present.",
    labels=[
    	"malicious-activity"
    ],
    pattern="[file:hashes.'SHA-256' = 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c']",
    pattern_type="stix",
    valid_from="2020-01-01T00:00:00.000Z",
    object_marking_refs=[
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
    ],
    extensions= {
        "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
            "extension_type": "property-extension",
            "impact": 5,
            "maliciousness": 8
        }
    }
)

print(IndicatorPropertyExtension)
```

### Using toplevel-property-extension

Now lets look at using the `toplevel-property-extension` approach. Here is my Extension Definition;

```json
{
    "id": "extension-definition--71736db5-10db-43d3-b0e3-65cf81601fe1",
    "type": "extension-definition",
    "spec_version": "2.1",
    "name": "Adding demo scoring properties to Indicator",
    "description": "This schema adds two custom properties to a STIX Indicator object",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    "schema": "https://raw.githubusercontent.com/another_example.json",
    "version": "1.0",
    "extension_types": [
        "toplevel-property-extension"
    ],
    "extension_properties" : [
        "toxicity",
        "rank"
    ],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
    ]
}
```

Here's the code you can use to generate it;

```python
import stix2
from stix2 import ExtensionDefinition

TopLevelPropertyExtensionDefinition = ExtensionDefinition(
    id="extension-definition--71736db5-10db-43d3-b0e3-65cf81601fe1",
    created_by_ref="identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="Adding demo scoring properties to Indicator",
    description="This schema adds two custom properties to a STIX Indicator object",
    schema="https://raw.githubusercontent.com/another_example.json",
    version="1.0",
    extension_types=[
    	"toplevel-property-extension"
    ],
    object_marking_refs=[
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
    ]
)

print(TopLevelPropertyExtensionDefinition)
```

And the schema:

```json
{
	"$id": "https://raw.githubusercontent.com/another_example.json",
	"$schema": "https://json-schema.org/draft/2020-12/schema",
	"title": "Adding demo scoring properties to Indicator",
	"description": "This schema adds two custom properties to a STIX Indicator object",
	"type": "object",
	"allOf": [
		{
			"$ref": "https://github.com/oasis-open/cti-stix2-json-schemas/blob/master/schemas/common/core.json"
		},
		{
			"properties": {
				"impact": {
					"type": "number",
					"description": "The impact of the Indicator on a scale between 1-10"
				},
				"maliciousness": {
					"type": "number",
					"description": "The maliciousness of the Indicator is on a scale between 1-10"
				},
				"extensions": {
					"type": "object",
					"properties": {
						"extension-definition--71736db5-10db-43d3-b0e3-65cf81601fe1": {
							"type": "object",
							"properties": {
            					"extension_type": {
									"enum": [
										"toplevel-property-extension"
									]
            					}
							},
							"required": ["toplevel-property-extension"]
						},
					"required": ["extension-definition--71736db5-10db-43d3-b0e3-65cf81601fe1"]
					}
				}
			}
		}
	],
	"required": [
		"extensions"
  	]
}
```

And finally, what all this looks like in the Indicator;

```json
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--66a63e16-92d7-4b2f-bd3d-21540d6b3fc7",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    "name": "File hash for Poison Ivy variant",
    "description": "This file hash indicates that a sample of Poison Ivy is present.",
    "labels": [
        "malicious-activity"
    ],
    "pattern": "[file:hashes.'SHA-256' = 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c']",
    "pattern_type": "stix",
    "valid_from": "2020-01-01T00:00:00.000Z",
    "impact": 1,
    "maliciousness": 2,
    "extensions": {
        "extension-definition--71736db5-10db-43d3-b0e3-65cf81601fe1" : {
            "extension_type": "toplevel-property-extension"
        }
    },
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
    ]
}
```

Which is generated by the code;

```python
import stix2
from stix2 import Indicator

IndicatorTopLevelPropertyExtension = Indicator(
    id="indicator--66a63e16-92d7-4b2f-bd3d-21540d6b3fc7",
    created_by_ref="identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="File hash for Poison Ivy variant",
    description="This file hash indicates that a sample of Poison Ivy is present.",
    labels=[
    	"malicious-activity"
    ],
    pattern="[file:hashes.'SHA-256' = 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c']",
    pattern_type="stix",
    valid_from="2020-01-01T00:00:00.000Z",
    object_marking_refs=[
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
    ],
    impact=1,
    maliciousness=2,
    extensions= {
        "extension-definition--71736db5-10db-43d3-b0e3-65cf81601fe1": {
            "extension_type": "toplevel-property-extension"
        }
    }
)

print(IndicatorTopLevelPropertyExtension)
```

Reviewing the two Indicator object I've created, the key difference being the custom properties in the `toplevel-property-extension` (`impact` and `maliciousness`) exist at the top level of the object. Where as for `property-extension` these are nested in the `extensions` object.

Beware though, as I noted earlier many downstream products will throw errors when the `toplevel-property-extension` is implemented as they often are built to strictly consider the Indicator SDOs pure STIX 2.1 properties defined in the STIX specification.

Having them nested inside an extension definition using the `property-extension` approach is much more widely supported in downstream tools as they don't conflict with the pure STIX 2.1 Indicator properties.

## The downstream impact of using custom objects and properties

Note, when working with custom objects and properties within the STIX2 Python library, [you need to pass the `allow_custom` argument](https://stix2.readthedocs.io/en/latest/guide/parsing.html).

For example, if you want to create a Bundle with a custom object (or property) in `objects`, you need to set `allow_custom=True`.

Here is an example to demonstrate this, adding a custom Weakness object to a STIX bundle;

```python
import stix2
from stix2 import CustomObject
from stix2 import Bundle
from stix2.properties import (
    BooleanProperty, ExtensionsProperty, ReferenceProperty,
    IDProperty, IntegerProperty, ListProperty, StringProperty,
    TimestampProperty, TypeProperty,
)
from stix2.v21.common import (
    ExternalReference,
)
from stix2.utils import NOW

_type = 'weakness'
@CustomObject('weakness', [
    ('type', TypeProperty(_type, spec_version='2.1')),
    ('spec_version', StringProperty(fixed='2.1')),
    ('id', IDProperty(_type, spec_version='2.1')),
    ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
    ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
    ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
    ('name', StringProperty(required=True)),
    ('description', StringProperty()),
    ('modes_of_introduction', ListProperty(StringProperty)),
    ('common_consequences', ListProperty(StringProperty)),
    ('detection_methods', ListProperty(StringProperty)),
    ('likelihood_of_exploit', ListProperty(StringProperty)),
    ('external_references', ListProperty(ExternalReference)),
    ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
    ('extensions', ExtensionsProperty(spec_version='2.1'))
])
class Weakness(object):
    def __init__(self, **kwargs):
        pass

WeaknessSDO = Weakness(
    id="weakness--c8feb14a-270e-50cb-8470-ecf91ef90e06",
    created_by_ref="identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
    name="CWE Demo",
    description="A demo weakness",
    modes_of_introduction=[
        "Implementation"
    ],
    likelihood_of_exploit=[
        "Medium"
    ],
    common_consequences=[
        "Confidentiality",
        "Integrity"
    ],
    detection_methods=[
        "Automated Static Analysis"
    ],
    external_references=[
        {
            "source_name": "cwe",
            "url": "http://cwe.mitre.org/data/definitions/117.html",
            "external_id": "CWE-117"
        }
    ],
    object_marking_refs=[
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
   	],
    extensions= {
        "extension-definition--31725edc-7d81-5db7-908a-9134f322284a": {
            "extension_type": "new-sdo"
        }
    }
)

BundleObjects = Bundle(
    id="bundle--84474af2-6c78-44b2-8945-56c1c8474e06",
    objects=WeaknessSDO,
    allow_custom=True
)

print(BundleObjects)
```

## A note on legacy custom objects and properties

In older version of the STIX specification, another way to define custom objects and properties was defined.

You will still see this a lot today, however, you should not follow this approach!

The STIX 2.1 MITRE ATT&CK dataset is a good example of the implementation of custom objects and properties.

### 2.1 Legacy Custom Objects

Legacy custom Objects used to be created by specifying a `type` Property value prefixed with `x-` (e.g. `"type": "x-my-custom-object"`).

MITRE ATT&CK is a good example of STIX 2.1 Custom Objects. To represent MITRE ATT&CK Tactics, MITRE use a custom Tactic Object (`x-mitre-tactic--`).

Here's TA0006: Credential Access...

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
    "modified": "2019-07-19T17:43:41.967Z",
    "name": "Credential Access",
    "description": "The adversary is trying to steal account names and passwords.\n\nCredential Access consists of techniques for stealing credentials like account names and passwords. Techniques used to get credentials include keylogging or credential dumping. Using legitimate credentials can give adversaries access to systems, make them harder to detect, and provide the opportunity to create more accounts to help achieve their goals.",
    "x_mitre_version": "1.0",
    "x_mitre_attack_spec_version": "2.1.0",
    "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
    "x_mitre_shortname": "credential-access"
}
```

Custom Objects can contain both Common Properties, Unique Object Properties defined in the STIX 2.1 specification, or Custom Properties (ultimately the producer defines the specification of their Custom Object).

Unlike when using Extension Definitions, Custom Objects defined in this way make no distinction between SDO, SCO, or SRO. The producer defines the `type` value of the Custom Object and it can be used for any of these three cases (or something else entirely, if need be).

### 2.2 Legacy Custom Properties

Custom Properties have historically been the most common way producers extend STIX 2.1 Objects because they are very useful for specific information relating to their service or processes, for example, internal references.

Custom Properties in a STIX 2.1 predefined Object or a Custom Object can be declared using the prefix `x_` (e.g `"x_custom_property": "value"`).

You can see them in the previous example of TA0006 where the following custom properties being used;

* `x_mitre_version`
* `x_mitre_attack_spec_version`
* `x_mitre_modified_by_ref`
* `x_mitre_shortname`

Again, because these properties don't have to have a defined schema in the way they do for Extension Definitions it can be hard for consumers (namely software products) to work with them.

## Need help creating your own custom objects?

[Check out our stix4doge repository for more code examples](https://github.com/muchdogesec/stix4doge).

In the stix4doge repository we've implemented a modular approach to generating the custom STIX objects we use including; Weakness, Cryptocurrency Transaction, Cryptocurrency Wallet, User Agent, Phone Number, Bank Account, and Bank Card.

txt2stix uses stix4doge to create the above custom objects. Sometimes it's helpful to grasp a concept by seeing it implemented in a working example. If that sounds like how you like to learn:

* [txt2stix](https://github.com/muchdogesec/txt2stix/)