---
date: 2024-06-10
last_modified: 2024-06-10
title: "Understanding the Structure of CVEs and CPEs"
description: "Our tools require CVEs and CPEs in a STIX format. We have spent a lot of time learning the data NVD provides. This post shows our learning."
categories:
  - DIY
tags: [
    NVD,
    CPE,
    CVE,
    SBOM
]
products:
    - cve2stix
    - cpe2stix
    - cxe2stix_helper
    - Vulmatch
author_staff_member: david-greenwood
image: /assets/images/blog/2024-06-10/header.png
featured_image: /assets/images/blog/2024-06-10/header.png
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

We needed to convert NVD CVEs and CPEs into STIX objects.

This is the research our team collated when designing the code for [cve2stix](https://github.com/muchdogesec/cve2stix) and [cpe2stix](https://github.com/muchdogesec/cpe2stix).

Bonus: I'll show you how to create STIX Patterns to detect if products (CPEs) in your stack are vulnerable.

### CPEs

Having a standardised way of to describe products becomes very useful when managing those you're using (for example in a software bill of materials). That is where Common Platform Enumerations (CPEs) come in;

> CPE is a structured naming scheme for information technology systems, software, and packages. Based upon the generic syntax for Uniform Resource Identifiers (URI), CPE includes a formal name format, a method for checking names against a system, and a description format for binding text and tests to a name.

[CPEs were originally managed by MITRE](https://cpe.mitre.org/) but ownership has since been transferred to the [US National Institute of Standard of Technology (NIST)](https://nvd.nist.gov/products/cpe).

For cpe2stix, the key takeaways for working with CPEs are that 1) they are published regularly, and, 2) NVD can updated the data inside at CPE record once it is published (where the modified time returned via the API will change).

#### CPE Structure

First it is important to understand the structure of a CPE.

The most important part of a CPE is the URI -- a computer readable format to describe the details of operating systems, software applications, or hardware devices. 

Here is the CPE 2.3 URI schema (there are older versions, but I won't go into those in this post);

```
cpe:2.3:<part>:<vendor>:<product>:
<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw:>:<target_hw>:<other>
```

Where:

* cpe: always `cpe`
* 2.3: the cpe version (currently latest is 2.3)
* `<part>`: The part attribute SHALL have one of these three string values:
    * `a` for applications,
    * `o` for operating systems,
    * `h` for hardware devices
* `<vendor>`: described or identifies the person or organisation that manufactured or created the product
* `<product>`: describes or identifies the most common and recognisable title or name of the product
* `<version>`: vendor-specific alphanumeric strings characterising the particular release version of the product
* `<update>`: vendor-specific alphanumeric strings characterising the particular update, service pack, or point release of the product.
* `<edition>` assigned the logical value ANY (`*`) except where required for backward compatibility with version 2.2 of the CPE specification
* `<language>`:  valid language tags as defined by [RFC5646]
* `<sw_edition>`: characterises how the product is tailored to a particular market or class
of end users.
* `<target_sw>`: characterises the software computing environment within which the product operates.
* `<target_hw>`: characterises the instruction set architecture (e.g., x86) on which the product being described or identified operates
* `<other>`:  capture any other general descriptive or identifying information which is vendor- or product-specific and which does not logically fit in any other attribute value

Here is an example of a CPE URI (for Apple Quicktime v7.71.80.42);

```
cpe:2.3:a:apple:quicktime:7.71.80.42:*:*:*:*:*:*:*
```

Where;

* `part`: `a` (application)
* `vendor`: apple
* `product`: quicktime
* `version`: 7.71.80.42
* `update`: *
* `edition`: *
* `language`: * 
* `sw_edition`: *
* `target_sw`: *
* `target_hw`: *
* `other`: *

Where;

* `*` means ANY specified or unspecified option
* `-` means no product version specified (but still represents a distinct version of the product)

A word of warning when parsing CPE URI's, you will occasionally see escape characters (`\\`) in the match string. Here, `"cpe:2.3:a:apple:swiftnio_http\\/2:1.19.1:*:*:*:*:swift:*:*"`, two backslashes `\\` escape the forward slash `/` present in the version string. For full information about when escaping is needed, [read the CPE 2.3 naming spec document here](https://www.govinfo.gov/content/pkg/GOVPUB-C13-c213837a04c3bcc778ebfd420c6a3f2a/pdf/GOVPUB-C13-c213837a04c3bcc778ebfd420c6a3f2a.pdf).

[You can browse all CPEs in the dictionary here](https://nvd.nist.gov/products/cpe/search). Here is the record shown in the example above: https://nvd.nist.gov/products/cpe/detail/165622

The NVD CPE data can be also accessed [via their APIs](https://nvd.nist.gov/developers/products).

[To start using the NVD APIs you will need to request an API key here](https://nvd.nist.gov/developers/start-here).

Once you have your API key, you can start making requests. The API Key must be passed in the header of the request using the `apiKey` property.

#### CPE API's

[There are two CPE endpoints](https://nvd.nist.gov/developers/products).

* CPE API: The CPE API is used to easily retrieve information on a single CPE record or a collection of CPE records from the Official CPE Dictionary.
* Match Criteria API: The CPE Match Criteria API is used to easily retrieve the complete list of valid CPE Match Strings. 

cpe2stix uses the CPE API, used to easily retrieve information on a single CPE record or a collection of CPE records from the [Official CPE Dictionary](https://nvd.nist.gov/products/cpe/statistics).

cve2stix used the Match Criteria API (I'll cover that later in this post when looking at cve2stix).

##### CPE API

The root endpoint will return all CPEs;

```shell
GET https://services.nvd.nist.gov/rest/json/cpes/2.0/
```

At the time of writing this returns over 1.25 million CPEs!

```json
{
    "resultsPerPage": 10000,
    "startIndex": 0,
    "totalResults": 1267211,
    "format": "NVD_CPE",
    "version": "2.0",
    "timestamp": "2024-05-21T10:41:59.670",
    "products": [
```

There are a range of parameters to filter the CPEs returned in the response.

For example, I can use a full or partial `cpeMatchString` parameter (the CPE URI shown earlier) to query the API for it;

```shell
GET https://services.nvd.nist.gov/rest/json/cpes/2.0/?cpeMatchString=cpe:2.3:a:microsoft:access:-:*:*:*:*:*:*:*
```

Which returns;

```json
{
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CPE",
    "version": "2.0",
    "timestamp": "2023-01-06T08:51:32.650",
    "products": [
        {
            "cpe": {
                "deprecated": false,
                "cpeName": "cpe:2.3:a:microsoft:access:-:*:*:*:*:*:*:*",
                "cpeNameId": "87316812-5F2C-4286-94FE-CC98B9EAEF53",
                "lastModified": "2011-01-12T14:35:56.427",
                "created": "2007-08-23T21:05:57.937",
                "titles": [
                    {
                        "title": "Microsoft Access",
                        "lang": "en"
                    },
                    {
                        "title": "マイクロソフト Access",
                        "lang": "ja"
                    }
                ]
            }
        }
    ]
}
```

The response shows the friendly name of the software in different languages (`Microsoft Access` (EN) and `マイクロソフト Access` (JA)) among other fields.

You do not need to pass all parts of a `cpeMatchString` (URI). `cpeMatchString=cpe:2.3:a:microsoft:access` is exactly the same as `cpeMatchString=cpe:2.3:a:microsoft:access:::` which is exactly the same as `cpe:2.3:a:microsoft:access:*:*:*:*:*:*:*:*` (all these `cpeMatchString`'s return 32 results at the time of writing).

Taking this further if I wanted a list of all Apple (`vendor=apple`) applications (`part=a`) released in the last 3 months of 2022 I could introduce a few more parameters and run the following query;

```shell
GET https://services.nvd.nist.gov/rest/json/cpes/2.0/?lastModStartDate=2021-08-04T13:00:00.000%2B01:00&lastModEndDate=2021-10-22T13:36:00.000%2B01:00&cpeMatchString=cpe:2.3:a:apple
```

Returns three results;

```json
{
    "resultsPerPage": 3,
    "startIndex": 0,
    "totalResults": 3,
    "format": "NVD_CPE",
    "version": "2.0",
    "timestamp": "2023-01-06T15:46:40.793",
    "products": [
        {
            "cpe": {
                "deprecated": false,
                "cpeName": "cpe:2.3:a:apple:safari:14.1.2:*:*:*:*:*:*:*",
                "cpeNameId": "78DEE287-2542-4591-99FC-E961C3DBE74E",
                "lastModified": "2021-09-17T18:29:54.370",
                "created": "2021-09-14T14:43:00.740",
                "titles": [
                    {
                        "title": "Apple Safari 14.1.2",
                        "lang": "en"
                    }
                ],
                "refs": [
                    {
                        "ref": "https://support.apple.com/en-us/HT212606",
                        "type": "Change Log"
                    }
                ]
            }
        },
        {
            "cpe": {
                "deprecated": false,
                "cpeName": "cpe:2.3:a:apple:boot_camp:6.1.14:*:*:*:*:*:*:*",
                "cpeNameId": "E5428D10-40C8-4C2A-BBEB-9936654714FF",
                "lastModified": "2021-09-19T01:27:12.450",
                "created": "2021-09-16T14:42:09.773",
                "titles": [
                    {
                        "title": "Apple Boot Camp 6.1.14",
                        "lang": "en"
                    }
                ],
                "refs": [
                    {
                        "ref": "https://support.apple.com/en-us/HT212517",
                        "type": "Product"
                    }
                ]
            }
        },
        {
            "cpe": {
                "deprecated": false,
                "cpeName": "cpe:2.3:a:apple:boot_camp:-:*:*:*:*:*:*:*",
                "cpeNameId": "0AAAB8F0-3F20-4DAB-B7D0-6AE256E4B64A",
                "lastModified": "2021-09-22T16:55:23.163",
                "created": "2021-09-21T13:32:21.907",
                "titles": [
                    {
                        "title": "Apple Boot Camp",
                        "lang": "en"
                    }
                ],
                "refs": [
                    {
                        "ref": "https://support.apple.com/boot-camp",
                        "type": "Product"
                    }
                ]
            }
        }
    ]
}
```

[Full CPE API response schema for reference](https://csrc.nist.gov/schema/nvd/api/2.0/cpe_api_json_2.0.schema).

Using each `cpe` entry, cpe2stix maps relevant values to properties found in the STIX 2.1 Software object. [See the cpe2stix docs for more information for the details of this mapping](https://github.com/muchdogesec/cpe2stix).

### CVEs

> The mission of the CVE® Program is to identify, define, and catalog publicly disclosed cybersecurity vulnerabilities. There is one CVE Record for each vulnerability in the catalog. The vulnerabilities are discovered then assigned and published by organizations from around the world that have partnered with the CVE Program. Partners publish CVE Records to communicate consistent descriptions of vulnerabilities. Information technology and cybersecurity professionals use CVE Records to ensure they are discussing the same issue, and to coordinate their efforts to prioritize and address the vulnerabilities.

Source: https://www.cve.org/About/Overview

In January 1999, the MITRE Corporation published “[Towards a Common Enumeration of Vulnerabilities](https://cve.mitre.org/docs/docs-2000/cerias.html)”.

The aim; to identify, define, and catalog publicly disclosed cybersecurity vulnerabilities.

Very soon after this meeting, the original 321 Common Vulnerabilities and Exposures (CVE) Entries, including entries from previous years, was created and the CVE List was officially launched to the public in September 1999.

Each CVE has a unique ID. In its first iteration, 9,999 CVEs were allowed per year because CVE IDs were assigned using the format CVE-YYYY-NNNN (CVE-2001-1473). Currently, tens-of-thousands of CVEs are reported a year. To account for this explosion of CVEs, the CVE ID syntax was extended by adding one more digit to the N potion from four to five digits to CVE-YYYY-NNNNN in 2015 (some now have up to 7 digits, e.g. CVE-2019-1010218). 

[Whilst CVEs are ultimately managed MITRE](https://www.cve.org/) and a network of CNA (CVE numbering authorities), NIST (the same organisation managing CPEs) manages a more comprehensive analysis of CVEs in the [US National Vulnerability Database (NVD)](https://nvd.nist.gov/).

<img class="img-fluid" src="/assets/images/blog/2024-06-10/CVE-Workflow_Diagram_Final.png" alt="NVD CVE lifecycle" title="NVD CVE lifecycle" />

Source: https://nvd.nist.gov/vuln/vulnerability-status

The NVD is tasked with analysing each CVE once it has been published to the CVE List (MITREs list) using the reference information provided with the CVE and any publicly available information at the time of analysis to associate Reference Tags, Common Vulnerability Scoring System (CVSS) v2.0, CVSS v3.1, CWE, and CPE Applicability statements.

Once a CVE is published and NVD analysis is provided, there may also be additional maintenance or modifications made. References may be added, descriptions may be updated, or a request may be made to have a set of CVE IDs reorganised (such as one CVE ID being split into several). Furthermore, the validity of an individual CVE ID can be disputed by the vendor that can result in the CVE being revoked (e.g at the time of writing [CVE-2022-27948](https://nvd.nist.gov/vuln/detail/CVE-2022-27948) is disputed).

[The full process is described here](https://nvd.nist.gov/general/cve-process).

[You can browse the NVD CVE database here to see examples of the data the NVD team include with each CVE](https://nvd.nist.gov/vuln/search).

For cve2stix, the key takeaways for working with CVEs are that 1) they are published regularly, 2) the NVD is one of the most comprehensive public sources of CVE analysis and, 3) NVD can updated the data inside at CVE record once it is published (where the modified time returned via the API will change)..

#### CVE API's

[There are two CVE APIs](https://nvd.nist.gov/developers/vulnerabilities);

1. CVE API: The CVE API is used to easily retrieve information on a single CVE or a collection of CVE from the NVD.
2. CVE Change History API: The CVE Change History API is used to easily retrieve information on changes made to a single CVE or a collection of CVE from the NVD.

##### CVE API

The root endpoint will return all CVE's.

```shell
GET https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=50
```

At the time of writing there are over 250k CVEs!

```json
{
    "resultsPerPage": 2000,
    "startIndex": 0,
    "totalResults": 250901,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2024-05-21T10:45:34.073",
    "vulnerabilities": [
```

There are a wide range of parameters to filter the CVEs returned in the response. If you know the CVE you want, you can add that to the query;

```shell
GET https://services.nvd.nist.gov/rest/json/cves/2.0/?cveId=CVE-2019-1010218
```

Which prints all the information about the CVE;

```json
{
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2023-01-08T14:10:27.753",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2019-1010218",
                "sourceIdentifier": "josh@bress.net",
                "published": "2019-07-22T18:15:10.917",
                "lastModified": "2020-09-30T13:40:18.163",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Cherokee Webserver Latest Cherokee Web server Upto Version 1.2.103 (Current stable) is affected by: Buffer Overflow - CWE-120. The impact is: Crash. The component is: Main cherokee command. The attack vector is: Overwrite argv[0] to an insane length with execl. The fixed version is: There's no fix yet."
                    },
                    {
                        "lang": "es",
                        "value": "El servidor web de Cherokee más reciente de Cherokee Webserver Hasta Versión 1.2.103 (estable actual) está afectado por: Desbordamiento de Búfer - CWE-120. El impacto es: Bloqueo. El componente es: Comando cherokee principal. El vector de ataque es: Sobrescribir argv[0] en una longitud no sana con execl. La versión corregida es: no hay ninguna solución aún."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 3.6
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
                                "accessVector": "NETWORK",
                                "accessComplexity": "LOW",
                                "authentication": "NONE",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "PARTIAL",
                                "baseScore": 5.0
                            },
                            "baseSeverity": "MEDIUM",
                            "exploitabilityScore": 10.0,
                            "impactScore": 2.9,
                            "acInsufInfo": false,
                            "obtainAllPrivilege": false,
                            "obtainUserPrivilege": false,
                            "obtainOtherPrivilege": false,
                            "userInteractionRequired": false
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-787"
                            }
                        ]
                    },
                    {
                        "source": "josh@bress.net",
                        "type": "Secondary",
                        "description": [
                            {
                                "lang": "en",
                                "value": "CWE-120"
                            }
                        ]
                    }
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:cherokee-project:cherokee_web_server:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "1.2.103",
                                        "matchCriteriaId": "DCE1E311-F9E5-4752-9F51-D5DA78B7BBFA"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://i.imgur.com/PWCCyir.png",
                        "source": "josh@bress.net",
                        "tags": [
                            "Exploit",
                            "Third Party Advisory"
                        ]
                    }
                ]
            }
        }
    ]
}
```

[Full CVE API response schema for reference](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema).

<img class="img-fluid" src="/assets/images/blog/2024-06-10/NVD-CVE-2019-1010218.png" alt="CVE-2019-1010218 NVD site" title="CVE-2019-1010218 NVD site" />

The NVD website CVE pages are populated from the response of this API -- see the similarities between the [CVE-2019-1010218 entry here](https://nvd.nist.gov/vuln/detail/CVE-2019-1010218), and the JSON payload above.

If you remember back to the NVD analysis process describe above the `vulnerabilities.cve.vulnStatus` property tells us the current state (in this case `Analyzed`). If you're seeing minimal data returned for a CVE it might be that is awaiting analysis (or rejected) so be sure to check this field (or validate it by checking the entry for the CVE on the NVD website if still unsure).

If you want to be more specific, instead of filtering on a specific CVE, you can also search using various properties of the CVEs you want returned, including;

* `cpeName`: a full or partial CPE match string (e.g. `cpe:2.3:o:microsoft`)
* `cvssV3Metrics`: a CVSS v3 full or partial string (e.g. `AV:N/AC:H/Au:N/C:C/I:C/A:C`)
* `cvssV3Severity`: a CVSS v3 severity (e.g. `LOW`)
* `cweId`: a CWE ID found in a CVE (e.g. `CWE-120`)
* `hasCertAlerts`: if set, only returns the CVE that contain a Technical Alert from US-CERT
* `hasCertNotes`: if set, only returns the CVE that contain a Vulnerability Note from CERT/CC
* `hasKev`: if set, ,only returns the CVE that appear in CISA's Known Exploited Vulnerabilities (KEV) Catalog
* `hasOval`: if set, only returns only CVE associated with a specific CPE, where the CPE is also considered vulnerable. The exact value provided with `cpeName` is compared against the CPE Match Criteria within a CVE applicability statement. If the value of `cpeName` is considered to match, and is also considered vulnerable the CVE is included in the results.
* `keywordExactMatch`: By default, `keywordSearch` returns any CVE where a word or phrase is found in the current description.
* `keywordSearch`: This parameter returns only the CVEs where a word or phrase is found in the current description. Descriptions associated with CVE are maintained by the CVE Assignment.
* `noRejected`: By default, the CVE API includes CVE records with the REJECT or Rejected status. This parameter excludes CVE records with the REJECT or Rejected status from API response.

There are also a few date specific parameters (e.g. `pubStartDate` & `pubEndDate`, e.g. `lastModStartDate` & `lastModEndDate`) that are useful for filtering by time. For example, when backfilling CVEs into a database.

CVE's can be changed over time (as new information is uncovered). As such `lastModStartDate` & `lastModEndDate` can become important to monitor for updated CVE's too.

The actual changes made to the CVE won't be shown in the response of the CVE API (only the most recent version of the CVE will be returned). The CVE Change History API allows for this to be done.

Using each `cve` entry, cve2stix maps relevant values to properties found in the STIX 2.1 Vulnerability object. [See the cve2stix docs for more information for the details of this mapping](https://github.com/muchdogesec/cve2stix).

##### CVE Change History API

The root endpoint will return all changes for every single CVE's which isn't particularly helpful (at least for what cve2stix does). However, you can filter this endpoint using a CVE ID like so;

```shell
GET https://services.nvd.nist.gov/rest/json/cvehistory/2.0/?cveId=CVE-2019-1010218
```

Which shows four changes (in the response below, I've only printed the first change);

```json
{
    "resultsPerPage": 4,
    "startIndex": 0,
    "totalResults": 4,
    "format": "NVD_CVEHistory",
    "version": "2.0",
    "timestamp": "2024-06-10T08:02:06.203",
    "cveChanges": [
        {
            "change": {
                "cveId": "CVE-2019-1010218",
                "eventName": "Initial Analysis",
                "cveChangeId": "E52AFC66-FAFE-4393-B7FF-4EC2FA6CB6C4",
                "sourceIdentifier": "nvd@nist.gov",
                "created": "2019-07-24T16:03:52.787",
                "details": [
                    {
                        "action": "Added",
                        "type": "CVSS V2",
                        "newValue": "(AV:N/AC:L/Au:N/C:N/I:N/A:P)"
                    },
                    {
                        "action": "Added",
                        "type": "CVSS V3",
                        "newValue": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                    },
                    {
                        "action": "Changed",
                        "type": "Reference Type",
                        "oldValue": "https://i.imgur.com/PWCCyir.png No Types Assigned",
                        "newValue": "https://i.imgur.com/PWCCyir.png Exploit, Third Party Advisory"
                    },
                    {
                        "action": "Added",
                        "type": "CWE",
                        "newValue": "CWE-119"
                    },
                    {
                        "action": "Added",
                        "type": "CPE Configuration",
                        "newValue": "OR\n     *cpe:2.3:a:cherokee-project:cherokee_webserver:*:*:*:*:*:*:*:* versions up to (including) 1.2.103"
                    }
                ]
            }
        },
        ...
    ]
}
```

[Full CVE change response schema for reference](https://csrc.nist.gov/schema/nvd/api/2.0/cve_history_api_json_2.0.schema).

Here four items were `Added` and one was `Changed` to CVE-2019-1010218.

[You can see this data represented clearly on the Change History section on the NVD website](https://nvd.nist.gov/vuln/detail/CVE-2019-1010218#VulnChangeHistorySection).

##### CPE Match Criteria API

In many cases you want to know all CPE variations are vulnerable to a CVE (often there are many language/versions/etc. combinations), this is where the Match Criteria API comes in useful.

The CPE Match Criteria API is used to easily retrieve the complete list of valid CPE Match Strings. Unlike a CPE Name, match strings and match string ranges do not require a value in the part, vendor, product, or version components.

In the CVE API response you will see the CPE URI `cpe:2.3:a:cherokee-project:cherokee_web_server:*:*:*:*:*:*:*:*`, under the property `vulnerabilities.cve.configurations.nodes.cpeMatch.criteria`. 

```json
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:cherokee-project:cherokee_web_server:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "1.2.103",
                                        "matchCriteriaId": "DCE1E311-F9E5-4752-9F51-D5DA78B7BBFA"
                                    }
                                ]
                            }
                        ]
                    }
                ],
```

Note, for each CPE created, the `swid` property in the software object also contains the cpeMatch ID.

Inside the `nodes` object, the single `cpeMatch` object contains information about how the software is `vulnerable`. In addition to the CPE URI (`criteria`) and `matchCriteriaId`, there are 4 four properties that can be, but not required, used describe the version ranges of the product;

* `versionStartIncluding`
* `versionStartExcluding`
* `versionEndIncluding`
* `versionEndExcluding`

Essentially this property makes it easy to see the last affected version, without having to query the CVE Match API. However to get all affected versions (as CPE URIs) covered in this `cpeMatch`, you will need to use the CVE Match API.

This is where the `matchCriteriaId` property comes in (here `DCE1E311-F9E5-4752-9F51-D5DA78B7BBFA`), and that can be passed to the CVE History API;

```shell
GET https://services.nvd.nist.gov/rest/json/cvehistory/2.0/?matchCriteriaId=DCE1E311-F9E5-4752-9F51-D5DA78B7BBFA
```

Which returns one match;

```json
{
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CPEMatchString",
    "version": "2.0",
    "timestamp": "2024-06-10T08:15:05.813",
    "matchStrings": [
        {
            "matchString": {
                "matchCriteriaId": "DCE1E311-F9E5-4752-9F51-D5DA78B7BBFA",
                "criteria": "cpe:2.3:a:cherokee-project:cherokee_web_server:*:*:*:*:*:*:*:*",
                "versionEndIncluding": "1.2.103",
                "lastModified": "2019-10-08T16:44:34.360",
                "cpeLastModified": "2019-10-08T16:44:34.377",
                "created": "2019-10-08T16:44:34.360",
                "status": "Active",
                "matches": [
                    {
                        "cpeName": "cpe:2.3:a:cherokee-project:cherokee_web_server:1.0.12:*:*:*:*:*:*:*",
                        "cpeNameId": "946ED27F-93AB-4447-9F04-30FEE3EAA8E7"
                    },
                    {
                        "cpeName": "cpe:2.3:a:cherokee-project:cherokee_web_server:1.0.13:*:*:*:*:*:*:*",
                        "cpeNameId": "E706BE3F-8E91-48E4-8677-C94244016A67"
                    },
                    {
                        "cpeName": "cpe:2.3:a:cherokee-project:cherokee_web_server:1.0.14:*:*:*:*:*:*:*",
                        "cpeNameId": "FB6C0C33-D9B8-45C2-BE5E-E836AA912A29"
                    },
                    {
                        "cpeName": "cpe:2.3:a:cherokee-project:cherokee_web_server:1.0.15:*:*:*:*:*:*:*",
                        "cpeNameId": "8EFC2886-764E-427B-8A8E-ADE7B848A516"
                    },
                    {
                        "cpeName": "cpe:2.3:a:cherokee-project:cherokee_web_server:1.0.16:*:*:*:*:*:*:*",
                        "cpeNameId": "6E542416-8B7A-402E-AFF7-97FEC339BC39"
                    },
                    {
                        "cpeName": "cpe:2.3:a:cherokee-project:cherokee_web_server:1.0.17:*:*:*:*:*:*:*",
                        "cpeNameId": "5C22473B-9EBD-49B6-86D6-E15538291DE6"
                    },
                    {
                        "cpeName": "cpe:2.3:a:cherokee-project:cherokee_web_server:1.0.18:*:*:*:*:*:*:*",
                        "cpeNameId": "2AF60F33-AABE-4C14-BE86-668AADDEC011"
                    },
                    {
                        "cpeName": "cpe:2.3:a:cherokee-project:cherokee_web_server:1.0.21:*:*:*:*:*:*:*",
                        "cpeNameId": "A36E8601-4E38-47E0-B91D-65B42A0A7AE8"
                    },
                    {
                        "cpeName": "cpe:2.3:a:cherokee-project:cherokee_web_server:1.2.0:*:*:*:*:*:*:*",
                        "cpeNameId": "64DCAC28-ADF7-442A-8746-2C237C877D27"
                    },
                    {
                        "cpeName": "cpe:2.3:a:cherokee-project:cherokee_web_server:1.2.2:*:*:*:*:*:*:*",
                        "cpeNameId": "59CF5F3E-5158-4116-8733-F65859CB43C3"
                    },
                    {
                        "cpeName": "cpe:2.3:a:cherokee-project:cherokee_web_server:1.2.98:*:*:*:*:*:*:*",
                        "cpeNameId": "2274D1F6-911C-45D1-8ED5-89B63DA542AD"
                    },
                    {
                        "cpeName": "cpe:2.3:a:cherokee-project:cherokee_web_server:1.2.99:*:*:*:*:*:*:*",
                        "cpeNameId": "460FA01F-61D5-4B8E-9F0E-B98159A4F980"
                    },
                    {
                        "cpeName": "cpe:2.3:a:cherokee-project:cherokee_web_server:1.2.101:*:*:*:*:*:*:*",
                        "cpeNameId": "9163CD3B-EEED-4658-8CFD-944827E2B05E"
                    },
                    {
                        "cpeName": "cpe:2.3:a:cherokee-project:cherokee_web_server:1.2.102:*:*:*:*:*:*:*",
                        "cpeNameId": "45747884-B233-4095-AA7E-012698B4C6A5"
                    },
                    {
                        "cpeName": "cpe:2.3:a:cherokee-project:cherokee_web_server:1.2.103:*:*:*:*:*:*:*",
                        "cpeNameId": "6F607266-EFB1-4737-A579-AFF23B18E5B1"
                    }
                ]
            }
        }
    ]
}
```

[Full CPE Match response schema for reference](https://csrc.nist.gov/schema/nvd/api/2.0/cpematch_api_json_2.0.schema).

The CPE criteria (in the CVE response) showed the CPE URI `cpe:2.3:a:cherokee-project:cherokee_web_server:*:*:*:*:*:*:*:*`. Using the Match Criteria API by passing the `matchCriteriaId` (DCE1E311-F9E5-4752-9F51-D5DA78B7BBFA) shows us the complete list of valid CPE Match Strings. Put another way, all iterations of the products that match the CPE URI in the CVE response.

In this case, 15 versions of `cherokee_web_server` are vulnerable to CVE-2019-1010218.

However, this is one of the most simplistic examples of a CPE node configuration inside a CVE.

Using each node configoration, cve2stix creates an Indicator object with a STIX `pattern` property defining the node configurations, like the one described above.

[The cve2stix docs for more information for the details of this mapping](https://github.com/muchdogesec/cve2stix). As this information is relevant beyond STIX mapping I will explain the logic in this post too.

### Understanding what CPEs have CVEs (Node Configurations)

In many cases product will only be vulnerable if it is being run in a certain way, or with other products. For example, Google Chrome 103.0.5060.114 might be vulnerable running on Apple MacOS 12.0.0 but any Windows OS.

Similarly it might be vulnerable on Apple MacOS 12.0.0 but not Apple MacOS 12.0.1 because a patch was issued to fix the vulnerability.

Each CPE `nodes` in the CVE configuration (returned by the CVE API) has either an `OR` or an `AND` `operator` value (and in rare cases a `negate` boolean) to convey the logical relationship of the CPEs within the `cpeMatch`. For example, if the vulnerability exists only when both CPE products are present, the operator is `AND`. If the vulnerability exists if either CPE is present, then the operator is `OR` (as in the CVE-2019-1010218 example). Though the use of nodes and operators can create more complex relationships.

[NVD describe three different types of configurations](https://nvd.nist.gov/vuln/vulnerability-detail-pages);

1. Basic: A single node containing one or more sets of match criteria. This configuration type communicates that each CPE URI that matches the match criteria is considered vulnerable. 
2. Running On/With: A combination of nodes containing both vulnerable and non-vulnerable match criteria. This configuration type communicates that CPE URIs that match the match criteria from both nodes must be present before a vulnerability applies.
3. Advanced: A complex combination of nodes with many enumerations based on the CPE 2.3 specification. Advanced configurations are displayed with the actual nodes and node values on the vulnerability detail page instead of in a simplified form such as the Basic and Running On/With configuration types.  

I appreciate this is likely confusing to begin with so let me illustrate with some real examples.

#### 1. Basic node configurations

As the name would suggest, these are fairly simple.

CVE-2022-29098 offers a good example: https://nvd.nist.gov/vuln/detail/CVE-2022-29098

First start by reviewing the Known Affected Software Configurations section of the page. It is a useful reference in understanding how the response of the API should be read.

<img class="img-fluid" src="/assets/images/blog/2024-06-10/CVE-2022-29098-known-affected-software-configs.png" alt="CVE-2022-29098 NVD site" title="CVE-2022-29098 NVD site" />

Querying via the API;

```shell
GET https://services.nvd.nist.gov/rest/json/cves/2.0/?cveId=CVE-2022-29098
```

Here is what the API returns (note the full response has been cut for brevity shown using `...`);

```json
{
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2023-01-09T19:40:03.140",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2022-29098",
                "sourceIdentifier": "security_alert@emc.com",
                "published": "2022-06-01T15:15:09.010",
                "lastModified": "2022-06-08T19:14:09.453",
                "vulnStatus": "Analyzed",
                ...
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.0.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "30687628-5C7F-4BB5-B990-93703294FDF0"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.1.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "68291D44-DBE1-4923-A848-04E64288DC23"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.1.1:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "DCC55FA4-AD91-4DA6-B60E-A4E34DDAE95A"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.2.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "B948CD53-3D17-4230-9B77-FCE8E0E548B9"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.2.1:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "5AB99A1A-8DD3-4DDE-B70C-0E91D1D3B682"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.3.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "61F14753-D64C-4E8B-AA94-07E014848B4D"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                ...
            }
        }
    ]
}
```

There is only one `nodes`. The operator for the entire node is `OR`.

Therefore each `cpeMatch` object in is considered with the `OR` statement.

Basic configurations only consider individual products (and not combinations) so all CPEs are `"vulnerable": true` (meaning the product itself is always vulnerable).

In this case, the 6 configurations variations that lead to matches (note, the third, forth, and fifth nodes are omitted in the snippet above);

1. Dell PowerScale OneFS version 9.0.0 (`"matchCriteriaId": "30687628-5C7F-4BB5-B990-93703294FDF0"`) `OR`,
2. Dell PowerScale OneFS version 9.1.0 (`"matchCriteriaId": "68291D44-DBE1-4923-A848-04E64288DC23"`) `OR`,
3. Dell PowerScale OneFS version 9.1.1 (`"matchCriteriaId": "DCC55FA4-AD91-4DA6-B60E-A4E34DDAE95A"`) `OR`,
4. Dell PowerScale OneFS (version 9.2.0) (`"matchCriteriaId": "B948CD53-3D17-4230-9B77-FCE8E0E548B9"`) `OR`,
5. Dell PowerScale OneFS (version 9.2.1) (`"matchCriteriaId": "5AB99A1A-8DD3-4DDE-B70C-0E91D1D3B682"`) `OR`,
6. Dell PowerScale OneFS (version 9.3.0) (`"matchCriteriaId": "61F14753-D64C-4E8B-AA94-07E014848B4D"`)

In this example, each `matchCriteriaId` returns the same CPE URI as shown in the CVE (meaning only one product version exists for this match string), e.g.

```shell
GET https://services.nvd.nist.gov/rest/json/cvehistory/2.0/?matchCriteriaId=30687628-5C7F-4BB5-B990-93703294FDF0
```

```json
                "matches": [
                    {
                        "cpeName": "cpe:2.3:a:dell:powerscale_onefs:9.0.0:*:*:*:*:*:*:*",
                        "cpeNameId": "2B8F2852-98F4-44E1-BBF2-6597C2481DB1"
                    }
                ]
```

However, keep in mind as I move on that this is not always the case (more CPEs might be returned by a `matchCriteriaId`).

#### 2. Running On/With node configurations

This type of configuration is defined using a combination of products that have a relationship (Running On/With) that makes at least one of these products vulnerable.

In this example, `nodes` can now contain both vulnerable and non-vulnerable products.

To explain this I will use CVE-2022-27948 as a an example: https://nvd.nist.gov/vuln/detail/CVE-2022-27948

<img class="img-fluid" src="/assets/images/blog/2024-06-10/CVE-2022-27948-known-affected-software-configs.png" alt="CVE-2022-27948 NVD site" title="CVE-2022-27948 NVD site" />

Querying via the API;

```shell
GET https://services.nvd.nist.gov/rest/json/cves/2.0/?cveId=CVE-2022-27948
```

Here is what the API returns (note 3 nodes have been cut for brevity shown using `...`);

```json
{
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2023-01-10T07:37:08.677",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2022-27948",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2022-03-27T13:15:13.573",
                "lastModified": "2022-04-06T03:39:12.913",
                "vulnStatus": "Analyzed",
                ...
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:tesla:model_3_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "2022-03-26",
                                        "matchCriteriaId": "86619D7A-ACB6-489C-9C29-37C6018E5B4B"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:tesla:model_s_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "2022-03-26",
                                        "matchCriteriaId": "FD68704D-C711-491F-B278-B02C6866738C"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:tesla:model_x_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "2022-03-26",
                                        "matchCriteriaId": "C3517683-8493-4D0D-9792-5C9034B1F0B3"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:tesla:model_3:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "825A79FD-C872-4564-9782-83BEEADDF5D9"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:tesla:model_s:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "8D28E699-B843-4641-9BA6-406D88231E7C"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:tesla:model_x:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "C550FF8A-58ED-4265-B33F-10AFDEA95519"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                ...
            }
        }
    ]
}
```

Note in this response, the top `nodes` object has an `operator` property (in the previous response, this was only at the `cpeMatch` level).

```json
                        "operator": "AND",
                        "nodes": [
```

This allows for more complex Running On/With combinations where each `cpeMatch` within a node can be considered using this addition operator.

The top level operator in this example is `AND`. In total there are two `cpeMatch`es in this `nodes`

Each `cpeMatch` itself has an `OR` operator, and each of these `cpeMatch` has three CPE URI's within it. The first contains only Tesla operating system (`o`) CPEs. The second contains only Tesla hardware (`h`) CPEs.

Logically, it is saying any entry from the first `cpeMatch` `AND` any entry from the second `cpeMatch` nested in the `nodes` will create a match.

It's also important to point out here that each `matchCriteriaId` returns more versions of the product. For example,

```json
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:tesla:model_3_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "2022-03-26",
                                        "matchCriteriaId": "86619D7A-ACB6-489C-9C29-37C6018E5B4B"
                                    },
```

```shell
GET https://services.nvd.nist.gov/rest/json/cvehistory/2.0/?matchCriteriaId=86619D7A-ACB6-489C-9C29-37C6018E5B4B
```

```json
                "matches": [
                    {
                        "cpeName": "cpe:2.3:o:tesla:model_3_firmware:-:*:*:*:*:*:*:*",
                        "cpeNameId": "979F9EB6-C9F6-49EE-9FED-2ED17E400E86"
                    },
                    {
                        "cpeName": "cpe:2.3:o:tesla:model_3_firmware:11.0:*:*:*:*:*:*:*",
                        "cpeNameId": "62DCA7AD-A796-486F-8FB6-DEACC078D402"
                    },
                    {
                        "cpeName": "cpe:2.3:o:tesla:model_3_firmware:2022-03-26:*:*:*:*:*:*:*",
                        "cpeNameId": "F010C8B7-83E9-45FB-A5D4-26EDF34EC312"
                    }
                ]
```

Here I can see this CPE URI in the node actually covers 3 CPE URI's.

Looking at all six `matchCriteriaId`s;

* `86619D7A-ACB6-489C-9C29-37C6018E5B4B`: 3 CPE URIs (shown above)
* `FD68704D-C711-491F-B278-B02C6866738C`: 2 CPE URIs
* `C3517683-8493-4D0D-9792-5C9034B1F0B3`: 3 CPE URIs
* `825A79FD-C872-4564-9782-83BEEADDF5D9`: 1 CPE URI
* `8D28E699-B843-4641-9BA6-406D88231E7C`: 1 CPE URI
* `C550FF8A-58ED-4265-B33F-10AFDEA95519`: 1 CPE URI

In this example you also need to consider the value of the `vulnerable` property. You'll see in the first node, but for all entries this is true. In the second, they're all false.

This is essentially describing the combinations of products, and which of them are actually affected by a vulnerability when running in this way.

It's easier to explain this by writing it all out, as there are a lot of combinations in this CVE.

* Tesla Model 3 Firmware (`86619D7A-ACB6-489C-9C29-37C6018E5B4B` -- 3 CPEs) and Tesla Model 3 Hardware (`825A79FD-C872-4564-9782-83BEEADDF5D9` -- 1 CPE) (ONLY FIRMWARE VULNERABLE) `OR`,
* Tesla Model 3 Firmware (`86619D7A-ACB6-489C-9C29-37C6018E5B4B` -- 3 CPEs) and Tesla Model S Hardware (`8D28E699-B843-4641-9BA6-406D88231E7C` -- 1 CPE) (ONLY FIRMWARE VULNERABLE) `OR`,
* Tesla Model 3 Firmware (`86619D7A-ACB6-489C-9C29-37C6018E5B4B` -- 3 CPEs) and Tesla Model X Hardware (`C550FF8A-58ED-4265-B33F-10AFDEA95519` -- 1 CPE) (ONLY FIRMWARE VULNERABLE) `OR`,
* Tesla Model S Firmware (`FD68704D-C711-491F-B278-B02C6866738C` -- 2 CPEs) and Tesla Model 3 Hardware (`825A79FD-C872-4564-9782-83BEEADDF5D9` -- 1 CPE) (ONLY FIRMWARE VULNERABLE) `OR`,
* Tesla Model S Firmware (`FD68704D-C711-491F-B278-B02C6866738C` -- 2 CPEs) and Tesla Model S Hardware (`8D28E699-B843-4641-9BA6-406D88231E7C` -- 1 CPE) (ONLY FIRMWARE VULNERABLE) `OR`,
* Tesla Model S Firmware (`FD68704D-C711-491F-B278-B02C6866738C` -- 2 CPEs) and Tesla Model X Hardware (`C550FF8A-58ED-4265-B33F-10AFDEA95519` -- 1 CPE) (ONLY FIRMWARE VULNERABLE) `OR`,
* Tesla Model X Firmware (`C3517683-8493-4D0D-9792-5C9034B1F0B3` -- 3 CPEs) and Tesla Model 3 Hardware (`825A79FD-C872-4564-9782-83BEEADDF5D9` -- 1 CPE) (ONLY FIRMWARE VULNERABLE) `OR`,
* Tesla Model X Firmware (`C3517683-8493-4D0D-9792-5C9034B1F0B3` -- 3 CPEs) and Tesla Model S Hardware (`8D28E699-B843-4641-9BA6-406D88231E7C` -- 1 CPE) (ONLY FIRMWARE VULNERABLE) `OR`,
* Tesla Model X Firmware (`C3517683-8493-4D0D-9792-5C9034B1F0B3` -- 3 CPEs) and Tesla Model X Hardware (`C550FF8A-58ED-4265-B33F-10AFDEA95519` -- 1 CPE) (ONLY FIRMWARE VULNERABLE)

In total there are 24 possible product combinations that are vulnerable in this CVE (`((3*1)+(3*1)+(3*1))+((2*1)+(2*1)+(2*1))+((3*1)+(3*1)+(3*1))`).

Note, this is not the most perfectly written `nodes` `cpeMatch`, though this is good to understand that not all CPE matches in a CVE will be as concise as they could be. In the real world, Tesla Model 3 firmware will always, as far as I'm aware, only be running Model 3 firmware. Therefore the matches comparing Model 3 OSs to Model X firmware, etc., are redundant.

#### 3. Advanced node configurations

The operators and structure in the previous configuration types are no different in advanced configurations. It is the number of `nodes` returned in the response that allows them to become more advanced.

To illustrate this, I will use CVE-2019-18939: https://nvd.nist.gov/vuln/detail/CVE-2019-18939

<img class="img-fluid" src="/assets/images/blog/2024-06-10/CVE-2019-18939-known-affected-software-configs.png" alt="CVE-2019-18939 NVD site" title="CVE-2019-18939 NVD site" />

Querying via the API;

```shell
GET https://services.nvd.nist.gov/rest/json/cves/2.0/?cveId=CVE-2019-18939
```

Here is what the API returns (note 3 nodes have been cut for brevity shown using `...`);

```json
{
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2023-01-10T08:23:24.183",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2019-18939",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2019-11-14T19:15:13.410",
                "lastModified": "2021-07-21T11:39:23.747",
                "vulnStatus": "Analyzed",
                ...
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "AND",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "286DA904-5631-4AAF-86DE-97C23982D2C5"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "9C2CF19C-7EDE-4E3C-A736-E6736FF03FDC"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "38BE17DA-7C5E-427E-B824-151EB27CFF26"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "nodes": [
                            {
                                "operator": "AND",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F5D8290F-3541-4452-99CB-0766CDC59073"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "33113AD0-F378-49B2-BCFC-C57B52FD3A04"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "285F4E29-E299-4F83-9F7E-BB19933AD654"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "nodes": [
                            {
                                "operator": "AND",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "286DA904-5631-4AAF-86DE-97C23982D2C5"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "33113AD0-F378-49B2-BCFC-C57B52FD3A04"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "285F4E29-E299-4F83-9F7E-BB19933AD654"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "nodes": [
                            {
                                "operator": "AND",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F5D8290F-3541-4452-99CB-0766CDC59073"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "9C2CF19C-7EDE-4E3C-A736-E6736FF03FDC"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "38BE17DA-7C5E-427E-B824-151EB27CFF26"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                ...
            }
        }
    ]
}
```

The key difference here being there are now multiple `nodes` objects (four `nodes` in this example). In the two previous examples, there was one `nodes`, with multiple `cpeMatch`es nested.

As such, combinations of CPEs can be written in more ways (though they're not necessarily more "advanced").

The response above has four separate `nodes`. Each is considered in isolation.

Each element inside a `cpeMatch` node is considered with an `AND` statement, as defined in the its `operator` field values.

Looking at the CPEs inside each `matchCriteriaId` returns a single CPE URI:

* Node 1
    * `286DA904-5631-4AAF-86DE-97C23982D2C5`: 1 CPE
    * `9C2CF19C-7EDE-4E3C-A736-E6736FF03FDC`: 1 CPE
    * `38BE17DA-7C5E-427E-B824-151EB27CFF26`: 1 CPE
* Node 2
    * `F5D8290F-3541-4452-99CB-0766CDC59073`: 1 CPE
    * `33113AD0-F378-49B2-BCFC-C57B52FD3A04`: 1 CPE
    * `285F4E29-E299-4F83-9F7E-BB19933AD654`: 1 CPE
* Node 3
    * `286DA904-5631-4AAF-86DE-97C23982D2C5`: 1 CPE
    * `33113AD0-F378-49B2-BCFC-C57B52FD3A04`: 1 CPE
    * `285F4E29-E299-4F83-9F7E-BB19933AD654`: 1 CPE
* Node 4
    * `F5D8290F-3541-4452-99CB-0766CDC59073`: 1 CPE
    * `9C2CF19C-7EDE-4E3C-A736-E6736FF03FDC`: 1 CPE
    * `38BE17DA-7C5E-427E-B824-151EB27CFF26`: 1 CPE

Note, the same CPEs appear in multiple nodes, hence there are only six unique `matchCriteriaId`s above.

With this information, I know there are exactly 4 CPE combinations that lead to a match (one for each `nodes`);

1. eQ-3 Homematic CCU2 (hardware) (version unspecified `-`) `AND` EQ-3 HomeMatic CCU2 version 2.47.20 (firmware) `AND` HM Print Project HM Print version 1.2a (application) (FIRMWARE AND APPLICATION VULNERABLE), `OR`,
2. eQ-3 Homematic CCU3 (hardware) (version unspecified `-`) `AND` EQ-3 HomeMatic CCU3 version 3.47.18 (firmware) `AND` HM Print Project HM Print version 1.2 (application) (FIRMWARE AND APPLICATION VULNERABLE), `OR`,
3.  eQ-3 Homematic CCU3 (hardware) (version unspecified `-`) `AND` EQ-3 HomeMatic CCU3 version 3.47.18 (firmware) `AND` HM Print Project HM Print version 1.2a (application) (FIRMWARE AND APPLICATION VULNERABLE), `OR`,
4. eQ-3 Homematic CCU2 (hardware) (version unspecified `-`) `AND` EQ-3 HomeMatic CCU2 version 2.47.20 (firmware) `AND` HM Print Project HM Print version 1.2 (application) (FIRMWARE AND APPLICATION VULNERABLE)

### Creating STIX patterns from node configoration

[STIX Pattern can be used as a detection language for observable level data](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_hdwfenduqtuh).

In the case of CVEs we can create STIX patterns from CPEs. This allows you to run STIX Patterns against lists of CPEs in your stack (perhaps in SBOMs) to identify which are vulnerable to know exploits.

First, some notes on creating patterns for CPEs from CVE node configurations...

#### Not all CVEs have CPE nodes

Some CVEs (typically older ones), e.g. CVE-1999-0635, do not contain any CPE node configurations.

#### Match criteria grouping parenthesis

A `matchCriteriaId` lookup might contain multiple CPEs in its response. All CPEs returned by a single match criteria ID are wrapped in parenthesis.

e.g. `86619D7A-ACB6-489C-9C29-37C6018E5B4B` returns 3 CPEs producing a pattern a group of 3 CPEs in the pattern wrapped in parenthesis, as follows;

```txt
( (software.cpe = 'cpe:2.3:o:tesla:model_3_firmware:-:*:*:*:*:*:*:*' OR software.cpe = 'cpe:2.3:o:tesla:model_3_firmware:11.0:*:*:*:*:*:*:*' OR software.cpe = 'cpe:2.3:o:tesla:model_3_firmware:2022-03-26:*:*:*:*:*:*:*') )
```

Note, even if only one CPE is returned for a match criteria API, the CPE is still wrapped up in brackets to indicate it is part of a CPE match string group.

#### cpeMatch grouping square brackets

All items inside a cpematch, once match criteria patterns have been formed are captured in square brackets.

For example CVE-2022-29098 contains 5 items in the cpeMatch once analysed against the match criteria API, so only one set of square brackets is used

```txt
( [ (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.0.0:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.1.0:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.1.1:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.2.0:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.2.1:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.3.0:*:*:*:*:*:*:*') ] )
```

However in CVE-2022-27948 there are two cpeMatch entries, which result in two square brackets in the pattern;

```txt
( [ (software.cpe = 'cpe:2.3:o:tesla:model_3_firmware:-:*:*:*:*:*:*:*' OR software.cpe = 'cpe:2.3:o:tesla:model_3_firmware:11.0:*:*:*:*:*:*:*' OR software.cpe = 'cpe:2.3:o:tesla:model_3_firmware:2022-03-26:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:o:tesla:model_s_firmware:-:*:*:*:*:*:*:*' OR software.cpe = 'cpe:2.3:o:tesla:model_s_firmware:2022-03-26:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:o:tesla:model_x_firmware:-:*:*:*:*:*:*:*' OR software.cpe = 'cpe:2.3:o:tesla:model_x_firmware:2020-11-23:*:*:*:*:*:*:*' OR software.cpe = 'cpe:2.3:o:tesla:model_x_firmware:2022-03-26:*:*:*:*:*:*:*') ] AND [ (software.cpe = 'cpe:2.3:h:tesla:model_3:-:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:tesla:model_s:-:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:tesla:model_x:-:*:*:*:*:*:*:*') ] )
```

#### Operators at cpematch level

A `cpematch` will have a corresponding `operator` property. This defines how all the CPE match entries are joined together. For CVE-2022-27948 above, the operator is an `OR`. However, for CVE-2019-18939 (next example) the operator is an `AND`

#### Operators at node level

In addition to cpematch `operators`, `nodes` can also contain an operator (if the node contains more than one CPE match).

For example, in CVE-2022-27948 above, there are two `cpematch`es in the node. The node operator is an `AND`. Thus the cpematches inside the node are joined with an AND.

#### Dealing with node groupings

In CVEs with advance relationships there might be more than one node reported. Nodes contain one or more cpeMatch groups, as discussed.

For example, CVE-2019-18939 has 4 nodes containing cpematches.

Content inside a node is captured in parenthesis. For example, the 4 nodes for CVE-2019-18939

```txt
( [ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*') ] ) OR ( [ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*') ] ) OR ( [ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*') ] ) OR ( [ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*') ] )
```

Node groups are always joined with an `OR` operator.

#### Putting this logic into practice to create CPE Patterns

I'll use the examples shown earlier in this post to demonstrate pattern construction...

##### Simple Relationships

[CVE-2022-29098 offers a good example of simple relationships](https://nvd.nist.gov/vuln/detail/CVE-2022-29098).

In this case, the 6 configurations variations that lead to matches inside one `nodes`.

```json
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.0.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "30687628-5C7F-4BB5-B990-93703294FDF0"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.1.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "68291D44-DBE1-4923-A848-04E64288DC23"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.1.1:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "DCC55FA4-AD91-4DA6-B60E-A4E34DDAE95A"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.2.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "B948CD53-3D17-4230-9B77-FCE8E0E548B9"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.2.1:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "5AB99A1A-8DD3-4DDE-B70C-0E91D1D3B682"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.3.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "61F14753-D64C-4E8B-AA94-07E014848B4D"
                                    }
                                ]
                            }
                        ]
                    }
                ],
```

1. `cpe:2.3:a:dell:powerscale_onefs:9.0.0:*:*:*:*:*:*:*` (`30687628-5C7F-4BB5-B990-93703294FDF0) OR`,
2. `cpe:2.3:a:dell:powerscale_onefs:9.1.0:*:*:*:*:*:*:*` (`68291D44-DBE1-4923-A848-04E64288DC23`) `OR`,
3. `cpe:2.3:a:dell:powerscale_onefs:9.1.1:*:*:*:*:*:*:*` (`DCC55FA4-AD91-4DA6-B60E-A4E34DDAE95A`) `OR`,
4. `cpe:2.3:a:dell:powerscale_onefs:9.2.0:*:*:*:*:*:*:*` (`B948CD53-3D17-4230-9B77-FCE8E0E548B9`) `OR`,
5. `cpe:2.3:a:dell:powerscale_onefs:9.2.1:*:*:*:*:*:*:*` (`5AB99A1A-8DD3-4DDE-B70C-0E91D1D3B682`) `OR`,
6. `cpe:2.3:a:dell:powerscale_onefs:9.3.0:*:*:*:*:*:*:*` (`61F14753-D64C-4E8B-AA94-07E014848B4D`)

Now the match criteria API must be checked for each entry. For example, for `30687628-5C7F-4BB5-B990-93703294FDF0`

Returns;

```json
    "matchStrings": [
        {
            "matchString": {
                "matchCriteriaId": "30687628-5C7F-4BB5-B990-93703294FDF0",
                "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.0.0:*:*:*:*:*:*:*",
                "lastModified": "2022-06-07T14:26:54.180",
                "cpeLastModified": "2021-04-26T17:43:46.887",
                "created": "2021-04-26T17:43:45.753",
                "status": "Active",
                "matches": [
                    {
                        "cpeName": "cpe:2.3:a:dell:powerscale_onefs:9.0.0:*:*:*:*:*:*:*",
                        "cpeNameId": "2B8F2852-98F4-44E1-BBF2-6597C2481DB1"
                    }
                ]
            }
        }
    ]
}
```

As you can see only one CPE belongs to this `matchCriteriaId`, so only one CPE will be used for this entry in the pattern. All `matchCriteriaId`'s for this CVE return just one CPE entry, so only that CPE is used in the pattern.

As such, in this example the `pattern` in the Indicator would be as follow;

```json
"pattern": "( [ (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.0.0:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.1.0:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.1.1:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.2.0:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.2.1:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.3.0:*:*:*:*:*:*:*') ] )"
```

The CPE statements are joined by `OR` as this is the top level `operator` in the API response (of course, in many cases this can be an `AND`).

#### Running On/With Relationships

[Let me demonstrate how more complex Relationships are modelled using the example CVE-2022-27948](https://nvd.nist.gov/vuln/detail/CVE-2022-27948).

In total there are 24 possible product combinations that are vulnerable in this CVE (see the last post for an explanation).

```json
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:tesla:model_3_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "2022-03-26",
                                        "matchCriteriaId": "86619D7A-ACB6-489C-9C29-37C6018E5B4B"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:tesla:model_s_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "2022-03-26",
                                        "matchCriteriaId": "FD68704D-C711-491F-B278-B02C6866738C"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:tesla:model_x_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "2022-03-26",
                                        "matchCriteriaId": "C3517683-8493-4D0D-9792-5C9034B1F0B3"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:tesla:model_3:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "825A79FD-C872-4564-9782-83BEEADDF5D9"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:tesla:model_s:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "8D28E699-B843-4641-9BA6-406D88231E7C"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:tesla:model_x:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "C550FF8A-58ED-4265-B33F-10AFDEA95519"
                                    }
                                ]
                            }
                        ]
                    }
                ],
```

Here there is one `nodes` again, however this time there are also two `cpeMatch`es inside it.

Note how in the Simple Relationships pattern all CPE key values were wrapped in square brackets (`[]`). Each CPE inside a `cpeMatch` is wrapped in square brackets.

So in this example I get pattern that will look like;

```json
    "pattern": "[ (software.cpe = 'A') OR (software.cpe = 'B') OR (software.cpe = 'N') ] AND [ (software.cpe = '1') OR (software.cpe = '2') OR (software.cpe = '0') ]",
```

Note how the `AND` joins the two square brackets, that's because the top level `operator` in the CVE response shown above is an `AND`. The CPE statements are joined by `OR` as this is the top level `operator` in the API response (of course, in many cases this can be an `AND`).

However, I must also check the `matchCriteriaId` results first. Let me use `86619D7A-ACB6-489C-9C29-37C6018E5B4B` as an example;

```json
   "matchStrings": [
        {
            "matchString": {
                "matchCriteriaId": "86619D7A-ACB6-489C-9C29-37C6018E5B4B",
                "criteria": "cpe:2.3:o:tesla:model_3_firmware:*:*:*:*:*:*:*:*",
                "versionEndIncluding": "2022-03-26",
                "lastModified": "2022-10-05T14:00:34.840",
                "cpeLastModified": "2022-10-05T14:00:34.840",
                "created": "2022-04-04T12:37:32.813",
                "status": "Active",
                "matches": [
                    {
                        "cpeName": "cpe:2.3:o:tesla:model_3_firmware:-:*:*:*:*:*:*:*",
                        "cpeNameId": "979F9EB6-C9F6-49EE-9FED-2ED17E400E86"
                    },
                    {
                        "cpeName": "cpe:2.3:o:tesla:model_3_firmware:11.0:*:*:*:*:*:*:*",
                        "cpeNameId": "62DCA7AD-A796-486F-8FB6-DEACC078D402"
                    },
                    {
                        "cpeName": "cpe:2.3:o:tesla:model_3_firmware:2022-03-26:*:*:*:*:*:*:*",
                        "cpeNameId": "F010C8B7-83E9-45FB-A5D4-26EDF34EC312"
                    }
                ]
            }
        }
    ]
```

Note, this returns 3 CPEs for the first CPE ID (match criteria) shown in the NVD response. Essentially what this is saying is `cpe:2.3:o:tesla:model_3_firmware:*:*:*:*:*:*:*:*` (`86619D7A-ACB6-489C-9C29-37C6018E5B4B`) actually contains 3 CPEs; `cpe:2.3:o:tesla:model_3_firmware:-:*:*:*:*:*:*:*`, or `cpe:2.3:o:tesla:model_3_firmware:11.0:*:*:*:*:*:*:*` or `cpe:2.3:o:tesla:model_3_firmware:2022-03-26:*:*:*:*:*:*:*`. Note, when multiple values are returned in the match criteria response, they are always joined with an `OR` inside the `pattern`.

Some of the other match criteria IDs also return more than one response. After querying the match criteria APIs, a pattern as follows results;

```json
    "pattern": "( [ (software.cpe = 'cpe:2.3:o:tesla:model_3_firmware:-:*:*:*:*:*:*:*' OR software.cpe = 'cpe:2.3:o:tesla:model_3_firmware:11.0:*:*:*:*:*:*:*' OR software.cpe = 'cpe:2.3:o:tesla:model_3_firmware:2022-03-26:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:o:tesla:model_s_firmware:-:*:*:*:*:*:*:*' OR software.cpe = 'cpe:2.3:o:tesla:model_s_firmware:2022-03-26:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:o:tesla:model_x_firmware:-:*:*:*:*:*:*:*' OR software.cpe = 'cpe:2.3:o:tesla:model_x_firmware:2020-11-23:*:*:*:*:*:*:*' OR software.cpe = 'cpe:2.3:o:tesla:model_x_firmware:2022-03-26:*:*:*:*:*:*:*') ] AND [ (software.cpe = 'cpe:2.3:h:tesla:model_3:-:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:tesla:model_s:-:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:tesla:model_x:-:*:*:*:*:*:*:*') ] )",
```

#### Advanced Relationships

[I will use CVE-2019-18939 to demonstrate another more complex `configuration`](https://nvd.nist.gov/vuln/detail/CVE-2019-18939).

```json
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "AND",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "286DA904-5631-4AAF-86DE-97C23982D2C5"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "9C2CF19C-7EDE-4E3C-A736-E6736FF03FDC"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "38BE17DA-7C5E-427E-B824-151EB27CFF26"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "nodes": [
                            {
                                "operator": "AND",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F5D8290F-3541-4452-99CB-0766CDC59073"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "33113AD0-F378-49B2-BCFC-C57B52FD3A04"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "285F4E29-E299-4F83-9F7E-BB19933AD654"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "nodes": [
                            {
                                "operator": "AND",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "286DA904-5631-4AAF-86DE-97C23982D2C5"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "33113AD0-F378-49B2-BCFC-C57B52FD3A04"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "285F4E29-E299-4F83-9F7E-BB19933AD654"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "nodes": [
                            {
                                "operator": "AND",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F5D8290F-3541-4452-99CB-0766CDC59073"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "9C2CF19C-7EDE-4E3C-A736-E6736FF03FDC"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "38BE17DA-7C5E-427E-B824-151EB27CFF26"
                                    }
                                ]
                            }
                        ]
                    }
                ],
```

In this CVE there are four nodes, so this time cve2stix will join the patterns with `OR` statement (because there is no top level operator -- see more advanced relationships for dealing with these).

This gives four patterns (note, all the match criterias return just one result)...

Pattern one;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*') ]",
```

Pattern two;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*') ]",
```

Pattern three;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*') ]",
```

Pattern four;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*') ]",
```

Which form a single pattern inside the Indicator SDO as follows (each above pattern is joined with `OR` in the final pattern as there is no top level `operator` in the NVD response);

```json
    "pattern": "( [ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*') ] ) OR ( [ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*') ] ) OR ( [ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*') ] ) OR ( [ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*') ] )",
```

#### (More) Advanced Relationships

Advance relationships are made slightly more complicated. For this I'll use CVE-2020-3543.

```json
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:cisco:8000p_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "955AED3C-3ED2-4467-AAA5-510521CD56E7"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:cisco:8000p_ip_camera:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "EC586459-C532-4A89-8C43-58DA17181A38"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:cisco:8020_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "0C59F1EE-2E1C-4001-A9A7-73B92F9827AB"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:cisco:8020_ip_camera:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "B783A438-0D5A-4BA7-97E0-0FA917045B37"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:cisco:8030_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "DD32F59C-A08D-4692-9F79-5F8F419B5B18"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:cisco:8030_ip_camera:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "42E1CC6F-8A71-4012-ABF8-F0DF96B23949"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:cisco:8070_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "934836A7-DBBD-44CF-8CE5-28C2FC7AC754"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:cisco:8070_ip_camera:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "BD2510BB-580C-4826-BE9D-4879F2B8BDA5"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:cisco:8400_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "4E28EB73-9705-4BED-9969-50DE456F8B5F"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:cisco:8400_ip_camera:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "12067AE1-9A55-43BE-8C75-849E060AF41A"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:cisco:8620_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "D84B5451-961F-4118-B288-C94CDEC6D40A"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:cisco:8620_ip_camera:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "AA06EF29-7996-4916-90E1-6A569EB95C6B"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:cisco:8630_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "D1397782-897F-44FB-A42D-5BAEF0CDAB77"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:cisco:8630_ip_camera:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "3214D558-A6FF-4B03-947B-40AD12355235"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:cisco:8930_speed_dome_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "37D529B4-C32B-4DFE-A216-C7A18228DA15"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:cisco:8930_speed_dome_ip_camera:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "39E0E98A-F382-4AA8-B940-78A78C99736A"
                                    }
                                ]
                            }
                        ]
                    }
                ],
```

See hee how you have a top level `operator` for each node. In this case the `operator` is always `AND`.

The `matchCriteriaId` in all nodes only return one CPE.

Pattern one;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:o:cisco:8000p_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8000p_ip_camera:-:*:*:*:*:*:*:*') ]",
```

Pattern two;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:o:cisco:8020_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8020_ip_camera:-:*:*:*:*:*:*:*') ]",
```

Pattern three;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:o:cisco:8030_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8030_ip_camera:-:*:*:*:*:*:*:*') ]",
```

Pattern four;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:o:cisco:8070_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8070_ip_camera:-:*:*:*:*:*:*:*') ]",
```

Pattern five;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:o:cisco:8400_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8400_ip_camera:-:*:*:*:*:*:*:*') ]",
```

Pattern six;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:o:cisco:8620_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8620_ip_camera:-:*:*:*:*:*:*:*') ]",
```

Pattern seven;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:o:cisco:8630_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8630_ip_camera:-:*:*:*:*:*:*:*') ]",
```

Pattern eight;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:o:cisco:8930_speed_dome_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8930_speed_dome_ip_camera:-:*:*:*:*:*:*:*') ]",
```

This will create a final pattern with all 8 patterns, joined with an `AND` statement, as this is the top level operator. Here is what it would look like

```json
    "pattern": "( [ (software.cpe = 'cpe:2.3:o:cisco:8000p_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8000p_ip_camera:-:*:*:*:*:*:*:*') ] ) AND ( [ (software.cpe = 'cpe:2.3:o:cisco:8020_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8020_ip_camera:-:*:*:*:*:*:*:*') ] ) AND ( [ (software.cpe = 'cpe:2.3:o:cisco:8030_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8030_ip_camera:-:*:*:*:*:*:*:*') ] ) AND ( [ (software.cpe = 'cpe:2.3:o:cisco:8070_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8070_ip_camera:-:*:*:*:*:*:*:*') ] ) AND ( [ (software.cpe = 'cpe:2.3:o:cisco:8400_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8400_ip_camera:-:*:*:*:*:*:*:*') ] ) AND ( [ (software.cpe = 'cpe:2.3:o:cisco:8620_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8620_ip_camera:-:*:*:*:*:*:*:*') ] ) AND ( [ (software.cpe = 'cpe:2.3:o:cisco:8630_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8630_ip_camera:-:*:*:*:*:*:*:*') ] ) AND ( [ (software.cpe = 'cpe:2.3:o:cisco:8930_speed_dome_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8930_speed_dome_ip_camera:-:*:*:*:*:*:*:*') ] )",
```

## Get started...

Hopefully for those of you starting out working with CVEs or CPEs this post has been helpful.

That said, if all you want is CVEs and CPEs as STIX 2.1 objects (with STIX Patterns included), let us do the legwork for you...

* [cve2stix](https://github.com/muchdogesec/cve2stix)
* [cpe2stix](https://github.com/muchdogesec/cpe2stix)