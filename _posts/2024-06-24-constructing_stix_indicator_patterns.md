---
date: 2024-06-24
last_modified: 2024-06-24
title: "Constructing STIX Indicator Patterns"
description: "The STIX 2.1 Indicator SDO specification is flexible enough to allow for a range of detection languages which means you can share your detection content with tools that understand STIX."
categories:
  - DIY
  - TUTORIAL
tags: [
    STIX
]
products:
    - stix4doge
    - txt2stix
    - sigma2stix
    - cve2stix
author_staff_member: david-greenwood
image: /assets/images/blog/2024-06-24/header.png
featured_image: /assets/images/blog/2024-06-24/header.png
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

Learn how to write STIX Patterns to create detection rules using some real examples.

## Overview

The ultimate use of intelligence is to try and defend or counteract for it. For example, understanding how to put in place network defenses or to mitigate an attack that has been successful in part of its initiatives.

Part of this is to ensure you are able to detect security events (to ensure the bit of intelligence you are looking at has not already impacted you).

Many of you will be familiar with detection languages in SIEMs to search for malicious events. There might be as simple as searching for an IP address, or more complex looking for behaviours and patterns alongside evidential breadcrumbs.

In STIX 2.1, [Indicator SDOs](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_muftrcpnf89v) must contain a `pattern` Property that can be used to describe suspicious or malicious cyber activity.

## STIX Patterns

The STIX 2.1 Indicator SDO specification is flexible enough to allow for a range of detection languages (`pattern_type`) as defined in the [Pattern Type Vocabulary](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_9lfdvxnyofxw), these are;

* `pcre`: Perl Compatible Regular Expressions language
* `sigma`: SIGMA language
* `snort`: SNORT language
* `suricata`: SURICATE language
* `yara`: YARA language
* `stix`: [STIX pattern language](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_me3pzm77qfnf)

For example, I could use a `sigma` pattern inside an Indicator SDO by defining the Properties `"pattern_type": "sigma"` and print the entire Sigma rule yaml content under the `"pattern"` Property.

[We do exactly this in sigma2stix](https://github.com/muchdogesec/sigma2stix).

For example, here is the  rule Suspicious ASPX File Drop by Exchange (https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_exchange_webshell_drop.yml) as a STIX 2.1 Indicator

```json
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--47a4804c-bdc8-5d3f-826f-15c8598cd642",
            "created_by_ref": "identity--860f4c0f-8c26-5889-b39d-ce94368bc416",
            "created": "2022-10-04T00:00:00.000Z",
            "modified": "2022-10-04T00:00:00.000Z",
            "name": "Suspicious File Drop by Exchange",
            "description": "Detects suspicious file type dropped by an Exchange component in IIS. The following false positives can result from this detection; Unknown",
            "indicator_types": [
                "malicious-activity",
                "anomalous-activity"
            ],
            "pattern": "{'title': 'Suspicious File Drop by Exchange', 'id': '6b269392-9eba-40b5-acb6-55c882b20ba6', 'related': [{'id': 'bd1212e5-78da-431e-95fa-c58e3237a8e6', 'type': 'similar'}], 'status': 'test', 'description': 'Detects suspicious file type dropped by an Exchange component in IIS', 'references': ['https://www.microsoft.com/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/', 'https://www.gteltsc.vn/blog/canh-bao-chien-dich-tan-cong-su-dung-lo-hong-zero-day-tren-microsoft-exchange-server-12714.html', 'https://en.gteltsc.vn/blog/cap-nhat-nhe-ve-lo-hong-bao-mat-0day-microsoft-exchange-dang-duoc-su-dung-de-tan-cong-cac-to-chuc-tai-viet-nam-9685.html'], 'author': 'Florian Roth (Nextron Systems)', 'date': '2022/10/04', 'tags': ['attack.persistence', 'attack.t1190', 'attack.initial_access', 'attack.t1505.003'], 'logsource': {'product': 'windows', 'category': 'file_event'}, 'detection': {'selection': {'Image|endswith': '\\\\w3wp.exe', 'CommandLine|contains': 'MSExchange'}, 'selection_types': {'TargetFilename|endswith': ['.aspx', '.asp', '.ashx', '.ps1', '.bat', '.exe', '.dll', '.vbs']}, 'condition': 'all of selection*'}, 'falsepositives': ['Unknown'], 'level': 'medium'}",
            "pattern_type": "sigma",
            "valid_from": "2022-10-04T00:00:00Z",
            "external_references": [
                {
                    "source_name": "sigma-rule",
                    "url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_exchange_webshell_drop_suspicious.yml",
                    "external_id": "rule"
                },
                {
                    "source_name": "sigma-rule",
                    "description": "6b269392-9eba-40b5-acb6-55c882b20ba6",
                    "external_id": "id"
                },
                {
                    "source_name": "sigma-rule",
                    "description": "medium",
                    "external_id": "level"
                },
                {
                    "source_name": "sigma-rule",
                    "description": "test",
                    "external_id": "status"
                },
                {
                    "source_name": "sigma-rule",
                    "description": "Florian Roth (Nextron Systems)",
                    "external_id": "author"
                },
                {
                    "source_name": "ATTACK",
                    "description": "tactic",
                    "external_id": "persistence"
                },
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1190",
                    "external_id": "T1190"
                },
                {
                    "source_name": "ATTACK",
                    "description": "tactic",
                    "external_id": "initial_access"
                },
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1505.003",
                    "external_id": "T1505.003"
                },
                {
                    "source_name": "sigma-rule",
                    "description": "https://www.microsoft.com/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/",
                    "external_id": "reference"
                },
                {
                    "source_name": "sigma-rule",
                    "description": "https://www.gteltsc.vn/blog/canh-bao-chien-dich-tan-cong-su-dung-lo-hong-zero-day-tren-microsoft-exchange-server-12714.html",
                    "external_id": "reference"
                },
                {
                    "source_name": "sigma-rule",
                    "description": "https://en.gteltsc.vn/blog/cap-nhat-nhe-ve-lo-hong-bao-mat-0day-microsoft-exchange-dang-duoc-su-dung-de-tan-cong-cac-to-chuc-tai-viet-nam-9685.html",
                    "external_id": "reference"
                }
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--860f4c0f-8c26-5889-b39d-ce94368bc416"
            ]
        }
```

You might have seen the `stix` specific `pattern_type` listed above. This is a detection pattern language similar to Sigma but defined by OASIS [in the STIX 2.1 specification](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_me3pzm77qfnf).

Here is the general structure of a STIX Pattern;

<img class="img-fluid" src="/assets/images/blog/2024-06-24/stix-pattern-structure.jpeg" alt="STIX Attack Pattern specification" title="STIX Attack Pattern specification" />

It is a lot! Let me try and take this structure apart for you.

### Comparison Expressions and Operators

[Comparison Expressions](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_boiciucr9smf) are the fundamental building blocks of STIX patterns.

They take an Object Path (using SCOs) and Object Value with a Comparison Operator to evaluate their relationship.

<img class="img-fluid" src="/assets/images/blog/2024-06-24/comparison-expressions-and-operators.jpeg" alt="Comparison Expressions and Operators" title="Comparison Expressions and Operators" />

Multiple Comparison Expressions can joined by Comparison Expression Operators to create an Observation Expression.

My earlier example of a filename showed a simple Comparison Expression in a Pattern.

Here is an example of a simple Comparison Expression to detect an IPv4 address:

```
[ipv4-addr:value='198.51.100.1']
```

It uses the [IPv4 Address SCO](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ki1ufj1ku8s0) (`ipv4-addr`) and its ID Contributing Property (`value`) as the Object path (shown in specification screenshot below). The Object value is `198.51.100.1`.

Another example, using a Windows Registry Key;

```
[windows-registry-key:key='HKEY_LOCAL_MACHINE\\System\\Foo\\Bar']
```

Here I use [Windows Registry Key Object Key SCO](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_luvw8wjlfo3y) and its ID Contributing Property (`key`) (shown in specification screenshot below). The Object value is `HKEY_LOCAL_MACHINE\\System\\Foo\\Bar`.


You can use a range [Comparison Operators
](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070783) in addition to equals (`=`). Does not equal (`!=`), is greater than (`>`), is less than or equal to (`>=`), etc.

```
[directory:path LIKE 'C:\\Windows\\%\\foo']
```

In the above example I am using the `LIKE` Comparison Operator. You will notice it is possible to pass capture groups. In the example above `%` catches 0 or more characters.

As such a pattern would match (be true) if `C:\Windows\DAVID\foo`, `C:\Windows\JAMES\foo`, etc. was observed.

### Observation Expressions, Operators and Qualifiers

More than one Comparison Expression can be joined using a Comparison Expression Operator to create an [Observation Expression](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_x1nsjyy75wtq).

<img class="img-fluid" src="/assets/images/blog/2024-06-24/observation-expressions-operators-and-qualifiers.jpeg" alt="Observation Expressions, Operators and Qualifiers" title="Observation Expressions, Operators and Qualifiers" />

The entire Observation Expression is captured in square brackets `[]`.

For example, a pattern to match match on either `198.51.100.1/32` or `203.0.113.33/32` could be expressed with the `OR` Comparison Expression Operator;

```
[ipv4-addr:value='198.51.100.1/32' OR ipv4-addr:value='203.0.113.33/32']
```

Changing the Comparison Expression Operator to an `AND` makes the pattern match on both `198.51.100.1/32` and `203.0.113.33/32`;

```
[ipv4-addr:value='198.51.100.1/32' AND ipv4-addr:value='203.0.113.33/32']
```

Observation Expressions can also be joinged using [Observation Operators](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_l72a2uz085od).

In the following example there are two Observation Expressions joined by the Observation Operator `FOLLOWEDBY`;

```
[ipv4-addr:value='198.51.100.1/32'] FOLLOWEDBY [ipv4-addr:value='203.0.113.33/32']
```

The `FOLLOWEDBY` Observation Operator defines the order in which Comparison Expressions must match. In this case `198.51.100.1/32` must be followed by `203.0.113.33/32`. Put another way, `198.51.100.1/32` must be detected before `203.0.113.33/32`.

[Observation Expression Qualifiers](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_itrc2pdxk4ef) allow for even more definition at the end of a pattern.

You can define `WITHIN`, `START`/ `STOP`, and `REPEATS` Observation Expression Qualifiers.

The following example requires the two Observation Expressions to repeat 5 times in order for a match;

```
([ipv4-addr:value='198.51.100.1/32'] FOLLOWEDBY [ipv4-addr:value='203.0.113.33/32']) REPEATS 5 TIMES
```

Here is another example that is very similar to a pattern used for malware detection;

```
([file:hashes.'SHA-256'='ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'] AND [win-registry-key:key='hkey']) WITHIN 120 SECONDS
```

Here if the file hash Observation Expression and a Windows Registry Observation Expression are true within 120 seconds of each other then the pattern matches.

### Precedence and Parenthesis

[Operator Precedence](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ictqjpsw7dia) is an important consideration to keep in mind when writing Patterns.

Consider the following Pattern:

```
[ipv4-addr:value='198.51.100.1/32'] FOLLOWEDBY ([ipv4-addr:value='203.0.113.33/32'] REPEATS 5 TIMES)
```

Here, the first Observation Expression requires a match on an `ipv4-addr:value` equal to `198.51.100.1/32` that precedes 5 occurrences of the Observation Expression where `ipv4-addr:value` equal to `203.0.113.33/32`.

Now consider the following Pattern (almost identical to before, but notice the parentheses):

```
([ipv4-addr:value='198.51.100.1/32'] FOLLOWEDBY [ipv4-addr:value='203.0.113.33/32']) REPEATS 5 TIMES
```

The first Observation Expression requires a match on an `ipv4-addr:value` equal to `198.51.100.1/32` followed by a match on the second Observation Expression for an `ipv4-addr:value` equal to `203.0.113.33/32`, this pattern must be seen 5 times for a match.

### Some examples to test you

Below is a sample from a Linux audit log...

```txt
2019-08-20 09:08:55:906 type=USER_LOGIN msg=audit(1566306445.906:280) user pid=2318 uid=0 auid 4294967295 ses=4294967295 username=unknown subj=system_u:system_r:sshd_t:s0-"(unknown)" exe="/usr/sbin/sshd" hostname=? addr=218.92.0.173 terminal=ssh res=failed'
2019-08-20 09:07:25:647 type=USER_LOGIN msg=audit(1566306445.647:242) user pid=2314 uid=0 auid 4294967295 ses=4294967295 username=mike subj=system_u:system_r:sshd_t:s0-"(mike)" exe="/usr/sbin/sshd" hostname=? addr=60.242.115.215 terminal=ssh res=failed'
2019-08-20 09:07:25:195 type=USER_LOGIN msg=audit(1566306445.195.262) user pid=2311 uid=0 auid 4294967295 ses=4294967295 username=mike subj=system_u:system_r:sshd_t:s0-"(mike)" exe="/usr/sbin/sshd" hostname=? addr=60.242.115.215 terminal=ssh res=failed'
```

Assume the SIEM has aliased field names correctly (e.g. `addr` field in the logs resolves to an IPv4 address field in the data model, which in turn is mapped to the `ipv4-addr` SCO).

#### Example 1: Using the `OR` Observation Expression

```
[ipv4-addr:value='218.92.0.173'] OR [ipv4-addr:value='1.1.1.1']
```

Matches.

The statement IPv4 `218.92.0.173` was True for one line (log line 1).

#### Example 2: Using the `AND` Observation Expression

```
[ipv4-addr:value='218.92.0.173'] AND [ipv4-addr:value='1.1.1.1']
```

Does not match.

Both of the statements needed to be True to satisfy the AND operator, but only the IPv4 `218.92.0.173` statement was ever true (log line 1).

#### Example 3: Using the `FOLLOWEDBY` Observation Expression

```
[ipv4-addr:value='60.242.115.215'] FOLLOWEDBY [user-account.account_login='mike']
```

Matches.

The IPv4 address `60.242.115.215` (log line 3) is immediately followed by `mike` user account login (log line 2)

#### Example 4: Using the `!=` Comparison Operators

```
[ipv4-addr:value!='218.92.0.173']
```

Matches.

The IPv4 address value `218.92.0.173` was not seen (log line 2 and 3)

#### Example 5: Using the `>` Comparison Operators

```
[process:pid>='2315']
```

Matches.

Log line 1 is the only line where process ID is greater than `pid=2315` (the other two lines have process IDs less than 2315)

#### Example 6: Parentheses Precedent

```
[ipv4-addr:value='218.92.0.173'] FOLLOWEDBY ([user-account:account_login='mike'] OR [user-account:account_login='david'])
```

Does not match.

The IPv4 address `218.92.0.173` must be followed by at least one of the statements in the parenthesis. Log line 1 contains `218.92.0.173` but does not have and logs that follow it (by time), thus this statement is not true for the 3 logs shown.

#### Example 7: Using the `WITHIN` Observation Expression Qualifier

```
[ipv4-addr:value='60.242.115.215'] FOLLOWEDBY [ipv4-addr:value='218.92.0.173'] WITHIN 1 MINUTE
```

Does not match.

The IPv4 address `60.242.115.215` was seen at `09:07:25:647` (log line 2) then the IPv4 address `218.92.0.173` was seen at `09:08:55:906` (log line 1) which is more than 1 minute apart.

#### Example 8: Using the `REPEATS` Observation Expression Qualifier

```
([ipv4-addr:value='60.242.115.215'] FOLLOWEDBY [ipv4-addr:value='60.242.115.215']) REPEATS 2 TIMES
```

Does not match.

The IPv4 address `60.242.115.215` (log line 2) was followed IPv4 address `218.92.0.173` (log line 1) but it was not repeated twice.

## Helpful tools to create and validate STIX Patterns

The [STIX 2 Pattern Validator from OASIS](https://github.com/oasis-open/cti-pattern-validator) is a great tool in checking your patterns are written correctly.

Simply run the STIX 2 Pattern Validator script by declaring your Pattern...

```shell
mkdir stix2-patterns
python3 -m venv stix2-patterns
source stix2-patterns/bin/activate
pip3 install stix2-patterns
validate-patterns
Enter a pattern to validate: [file:hashes.md5 = '79054025255fb1a26e4bc422aef54eb4']
PASS: [file:hashes.md5 = '79054025255fb1a26e4bc422aef54eb4']
Enter a pattern to validate: [bad pattern]
FAIL: Error found at line 1:5. no viable alternative at input 'badpattern' 
```

If you are trying to see if content in an Observed Data SDO matches an existing STIX Pattern you can use the [CTI Pattern Matcher](https://github.com/oasis-open/cti-pattern-matcher).

Lets start by creating an [Observed Data SDO](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_p49j1fwoxldc), and two related SCOs;

```json
{
    "type": "observed-data",
    "spec_version": "2.1",
    "id": "observed-data--699546f4-6d73-4a35-a961-181a34fa3b14",
    "created": "2016-04-06T19:58:16.000Z",
    "modified": "2016-04-06T19:58:16.000Z",
    "first_observed": "2015-12-21T19:00:00Z",
    "last_observed": "2015-12-21T19:00:00Z",
    "number_observed": 2,
    "object_refs": [
        "ipv4-addr--dc63603e-e634-5357-b239-d4b562bc5445",
        "domain-name--dd686e37-6889-53bd-8ae1-b1a503452613"
    ]
}
```

```json
{
    "type": "ipv4-addr",
    "spec_version": "2.1",
    "id": "ipv4-addr--dc63603e-e634-5357-b239-d4b562bc5445",
    "value": "177.60.40.7"
}
```

```json
{
    "type": "domain-name",
    "spec_version": "2.1",
    "id": "domain-name--dd686e37-6889-53bd-8ae1-b1a503452613",
    "value": "google.com"
}
```

The CTI Pattern Matcher accepts "A file containing JSON list of STIX observed-data SDOs" (in a STIX bundle). Lets create that `objects-bundle.json`;

```json
{
    "type": "bundle",
    "id": "bundle--cb06ef7f-acb8-46b6-98e1-27c6fe8d23c2",
    "objects": [
        {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": "observed-data--699546f4-6d73-4a35-a961-181a34fa3b14",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "first_observed": "2020-01-01T00:00:00.000Z",
            "last_observed": "2020-01-01T00:00:00.000Z",
            "number_observed": 2,
            "object_refs": [
                "ipv4-addr--dc63603e-e634-5357-b239-d4b562bc5445",
                "domain-name--dd686e37-6889-53bd-8ae1-b1a503452613"
            ]
        },
        {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--dc63603e-e634-5357-b239-d4b562bc5445",
            "value": "177.60.40.7"
        },
        {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": "domain-name--dd686e37-6889-53bd-8ae1-b1a503452613",
            "value": "google.com"
        }
    ]
}
```

And lets write a pattern I know matches, and does not match, and store it to `patterns.txt`

```
[ipv4-addr:value='177.60.40.7']
[domain:value='microsoft.com']
```

So if I pass both of these to stix2-matcher;

```shell
mkdir stix2-matcher
python3 -m venv stix2-matcher
source stix2-matcher/bin/activate
pip3 install stix2-matcher
stix2-matcher --patterns patterns.txt --file objects-bundle.json --stix_version 2.1
MATCH:  [ipv4-addr:value='177.60.40.7']
NO MATCH:  [domain:value='microsoft.com']
```

Which brings us to a slight tangent; how to use Observed Data SDOs.

## Representing Pattern Matches as Sighting SROs

Now you have seen how Patterns can be used, detections (aka sightings) of these patterns need to modelled.

If you start to use STIX Patterns for threat detection, you will probably want to represent the detection matches in STIX format too.

That is where the STIX [Sighting](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070677) SRO and [Observed Data](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070654) SDO can help, as detailed in the previous post.

<img class="img-fluid" src="/assets/images/blog/2024-06-24/pattern-matches-sightings.png" alt="Representing Pattern Matches as Sighting SROs" title="Representing Pattern Matches as Sighting SROs" />

The previous steps to create this relationship might be;

* IPv4 SCO created with Indicator containing pattern referencing the IPv4 SCO
* IPv4 SCO sent to SIEM (or other tooling) for detections
* Detection observed and Observed Data SDO and Sighting SRO created

Creating a series of objects as follows;

```json
{
    "type": "bundle",
    "id": "bundle--177c6477-2dee-43d5-b4c9-8b7f3f5ec542",
    "objects": [
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "indicator_types": [
                "malicious-activity"
            ],
            "name": "Some Malware",
            "description": "Some malware description",
            "pattern": "[ipv4-addr:value='177.60.40.7']",
            "pattern_type": "stix",
            "valid_from": "2016-01-01T00:00:00Z"
        },
        {
            "type": "sighting",
            "spec_version": "2.1",
            "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "first_seen": "2020-01-01T00:00:00.000Z",
            "last_seen": "2020-01-01T00:00:00.000Z",
            "count": 50,
            "sighting_of_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "observed_data_refs": [
                "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf"
            ],
            "where_sighted_refs": [
                "identity--d3f9a82b-7272-417e-9195-f3b0f68159e9"
            ]
        },
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--d3f9a82b-7272-417e-9195-f3b0f68159e9",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "Splunk Enterprise Security",
            "identity_class": "system"
        },
        {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
            "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "first_observed": "2020-01-01T00:00:00.000Z",
            "last_observed": "2020-01-01T00:00:00.000Z",
            "number_observed": 1,
            "object_refs": [
                "ipv4-addr--dc63603e-e634-5357-b239-d4b562bc5445"
            ]
        },
        {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--dc63603e-e634-5357-b239-d4b562bc5445",
            "value": "177.60.40.7"
        }
    ]
}
```

Which looks as follows on a graph;

<div class="stixview" data-stix-url="/assets/images/blog/2024-06-24/bundle--177c6477-2dee-43d5-b4c9-8b7f3f5ec542.json" data-stix-allow-dragdrop="false" data-show-idrefs="false" data-show-markings="true" data-show-sidebar="true" data-graph-layout="cise" data-caption="Sighting of a STIX pattern" data-disable-mouse-zoom="false" data-graph-width="100%" data-graph-height="85vh" data-show-footer="true"></div>

## Converting STIX patterns so they are understood by downstream tools

So you've read this far, now for the harsh reality; I've never come across a SIEM / EDR / XDR / whatever that understands STIX formatted patterns natively.

One advantage of using other `pattern_type`s in a STIX pattern, like Sigma, is that the `pattern` can be understood by these downstream tools for this reason.

This is where STIX Shifter comes in.

https://github.com/opencybersecurityalliance/stix-shifter

STIX Shifter can convert STIX formatted patterns into other detection languages. Let me show you how...

> STIX-shifter is an open source python library allowing software to connect to products that house data repositories by using STIX Patterning, and return results as STIX Observations.

STIX Shifter;

1. takes STIX 2.x Patterns as input
2. converts them to target rule formats
3. sends the converted rule to the downstream tool
4. detects data that matches the patterns inside downstream tools (e.g. SIEMs, EDRs, etc)
5. transforms the output (the detection) into STIX 2.x Observed Data Objects.

Here's a nice presentation describing STIX Shifter;

<iframe width="560" height="315" src="https://www.youtube.com/embed/aUiZkmqVczQ?si=xmhAUKANiVvhXNho" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

### STIX Shifter Connectors

STIX Shifter is based around the concept of Connectors.

A STIX Shifter connector is a module inside the STIX Shifter library that implements an interface for:

* data source query and result set translation
* data source communication

Each Connector supports a set of STIX objects and properties as defined in the connector's mapping files. 

There are about 30 Connectors that currently exist, [detailed here](https://stix-shifter.readthedocs.io/en/latest/CONNECTORS.html).

Let me demonstrate this concept using some examples.

### Installing STIX Shifter

STIX Shifter can be used as a command line utility or as a Python library.

To install STIX Shifter in both ways;

```shell
mkdir stix-shifter
python3 -m venv stix-shifter
source stix-shifter/bin/activate
pip3 install stix-shifter
pip3 install stix-shifter-utils
stix-shifter -h
```

### STIX Shifter core functions

STIX Shifter provides three core functions;

1. `translate`: The translate command converts STIX patterns into data source queries (in whatever query language the data source might use) and translates data source results (in JSON format) into bundled STIX observation objects.
2. `transmit`: The transmit command allows stix-shifter to connect with products that house repositories of cybersecurity data. Connection and authentication credentials are passed to the data source APIs where stix-shifter can make calls to ping the data source, make queries, delete queries, check query status, and fetch query results.
3. `execute`: The translation and transmission functions can work in sequence by using the execute command from the CLI.

### Converting STIX Patterns to target formats

To use a connector (to translate a STIX pattern), you must first install it. You can do this using pip as follows;

```shell
pip3 install stix-shifter-modules-<CONNECTOR NAME>
```

For example, to install the Splunk Connector;

```shell
pip3 install stix-shifter-modules-splunk
```

The translate command line argument takes the form;

```shell
stix-shifter translate <CONNECTOR NAME> query "<STIX IDENTITY OBJECT>" "<STIX PATTERN>" "<OPTIONS>"
```

Therefore to convert the STIX Pattern `[url:value = 'http://www.testaddress.com'] OR [ipv4-addr:value = '192.168.122.84']` using the newly installed Splunk Connector I can run;

```shell
stix-shifter translate splunk query "{}" "[url:value = 'http://www.testaddress.com'] OR [ipv4-addr:value = '192.168.122.84']"
```

Note, I passed an empty 

Prints the converted Splunk query in a JSON response;

```json
{
    "queries": [
        "search (url = \"http://www.testaddress.com\") OR ((src_ip = \"192.168.122.84\") OR (dest_ip = \"192.168.122.84\")) earliest=\"-5minutes\" | head 10000 | fields src_ip, src_port, src_mac, src_ipv6, dest_ip, dest_port, dest_mac, dest_ipv6, file_hash, user, url, protocol, host, source, DeviceType, Direction, severity, EventID, EventName, ss_name, TacticId, Tactic, TechniqueId, Technique, process, process_id, process_name, process_exec, process_path, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_exec, description, result, signature, signature_id, query, answer"
    ]
}
```

You will notice the Splunk search (nested in the `queries` field). The key part of the search is;

```
(url = \"http://www.testaddress.com\") OR ((src_ip = \"192.168.122.84\") OR (dest_ip = \"192.168.122.84\"))
```

STIX Shifter has converted the STIX fields `url:value` into `url` and `ipv4-addr:value` into both `src_ip` and `dest_ip` fields (as the STIX pattern could refer to either).

[You read a description of the logic performed by the Splunk Connector to perform the translation here](https://github.com/opencybersecurityalliance/stix-shifter/tree/develop/stix_shifter_modules/splunk/stix_translation).

Splunk data ([assumed to be in the Common Information Model (CIM) standard](https://docs.splunk.com/Documentation/CIM/5.0.1/User/Overview)) to STIX mapping is defined in the Splunk modules [to_stix_map.json](https://github.com/opencybersecurityalliance/stix-shifter/blob/develop/stix_shifter_modules/splunk/stix_translation/json/from_stix_map.json) file.

Also notice how the search ends with `earliest=\"-5minutes\" | head 10000 | fields src_ip,...`. These are added by default in the conversion and are not converted from the STIX Pattern. In short these Splunk commands:

* `earliest=\"-5minutes\"` is defining the time range to look back 
* `head` is limiting the number of results returned (to first 10,000) and
* `fields` specifies which fields to keep or remove from the search results

The purpose of including these commands is to limit to scope of the search and ensure all fields are present when matches are found, when STIX-Shifter is used to created Observed Data Object (more on that to follow). If you just want to use STIX-Shifter for conversion to Splunk format, I would remove this from the output as it's not really useful.

Lets try another conversion, this time using the [Elastic ECS Connector](https://github.com/opencybersecurityalliance/stix-shifter/tree/develop/stix_shifter_modules/elastic_ecs) on the same STIX Pattern;

```shell
pip3 install stix-shifter-modules-elastic_ecs
```

The [Elastic Common Schema (ECS) is Elastics own standard](https://www.elastic.co/guide/en/ecs/current/index.html), similar to the Splunk CIM.

```shell
stix-shifter translate elastic_ecs query "{}" "[url:value = 'http://www.testaddress.com'] OR [ipv4-addr:value = '192.168.122.84']"
```

```json
{
    "queries": [
        "(url.original : \"http://www.testaddress.com\") OR ((source.ip : \"192.168.122.84\" OR destination.ip : \"192.168.122.84\" OR client.ip : \"192.168.122.84\" OR server.ip : \"192.168.122.84\" OR host.ip : \"192.168.122.84\" OR dns.resolved_ip : \"192.168.122.84\")) AND (@timestamp:[\"2022-08-23T06:28:44.754Z\" TO \"2022-08-23T06:33:44.754Z\"])"
    ]
}
```

[You can see the STIX Pattern to Elastic ECS conversion logic here](https://github.com/opencybersecurityalliance/stix-shifter/tree/develop/stix_shifter_modules/elastic_ecs/stix_translation).

STIX Shifter has converted the STIX fields `url:value` into `url.original` and `ipv4-addr:value` into `source.ip`, `server.ip`, `host.ip`, and `dns.resolved_ip`.

Like with Splunk, the query also included a 5 minute time window `@timestamp:[\"2022-08-23T06:28:44.754Z\" TO \"2022-08-23T06:33:44.754Z\"])`.

### Creating STIX Observed Data from Detections

In this post I won't cover `transmit`, where STIX-Shifter can authenticate to downstream products via a Connector which can be used to push rules. However, imagine my converted rules were sent down to Splunk to look for matching log lines.

I will show a simulated example of a match being detected and written into a STIX 2.1 Observed Data Object, similar to the flow I showed manually before.

Lets assume the downstream tool (Splunk) detects a match between a converted STIX Pattern (`[ipv4-addr:value = '1.1.1.1']` -> `src_ip=1.1.1.1 OR dest_ip=1.1.1.1`) and a log line that contains `src_ip=1.1.1.1`. In addition to the matching field, the log line has the following fields (this is where the `fields` command in the the Splunk STIX-Shifter output is important) modelled in json;

```json
[
    {
        "src_ip": "1.1.1.1",
        "dest_ip": "2.2.2.2",
        "url": "www.testaddress.com"
    }
]
```

It is vital that the fields match those defined in the STIX-Shifter Connector so that the can be mapped to the correct STIX Cyber Observable Object (e.g. [IPv4 STIX Cyber Observable Object](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ki1ufj1ku8s0)) during the translation. The STIX-Shifter Splunk Connector expects [CIM](https://docs.splunk.com/Documentation/CIM/5.0.1/User/Overview) compliant fields (`src_ip`, `dest_ip` and `url` are all CIM compliant). 

This time the `translate` query takes a slightly different form to create STIX 2.1 Observed Data and Cyber Observable Objects from the detection (using `result` instead of `query`);

```shell
stix-shifter translate <MODULE NAME> results '<STIX IDENTITY OBJECT>' '<LIST OF JSON RESULTS>'
```

Unlike before, a STIX Identity Object is required to be used in the command to attribute the Observed Data Objects to someone. I will use a demo Identity as follows;

```json
{
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--d2916708-57b9-5636-8689-62f049e9f727",
    "created_by_ref": "identity--aae8eb2d-ea6c-56d6-a606-cc9f755e2dd3",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "name": "dogesec-demo",
    "description": "https://github.com/dogesec/",
    "identity_class": "organization",
    "sectors": [
        "technology"
    ],
    "contact_information": "https://www.dogesec.com/contact/",
    "object_marking_refs": [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "marking-definition--3f588e96-e413-57b5-b735-f0ec6c3a8771"
    ]
}
```

Which written out into an entire translate query gives;

```shell
python main.py translate splunk results \
    '{"type":"identity","spec_version":"2.1","id":"identity--d2916708-57b9-5636-8689-62f049e9f727","created_by_ref":"identity--aae8eb2d-ea6c-56d6-a606-cc9f755e2dd3","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"dogesec-demo","description":"https://github.com/dogesec/","identity_class":"organization","sectors":["technology"],"contact_information":"https://www.dogesec.com/contact/","object_marking_refs":["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9","marking-definition--3f588e96-e413-57b5-b735-f0ec6c3a8771"]}' \
    '[{"src_ip":"1.1.1.1","dest_ip":"2.2.2.2","url":"www.testaddress.com"}]' \
    '{"stix_2.1": true}'
```

By default, JSON results are translated into STIX 2.0. To return STIX 2.1 results include `{"stix_2.1": true}` in the options part (last part) of the CLI command.

This command prints a JSON bundle with a STIX 2.1 Observed Data Object (covering the entire log line representing the match), and four STIX 2.1 Cyber Observable Objects representing each field type in the log line, `src_ip`, `dest_ip`, and `url`. Note, there are four results as the single `url` in my log (`www.testaddress.com`) is converted by the Splunk STIX-Shifter Connector into STIX 2.1 SCO types [URL](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ah3hict2dez0) and [Domain Name](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_prhhksbxbg87).

```json
{
    "type": "bundle",
    "id": "bundle--9bbb1b3e-ddfe-4ca7-979d-2610371b8de7",
    "objects": [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--d2916708-57b9-5636-8689-62f049e9f727",
            "created_by_ref": "identity--aae8eb2d-ea6c-56d6-a606-cc9f755e2dd3",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "dogesec-demo",
            "description": "https://github.com/dogesec/",
            "identity_class": "organization",
            "sectors": [
                "technology"
            ],
            "contact_information": "https://www.dogesec.com/contact/",
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                "marking-definition--3f588e96-e413-57b5-b735-f0ec6c3a8771"
            ]
        },
        {
            "id": "observed-data--130b5d08-e0a2-4f0d-9c21-c8f77f66d987",
            "type": "observed-data",
            "created_by_ref": "identity--d2916708-57b9-5636-8689-62f049e9f727",
            "created": "2020-01-01T07:40:50.410Z",
            "modified": "2020-01-01T07:40:50.410Z",
            "first_observed": "2020-01-01T07:40:50.410Z",
            "last_observed": "2020-01-01T07:40:50.410Z",
            "number_observed": 1,
            "object_refs": [
                "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
                "ipv4-addr--a4c470a9-5498-5e8e-9fa2-66b1ceadcc12",
                "url--cc6ef2fe-d31f-510e-9809-bf0f6478e749",
                "domain-name--cc6ef2fe-d31f-510e-9809-bf0f6478e749"
            ],
            "spec_version": "2.1"
        },
        {
            "type": "ipv4-addr",
            "value": "1.1.1.1",
            "id": "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc",
            "spec_version": "2.1"
        },
        {
            "type": "ipv4-addr",
            "value": "2.2.2.2",
            "id": "ipv4-addr--a4c470a9-5498-5e8e-9fa2-66b1ceadcc12",
            "spec_version": "2.1"
        },
        {
            "type": "url",
            "value": "www.testaddress.com",
            "id": "url--cc6ef2fe-d31f-510e-9809-bf0f6478e749",
            "spec_version": "2.1"
        },
        {
            "type": "domain-name",
            "value": "www.testaddress.com",
            "id": "domain-name--cc6ef2fe-d31f-510e-9809-bf0f6478e749",
            "spec_version": "2.1"
        }
    ]
}
```

Now let me highlight why the fields printed in the log data, must match those expected by the Connector.

This time I will use the Elastic ECS Connector on the same log line. Elastic ECS does not use the CIM field name standard used by Splunk. For example, as shown in the example translate conversion from STIX Pattern to Elastic ECS, IPs are captured in the field name `source.ip` (in Splunk the CIM compliant field is `src_ip`).

Demonstrating using the same command as I did for Splunk, the only difference being the connector used (this time `elastic_ecs`);

```shell
python main.py translate elastic_ecs results \
    '{"type":"identity","spec_version":"2.1","id":"identity--d2916708-57b9-5636-8689-62f049e9f727","created_by_ref":"identity--aae8eb2d-ea6c-56d6-a606-cc9f755e2dd3","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"dogesec-demo","description":"https://github.com/dogesec/","identity_class":"organization","sectors":["technology"],"contact_information":"https://www.dogesec.com/contact/","object_marking_refs":["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9","marking-definition--3f588e96-e413-57b5-b735-f0ec6c3a8771"]}' \
    '[{"src_ip":"1.1.1.1","dest_ip":"2.2.2.2","url":"www.testaddress.com"}]' \
    '{"stix_2.1": true}'
```

```json
{
    "type": "bundle",
    "id": "bundle--a95e4858-6508-49fd-a280-1dbade00fd84",
    "objects": [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--d2916708-57b9-5636-8689-62f049e9f727",
            "created_by_ref": "identity--aae8eb2d-ea6c-56d6-a606-cc9f755e2dd3",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "dogesec-demo",
            "description": "https://github.com/dogesec/",
            "identity_class": "organization",
            "sectors": [
                "technology"
            ],
            "contact_information": "https://www.dogesec.com/contact/",
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                "marking-definition--3f588e96-e413-57b5-b735-f0ec6c3a8771"
            ]
        },
        {
            "id": "observed-data--733197a4-dc58-4d27-a656-51e76c65582b",
            "type": "observed-data",
            "created_by_ref": "identity--d2916708-57b9-5636-8689-62f049e9f727",
            "created": "2020-01-01T08:14:17.421Z",
            "modified": "2020-01-01T08:14:17.421Z",
            "first_observed": "2020-01-01T08:14:17.421Z",
            "last_observed": "2020-01-01T08:14:17.421Z",
            "number_observed": 1,
            "object_refs": [],
            "spec_version": "2.1"
        }
    ]
}
```

See how an Observed Data Object is created, but STIX Shifter cannot convert any Cyber Observable Data Objects from the input because the field names in the log are not mapped in the Elastic ECS Connector configuration.

It is important to understand that when field mappings are incorrect, STIX Shifter can product inconsistent results.

Let me demonstrate using the QRadar Connector;

```shell
pip3 install stix-shifter-modules-qradar
```

```shell
python main.py translate qradar results \
    '{"type":"identity","spec_version":"2.1","id":"identity--d2916708-57b9-5636-8689-62f049e9f727","created_by_ref":"identity--aae8eb2d-ea6c-56d6-a606-cc9f755e2dd3","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","name":"dogesec-demo","description":"https://github.com/dogesec/","identity_class":"organization","sectors":["technology"],"contact_information":"https://www.dogesec.com/contact/","object_marking_refs":["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9","marking-definition--3f588e96-e413-57b5-b735-f0ec6c3a8771"]}' \
    '[{"src_ip":"1.1.1.1","dest_ip":"2.2.2.2","url":"www.testaddress.com"}]' \
    '{"stix_2.1": true}'
```

```json
{
    "type": "bundle",
    "id": "bundle--fb406a9f-df00-4286-8f34-fb9dc1844f75",
    "objects": [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--d2916708-57b9-5636-8689-62f049e9f727",
            "created_by_ref": "identity--aae8eb2d-ea6c-56d6-a606-cc9f755e2dd3",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "dogesec-demo",
            "description": "https://github.com/dogesec/",
            "identity_class": "organization",
            "sectors": [
                "technology"
            ],
            "contact_information": "https://www.dogesec.com/contact/",
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                "marking-definition--3f588e96-e413-57b5-b735-f0ec6c3a8771"
            ]
        },
        {
            "id": "observed-data--71aa43a9-7915-419a-bfb5-f84fbf3e22b6",
            "type": "observed-data",
            "created_by_ref": "identity--d2916708-57b9-5636-8689-62f049e9f727",
            "created": "2020-01-01T08:24:24.811Z",
            "modified": "2020-01-01T08:24:24.811Z",
            "first_observed": "2020-01-01T08:24:24.811Z",
            "last_observed": "2020-01-01T08:24:24.811Z",
            "number_observed": 1,
            "object_refs": [
                "x-dogesec-demo--52107335-d213-49da-b739-d865001c2007",
                "url--cc6ef2fe-d31f-510e-9809-bf0f6478e749"
            ],
            "spec_version": "2.1"
        },
        {
            "type": "x-dogesec-demo",
            "src_ip": "1.1.1.1",
            "id": "x-dogesec-demo--52107335-d213-49da-b739-d865001c2007",
            "spec_version": "2.1",
            "dest_ip": "2.2.2.2"
        },
        {
            "type": "url",
            "value": "www.testaddress.com",
            "id": "url--cc6ef2fe-d31f-510e-9809-bf0f6478e749",
            "spec_version": "2.1"
        }
    ]
}
```

QRadar does use the `url` field name, so this is mapped correctly to a STIX URL Cyber Observable Object (note, this is different behaviour to the Splunk Connector which creates a URL and Domain Observable for this record).

However, for the unrecognised fields (`src_ip` and `dest_ip`) the QRadar Connector creates a custom STIX 2.1 Cyber Observable Object (`"type": "dogesec-demo"`), which contains the properties `"src_ip": "1.1.1.1"` and `"dest_ip": "2.2.2.2"` for these unrecognised fields. I'll cover custom STIX Objects in the next post.

The point being here; be careful with field mappings, because if the Connector does not support the fields in the log, the results from STIX-Shifter can be unexpected. This is the age old problem of SIEMs -- normalising fields between logs being ingested and normalising fields across SIEMs.

## Some real-life STIX patterns

We use STIX patterns in two of our products that will aid your learning:

* [txt2stix](https://github.com/muchdogesec/txt2stix): creates simple STIX patterns that represented observables extracted from threat reports (a simple example to learn from)
* [cve2stix](https://github.com/muchdogesec/cve2stix): creates much more advanced STIX patterns to represent what CPEs are vulnerable to a CVE using NVD data (more complex, but a good example of what's possible)
    * [I've also covered this in a blog post here](/blog/understanding_nvd_cve_cpe_api_responses)