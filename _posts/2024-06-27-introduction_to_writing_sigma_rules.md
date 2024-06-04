---
date: 2024-06-27
last_modified: 2024-06-27
title: "An Introduction to Writing Sigma Rules"
description: "Sigma Rules are becoming more widely adopted. You should probably learn how to write them. Let me show you."
categories:
  - TUTORIAL
  - PRODUCTS
tags: [
    STIX,
    Sigma Rules
]
products:
    - sigma2stix
    - CTI Butler
author_staff_member: david-greenwood
image: /assets/images/blog/2024-06-27/header.jpeg
featured_image: /assets/images/blog/2024-06-27/header.jpeg
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

Learn how to write Sigma Rules. Learn how to upload and share Sigma Rules (using tools that support STIX).

## Overview

I would be willing to bet that for every hundred readers of this post, there will be more than 10 SIEM or XDR tools being used among you.

This is problematic because it adds a large amount of friction to the sharing detection content.

What is needed is a detection rule standard. A way to write a query once and use it everywhere, on any system.

That is the ambitious aim of the Sigma project.

Sigma has been around for about three years. Though in the last year it has seen a marked increase in adoption.

> Sigma is for log files what Snort is for network traffic and YARA is for files.

- [Sigma Github Repo](https://github.com/SigmaHQ/sigma)

The Sigma Rule format has been designed to accommodate for conversion into other query languages to match the systems on which they will be used. For example, a Sigma Rule could be translated into Splunk's query language, SPL, or Google Chronicle's YARA-L 2.0 queries.

Before jumping into the detail, let me first explain the foundations of Sigma Rules.

## The YAML Structure

Sigma Rules are structured in a YAML format.

[The Sigma Rule specification documents and describes the available attributes and the values they support](https://github.com/SigmaHQ/sigma-specification).

As I go through this tutorial, I recommend having some example rules open to cross-reference this theory to real world implementations.

[The Sigma project maintains a body of public rules in the core Sigma repository here](https://github.com/SigmaHQ/sigma/tree/master/rules).

When writing Sigma Rules, I find it helpful to think of them as five core sections:

1. Metadata
  * General info: Descriptive information about the rule
  * Versioning: How to handle and track changes to the rule
  * Tags: how to add further classification to the rule
2. Log sources: describes the log data on which the detection is meant to be applied to
3. Detection: the logic to identify something in the log

The log information (4) and detections (5) are the most important part, and what I'll focus on in this tutorial.

## 1. Metadata

### 1.1 General info

The main purpose of these properties is to help manage and maintain rules. I won't explain the obvious ones here and will instead link to the official specification. My advice would be to take a look at some existing Sigma Rules to see some example values used for these properties;

* [`id`](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#rule-identification) (required)
* [`title`](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md) (required)
* [`status`](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#status-optional) (optional)
* [`description`](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#description-optional) (optional)
* [`author`](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#author-optional) (optional)
* [`license`](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#license-optional) (optional)
* [`references`](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#references-optional) (optional)
* [`level`](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#level) (optional)

Here's a example of a partial Sigma rule incorporation ONLY the properties above;

```yaml
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
title: Test rule
status: experimental
description: Just a demo for the blog
author: Someone
license: MIT
references:
    - https://www.example.com
level: high
```

### 1.2 Versioning

I showed that `id` is a required property for a Sigma Rule.

Sigma rules should be identified by a globally unique identifier using this `id` attribute. For this purpose randomly generated UUIDs (version 4) are recommended but not mandatory.

To help version Sigma Rules when rules are updated the `date` (the date the rule was created) and `modified` (the date it was last modified) values can be used in the format `YYYY/MM/DD`.

For example;

```yaml
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
title: Test rule
date: 2020/01/01
modified: 2022/01/01
```

Rule `id`s can change for the following reasons:

* Major version changes of the rule. E.g. a different rule logic.
* Derivation of a new rule from an existing or refinement of a rule in a way that both are kept active.
* Merge of rules

To being able to keep track on relationships between detections, Sigma rules may also contain references to related rule `id`s along with the description of the relationships. For example


```yaml
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
related:
  - id: 08fbc97d-0a2f-491c-ae21-8ffcfd3174e9
  type: derived
  - id: 929a690e-bef0-4204-a928-ef5e620d6fcc
  type: obsoletes
```

Here the current rule (`929a690e-bef0-4204-a928-ef5e620d6fcc`) is derived from another rule (`08fbc97d-0a2f-491c-ae21-8ffcfd3174e9`) and replaced (obsoletes) a rule (`929a690e-bef0-4204-a928-ef5e620d6fcc`).

This can also be used to link rules. For example, you might link two rules that have some other relationship, in which case you just use a different `related.id` property.

That said, it's probably better to use [Rule Collections](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#rule-collections) for this purpose.

### 1.3 Tags 

A Sigma rule can be categorised with tags. Tags can be anything, but [Sigma ships with some predefined tags](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#tags) which I'd recommend you use where possible (or sending a pull request / creating an issue to the Sigma repo with proposals for new tags).

A tag ultimately provides more contextual information about the rule.

Tags are namespaced, (a `.` is used as separator, e.g. `attack.t1059.001`, here `attack` is the namespace).

The three predefined Sigma tags have the following namespaces;

* `attack.`: [MITRE ATT&CK](https://github.com/SigmaHQ/sigma-specification/blob/main/Tags_specification.md#namespace-attack)
* `car.`: [MITRE Cyber Analytics Repository](https://github.com/SigmaHQ/sigma-specification/blob/main/Tags_specification.md#namespace-car)
* `tlp.` [Traffic Light Protocol](https://github.com/SigmaHQ/sigma-specification/blob/main/Tags_specification.md#namespace-cve)
* `cve.` [NVD CVEs](https://www.first.org/tlp/)
* `detection.` [Indicates the type of rule](https://github.com/SigmaHQ/sigma-specification/blob/main/Tags_specification.md#namespace-detection)

Example;

```yaml
tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001
  - car.2016-04-005
  - tlp.amber
```

Of course, you can use any tag you with, e.g. 

```yaml
tags:
  - david.tag
```

Though, categorising on the standard tags will allow for easier discoverability of related rules.

## 2. Log sources

The `logsource` attribute describes the log data on which the detection is meant to be applied to and has a number of sub-attributes to allow it to be very specific;

* `category`:
    * used to select all log files written by a certain group of products, like firewalls or web server logs. 
        * e.g. `firewall`, `web`, `antivirus`
* `product`:
    * used to select all log outputs of a certain product, e.g. all Windows Eventlog types including "Security", "System", "Application" and the new log types like "AppLocker" and "Windows Defender".
        * e.g. `windows`, `apache`
* `service`:
    * used to select only a subset of a product's logs, like the "sshd" on Linux or the "Security" Eventlog on Windows systems.
        * e.g. `sshd`, `applocker`
* `definition`
    * used to describe the logsource, including some information on the log verbosity level or configurations that have to be applied.
        * e.g. `INFO`, `DEBUG`

[Read the Log Source specification here](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#log-source).

[A list of standard logsources can be viewed here](https://sigmahq.io/docs/basics/log-sources.html#available-logsources).

You'll see these in most of the public rules in the SigmaHQ repository. For example;

```yaml
logsource:
  product: aws
  service: cloudtrail
```

Sigma compiles the `logsource` sub-attributes using `AND` statements, so for the last example I am saying the `logsource` must be; `product:aws` AND `service: cloudtrail`.

You can also only pass one `logsource` attribute per rule, and thus by definition Sigma Rules are specific to `logsource`s.

You may also see a definition field within logsource description. This can also provide more information about how to onboard the log data source correctly so it can be detected by the Sigma Rule.

For example;

```yaml
logsource: 
  product: windows
  category: ps_script
  definition: Script Block Logging must be enabled
```
Above, the author is noting that unless Script Block Logging is enabled in Windows Powershell scripts, the rule won't work properly. The `definition` property is purely informational.

Generally, you'll want to use a pre-existing logsource. Of course, if a log source does not exist for your log type, most likely when custom products, logs, or field naming is used, then you can specify a non-standard logsource using the logic defined.

Sigma does not restrict what a Sigma logsource can be defined as, meaning you can use Sigma for just about any kind of logsource within your SIEM.

With the use of [Pipelines](https://sigmahq.io/docs/digging-deeper/pipelines.html), you can specify granular field-mapping, and logsource-mapping to ensure that your Sigma rules get converted correctly to the intended SIEM format downstream.

In short, this means fields in the detection part of the Sigma Rule map to those used in the SIEM.

For now, park that thought though. I will revisit pipelines once we've covered detections. The takeaway here should be; you should first refer to [the standard `logsource`s](https://sigmahq.io/docs/basics/log-sources.html#standard-logsources), and use these where possible.

A shortcut [is also to take a look at existing Sigma Rules](https://github.com/SigmaHQ/sigma/tree/master/rules) to see if a rule exists with a logsource you're using.

## 3. Detections

Inside a Sigma Rules, the `detection` attribute is where the actual logic for when the rule will be triggered.

[Here is the detection specification defined by Sigma](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#detection)... it's long and fairly complex, I'll try and simplify here as best I can.

The `detection` section contains a set of sub-attributes that represent searches on log data and how they should be evaluated:

* Selections: What you actually wish to select/search from the log data
* Conditions: How should the Selections or filters are to be evaluated

Let me show you how these work using a few examples.

### Selections

Each Sigma detection is categorised and split up into groups called selections. Each selection contains the definition for the detection itself.

At the most basic lists are the simplest way to define a Search Identifier. They contain strings that are applied to the full log message and are linked with a logical `OR` statement.

```yaml
logsource:
  product: windows
  service: system
detection:
  keywords:
    - 4728
    - 4729
    - 4730
  condition: keywords
```

In this example, `keywords` matches on `4728` `OR` `4729` `OR` `4730`.

The naming of the field `keywords` under the detection and selection fields in this example is arbitrary. 

For example, this detection would work in the same way

```yaml
logsource:
  product: windows
  service: system
detection:
  selection:
    - 4728
    - 4729
    - 4730
  condition: selection
```
However, you should use a standard for the value when creating your own Sigma rules. In other words, make the selection names descriptive and obvious to the reader.

The rule above is simple, it will simply search for either of the two strings in Windows logs in any field used by the SIEM. This is, of course, very inefficient.

That's where we can search by field list. For example, lets narrow the last rule down to only search for the specified values in a field called `EventID`...

```yaml
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID:
      - 4728
      - 4729
      - 4730
  condition: selection
```

For example, now only the EventID field in downstream tools will be searched for the values `4728` `OR` `4729` `OR` `4730`.

You can also use key value selections to search for single fields. For example,

```yaml
logsource:
  product: windows
  service: system
detection: 
    selection:
        EventID: 6416
    condition: selection
```

You can also pass multiple fields to be joined with an `AND` statement;

```yaml
logsource:
  product: windows
  service: system
detection: 
    selection:
        EventID: 6416
        ClassName: DiskDrive
    condition: selection
```

In this example I am matching on any events where the `EventID=6416 ` `AND` the `ClassName=DiskDrive`. I could add more field/values to filter on, if needed.

You can also combine these concepts together.

```yaml
logsource:
  product: windows
  service: system
detection:
  selection:
    EventLog: Security
    EventID:
      - 517
      - 1102
condition: selection
```

Here the selection matches on `Eventlog=Security` `AND` ( `EventID=517` `OR` `EventID=1102`).

You should be aware there are [special field values](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#special-field-values) that can be used for values.

* An empty value is defined with `''`
* A non-existent value is defined with `null`

To demonstrate...

```yaml
logsource:
  product: windows
  service: system
detection:
  selection:
    EventLog: Security
    EventID:
      - ''
condition: selection
```

Would mean `EventID` field should be present, but have no value.

```yaml
logsource:
  product: windows
  service: system
detection:
  selection:
    EventLog: Security
    EventID:
      - null
condition: selection
```

Would mean the `EventID` should not be present.

You can also use wildcards in the value string. For example using `*` to replace an unbounded length wildcard;

```yaml
logsource:
  product: windows
  service: system
detection:
  selection:
    EventLog: Security
    EventID: 5*
condition: selection
```

Would match on any EventID starting with `5` (e.g. `500`, `5121`, etc.)

`?` is used to replace a single mandatory character, for example;

```yaml
logsource:
  product: windows
  service: system
detection:
  selection:
    FileName: prog?.exe
condition: selection
```

Would match on any FileName where the `?` had a value (e.g. `prog1.exe`, `prog2.exe`, `proga.exe`)


The backslash character `\` is used for escaping of wildcards `*` and `?` as well as the backslash character itself. Escaping of the backslash is necessary if it is followed by a wildcard depending on the desired result.

For example, if you wanted to match on a value `?` or `*`, you'd need to use a `\` to show that it should not be used as a wildcard,

```yaml
logsource:
  product: windows
  service: system
detection:
  keywords:
    - question\?
    - star\*
condition: selection
```

Would match on the literal values `question? or star*`.

Similarly, if a backslash is to be matched on (e.g. a Windows path) it also needs to be escaped.

```yaml
logsource:
  product: windows
  service: system
detection:
  selection:
    FilePath: \\example.exe
condition: selection
```

Would match on the value `\example.exe`.

I won't cover all escapes here, [you can read more about them here](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#escaping). 

So far I've only covered one selection in a rule. In fact, a Sigma Rule detection can have many selections. [That's where conditions come into play](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#condition).

For example;

```yaml
detection:
  selection_1:
    CommandLine:
      - DumpCreds
      - invoke-mimikatz
  selection_2:
    CommandLine:
      - rpc
      - token
      - crypto
  selection_3:
    CommandLine:
      - bitcoin
  condition: selection_1 OR selection_2 OR selection_3
```

Here I use three selection. The `condition` property defines the combinations of selections that should trigger a detection.

In this case, if one of the three Search Identifiers (`selection_1 OR selection_2 OR selection_3`) is true, then a detection should be triggered.

### Conditions

Conditions can be defined using a variety of Operators, all of which I will cover in the next tutorial.

[There are a range of `condition`s that can be defined for `detection`](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#condition).

There are currently eight operators that can prove useful in tuning the extensibility and accuracy a rule by describing how the selections should be considered. We've already covered two...

1. Exact match
  * e.g. `selection_1`
2. Logical AND/OR
  * e.g. `selection_1 OR selection_2`
  * e.g. `selection_1 AND selection_2`

#### x/all of them

Before I showed the example `condition: selection_1 OR selection_2 OR selection_3`. 

This could actually be mapped in a simpler way...

```yaml
detection:
  selection_1:
    CommandLine:
      - DumpCreds
      - invoke-mimikatz
  selection_2:
    CommandLine:
      - rpc
      - token
      - crypto
  selection_3:
    CommandLine:
      - bitcoin
  condition: 1 of them
```

To denote at least 1 of the selections should be true (`selection_1 OR selection_2 OR selection_3`).

You can ensure more than selection matches in the format `x of them`, e.g. `2 of them`, `3 of them`, etc.

#### x/all of selection

Instead of `all of them` or `them` you can be more granular and use specific selections.

This condition type type can be very useful in overriding the default behaviour of a Lists (where items are considered with `OR` operators). For example,

```yaml
detection:
  selection_1:
  - EVILSERVICE
  - svchost.exe -n evil
  selection_2:
  - token
  - rpc
  - crypto
condition: 2 of selection_1 and selection_2
```

Here both values (2) for `search_identifier_1` must be true and 1 value from search_identifier_2 must be true. Here the `condition` is overriding the default list behaviour for `search_identifier_1`.

`*` wildcards (i.e. any number of characters) at arbitrary positions in the condition pattern can also be used. For example;

```yaml
logsource:
  product: windows
  service: system
detection:
  selection_1:
    EventLog: Security
    EventID:
      - 517
      - 1102
  selection_2:
      EventID: 6416
      ClassName: DiskDrive
  keywords_filter:
    - error
    - failure
  condition: 1 of selection* and not keywords_*
```

Here either `selection_1 OR selection_2` must be true, however these events must not contain `error OR failure` (keywords_filter).

#### Negation with `not`

Conditions can be especially useful for filtering use-cases which is where the `not` operator comes in handy. Take this example;

```yaml
detection:
  search_identifier_1:
     EventID: 4738
  search_identifier_2:
     PasswordLastSet: null
  condition: search_identifier_1 and not search_identifier_2
```
Here I am using the `and not` condition to say the log line must contain `EventID` EQUALS `4738` but not `PasswordLastSet` EQUALS `null`.

#### Using Parenthesis

Parenthesis can be used to add more complex logic to the expression. The part of the condition in parenthesis will be considered first. For example;

As `condition`s need to become more complex, using brackets (parenthesis) can offer additional options to the other Condition options specified.

```yaml
detection:
  keywords_1:
    - DumpCreds
    - invoke-mimikatz
  keywords_2:
    - rpc
    - token
    - crypto
  keywords_3:
     - bitcoin
  condition: (keywords_1 and keywords_2) or (keywords_2 and keywords_3)
```

In this example, if any value from `keywords_1 and keywords_2` OR `keywords_2 and keywords_3` being seen in the same log line will trigger a detection.

Bracket are considered with the highest order of operation by downstream Sigma tooling.

## Dealing with false positive detections

Once you deploy a rule to one of your security tools analysts will also start to discover some incorrect detections.

You can try to avoid false positive detections by tuning the rule to ignore known erroneous triggers, for example...

```yaml
detection:
  selection:
    - 'rm /var/log/syslog'
    - 'rm -r /var/log/syslog'
    - 'rm -f /var/log/syslog'
    - 'rm -rf /var/log/syslog'
    - 'mv /var/log/syslog'
    - ' >/var/log/syslog'
    - ' > /var/log/syslog'
  false_positives:
    - '/syslog.'
  condition: selection and not false_positives
```

However, it's not always possible to account for all reasons false positives occur. This is where the informational [`falsepositive` field](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#falsepositives) can be used to describe a list of known false positives which can occur from a detection.

```yaml
falsepositives:
  - PIM (Privileged Identity Management) generates this event each time 'eligible role' is enabled.
  - Legitimate administration activities
```

When the rule is triggered, the `falsepositives` information inside the rule can help an analyst triaging alerts as to how they proceed (or if they follow up on it at all).

## Dealing with detections

When a rule is deployed, it is only a matter of time before it triggers a detection. When that happens, the analyst handling the detection event might want to start a deeper investigation.

The [`fields` attribute](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#fields) inside a Sigma Rule can help an analyst decide the next steps by defining a log fields that could be interesting in further analysis of the event.

```yaml
fields:
  - CommandLine
  - ParentCommandLine
```

## Value modifiers

1. Transformation Modifier: transform values into different values. Furthermore, this type of modifier is also able to change the logical operation between values. 
2. Type Modifier: change the type of a value. The value itself might also be changed by such a modifier, but the main purpose is to tell the backend that a value should be handled differently by the backend (e.g. it should be treated as regular expression when the re modifier is used). More on backends in a later tutorial.

## Transformation Modifiers

[A full list of Transformation Modifiers are available to view here](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#transformations).

Lets examine them one-by-one.

### contains

`contains` which puts `*` wildcards around the values, such that the value is matched anywhere in the field. Here is an example;

```yaml
detection:
  selection:
    CommandLine|contains:
      - DumpCreds
      - invoke-mimikatz
  condition: selection
```

This is the same as using:

```yaml
detection:
  selection:
    CommandLine:
      - *DumpCreds*
      - *invoke-mimikatz*
  condition: selection
```

It's also important to point out how modifiers are written -- they are appended after the field name with a `|` character.

In the first example, the selection matches the `CommandLine` field in the log data and uses the Transformation Modifier `contains` in order to check if the keywords `DumpCreds` OR `invoke-mimikatz` are present in the field.

For example this detection would match on `CommandLine="Has detected DumpCreds"` OR `CommandLine="DumpCreds"` OR `CommandLine="now invoke-mimikatz"`

If I did not use the `contains` Value Modifier like so;

```yaml
detection:
  selection:
    CommandLine:
      - DumpCreds
      - invoke-mimikatz
  condition: selection
```

Now only an exact match for the `CommandLine` field would match. This would be either `CommandLine="DumpCreds"` OR `CommandLine="invoke-mimikatz"`. `CommandLine="Has detected DumpCreds"` would not match.

### startswith / ends with

You might want to use a more specific Transformation Modifier, like `startswith` OR `endswith`.

```yaml
detection:
  selection:
    CommandLine|startswith:
      - DumpCreds
      - invoke-mimikatz
  condition: selection
```

Here the `CommandLine` field in the log line must start with either `DumpCreds` or `invoke-mimikatz`.

### all

The `all` Transformation Modifier can also prove very useful on occasion. As noted, Lists of values are treated by default using the logical `OR` statement. This modifier changes this to `AND`.

```yaml
detection:
  selection:
    CommandLine|all:
      - DumpCreds
      - invoke-mimikatz
  condition: selection
```

In this example, I am now saying the `CommandLine` field in the log line must have both `DumpCreds` AND `invoke-mimikatz` in its value.

### windash

Will replace all `-` occurrences with `/`

```yaml
detection:
  selection:
    CommandLine|windash|contains:
      - '-s '
      - '-f '
      - '-t '
      - '-m '
      - '-a '
      - '-u '
```

Here `-s ` would be searched as `/s ` in the log. The same is true for other items in the list.

As you can see above, Modifiers can also be chained using a `|`, (e.g. `fieldname|mod1|mod2:`). The value modifiers are applied in the given order to the value.

This example logically reads the `CommandLine` field should be searched for one of the list items after the dash is replaced with a forward slash, and the search should consider that the field contains the converted value.

### base64

The `base64` denotes the value will be base64 encoded in the log.

```yaml
detection:
  selection_destination:
    Destination|base64:
      - 'WriteProcessMemory'
      - 'This program cannot be run in DOS mode'
      - 'This program must be run under Win32'
  condition: selection_destination
```

Is essentially looking for either;

* `WriteProcessMemory` that will be `V3JpdGVQcm9jZXNzTWVtb3J5` in the log OR,
* `This program cannot be run in DOS mode` that will be `VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGU` in the log OR,
* `This program must be run under Win32` that will be `VGhpcyBwcm9ncmFtIG11c3QgYmUgcnVuIHVuZGVyIFdpbjMy` in the log

### base64offset

If a value might appear somewhere in a base64-encoded value the representation might change depending on the position in the overall value. There are three variants for shifts by zero to two bytes and except the first and last byte the encoded values have a static part in the middle that can be recognized.

```yaml
detection:
  selection_destination:
    Destination|base64offset|contains:
      - 'WriteProcessMemory'
      - 'This program cannot be run in DOS mode'
      - 'This program must be run under Win32'
  condition: selection_destination
```

### Type Modifiers

Sometimes Transformation Modifiers do not quite suit what you are trying to achieve, particularly with more complex/varying values that need to be detected.

Currently only one type of Type Modifier exists for Regular Expressions (`re`). Here is an example of it being used;

```yaml
detection:
  search_identifier_1:
    - CommandLine|re: '\$PSHome\[\s*\d{1,3}\s*\]\s*\+\s*\$PSHome\['
    - CommandLine|re: '\$ShellId\[\s*\d{1,3}\s*\]\s*\+\s*\$ShellId\['
    - CommandLine|re: '\$env:Public\[\s*\d{1,3}\s*\]\s*\+\s*\$env:Public\['
  condition: search_identifier_1
```

Here the log line `CommandLine` field values must match at least one of the Regular Expressions defined.

You might be tempted to use the Regular Expressions Type Modifier a lot, though avoid it where possible (as it can create downstream conversion issues) this is because in many cases a Transformation Modifier is better supported during rule conversion.

## Sharing your Sigma Rules

Sigma Rules are becoming more widely understood by many tools in their raw YAML format.

However, in the world of cyber threat intelligence, many tools use STIX as their underlying data model, us included.

As such, we needed a way to convert Sigma Rules into STIX objects. [I touched on that a bit in a previous post](/blog/constructing_stix_indicator_patterns/), but want to go a bit deeper this time around.

We have built a tool, [sigma2stix](https://github.com/muchdogesec/sigma2stix/) (mentioned briefly earlier in this post), that will take a Sigma Rule and convert it into a STIX Indicator object.

First, install sigma2stix:

```shell
git clone https://github.com/muchdogesec/sigma2stix
cd sigma2stix
python3 -m venv sigma2stix-venv
source sigma2stix-venv/bin/activate
pip3 install -r requirements.txt
```

As an example using [this Sigma Rule](https://raw.githubusercontent.com/muchdogesec/sigma2stix/main/tests/demo_rule.yml?token=GHSAT0AAAAAACRYETUGHGA2INQRL57VDWC4ZSV7LEQ), I can create a STIX 2.1 Indicator as follows;

```shell
python3 sigma2stix.py \
  --mode sigmayaml \
  --file tests/demo_rule.yml
```

```json
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--c921081d-3ea0-5ec6-88fa-1d7a46e083b5",
    "created_by_ref": "identity--860f4c0f-8c26-5889-b39d-ce94368bc416",
    "created": "2023-10-20T00:00:00.000Z",
    "modified": "2023-10-20T00:00:00.000Z",
    "name": "Exploitation Indicators Of CVE-2023-20198",
    "description": "Detecting exploitation indicators of CVE-2023-20198 a privilege escalation vulnerability in Cisco IOS XE Software Web UI.. The following false positives can result from this detection; Rare false positives might occur if there are valid users named \"cisco_tac_admin\" or \"cisco_support\", which are not created by default or CISCO representatives",
    "indicator_types": [
        "malicious-activity",
        "anomalous-activity"
    ],
    "pattern": "{'title': 'Exploitation Indicators Of CVE-2023-20198', 'id': '2ece8816-b7a0-4d9b-b0e8-ae7ad18bc02b', 'status': 'experimental', 'description': 'Detecting exploitation indicators of CVE-2023-20198 a privilege escalation vulnerability in Cisco IOS XE Software Web UI.', 'references': ['https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z', 'https://www.thestack.technology/security-experts-call-for-incident-response-exercises-after-mass-cisco-device-exploitation/'], 'author': 'Lars B. P. Frydenskov (Trifork Security)', 'date': '2023/10/20', 'tags': ['attack.privilege_escalation', 'attack.initial_access', 'attack.t1114', 'detection.emerging_threats', 'cve.2023.20198'], 'logsource': {'product': 'cisco', 'service': 'syslog', 'definition': 'Requirements: Cisco IOS XE system logs needs to be configured and ingested'}, 'detection': {'keyword_event': ['%WEBUI-6-INSTALL_OPERATION_INFO:', '%SYS-5-CONFIG_P:', '%SEC_LOGIN-5-WEBLOGIN_SUCCESS:'], 'keyword_user': ['cisco_tac_admin', 'cisco_support', 'cisco_sys_manager'], 'condition': 'keyword_event and keyword_user'}, 'falsepositives': ['Rare false positives might occur if there are valid users named \"cisco_tac_admin\" or \"cisco_support\", which are not created by default or CISCO representatives'], 'level': 'high'}",
    "pattern_type": "sigma",
    "valid_from": "2023-10-20T00:00:00Z",
    "external_references": [
        {
            "source_name": "sigma-rule",
            "url": "file:///sigma2stix/tests/demo_rule.yml",
            "external_id": "rule"
        },
        {
            "source_name": "sigma-rule",
            "description": "2ece8816-b7a0-4d9b-b0e8-ae7ad18bc02b",
            "external_id": "id"
        },
        {
            "source_name": "sigma-rule",
            "description": "high",
            "external_id": "level"
        },
        {
            "source_name": "sigma-rule",
            "description": "experimental",
            "external_id": "status"
        },
        {
            "source_name": "sigma-rule",
            "description": "Lars B. P. Frydenskov (Trifork Security)",
            "external_id": "author"
        },
        {
            "source_name": "ATTACK",
            "description": "tactic",
            "external_id": "privilege_escalation"
        },
        {
            "source_name": "ATTACK",
            "description": "tactic",
            "external_id": "initial_access"
        },
        {
            "source_name": "mitre-attack",
            "url": "https://attack.mitre.org/techniques/T1114",
            "external_id": "T1114"
        },
        {
            "source_name": "sigma-rule",
            "description": "emerging_threats",
            "external_id": "detection"
        },
        {
            "source_name": "cve",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-20198",
            "external_id": "CVE-2023-20198"
        },
        {
            "source_name": "sigma-rule",
            "description": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z",
            "external_id": "reference"
        },
        {
            "source_name": "sigma-rule",
            "description": "https://www.thestack.technology/security-experts-call-for-incident-response-exercises-after-mass-cisco-device-exploitation/",
            "external_id": "reference"
        }
    ],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--860f4c0f-8c26-5889-b39d-ce94368bc416"
    ]
}
```

This Indicator can now be uploaded to my threat intelligence platform (or wherever your intel team uses to manage detection content).

## Explore Sigma Rules as STIX

If you want to start exploring ATT&CK data in even more detail, including how it references other knowledge-bases, check out [CTI Butler](https://www.ctibutler.com/).

Here's a few queries to get started...

### Return all rules

```sql
FOR doc IN sigma_rules_vertex_collection
  AND doc._stix2arango_note == "r2024-05-13"
  RETURN [doc]
```

Currently 3267 rules.

### Filter all rules with a high level

```sql
FOR doc IN sigma_rules_vertex_collection
  FILTER doc.external_references != null 
    AND LENGTH(doc.external_references) > 0
    AND doc._stix2arango_note == "r2024-05-13"
  FILTER LENGTH(
    FOR ref IN doc.external_references
      FILTER ref.source_name == "sigma-rule"
        AND ref.description == "high"
        AND ref.external_id == "level"
      RETURN ref
  ) > 0
  RETURN [doc]
```

Currently 1396 rules.

### Filter all rules with a reference to MITRE ATT&CKs Credential Access Tactic

```sql
FOR doc IN sigma_rules_vertex_collection
  FILTER doc.external_references != null 
    AND LENGTH(doc.external_references) > 0
    AND doc._stix2arango_note == "r2024-05-13"
  FILTER LENGTH(
    FOR ref IN doc.external_references
      FILTER ref.source_name == "ATTACK"
        AND ref.description == "tactic"
        AND ref.external_id == "credential_access"
      RETURN ref
  ) > 0
  RETURN [doc]
```

Currently 279 rules.

### Filter all rules with a reference to a CVE

```sql
FOR doc IN sigma_rules_vertex_collection
  FILTER doc.external_references != null 
    AND LENGTH(doc.external_references) > 0
    AND doc._stix2arango_note == "r2024-05-13"
  FILTER LENGTH(
    FOR ref IN doc.external_references
      FILTER ref.source_name == "cve"
      RETURN ref
  ) > 0
  RETURN [doc]
```

Currently 82 rules.