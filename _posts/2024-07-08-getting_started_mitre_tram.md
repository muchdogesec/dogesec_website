---
date: 2024-07-08
last_modified: 2024-07-08
title: "Getting Started with MITRE TRAM"
description: "MITRE TRAM automatically extracts ATT&CK Techniques being discussed in reports."
categories:
  - TUTORIAL
  - PRODUCTS
tags: [
    MITRE,
    ATT&CK,
    STIX,
    TRAM
]
products:
    - arango_cti_processor
    - CTI Butler
    - txt2stix
    - Obstracts
    - Stixify
author_staff_member: david-greenwood
image: /assets/images/blog/2024-07-08/header.png
featured_image: /assets/images/blog/2024-07-08/header.png
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

Take threat report. Upload threat report. Automatically identify ATT&CK Techniques.

## Background

A significant amount of intelligence available today is still shared through blogs, advisories and research articles, which requires further processing to make it machine readable (and usable by SIEM and SOAR tools). It's why we built [Obstracts](https://www.obstracts.com/) and [Stixify](https://www.stixify.com/).

Manually annotating threat reports with MITRE ATT&CK like this is useful, but very tedious.

Natural language processing (NLP) refers to the branch of computer science—and more specifically, the branch of artificial intelligence or AI—concerned with giving computers the ability to understand text and spoken words in much the same way human beings can.

MITRE's Threat Report ATT&CK Mapping (TRAM) uses Natural Language Processing (NLP) to map Threat Reports to MITRE ATT&CK Techniques.

## TRAM

Here is a nice overview of the ATT&CK Navigator presented by MITRE:

<iframe width="560" height="315" src="https://www.youtube.com/embed/bGN3jak_6bE?si=hWZ-_vn7PCqXI40t" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

TRAM has been around since 2020, well before AI hit the consumer mainstream, and has seen continued updates over the intervening years.

Lets take a look at it...

### Install TRAM

[The documentation for TRAM is here](https://github.com/center-for-threat-informed-defense/tram/blob/main/README.md). You will need Docker installed to run it using the following commands;

```shell
git clone https://github.com/center-for-threat-informed-defense/tram/
cd tram/docker
docker-compose up
```

Now open up a browser and navigate to `http://localhost:8000/`.

[If you are using the default `docker-compose.yml`](https://github.com/center-for-threat-informed-defense/tram/blob/main/docker/docker-compose.yml#L16) the default username and password values can be found in the variables `DJANGO_SUPERUSER_USERNAME` and `DJANGO_SUPERUSER_PASSWORD` (which are user: `djangoSuperuser`, password: `LEGITPassword1234`).

### TRAM Workflow

The general TRAM workflow is;

1. A Threat Report is added to the job processing queue
2. TRAM breaks the Threat Report into Sentences
3. The AI/ML model proposes ATT&CK Techniques on a per-sentence basis
4. Someone (e.g. an analyst) edits and confirms the mappings
5. (Optional) The mappings can be exported to support other workflows
6. (Optional) The AI/ML model can be retrained on confirmed mappings

<img class="img-fluid" src="/assets/images/blog/2024-07-08/tram-report-list.png" alt="TRAM Report List" title="TRAM Report List" />

On first install you will see some training data listed (Bootstrap Training Data). I will go ahead and upload my own report.

To upload via the UI, simply click the "Upload Report" button in the navigation bar.

For this demo I will use the following report from FireEye; [APT39: An Iranian Cyber Espionage Group Focused on Personal Information](https://www.mandiant.com/resources/apt39-iranian-cyber-espionage-group-focused-on-personal-information).

[MITRE have created a .pdf copy I can use](https://attack.mitre.org/docs/training-cti/FireEye%20APT39%20-%20original%20report.pdf).

**Pro-tip**: Many of you will want to use TRAM with web content. To to do this, I export the page a .pdf and using that with TRAM instead (in Chrome; `Print` > `Destination = Save as PDF`).

Once TRAM has finished processing the report and comparing the sentences extracted against the default model, its status will change from "Queued" to "Reviewing".

<img class="img-fluid" src="/assets/images/blog/2024-07-08/tram-analyse-report.png" alt="TRAM analyse report" title="TRAM analyse report" />

You can see TRAM has extracted a total of 32 ATT&CK Techniques for review. I can review them by clicking "Analyze".

<img class="img-fluid" src="/assets/images/blog/2024-07-08/tram-review-report.png" alt="TRAM review report" title="TRAM review report" />

You can now see each sentence extracted on the left hand side. Where a number is shown in the left column, it indicates TRAM has detected that number of Techniques for the sentence (might be more than one).

Clicking a sentence where a Technique has been extracted shows the Technique(s) identified and the confidence score of the extraction.

I can now review the accuracy manually with one of three outcomes;

1. I agree with the extraction and want to assign the Technique(s) to the sentence by clicking "Accepted". You will see the row turn green.
2. I disagree with the extraction and want to remove it by clicking the red no entry button. It will remove the Technique.
3. I want to add an additional Technique to the sentence by clicking the green "Add Mapping" button and selecting the Object I want to add. The TRAM model support Technique mappings by default, however, this manual option also allows you to link any ATT&CK Object (Groups, Software, etc.) to the sentence. In the screenshot below, I am adding the Group G0087 to a sentence.

<img class="img-fluid" src="/assets/images/blog/2024-07-08/tram-add-mapping.png" alt="TRAM add mapping" title="TRAM add mapping" />

Once all the mappings have been reviewed and accepted you can close the report.

<img class="img-fluid" src="/assets/images/blog/2024-07-08/tram-new-mapping.png" alt="TRAM new mapping" title="TRAM new mapping" />

Note, if you do not review and accept all sentences (some remain yellow), even ones with no mappings, the report will remain in "Reviewing" state.

<img class="img-fluid" src="/assets/images/blog/2024-07-08/tram-download-report.png" alt="TRAM download report" title="TRAM download report" />

You can now export the data in either `.docx` and `.json format`, using the "Export" button (not the "Download" button which simply exports the original upload).

The `.docx` structure is as follows;

<img class="img-fluid" src="/assets/images/blog/2024-07-08/tram-doc-output.png" alt="TRAM .doc output" title="TRAM .doc output" />

The `.json` structure is more verbose, as it includes the original text as well as the ATT&CK mappings. Each sentence and its mapping is represented like so;

```json
{
    "id": 5,
    "document_id": 4,
    "name": "Report for FireEye_APT39_-_original_report_3B3msoN.pdf",
    "byline": "djangoSuperuser on 2022-07-01 08:05:07 UTC",
    "accepted_sentences": 32,
    "reviewing_sentences": 0,
    "total_sentences": 32,
    "text": " \n \n \n \n \nAPT39: An Iranian Cyber \nEspionage Group Focused on \nPersonal Information \n \n \n \n \n \n \nJanuary 29, 2019\t\n\t\nSarah\tHawley,\tBen\tRead,\tCristiana\tBrafman-Kittner,\tNalani\tFraser,\tAndrew\t\nThompson,\tYuri\tRozhansky,\tSanaz\tYashar\t\n \n In December 2018, FireEye identified APT39 as an Iranian cyber espionage group \nresponsible for widespread theft of personal information. We have tracked activity linked to \nthis group since November 2014 in order to protect organizations from APT39 activity to \ndate. APT39’s focus on the widespread theft of personal information sets it apart from \nother Iranian groups FireEye tracks, which have been linked to influence\t\noperations, disruptive\tattacks, and other threats. APT39 likely focuses on personal \ninformation to support monitoring, tracking, or surveillance operations that serve Iran’s \nnational priorities, or potentially to create additional accesses and vectors to facilitate future \ncampaigns.  \n \nAPT39 was created to bring together previous activities and methods used by this actor, \nand its activities largely align with a group publicly referred to as \"Chafer.\" However, there \nare differences in what has been publicly reported due to the variances in how \norganizations track activity. APT39 primarily leverages the SEAWEED and \nCACHEMONEY backdoors along with a specific variant of the POWBAT backdoor. While \nAPT39's targeting scope is global, its activities are concentrated in the Middle East. APT39 \nhas prioritized the telecommunications sector, with additional targeting of the travel \nindustry and IT firms that support it and the high-tech industry. The countries and industries \ntargeted by APT39 are depicted in Figure 1. \n \n \nFigure\t1:\tCountries\tand\tindustries\ttargeted\tby\tAPT39 \n \n \n Operational Intent \nAPT39's focus on the telecommunications and travel industries suggests intent to perform \nmonitoring, tracking, or surveillance operations against specific individuals, collect \nproprietary or customer data for commercial or operational purposes that serve strategic \nrequirements related to national priorities, or create additional accesses and vectors to \nfacilitate future campaigns. Government entities targeting suggests a potential secondary \nintent to collect geopolitical data that may benefit nation-state decision making. Targeting \ndata supports the belief that APT39's key mission is to track or monitor targets of interest, \ncollect personal information, including travel itineraries, and gather customer data from \ntelecommunications firms. \nIran Nexus Indicators \nWe have moderate confidence APT39 operations are conducted in support of Iranian \nnational interests based on regional targeting patterns focused in the Middle East, \ninfrastructure, timing, and similarities to APT34, a group that loosely aligns with activity \npublicly reported as “OilRig”. While APT39 and APT34 share some similarities, including \nmalware distribution methods, POWBAT backdoor use, infrastructure nomenclature, and \ntargeting overlaps, we consider APT39 to be distinct from APT34 given its use of a \ndifferent POWBAT variant. It is possible that these groups work together or share \nresources at some level. \nAttack Lifecycle \nAPT39 uses a variety of custom and publicly available malware and tools at all stages of \nthe attack lifecycle. \nInitial\tCompromise \nFor initial compromise, FireEye Intelligence has observed APT39 leverage spear phishing \nemails with malicious attachments and/or hyperlinks typically resulting in a POWBAT \ninfection. APT39 frequently registers and leverages domains that masquerade as \nlegitimate web services and organizations that are relevant to the intended target.  \nFurthermore, this group has routinely identified and exploited vulnerable web servers of \ntargeted organizations to install web shells, such as ANTAK and ASPXSPY, and used \nstolen legitimate credentials to compromise externally facing Outlook Web Access (OWA) \nresources. \nEstablish\tFoothold,\tEscalate\tPrivileges,\tand\tInternal\tReconnaissance \nPost-compromise, APT39 leverages custom backdoors such as SEAWEED, \nCACHEMONEY, and a unique variant of POWBAT to establish a foothold in a target \nenvironment. During privilege escalation, freely available tools such as Mimikatz and \nNcrack have been observed, in addition to legitimate tools such as Windows Credential \nEditor and ProcDump. Internal reconnaissance has been performed using custom scripts \nand both freely available and custom tools such as the port scanner, BLUETORCH. \n\t\n\t\n\tLateral\tMovement,\tMaintain\tPresence,\tand\tComplete\tMission \nAPT39 facilitates lateral movement through myriad tools such as Remote Desktop Protocol \n(RDP), Secure Shell (SSH), PsExec, RemCom, and xCmdSvc. Custom tools such as \nREDTRIP, PINKTRIP, and BLUETRIP have also been used to create SOCKS5 proxies \nbetween infected hosts. In addition to using RDP for lateral movement, APT39 has used \nthis protocol to maintain persistence in a victim environment. To complete its mission, \nAPT39 typically archives stolen data with compression tools such as WinRAR or 7-Zip. \n \nFigure\t2:\tAPT39\tattack\tlifecycle \n \nThere are some indications that APT39 demonstrated a penchant for operational security \nto bypass detection efforts by network defenders, including the use of a modified version of \nMimikatz that was repacked to thwart anti-virus detection in one case, as well as another \ninstance when after gaining initial access APT39 performed credential harvesting outside \nof a compromised entity's environment to avoid detection. \nOutlook \nWe believe APT39's significant targeting of the telecommunications and travel industries \nreflects efforts to collect personal information on targets of interest and customer data for \nthe purposes of surveillance to facilitate future operations. Telecommunications firms are \nattractive targets given that they store large amounts of personal and customer \ninformation, provide access to critical infrastructure used for communications, and enable \naccess to a wide range of potential targets across multiple verticals. APT39's targeting not \nonly represents a threat to known targeted industries, but it extends to these organizations' \nclientele, which includes a wide variety of sectors and individuals on a global scale. \nAPT39's activity showcases Iran's potential global operational reach and how it uses cyber \noperations as a low-cost and effective tool to facilitate the collection of key data on \nperceived national security threats and gain advantages against regional and global rivals. ",
    "ml_model": "LogisticRegressionModel",
    "created_by": 2,
    "created_on": "2022-07-01T08:05:07.437104Z",
    "updated_on": "2022-07-01T08:05:07.437132Z",
    "status": "Accepted",
    "sentences": [
        {
            "id": 13568,
            "text": " \n \n \n \n \nAPT39: An Iranian Cyber \nEspionage Group Focused on \nPersonal Information \n \n \n \n \n \n \nJanuary 29, 2019\t\n\t\nSarah\tHawley,\tBen\tRead,\tCristiana\tBrafman-Kittner,\tNalani\tFraser,\tAndrew\t\nThompson,\tYuri\tRozhansky,\tSanaz\tYashar\t\n \n In December 2018, FireEye identified APT39 as an Iranian cyber espionage group \nresponsible for widespread theft of personal information.",
            "order": 0,
            "disposition": "accept",
            "mappings": [
                {
                    "id": 1785,
                    "attack_id": "G0087",
                    "name": "APT39",
                    "confidence": "100.0"
                }
            ]
        },
        {
            "id": 13569,
            "text": "We have tracked activity linked to \nthis group since November 2014 in order to protect organizations from APT39 activity to \ndate.",
            "order": 1,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13570,
            "text": "APT39’s focus on the widespread theft of personal information sets it apart from \nother Iranian groups FireEye tracks, which have been linked to influence\t\noperations, disruptive\tattacks, and other threats.",
            "order": 2,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13571,
            "text": "APT39 likely focuses on personal \ninformation to support monitoring, tracking, or surveillance operations that serve Iran’s \nnational priorities, or potentially to create additional accesses and vectors to facilitate future \ncampaigns.",
            "order": 3,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13572,
            "text": "APT39 was created to bring together previous activities and methods used by this actor, \nand its activities largely align with a group publicly referred to as \"Chafer.\"",
            "order": 4,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13573,
            "text": "However, there \nare differences in what has been publicly reported due to the variances in how \norganizations track activity.",
            "order": 5,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13574,
            "text": "APT39 primarily leverages the SEAWEED and \nCACHEMONEY backdoors along with a specific variant of the POWBAT backdoor.",
            "order": 6,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13575,
            "text": "While \nAPT39's targeting scope is global, its activities are concentrated in the Middle East.",
            "order": 7,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13576,
            "text": "APT39 \nhas prioritized the telecommunications sector, with additional targeting of the travel \nindustry and IT firms that support it and the high-tech industry.",
            "order": 8,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13577,
            "text": "The countries and industries \ntargeted by APT39 are depicted in Figure 1.",
            "order": 9,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13578,
            "text": "Figure\t1:\tCountries\tand\tindustries\ttargeted\tby\tAPT39 \n \n \n Operational Intent \nAPT39's focus on the telecommunications and travel industries suggests intent to perform \nmonitoring, tracking, or surveillance operations against specific individuals, collect \nproprietary or customer data for commercial or operational purposes that serve strategic \nrequirements related to national priorities, or create additional accesses and vectors to \nfacilitate future campaigns.",
            "order": 10,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13579,
            "text": "Government entities targeting suggests a potential secondary \nintent to collect geopolitical data that may benefit nation-state decision making.",
            "order": 11,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13580,
            "text": "Targeting \ndata supports the belief that APT39's key mission is to track or monitor targets of interest, \ncollect personal information, including travel itineraries, and gather customer data from \ntelecommunications firms.",
            "order": 12,
            "disposition": "accept",
            "mappings": [
                {
                    "id": 1775,
                    "attack_id": "T1082",
                    "name": "System Information Discovery",
                    "confidence": "31.4"
                }
            ]
        },
        {
            "id": 13581,
            "text": "Iran Nexus Indicators \nWe have moderate confidence APT39 operations are conducted in support of Iranian \nnational interests based on regional targeting patterns focused in the Middle East, \ninfrastructure, timing, and similarities to APT34, a group that loosely aligns with activity \npublicly reported as “OilRig”.",
            "order": 13,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13582,
            "text": "While APT39 and APT34 share some similarities, including \nmalware distribution methods, POWBAT backdoor use, infrastructure nomenclature, and \ntargeting overlaps, we consider APT39 to be distinct from APT34 given its use of a \ndifferent POWBAT variant.",
            "order": 14,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13583,
            "text": "It is possible that these groups work together or share \nresources at some level.",
            "order": 15,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13584,
            "text": "Attack Lifecycle \nAPT39 uses a variety of custom and publicly available malware and tools at all stages of \nthe attack lifecycle.",
            "order": 16,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13585,
            "text": "Initial\tCompromise \nFor initial compromise, FireEye Intelligence has observed APT39 leverage spear phishing \nemails with malicious attachments and/or hyperlinks typically resulting in a POWBAT \ninfection.",
            "order": 17,
            "disposition": "accept",
            "mappings": [
                {
                    "id": 1776,
                    "attack_id": "T1566.001",
                    "name": "Spearphishing Attachment",
                    "confidence": "50.9"
                }
            ]
        },
        {
            "id": 13586,
            "text": "APT39 frequently registers and leverages domains that masquerade as \nlegitimate web services and organizations that are relevant to the intended target.",
            "order": 18,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13587,
            "text": "Furthermore, this group has routinely identified and exploited vulnerable web servers of \ntargeted organizations to install web shells, such as ANTAK and ASPXSPY, and used \nstolen legitimate credentials to compromise externally facing Outlook Web Access (OWA) \nresources.",
            "order": 19,
            "disposition": "accept",
            "mappings": [
                {
                    "id": 1777,
                    "attack_id": "T1505.003",
                    "name": "Web Shell",
                    "confidence": "99.4"
                }
            ]
        },
        {
            "id": 13588,
            "text": "Establish\tFoothold,\tEscalate\tPrivileges,\tand\tInternal\tReconnaissance \nPost-compromise, APT39 leverages custom backdoors such as SEAWEED, \nCACHEMONEY, and a unique variant of POWBAT to establish a foothold in a target \nenvironment.",
            "order": 20,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13589,
            "text": "During privilege escalation, freely available tools such as Mimikatz and \nNcrack have been observed, in addition to legitimate tools such as Windows Credential \nEditor and ProcDump.",
            "order": 21,
            "disposition": "accept",
            "mappings": [
                {
                    "id": 1778,
                    "attack_id": "T1003",
                    "name": "OS Credential Dumping",
                    "confidence": "76.6"
                }
            ]
        },
        {
            "id": 13590,
            "text": "Internal reconnaissance has been performed using custom scripts \nand both freely available and custom tools such as the port scanner, BLUETORCH.",
            "order": 22,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13591,
            "text": "Lateral\tMovement,\tMaintain\tPresence,\tand\tComplete\tMission \nAPT39 facilitates lateral movement through myriad tools such as Remote Desktop Protocol \n(RDP), Secure Shell (SSH), PsExec, RemCom, and xCmdSvc.",
            "order": 23,
            "disposition": "accept",
            "mappings": [
                {
                    "id": 1779,
                    "attack_id": "T1021.001",
                    "name": "Remote Desktop Protocol",
                    "confidence": "30.1"
                },
                {
                    "id": 1780,
                    "attack_id": "T1059",
                    "name": "Command and Scripting Interpreter",
                    "confidence": "39.6"
                }
            ]
        },
        {
            "id": 13592,
            "text": "Custom tools such as \nREDTRIP, PINKTRIP, and BLUETRIP have also been used to create SOCKS5 proxies \nbetween infected hosts.",
            "order": 24,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13593,
            "text": "In addition to using RDP for lateral movement, APT39 has used \nthis protocol to maintain persistence in a victim environment.",
            "order": 25,
            "disposition": "accept",
            "mappings": [
                {
                    "id": 1781,
                    "attack_id": "T1021.001",
                    "name": "Remote Desktop Protocol",
                    "confidence": "65.9"
                }
            ]
        },
        {
            "id": 13594,
            "text": "To complete its mission, \nAPT39 typically archives stolen data with compression tools such as WinRAR or 7-Zip.",
            "order": 26,
            "disposition": "accept",
            "mappings": [
                {
                    "id": 1782,
                    "attack_id": "T1560",
                    "name": "Archive Collected Data",
                    "confidence": "27.9"
                }
            ]
        },
        {
            "id": 13595,
            "text": "Figure\t2:\tAPT39\tattack\tlifecycle \n \nThere are some indications that APT39 demonstrated a penchant for operational security \nto bypass detection efforts by network defenders, including the use of a modified version of \nMimikatz that was repacked to thwart anti-virus detection in one case, as well as another \ninstance when after gaining initial access APT39 performed credential harvesting outside \nof a compromised entity's environment to avoid detection.",
            "order": 27,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13596,
            "text": "Outlook \nWe believe APT39's significant targeting of the telecommunications and travel industries \nreflects efforts to collect personal information on targets of interest and customer data for \nthe purposes of surveillance to facilitate future operations.",
            "order": 28,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13597,
            "text": "Telecommunications firms are \nattractive targets given that they store large amounts of personal and customer \ninformation, provide access to critical infrastructure used for communications, and enable \naccess to a wide range of potential targets across multiple verticals.",
            "order": 29,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13598,
            "text": "APT39's targeting not \nonly represents a threat to known targeted industries, but it extends to these organizations' \nclientele, which includes a wide variety of sectors and individuals on a global scale.",
            "order": 30,
            "disposition": "accept",
            "mappings": []
        },
        {
            "id": 13599,
            "text": "APT39's activity showcases Iran's potential global operational reach and how it uses cyber \noperations as a low-cost and effective tool to facilitate the collection of key data on \nperceived national security threats and gain advantages against regional and global rivals.",
            "order": 31,
            "disposition": "accept",
            "mappings": []
        }
    ]
}
```

### TRAM Limitations

Currently TRAM only supports 50 ATT&CK Techniques, [as listed here](https://github.com/center-for-threat-informed-defense/tram/blob/main/data/ml-models/bert_model/classes.txt). There are currently 780 in ATT&CK Enterprise v15.1, as this query from [CTI Butler](https://www.ctibutler.com/) uncovers;

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc._stix2arango_note == "v15.1"
  AND doc.type == "attack-pattern"
  RETURN [doc]
```

It is possible to add your own models to TRAM. I will not cover that in this tutorial. You can [read the following section of the TRAM documentation for more information about how this can be achieved](https://github.com/center-for-threat-informed-defense/tram/#creating-your-own-ml-model).

## txt2stix

We've also built an open-source tool, [txt2stix](https://github.com/muchdogesec/txt2stix/), that extracts intelligence automatically from threat reports, including mapping all 780 ATT&CK techniques, [as well as all the other available ATT&CK objects](/blog/mitre_attack_data_structure/).

You can download an install txt2stix [using the instructions here](https://github.com/muchdogesec/txt2stix/). You will also need a CTI Butler account.

Once everything is configured we can run it. I'll use the same report used earlier with TRAM:

```shell
python3 txt2stix.py \
    --relationship_mode ai \
    --input_file tests/inputs/real_intel_reports/FireEyeAPT39.txt \
    --name 'FireEye APT39' \
    --tlp_level clear \
    --confidence 80 \
    --use_extractions ai_mitre_attack_enterprise
```

Note in this command I am using an OpenAI model (you can swap in your own models if desired) to extract ATT&CK Enterprise data. txt2stix ships with a wide range of other extractions you can use.

txt2stix outputs a STIX 2.1 bundle which makes the data immediately importable to downstream tools. Here's what the output bundle looks like for the command above;

<div class="stixview" data-stix-url="/assets/images/blog/2024-07-08/bundle--2538b780-5423-47dd-aadf-55f8cfd9b71c.json" data-stix-allow-dragdrop="false" data-show-idrefs="false" data-show-markings="true" data-show-sidebar="true" data-graph-layout="cise" data-caption="FireEye APT39 txt2stix extracted ATT&CK Enterprise objects" data-disable-mouse-zoom="false" data-graph-width="100%" data-graph-height="85vh" data-show-footer="true"></div>

Give it a try (with more extractions enabled) on your own reports.