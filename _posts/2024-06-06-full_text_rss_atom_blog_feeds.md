---
date: 2024-06-06
last_modified: 2024-06-06
title: "A Better Way of Working with RSS and ATOM Feeds"
description: "Blog feeds are incredibly useful for research, but there are many limitations that make working with them tedious. Here is how our team became significantly more efficient using them."
categories:
  - PRODUCTS
  - DIY
tags: [
	RSS,
	ATOM,
    Blog,
    Feed
]
products:
    - Obstracts
    - history4feed
author_staff_member: david-greenwood
image: /assets/images/blog/2024-06-06/header.jpeg
featured_image: /assets/images/blog/2024-06-06/header.jpeg
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

RSS and ATOM feeds are problematic for two reasons; 1) lack of history, 2) partially printed content.

We built some software to fix that.

## But why?

There are many brilliant cyber-security researchers sharing their findings via online blogs. If you are one of these people, thank you!

Much of the research they share publicly is incredibly comprehensive.

As such, for the last four years now I have been curating a list of _awesome_ blogs that publish cyber threat intelligence research.

[It currently lists over 300 feeds](https://github.com/muchdogesec/awesome-threat-intel-blogs), with almost 200 stars!

However, most of the RSS and ATOM feeds listed in that repository, and more generally any blogs RSS and ATOM feeds, are limited in two ways;

1. the feeds show the partial content of the article, requiring you to navigate to the blog post on the internet to read the entire article.
2. the feeds contain a limited history of posts, typically about 20 posts (but this is determined by the blog owner).

Unless you have subscribed to a blog since its inception, there is no easy way to get a complete history of posts in that blog without having to web scrape.

For me, and perhaps you, this is problematic because there is no easy way to access historic research.

If you are wondering why I would want to do this, let me explain with a simple example...

A few months ago I was researching CVE-2024-3094, _as was every-single security researcher on the planet_.

Which brings me to problem 1;

## Problem 1: Partial Feed Content

When it comes to working with RSS and ATOM feeds, I like to have a local copy of the post for text search.

By being able to search and pivot on my machine in this way I can easily drill down on particular parts of the research being described in different ways, by different authors.

In the case of CVE-2024-3094, this could be a search for `build-to-host.m4` to read how authors of each post I have indexed describe what is unpacked by this macro, and ultimately what the unpacked content does.

Problem is; almost all RSS feeds only contain a summary of the articles actual content, not the full article.

Take this example from [PANs Unit42 ATOM feed](https://feeds.feedburner.com/Unit42):

```xml
<item>
	<title>Threat Brief: Vulnerability in XZ Utils Data Compression Library Impacting Multiple Linux Distributions (CVE-2024-3094)</title>
	<link>https://unit42.paloaltonetworks.com/threat-brief-xz-utils-cve-2024-3094/</link>
	<guid isPermaLink="false">https://unit42.paloaltonetworks.com/?p=133225</guid>
	<description>
		<![CDATA[ <p>An overview of CVE-2024-3094, a vulnerability in XZ Utils, and information about how to mitigate.</p> <p>The post <a href="https://unit42.paloaltonetworks.com/threat-brief-xz-utils-cve-2024-3094/">Threat Brief: Vulnerability in XZ Utils Data Compression Library Impacting Multiple Linux Distributions (CVE-2024-3094)</a> appeared first on <a href="https://unit42.paloaltonetworks.com">Unit 42</a>.</p> ]]>
	</description>
</item>
```

The `<description>` property contains a paragraph of data. Compare that to the full post content by visiting the `<link>` (`https://unit42.paloaltonetworks.com/threat-brief-xz-utils-cve-2024-3094/`), which contains paragraphs, images, tables, etc.

If you look at the HTML code for the article, you will also see the content is wrapped up in unrelated (e.g. nav bar) and other messy (e.g. CSS) HTML content.

Step in [readability-lxml](https://pypi.org/project/readability-lxml/), a Python library that takes a html document, pulls out the main body of text (for blogs, the post), and cleans it up.

Thus, to get the full text needed I can;

1. take the `<link>` value
2. grab the HTML content (e.g. `curl -L -o code.html http://website.domain`)
3. run it through readability-lxml to get the post content (the `doc.summary()`)

Problem solved.

Which brings me nicely on to problem 2...

## Problem 2: Limited history in feeds

CVE-2024-3094 is relatively new. It has only existed for a few months.

However, in many cases malicious actors rehash old tactics, techniques and procedures.

Searching through historic data based on information about current threats can uncover similarities with past research, and thus aid the running investigation.

Though as mentioned earlier, most blogs tend to limit the blog items posted in their feeds. I've found no more than the 20 most recent posts exist in a feed, at best.

Thinking for an hour-or-two I came to the conclusion there are two feasible approaches to getting content for posts that are no longer found in feeds provided for the blog;

1. Scrape the blog for historic posts. Probably the most accurate way to do it, though given the different structure of blogs and websites, this can become complex, requiring a fair bit of manual scraping logic to be written for each blog you want to follow. I'm sure an AI model could also be useful for this too, but this would likely require some fine-tuning for each blog. Or;
2. Use the Wayback Machine's archive. In the case of popular blogs the Wayback Machine will likely have captured many snapshots of a feed (though not always). For example, the feed for The Record by Recorded Future (`https://therecord.media/feed/`) has, at the time of writing, [been captured 187 times between 260 times between November 1, 2020 and December 7, 2023](https://web.archive.org/web/20231101000000*/https://therecord.media/feed/).

Here is one such snapshot taken by the Wayback Machine on July 8th 2023: https://web.archive.org/web/20230708200712/https://therecord.media/feed

Step in [waybackpack](https://pypi.org/project/waybackpack/), a command-line tool that lets you download the entire Wayback Machine archive for a given URL.

In the following command I am requesting all unique feed pages downloaded by the Wayback Machine (`--uniques-only`) from 2020 (`--from-date 2020`) from the feed URL `https://therecord.media/feed/` with each item to be written to a directory called `therecord_media_feed`.

Try it out...

```shell
waybackpack https://therecord.media/feed/ -d therecord_media_feed --from-date 2020 --uniques-only  
```

This run produces 100's of unique `index.html` files (where `index.html` is the actual RSS feed in pure XML). Each `index.html` is nested in directories named with the index datetime (time captured by Wayback Machine) in the format `YYYYMMDDHHMMSS` like so;

```txt
therecord_media_feed
├── 20220808162900
│   └── therecord.media
│       └── feed
│           └── index.html
├── 20220805213430
│   └── therecord.media
│       └── feed
│           └── index.html
...
└── 20201101220102
    └── therecord.media
        └── feed
            └── index.html
```

It is important to point out unique entries (defined in the CLI) just means the `index.html` files have at least one difference. That is to say, much of the file can actually be the same (thus in this case, include the same feed items).

Take `20220808162900 > therecord.media > index.html` and `20220805213430 > therecord.media > index.html`

Both of these files contain the item;

```xml
<item>
    <title>Twitter confirms January breach, urges pseudonymous accounts to not add email or phone number</title>
    <link>https://therecord.media/twitter-confirms-january-breach-urges-pseudonymous-accounts-to-not-add-email-or-phone-number/</link>
```

Therefore, the final step of the process requires de-duplication of feed items. This process can be done using the `<link>` values, first by searching for duplicates and then selecting the most recent feed entry (by Wayback Machine capture time) for the entry to be stored.

Again, problem 1 persists (partial post content) exists with this approach, but I have already shown you how to deal with that.

## Get started...

[Our proof-of-concept implementation, history4feed, is available on Github here](https://github.com/muchdogesec/history4feed).