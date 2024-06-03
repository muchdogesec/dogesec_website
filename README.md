# DOGESEC Website

## Overview

Jekyll build for our main website site: https://www.dogesec.com

## Install locally

Install the dependencies with Bundler:

```shell
bundle install
```

Run jekyll commands through Bundler to ensure you're using the right versions:

```shell
bundle exec jekyll serve
```

## For development

To test future/draft posts run

```shell
bundle exec jekyll serve --future --draft
```

You should also check manually for 404's

```shell
bundle exec htmlproofer --check-html --internal-domains localhost:4000 ./_site
````

## For M1 Macs

```shell
brew install rbenv ruby-build
rbenv install 3.0.0
rbenv global 3.0.0
ruby -v
rbenv rehash
echo 'eval "$(rbenv init - zsh)"' >> ~/.zshrc
```

SourceL http://www.earthinversion.com/blogging/how-to-install-jekyll-on-appple-m1-macbook/

## Cloudflare pages

The main branch hosts build for: https://www.dogesec.com (auto deployed via Cloudflare pages)

## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## Licenses

* Code: [Apache 2.0](/LICENSE).
* Content: [Creative Commons Attribution 4.0 International Public License](/LICENSE-CONTENT)