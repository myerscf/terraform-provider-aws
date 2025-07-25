---
subcategory: "Connect"
layout: "aws"
page_title: "AWS: aws_connect_vocabulary"
description: |-
  Provides details about a specific Amazon Connect Vocabulary.
---

# Data Source: aws_connect_vocabulary

Provides details about a specific Amazon Connect Vocabulary.

## Example Usage

By `name`

```terraform
data "aws_connect_vocabulary" "example" {
  instance_id = "aaaaaaaa-bbbb-cccc-dddd-111111111111"
  name        = "Example"
}
```

By `vocabulary_id`

```terraform
data "aws_connect_vocabulary" "example" {
  instance_id   = "aaaaaaaa-bbbb-cccc-dddd-111111111111"
  vocabulary_id = "cccccccc-bbbb-cccc-dddd-111111111111"
}
```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `instance_id` - (Required) Reference to the hosting Amazon Connect Instance
* `name` - (Optional) Returns information on a specific Vocabulary by name
* `vocabulary_id` - (Optional) Returns information on a specific Vocabulary by Vocabulary id

~> **NOTE:** `instance_id` and one of either `name` or `vocabulary_id` is required.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `arn` - The Amazon Resource Name (ARN) of the Vocabulary.
* `content` - The content of the custom vocabulary in plain-text format with a table of values. Each row in the table represents a word or a phrase, described with Phrase, IPA, SoundsLike, and DisplayAs fields. Separate the fields with TAB characters. For more information, see [Create a custom vocabulary using a table](https://docs.aws.amazon.com/transcribe/latest/dg/custom-vocabulary.html#create-vocabulary-table).
* `failure_reason` - The reason why the custom vocabulary was not created.
* `id` - The identifier of the hosting Amazon Connect Instance and identifier of the vocabulary
separated by a colon (`:`).
* `language_code` - The language code of the vocabulary entries. For a list of languages and their corresponding language codes, see [What is Amazon Transcribe?](https://docs.aws.amazon.com/transcribe/latest/dg/transcribe-whatis.html). Valid Values are `ar-AE`, `de-CH`, `de-DE`, `en-AB`, `en-AU`, `en-GB`, `en-IE`, `en-IN`, `en-US`, `en-WL`, `es-ES`, `es-US`, `fr-CA`, `fr-FR`, `hi-IN`, `it-IT`, `ja-JP`, `ko-KR`, `pt-BR`, `pt-PT`, `zh-CN`.
* `last_modified_time` - The timestamp when the custom vocabulary was last modified.
* `state` - The current state of the custom vocabulary. Valid values are `CREATION_IN_PROGRESS`, `ACTIVE`, `CREATION_FAILED`, `DELETE_IN_PROGRESS`.
* `tags` - A map of tags to assign to the Vocabulary.
* `vocabulary_id` - The identifier of the custom vocabulary.
