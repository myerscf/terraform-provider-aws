---
subcategory: "Connect"
layout: "aws"
page_title: "AWS: aws_connect_contact_flow"
description: |-
  Provides details about a specific Amazon Connect Contact Flow.
---

# Resource: aws_connect_contact_flow

Provides an Amazon Connect Contact Flow resource. For more information see
[Amazon Connect: Getting Started](https://docs.aws.amazon.com/connect/latest/adminguide/amazon-connect-get-started.html)

This resource embeds or references Contact Flows specified in Amazon Connect Contact Flow Language. For more information see
[Amazon Connect Flow language](https://docs.aws.amazon.com/connect/latest/adminguide/flow-language.html)

!> **WARN:** Contact Flows exported from the Console [Contact Flow import/export](https://docs.aws.amazon.com/connect/latest/adminguide/contact-flow-import-export.html) are not in the Amazon Connect Contact Flow Language and can not be used with this resource. Instead, the recommendation is to use the AWS CLI [`describe-contact-flow`](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/connect/describe-contact-flow.html).
See [example](#with-external-content) below which uses `jq` to extract the `Content` attribute and saves it to a local file.

## Example Usage

### Basic

```terraform
resource "aws_connect_contact_flow" "test" {
  instance_id = "aaaaaaaa-bbbb-cccc-dddd-111111111111"
  name        = "Test"
  description = "Test Contact Flow Description"
  type        = "CONTACT_FLOW"
  content = jsonencode({
    Version     = "2019-10-30"
    StartAction = "12345678-1234-1234-1234-123456789012"
    Actions = [
      {
        Identifier = "12345678-1234-1234-1234-123456789012"
        Type       = "MessageParticipant"

        Transitions = {
          NextAction = "abcdef-abcd-abcd-abcd-abcdefghijkl"
          Errors     = []
          Conditions = []
        }

        Parameters = {
          Text = "Thanks for calling the sample flow!"
        }
      },
      {
        Identifier  = "abcdef-abcd-abcd-abcd-abcdefghijkl"
        Type        = "DisconnectParticipant"
        Transitions = {}
        Parameters  = {}
      }
    ]
  })

  tags = {
    "Name"        = "Test Contact Flow"
    "Application" = "Terraform"
    "Method"      = "Create"
  }
}
```

### With External Content

Use the AWS CLI to extract Contact Flow Content:

```console
% aws connect describe-contact-flow --instance-id 1b3c5d8-1b3c-1b3c-1b3c-1b3c5d81b3c5 --contact-flow-id c1d4e5f6-1b3c-1b3c-1b3c-c1d4e5f6c1d4e5 --region us-west-2 | jq '.ContactFlow.Content | fromjson' > contact_flow.json
```

Use the generated file as input:

```terraform
resource "aws_connect_contact_flow" "test" {
  instance_id  = "aaaaaaaa-bbbb-cccc-dddd-111111111111"
  name         = "Test"
  description  = "Test Contact Flow Description"
  type         = "CONTACT_FLOW"
  filename     = "contact_flow.json"
  content_hash = filebase64sha256("contact_flow.json")
  tags = {
    "Name"        = "Test Contact Flow",
    "Application" = "Terraform",
    "Method"      = "Create"
  }
}
```

## Argument Reference

This resource supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `content` - (Optional) Specifies the content of the Contact Flow, provided as a JSON string, written in Amazon Connect Contact Flow Language. If defined, the `filename` argument cannot be used.
* `content_hash` - (Optional) Used to trigger updates. Must be set to a base64-encoded SHA256 hash of the Contact Flow source specified with `filename`. The usual way to set this is filebase64sha256("mycontact_flow.json") (Terraform 0.11.12 and later) or base64sha256(file("mycontact_flow.json")) (Terraform 0.11.11 and earlier), where "mycontact_flow.json" is the local filename of the Contact Flow source.
* `description` - (Optional) Specifies the description of the Contact Flow.
* `filename` - (Optional) The path to the Contact Flow source within the local filesystem. Conflicts with `content`.
* `instance_id` - (Required) Specifies the identifier of the hosting Amazon Connect Instance.
* `name` - (Required) Specifies the name of the Contact Flow.
* `tags` - (Optional) Tags to apply to the Contact Flow. If configured with a provider [`default_tags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.
* `type` - (Optional, Forces new resource) Specifies the type of the Contact Flow. Defaults to `CONTACT_FLOW`. Allowed Values are: `CONTACT_FLOW`, `CUSTOMER_QUEUE`, `CUSTOMER_HOLD`, `CUSTOMER_WHISPER`, `AGENT_HOLD`, `AGENT_WHISPER`, `OUTBOUND_WHISPER`, `AGENT_TRANSFER`, `QUEUE_TRANSFER`.

## Attribute Reference

This resource exports the following attributes in addition to the arguments above:

* `arn` - The Amazon Resource Name (ARN) of the Contact Flow.
* `id` - The identifier of the hosting Amazon Connect Instance and identifier of the Contact Flow separated by a colon (`:`).
* `contact_flow_id` - The identifier of the Contact Flow.
* `tags_all` - A map of tags assigned to the resource, including those inherited from the provider [`default_tags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block).

## Import

In Terraform v1.5.0 and later, use an [`import` block](https://developer.hashicorp.com/terraform/language/import) to import Amazon Connect Contact Flows using the `instance_id` and `contact_flow_id` separated by a colon (`:`). For example:

```terraform
import {
  to = aws_connect_contact_flow.example
  id = "f1288a1f-6193-445a-b47e-af739b2:c1d4e5f6-1b3c-1b3c-1b3c-c1d4e5f6c1d4e5"
}
```

Using `terraform import`, import Amazon Connect Contact Flows using the `instance_id` and `contact_flow_id` separated by a colon (`:`). For example:

```console
% terraform import aws_connect_contact_flow.example f1288a1f-6193-445a-b47e-af739b2:c1d4e5f6-1b3c-1b3c-1b3c-c1d4e5f6c1d4e5
```
