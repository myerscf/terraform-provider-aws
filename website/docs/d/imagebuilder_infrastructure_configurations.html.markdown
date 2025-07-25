---
subcategory: "EC2 Image Builder"
layout: "aws"
page_title: "AWS: aws_imagebuilder_infrastructure_configurations"
description: |-
    Get information on Image Builder Infrastructure Configurations.
---

# Data Source: aws_imagebuilder_infrastructure_configurations

Use this data source to get the ARNs and names of Image Builder Infrastructure Configurations matching the specified criteria.

## Example Usage

```terraform
data "aws_imagebuilder_infrastructure_configurations" "example" {
  filter {
    name   = "name"
    values = ["example"]
  }
}
```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `filter` - (Optional) Configuration block(s) for filtering. Detailed below.

## filter Configuration Block

The `filter` configuration block supports the following arguments:

* `name` - (Required) Name of the filter field. Valid values can be found in the [Image Builder ListInfrastructureConfigurations API Reference](https://docs.aws.amazon.com/imagebuilder/latest/APIReference/API_ListInfrastructureConfigurations.html).
* `values` - (Required) Set of values that are accepted for the given filter field. Results will be selected if any given value matches.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `arns` - Set of ARNs of the matched Image Builder Infrastructure Configurations.
* `names` - Set of names of the matched Image Builder Infrastructure Configurations.
