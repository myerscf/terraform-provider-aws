---
subcategory: "Service Catalog AppRegistry"
layout: "aws"
page_title: "AWS: aws_servicecatalogappregistry_application"
description: |-
  Terraform data source for managing an AWS Service Catalog AppRegistry Application.
---

# Data Source: aws_servicecatalogappregistry_application

Terraform data source for managing an AWS Service Catalog AppRegistry Application.

## Example Usage

### Basic Usage

```terraform
data "aws_servicecatalogappregistry_application" "example" {
  id = "application-1234"
}
```

## Argument Reference

This data source supports the following arguments:

* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `id` - (Required) Application identifier.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `application_tag` - A map with a single tag key-value pair used to associate resources with the application.
* `arn` - ARN (Amazon Resource Name) of the application.
* `description` - Description of the application.
* `name` - Name of the application.
* `tags` - A map of tags assigned to the Application. If configured with a provider [`default_tags` configuration block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block) present, tags with matching keys will overwrite those defined at the provider-level.
