# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

resource "aws_iot_event_configurations" "test" {
  region = var.region

  event_configurations = {
    "THING"                  = true,
    "THING_GROUP"            = false,
    "THING_TYPE"             = false,
    "THING_GROUP_MEMBERSHIP" = false,
    "THING_GROUP_HIERARCHY"  = false,
    "THING_TYPE_ASSOCIATION" = false,
    "JOB"                    = false,
    "JOB_EXECUTION"          = false,
    "POLICY"                 = false,
    "CERTIFICATE"            = true,
    "CA_CERTIFICATE"         = true,
  }
}


variable "region" {
  description = "Region to deploy resource in"
  type        = string
  nullable    = false
}
