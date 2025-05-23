// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package redshift

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/YakDriver/regexache"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	awstypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_redshift_parameter_group", name="Parameter Group")
// @Tags(identifierAttribute="arn")
func resourceParameterGroup() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceParameterGroupCreate,
		ReadWithoutTimeout:   resourceParameterGroupRead,
		UpdateWithoutTimeout: resourceParameterGroupUpdate,
		DeleteWithoutTimeout: resourceParameterGroupDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			names.AttrARN: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrDescription: {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "Managed by Terraform",
			},
			names.AttrFamily: {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			names.AttrName: {
				Type:     schema.TypeString,
				ForceNew: true,
				Required: true,
				ValidateFunc: validation.All(
					validation.StringLenBetween(1, 255),
					validation.StringMatch(regexache.MustCompile(`^[0-9a-z-]+$`), "must contain only lowercase alphanumeric characters and hyphens"),
					validation.StringMatch(regexache.MustCompile(`(?i)^[a-z]`), "first character must be a letter"),
					validation.StringDoesNotMatch(regexache.MustCompile(`--`), "cannot contain two consecutive hyphens"),
					validation.StringDoesNotMatch(regexache.MustCompile(`-$`), "cannot end with a hyphen"),
				),
			},
			names.AttrParameter: {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						names.AttrName: {
							Type:     schema.TypeString,
							Required: true,
						},
						names.AttrValue: {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
				Set: resourceParameterHash,
			},
			names.AttrTags:    tftags.TagsSchema(),
			names.AttrTagsAll: tftags.TagsSchemaComputed(),
		},
	}
}

func resourceParameterGroupCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).RedshiftClient(ctx)

	name := d.Get(names.AttrName).(string)
	input := &redshift.CreateClusterParameterGroupInput{
		Description:          aws.String(d.Get(names.AttrDescription).(string)),
		ParameterGroupFamily: aws.String(d.Get(names.AttrFamily).(string)),
		ParameterGroupName:   aws.String(name),
		Tags:                 getTagsIn(ctx),
	}

	_, err := conn.CreateClusterParameterGroup(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating Redshift Parameter Group (%s): %s", name, err)
	}

	d.SetId(name)

	if v := d.Get(names.AttrParameter).(*schema.Set); v.Len() > 0 {
		input := &redshift.ModifyClusterParameterGroupInput{
			ParameterGroupName: aws.String(d.Id()),
			Parameters:         expandParameters(v.List()),
		}

		_, err := conn.ModifyClusterParameterGroup(ctx, input)

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "setting Redshift Parameter Group (%s) parameters: %s", d.Id(), err)
		}
	}

	return append(diags, resourceParameterGroupRead(ctx, d, meta)...)
}

func resourceParameterGroupRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).RedshiftClient(ctx)

	parameterGroup, err := findParameterGroupByName(ctx, conn, d.Id())

	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN] Redshift Parameter Group (%s) not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Redshift Parameter Group (%s): %s", d.Id(), err)
	}

	arn := arn.ARN{
		Partition: meta.(*conns.AWSClient).Partition(ctx),
		Service:   names.Redshift,
		Region:    meta.(*conns.AWSClient).Region(ctx),
		AccountID: meta.(*conns.AWSClient).AccountID(ctx),
		Resource:  fmt.Sprintf("parametergroup:%s", d.Id()),
	}.String()
	d.Set(names.AttrARN, arn)
	d.Set(names.AttrDescription, parameterGroup.Description)
	d.Set(names.AttrFamily, parameterGroup.ParameterGroupFamily)
	d.Set(names.AttrName, parameterGroup.ParameterGroupName)

	setTagsOut(ctx, parameterGroup.Tags)

	input := &redshift.DescribeClusterParametersInput{
		ParameterGroupName: aws.String(d.Id()),
		Source:             aws.String("user"),
	}

	output, err := conn.DescribeClusterParameters(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Redshift Parameter Group (%s) parameters: %s", d.Id(), err)
	}

	d.Set(names.AttrParameter, flattenParameters(output.Parameters))

	return diags
}

func resourceParameterGroupUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).RedshiftClient(ctx)

	if d.HasChange(names.AttrParameter) {
		o, n := d.GetChange(names.AttrParameter)
		if o == nil {
			o = new(schema.Set)
		}
		if n == nil {
			n = new(schema.Set)
		}
		os := o.(*schema.Set)
		ns := n.(*schema.Set)

		parameters := expandParameters(ns.Difference(os).List())
		if len(parameters) > 0 {
			input := &redshift.ModifyClusterParameterGroupInput{
				ParameterGroupName: aws.String(d.Id()),
				Parameters:         parameters,
			}

			_, err := conn.ModifyClusterParameterGroup(ctx, input)

			if err != nil {
				return sdkdiag.AppendErrorf(diags, "setting Redshift Parameter Group (%s) parameters: %s", d.Id(), err)
			}
		}
	}

	return append(diags, resourceParameterGroupRead(ctx, d, meta)...)
}

func resourceParameterGroupDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).RedshiftClient(ctx)

	log.Printf("[DEBUG] Deleting Redshift Parameter Group: %s", d.Id())
	_, err := conn.DeleteClusterParameterGroup(ctx, &redshift.DeleteClusterParameterGroupInput{
		ParameterGroupName: aws.String(d.Id()),
	})
	if errs.IsA[*awstypes.ClusterParameterGroupNotFoundFault](err) {
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting Redshift Parameter Group (%s): %s", d.Id(), err)
	}

	return diags
}

func findParameterGroupByName(ctx context.Context, conn *redshift.Client, name string) (*awstypes.ClusterParameterGroup, error) {
	input := &redshift.DescribeClusterParameterGroupsInput{
		ParameterGroupName: aws.String(name),
	}

	output, err := conn.DescribeClusterParameterGroups(ctx, input)

	if errs.IsA[*awstypes.ClusterParameterGroupNotFoundFault](err) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: input,
		}
	}

	if err != nil {
		return nil, err
	}

	if output == nil || len(output.ParameterGroups) == 0 {
		return nil, tfresource.NewEmptyResultError(input)
	}

	parameterGroup := output.ParameterGroups[0]

	// Eventual consistency check.
	if aws.ToString(parameterGroup.ParameterGroupName) != name {
		return nil, &retry.NotFoundError{
			LastRequest: input,
		}
	}

	return &parameterGroup, nil
}

func resourceParameterHash(v any) int {
	var buf bytes.Buffer
	m := v.(map[string]any)
	fmt.Fprintf(&buf, "%s-", m[names.AttrName].(string))
	// Store the value as a lower case string, to match how we store them in FlattenParameters
	fmt.Fprintf(&buf, "%s-", strings.ToLower(m[names.AttrValue].(string)))

	return create.StringHashcode(buf.String())
}

func expandParameters(configured []any) []awstypes.Parameter {
	var parameters []awstypes.Parameter

	// Loop over our configured parameters and create
	// an array of aws-sdk-go compatible objects
	for _, pRaw := range configured {
		data := pRaw.(map[string]any)

		if data[names.AttrName].(string) == "" {
			continue
		}

		p := awstypes.Parameter{
			ParameterName:  aws.String(data[names.AttrName].(string)),
			ParameterValue: aws.String(data[names.AttrValue].(string)),
		}

		parameters = append(parameters, p)
	}

	return parameters
}

func flattenParameters(list []awstypes.Parameter) []map[string]any {
	result := make([]map[string]any, 0, len(list))
	for _, i := range list {
		result = append(result, map[string]any{
			names.AttrName:  aws.ToString(i.ParameterName),
			names.AttrValue: aws.ToString(i.ParameterValue),
		})
	}
	return result
}
