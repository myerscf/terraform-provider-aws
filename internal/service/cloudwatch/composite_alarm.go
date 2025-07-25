// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudwatch

import (
	"context"
	"log"

	"github.com/YakDriver/smarterr"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	"github.com/hashicorp/terraform-provider-aws/internal/flex"
	"github.com/hashicorp/terraform-provider-aws/internal/smerr"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_cloudwatch_composite_alarm", name="Composite Alarm")
// @Tags(identifierAttribute="arn")
func resourceCompositeAlarm() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceCompositeAlarmCreate,
		ReadWithoutTimeout:   resourceCompositeAlarmRead,
		UpdateWithoutTimeout: resourceCompositeAlarmUpdate,
		DeleteWithoutTimeout: resourceCompositeAlarmDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"actions_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
				ForceNew: true,
			},
			"actions_suppressor": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"alarm": {
							Type:     schema.TypeString,
							Required: true,
						},
						"extension_period": {
							Type:     schema.TypeInt,
							Required: true,
						},
						"wait_period": {
							Type:     schema.TypeInt,
							Required: true,
						},
					},
				},
			},
			"alarm_actions": {
				Type:     schema.TypeSet,
				Optional: true,
				MaxItems: 5,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: verify.ValidARN,
				},
			},
			"alarm_description": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringLenBetween(0, 1024),
			},
			"alarm_name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringLenBetween(0, 255),
			},
			"alarm_rule": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringLenBetween(1, 10240),
			},
			names.AttrARN: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"insufficient_data_actions": {
				Type:     schema.TypeSet,
				Optional: true,
				MaxItems: 5,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: verify.ValidARN,
				},
			},
			"ok_actions": {
				Type:     schema.TypeSet,
				Optional: true,
				MaxItems: 5,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: verify.ValidARN,
				},
			},
			names.AttrTags:    tftags.TagsSchema(),
			names.AttrTagsAll: tftags.TagsSchemaComputed(),
		},
	}
}

func resourceCompositeAlarmCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CloudWatchClient(ctx)

	name := d.Get("alarm_name").(string)
	input := expandPutCompositeAlarmInput(ctx, d)

	_, err := conn.PutCompositeAlarm(ctx, input)

	// Some partitions (e.g. ISO) may not support tag-on-create.
	if input.Tags != nil && errs.IsUnsupportedOperationInPartitionError(meta.(*conns.AWSClient).Partition(ctx), err) {
		input.Tags = nil

		_, err = conn.PutCompositeAlarm(ctx, input)
	}

	if err != nil {
		return smerr.Append(ctx, diags, err, smerr.ID, name)
	}

	d.SetId(name)

	// For partitions not supporting tag-on-create, attempt tag after create.
	if tags := getTagsIn(ctx); input.Tags == nil && len(tags) > 0 {
		alarm, err := findCompositeAlarmByName(ctx, conn, d.Id())

		if err != nil {
			return smerr.Append(ctx, diags, err, smerr.ID, d.Id())
		}

		err = createTags(ctx, conn, aws.ToString(alarm.AlarmArn), tags)

		// If default tags only, continue. Otherwise, error.
		if v, ok := d.GetOk(names.AttrTags); (!ok || len(v.(map[string]any)) == 0) && errs.IsUnsupportedOperationInPartitionError(meta.(*conns.AWSClient).Partition(ctx), err) {
			return append(diags, resourceCompositeAlarmRead(ctx, d, meta)...)
		}

		if err != nil {
			return smerr.Append(ctx, diags, err, smerr.ID, d.Id())
		}
	}

	return append(diags, resourceCompositeAlarmRead(ctx, d, meta)...)
}

func resourceCompositeAlarmRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CloudWatchClient(ctx)

	alarm, err := findCompositeAlarmByName(ctx, conn, d.Id())

	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN] CloudWatch Composite Alarm %s not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return smerr.Append(ctx, diags, err, smerr.ID, d.Id())
	}

	d.Set("actions_enabled", alarm.ActionsEnabled)
	if alarm.ActionsSuppressor != nil {
		if err := d.Set("actions_suppressor", []any{flattenActionsSuppressor(alarm)}); err != nil {
			return smerr.Append(ctx, diags, err, smerr.ID, d.Id())
		}
	} else {
		d.Set("actions_suppressor", nil)
	}
	d.Set("alarm_actions", alarm.AlarmActions)
	d.Set("alarm_description", alarm.AlarmDescription)
	d.Set("alarm_name", alarm.AlarmName)
	d.Set("alarm_rule", alarm.AlarmRule)
	d.Set(names.AttrARN, alarm.AlarmArn)
	d.Set("insufficient_data_actions", alarm.InsufficientDataActions)
	d.Set("ok_actions", alarm.OKActions)

	return diags
}

func resourceCompositeAlarmUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CloudWatchClient(ctx)

	if d.HasChangesExcept(names.AttrTags, names.AttrTagsAll) {
		input := expandPutCompositeAlarmInput(ctx, d)

		_, err := conn.PutCompositeAlarm(ctx, input)

		if err != nil {
			return smerr.Append(ctx, diags, err, smerr.ID, d.Id())
		}
	}

	return append(diags, resourceCompositeAlarmRead(ctx, d, meta)...)
}

func resourceCompositeAlarmDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).CloudWatchClient(ctx)

	log.Printf("[INFO] Deleting CloudWatch Composite Alarm: %s", d.Id())
	input := cloudwatch.DeleteAlarmsInput{
		AlarmNames: []string{d.Id()},
	}
	_, err := conn.DeleteAlarms(ctx, &input)

	if errs.IsA[*types.ResourceNotFoundException](err) {
		return diags
	}

	if err != nil {
		return smerr.Append(ctx, diags, err, smerr.ID, d.Id())
	}

	return diags
}

func findCompositeAlarmByName(ctx context.Context, conn *cloudwatch.Client, name string) (*types.CompositeAlarm, error) {
	input := &cloudwatch.DescribeAlarmsInput{
		AlarmNames: []string{name},
		AlarmTypes: []types.AlarmType{types.AlarmTypeCompositeAlarm},
	}

	output, err := conn.DescribeAlarms(ctx, input)
	if err != nil {
		return nil, smarterr.NewError(err)
	}

	if output == nil {
		return nil, smarterr.NewError(tfresource.NewEmptyResultError(input))
	}

	return smarterr.Assert(tfresource.AssertSingleValueResult(output.CompositeAlarms))
}

func expandPutCompositeAlarmInput(ctx context.Context, d *schema.ResourceData) *cloudwatch.PutCompositeAlarmInput {
	apiObject := &cloudwatch.PutCompositeAlarmInput{
		ActionsEnabled: aws.Bool(d.Get("actions_enabled").(bool)),
		Tags:           getTagsIn(ctx),
	}

	if v, ok := d.GetOk("alarm_actions"); ok && v.(*schema.Set).Len() > 0 {
		apiObject.AlarmActions = flex.ExpandStringValueSet(v.(*schema.Set))
	}

	if v, ok := d.GetOk("actions_suppressor"); ok && len(v.([]any)) > 0 && v.([]any)[0] != nil {
		alarm := expandActionsSuppressor(v.([]any)[0].(map[string]any))
		apiObject.ActionsSuppressor = alarm.ActionsSuppressor
		apiObject.ActionsSuppressorExtensionPeriod = alarm.ActionsSuppressorExtensionPeriod
		apiObject.ActionsSuppressorWaitPeriod = alarm.ActionsSuppressorWaitPeriod
	}

	if v, ok := d.GetOk("alarm_description"); ok {
		apiObject.AlarmDescription = aws.String(v.(string))
	}

	if v, ok := d.GetOk("alarm_name"); ok {
		apiObject.AlarmName = aws.String(v.(string))
	}

	if v, ok := d.GetOk("alarm_rule"); ok {
		apiObject.AlarmRule = aws.String(v.(string))
	}

	if v, ok := d.GetOk("insufficient_data_actions"); ok && v.(*schema.Set).Len() > 0 {
		apiObject.InsufficientDataActions = flex.ExpandStringValueSet(v.(*schema.Set))
	}

	if v, ok := d.GetOk("ok_actions"); ok && v.(*schema.Set).Len() > 0 {
		apiObject.OKActions = flex.ExpandStringValueSet(v.(*schema.Set))
	}

	return apiObject
}

func flattenActionsSuppressor(apiObject *types.CompositeAlarm) map[string]any {
	if apiObject == nil || apiObject.ActionsSuppressor == nil {
		return nil
	}

	tfMap := map[string]any{
		"alarm":            aws.ToString(apiObject.ActionsSuppressor),
		"extension_period": aws.ToInt32(apiObject.ActionsSuppressorExtensionPeriod),
		"wait_period":      aws.ToInt32(apiObject.ActionsSuppressorWaitPeriod),
	}

	return tfMap
}

func expandActionsSuppressor(tfMap map[string]any) *types.CompositeAlarm {
	if tfMap == nil {
		return nil
	}

	apiObject := &types.CompositeAlarm{}

	if v, ok := tfMap["alarm"]; ok && v.(string) != "" {
		apiObject.ActionsSuppressor = aws.String(v.(string))
	}

	if v, ok := tfMap["extension_period"]; ok {
		apiObject.ActionsSuppressorExtensionPeriod = aws.Int32(int32(v.(int)))
	}

	if v, ok := tfMap["wait_period"]; ok {
		apiObject.ActionsSuppressorWaitPeriod = aws.Int32(int32(v.(int)))
	}

	return apiObject
}
