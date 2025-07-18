// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ec2

import (
	"context"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	awstypes "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/flex"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKDataSource("aws_ebs_snapshot", name="EBS Snapshot")
// @Tags
// @Testing(tagsTest=false)
func dataSourceEBSSnapshot() *schema.Resource {
	return &schema.Resource{
		ReadWithoutTimeout: dataSourceEBSSnapshotRead,

		Timeouts: &schema.ResourceTimeout{
			Read: schema.DefaultTimeout(20 * time.Minute),
		},

		Schema: map[string]*schema.Schema{
			names.AttrARN: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"data_encryption_key_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrDescription: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrEncrypted: {
				Type:     schema.TypeBool,
				Computed: true,
			},
			names.AttrFilter: customFiltersSchema(),
			names.AttrKMSKeyID: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrMostRecent: {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"outpost_arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"owner_alias": {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrOwnerID: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"owners": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"restorable_by_user_ids": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			names.AttrSnapshotID: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"snapshot_ids": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			names.AttrStartTime: {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrState: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"storage_tier": {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrTags: tftags.TagsSchemaComputed(),
			"volume_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrVolumeSize: {
				Type:     schema.TypeInt,
				Computed: true,
			},
		},
	}
}

func dataSourceEBSSnapshotRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	c := meta.(*conns.AWSClient)
	conn := c.EC2Client(ctx)

	input := ec2.DescribeSnapshotsInput{}

	if v, ok := d.GetOk("owners"); ok && len(v.([]any)) > 0 {
		input.OwnerIds = flex.ExpandStringValueList(v.([]any))
	}

	if v, ok := d.GetOk("restorable_by_user_ids"); ok && len(v.([]any)) > 0 {
		input.RestorableByUserIds = flex.ExpandStringValueList(v.([]any))
	}

	if v, ok := d.GetOk("snapshot_ids"); ok && len(v.([]any)) > 0 {
		input.SnapshotIds = flex.ExpandStringValueList(v.([]any))
	}

	input.Filters = append(input.Filters, newCustomFilterList(
		d.Get(names.AttrFilter).(*schema.Set),
	)...)

	if len(input.Filters) == 0 {
		input.Filters = nil
	}

	snapshots, err := findSnapshots(ctx, conn, &input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading EBS Snapshots: %s", err)
	}

	if len(snapshots) < 1 {
		return sdkdiag.AppendErrorf(diags, "Your query returned no results. Please change your search criteria and try again.")
	}

	if len(snapshots) > 1 && !d.Get(names.AttrMostRecent).(bool) {
		return sdkdiag.AppendErrorf(diags, "Your query returned more than one result. Please try a more "+
			"specific search criteria, or set `most_recent` attribute to true.")
	}

	sortSnapshotsDescending(snapshots)

	snapshot := slices.MaxFunc(snapshots, func(a, b awstypes.Snapshot) int {
		return aws.ToTime(a.StartTime).Compare(aws.ToTime(b.StartTime))
	})

	d.SetId(aws.ToString(snapshot.SnapshotId))
	d.Set(names.AttrARN, ebsSnapshotARN(ctx, c, d.Id()))
	d.Set("data_encryption_key_id", snapshot.DataEncryptionKeyId)
	d.Set(names.AttrDescription, snapshot.Description)
	d.Set(names.AttrEncrypted, snapshot.Encrypted)
	d.Set(names.AttrKMSKeyID, snapshot.KmsKeyId)
	d.Set("outpost_arn", snapshot.OutpostArn)
	d.Set("owner_alias", snapshot.OwnerAlias)
	d.Set(names.AttrOwnerID, snapshot.OwnerId)
	d.Set(names.AttrSnapshotID, snapshot.SnapshotId)
	d.Set(names.AttrState, snapshot.State)
	d.Set(names.AttrStartTime, aws.ToTime(snapshot.StartTime).Format(time.RFC3339))
	d.Set("storage_tier", snapshot.StorageTier)
	d.Set("volume_id", snapshot.VolumeId)
	d.Set(names.AttrVolumeSize, snapshot.VolumeSize)

	setTagsOut(ctx, snapshot.Tags)

	return diags
}
