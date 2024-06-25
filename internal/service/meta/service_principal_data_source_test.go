package meta_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	tfmeta "github.com/hashicorp/terraform-provider-aws/internal/service/meta"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func TestServicePrincipalNameDefault(t *testing.T) {
	ctx := acctest.Context(t)
	dataSourceName := "data.aws_service_principal.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, tfmeta.PseudoServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSPNDataSourceConfig_empty,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, names.AttrID, "."+acctest.Region()+"."+acctest.PartitionSPNSuffix()),
					resource.TestCheckResourceAttr(dataSourceName, names.AttrName, "."+acctest.PartitionSPNSuffix()),
					resource.TestCheckResourceAttr(dataSourceName, names.AttrSuffix, acctest.PartitionSPNSuffix()),
					resource.TestCheckResourceAttr(dataSourceName, names.AttrRegion, acctest.Region()),
				),
			},
		},
	})
}

func TestServicePrincipalNameByRegion(t *testing.T) {
	ctx := acctest.Context(t)

	var testCases = []struct {
		TestName       string
		DataSourceName string
		Region         string
		Suffix         string
	}{
		{
			TestName:       "commercial_spn",
			DataSourceName: "data.aws_service_principal.commercial",
			Region:         "us-east-1",
			Suffix:         "amazonaws.com",
		},
		{
			TestName:       "govcloud_spn",
			DataSourceName: "data.aws_service_principal.gov",
			Region:         "us-gov-east-1",
			Suffix:         "amazonaws.com",
		},
		{
			TestName:       "china_spn",
			DataSourceName: "data.aws_service_principal.china",
			Region:         "cn-north-1",
			Suffix:         "amazonaws.com",
		},
		{
			TestName:       "isoa_spn",
			DataSourceName: "data.aws_service_principal.isoa",
			Region:         "us-iso-east-1",
			Suffix:         "amazonaws.com",
		},
		{
			TestName:       "isob_spn",
			DataSourceName: "data.aws_service_principal.isob",
			Region:         "us-isob-east-1",
			Suffix:         "amazonaws.com",
		},
		{
			TestName:       "isoe_spn",
			DataSourceName: "data.aws_service_principal.isoe",
			Region:         "eu-isoe-west-1",
			Suffix:         "amazonaws.com",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.TestName, func(t *testing.T) {
			t.Parallel()
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(ctx, t) },
				ErrorCheck:               acctest.ErrorCheck(t, tfmeta.PseudoServiceID),
				ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: testAccSPNDataSourceConfig_withRegion,
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr(testCase.DataSourceName, names.AttrID, "."+testCase.Region+"."+acctest.PartitionSPNSuffix()),
							resource.TestCheckResourceAttr(testCase.DataSourceName, names.AttrName, "."+testCase.Suffix),
							resource.TestCheckResourceAttr(testCase.DataSourceName, names.AttrSuffix, testCase.Suffix),
							resource.TestCheckResourceAttr(testCase.DataSourceName, names.AttrRegion, testCase.Region),
						),
					},
				},
			})
		})
	}

}

func TestServicePrincipalNameWithService(t *testing.T) {
	ctx := acctest.Context(t)
	dataSourceNameS3 := "data.aws_service_principal.s3"
	dataSourceNameEC2 := "data.aws_service_principal.ec2"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, tfmeta.PseudoServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSPNDataSourceConfig_withService,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceNameS3, names.AttrID, "s3."+acctest.Region()+"."+acctest.PartitionSPNSuffix()),
					resource.TestCheckResourceAttr(dataSourceNameS3, names.AttrName, "s3."+acctest.PartitionSPNSuffix()),
					resource.TestCheckResourceAttr(dataSourceNameS3, names.AttrServiceName, "s3"),
				),
			},
			{
				Config: testAccSPNDataSourceConfig_withService,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceNameEC2, names.AttrID, "ec2."+acctest.Region()+"."+acctest.PartitionSPNSuffix()),
					resource.TestCheckResourceAttr(dataSourceNameEC2, names.AttrName, "ec2."+acctest.PartitionSPNSuffix()),
					resource.TestCheckResourceAttr(dataSourceNameEC2, names.AttrServiceName, "ec2"),
				),
			},
		},
	})
}

func TestServicePrincipalNameWithServiceAndRegionFallback(t *testing.T) {
	ctx := acctest.Context(t)
	dataSourceNameLogs := "data.aws_service_principal.logs"
	dataSourceNameCodeDeploy := "data.aws_service_principal.codedeploy"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, tfmeta.PseudoServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSPNDataSourceConfig_withServiceAndRegionFallback,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceNameLogs, names.AttrID, "logs.us-iso-east-1.c2s.ic.gov"),
					resource.TestCheckResourceAttr(dataSourceNameLogs, names.AttrName, "logs.c2s.ic.gov"),
					resource.TestCheckResourceAttr(dataSourceNameLogs, names.AttrServiceName, "logs"),
				),
			},
			{
				Config: testAccSPNDataSourceConfig_withServiceAndRegionFallback,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceNameCodeDeploy, names.AttrID, "codedeploy.cn-north-1.amazonaws.com.cn"),
					resource.TestCheckResourceAttr(dataSourceNameCodeDeploy, names.AttrName, "codedeploy.amazonaws.com.cn"),
					resource.TestCheckResourceAttr(dataSourceNameCodeDeploy, names.AttrServiceName, "codedeploy"),
				),
			},
		},
	})
}

const testAccSPNDataSourceConfig_empty = `
data "aws_service_principal" "test" {}
`

const testAccSPNDataSourceConfig_withRegion = `
data "aws_service_principal" "commercial" {
	region = "us-east-1"
}
data "aws_service_principal" "gov" {
	region = "us-gov-east-1"
}
data "aws_service_principal" "china" {
	region = "cn-north-1"
}
data "aws_service_principal" "isoa" {
	region = "us-iso-east-1"
}
data "aws_service_principal" "isob" {
	region = "us-isob-east-1"
}
data "aws_service_principal" "isoe" {
	region = "eu-isoe-west-1"
}
`

const testAccSPNDataSourceConfig_withService = `
data "aws_service_principal" "s3" {
	service_name = "s3"
}
data "aws_service_principal" "ec2" {
	service_name = "ec2"
}
`

const testAccSPNDataSourceConfig_withServiceAndRegionFallback = `
data "aws_service_principal" "logs" {
	service_name = "logs"
	region = "us-iso-east-1"
}
data "aws_service_principal" "codedeploy" {
	service_name = "codedeploy"
	region = "cn-north-1"
}
`
