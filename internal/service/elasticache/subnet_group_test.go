// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package elasticache_test

import (
	"context"
	"fmt"
	"testing"

	awstypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/retry"
	tfelasticache "github.com/hashicorp/terraform-provider-aws/internal/service/elasticache"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func TestAccElastiCacheSubnetGroup_basic(t *testing.T) {
	ctx := acctest.Context(t)
	var csg awstypes.CacheSubnetGroup
	resourceName := "aws_elasticache_subnet_group.test"
	rName := acctest.RandomWithPrefix(t, acctest.ResourcePrefix)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ElastiCacheServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckSubnetGroupDestroy(ctx, t),
		Steps: []resource.TestStep{
			{
				Config: testAccSubnetGroupConfig_basic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckSubnetGroupExists(ctx, t, resourceName, &csg),
					acctest.CheckResourceAttrRegionalARNFormat(ctx, resourceName, names.AttrARN, "elasticache", "subnetgroup:{name}"),
					resource.TestCheckResourceAttr(resourceName, names.AttrDescription, "Managed by Terraform"),
					resource.TestCheckResourceAttrPair(resourceName, names.AttrID, resourceName, names.AttrName),
					resource.TestCheckResourceAttr(resourceName, names.AttrName, rName),
					resource.TestCheckResourceAttr(resourceName, "subnet_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsPercent, "0"),
					resource.TestCheckResourceAttrSet(resourceName, names.AttrVPCID),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccElastiCacheSubnetGroup_disappears(t *testing.T) {
	ctx := acctest.Context(t)
	var csg awstypes.CacheSubnetGroup
	resourceName := "aws_elasticache_subnet_group.test"
	rName := acctest.RandomWithPrefix(t, acctest.ResourcePrefix)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ElastiCacheServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckSubnetGroupDestroy(ctx, t),
		Steps: []resource.TestStep{
			{
				Config: testAccSubnetGroupConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSubnetGroupExists(ctx, t, resourceName, &csg),
					acctest.CheckResourceDisappears(ctx, acctest.Provider, tfelasticache.ResourceSubnetGroup(), resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccElastiCacheSubnetGroup_tags(t *testing.T) {
	ctx := acctest.Context(t)
	var csg awstypes.CacheSubnetGroup
	resourceName := "aws_elasticache_subnet_group.test"
	rName := acctest.RandomWithPrefix(t, acctest.ResourcePrefix)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ElastiCacheServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckSubnetGroupDestroy(ctx, t),
		Steps: []resource.TestStep{
			{
				Config: testAccSubnetGroupConfig_tags1(rName, acctest.CtKey1, acctest.CtValue1),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSubnetGroupExists(ctx, t, resourceName, &csg),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsPercent, "1"),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsKey1, acctest.CtValue1),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccSubnetGroupConfig_tags2(rName, acctest.CtKey1, acctest.CtValue1Updated, acctest.CtKey2, acctest.CtValue2),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSubnetGroupExists(ctx, t, resourceName, &csg),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsPercent, "2"),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsKey1, acctest.CtValue1Updated),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsKey2, acctest.CtValue2),
				),
			},
			{
				Config: testAccSubnetGroupConfig_tags1(rName, acctest.CtKey2, acctest.CtValue2),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSubnetGroupExists(ctx, t, resourceName, &csg),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsPercent, "1"),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsKey2, acctest.CtValue2),
				),
			},
		},
	})
}

func TestAccElastiCacheSubnetGroup_update(t *testing.T) {
	ctx := acctest.Context(t)
	var csg awstypes.CacheSubnetGroup
	resourceName := "aws_elasticache_subnet_group.test"
	rName := acctest.RandomWithPrefix(t, acctest.ResourcePrefix)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.ElastiCacheServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckSubnetGroupDestroy(ctx, t),
		Steps: []resource.TestStep{
			{
				Config: testAccSubnetGroupConfig_updatePre(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSubnetGroupExists(ctx, t, resourceName, &csg),
					resource.TestCheckResourceAttr(resourceName, names.AttrDescription, "Description1"),
					resource.TestCheckResourceAttr(resourceName, names.AttrName, rName),
					resource.TestCheckResourceAttr(resourceName, "subnet_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsPercent, "0"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccSubnetGroupConfig_updatePost(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSubnetGroupExists(ctx, t, resourceName, &csg),
					resource.TestCheckResourceAttr(resourceName, names.AttrDescription, "Description2"),
					resource.TestCheckResourceAttr(resourceName, names.AttrName, rName),
					resource.TestCheckResourceAttr(resourceName, "subnet_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsPercent, "0"),
				),
			},
		},
	})
}

func testAccCheckSubnetGroupDestroy(ctx context.Context, t *testing.T) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.ProviderMeta(ctx, t).ElastiCacheClient(ctx)

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "aws_elasticache_subnet_group" {
				continue
			}

			_, err := tfelasticache.FindCacheSubnetGroupByName(ctx, conn, rs.Primary.ID)

			if retry.NotFound(err) {
				continue
			}

			if err != nil {
				return err
			}

			return fmt.Errorf("ElastiCache Subnet Group %s still exists", rs.Primary.ID)
		}

		return nil
	}
}

func testAccCheckSubnetGroupExists(ctx context.Context, t *testing.T, n string, v *awstypes.CacheSubnetGroup) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ElastiCache Subnet Group ID is set")
		}

		conn := acctest.ProviderMeta(ctx, t).ElastiCacheClient(ctx)

		output, err := tfelasticache.FindCacheSubnetGroupByName(ctx, conn, rs.Primary.ID)

		if err != nil {
			return err
		}

		*v = *output

		return nil
	}
}

func testAccSubnetGroupConfig_basic(rName string) string {
	return acctest.ConfigCompose(acctest.ConfigVPCWithSubnets(rName, 1), fmt.Sprintf(`
resource "aws_elasticache_subnet_group" "test" {
  # Including uppercase letters in this name to ensure
  # that we correctly handle the fact that the API
  # normalizes names to lowercase.
  name       = upper(%[1]q)
  subnet_ids = aws_subnet.test[*].id
}
`, rName))
}

func testAccSubnetGroupConfig_updatePre(rName string) string {
	return acctest.ConfigCompose(acctest.ConfigVPCWithSubnets(rName, 2), fmt.Sprintf(`
resource "aws_elasticache_subnet_group" "test" {
  name        = %[1]q
  description = "Description1"
  subnet_ids  = [aws_subnet.test[0].id]
}
`, rName))
}

func testAccSubnetGroupConfig_updatePost(rName string) string {
	return acctest.ConfigCompose(acctest.ConfigVPCWithSubnets(rName, 2), fmt.Sprintf(`
resource "aws_elasticache_subnet_group" "test" {
  name        = %[1]q
  description = "Description2"
  subnet_ids  = [aws_subnet.test[0].id, aws_subnet.test[1].id]
}
`, rName))
}

func testAccSubnetGroupConfig_tags1(rName, tag1Key, tag1Value string) string {
	return acctest.ConfigCompose(acctest.ConfigVPCWithSubnets(rName, 1), fmt.Sprintf(`
resource "aws_elasticache_subnet_group" "test" {
  name       = %[1]q
  subnet_ids = aws_subnet.test[*].id

  tags = {
    %[2]q = %[3]q
  }
}
`, rName, tag1Key, tag1Value))
}

func testAccSubnetGroupConfig_tags2(rName, tag1Key, tag1Value, tag2Key, tag2Value string) string {
	return acctest.ConfigCompose(acctest.ConfigVPCWithSubnets(rName, 1), fmt.Sprintf(`
resource "aws_elasticache_subnet_group" "test" {
  name       = %[1]q
  subnet_ids = aws_subnet.test[*].id

  tags = {
    %[2]q = %[3]q
    %[4]q = %[5]q
  }
}
`, rName, tag1Key, tag1Value, tag2Key, tag2Value))
}
