// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package eks_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/YakDriver/regexache"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eks/types"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	tfeks "github.com/hashicorp/terraform-provider-aws/internal/service/eks"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func TestAccEKSAddon_basic(t *testing.T) {
	ctx := acctest.Context(t)
	var addon types.Addon
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	clusterResourceName := "aws_eks_cluster.test"
	addonResourceName := "aws_eks_addon.test"
	addonName := "vpc-cni"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheck(ctx, t); testAccPreCheckAddon(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.EKSServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckAddonDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccAddonConfig_basic(rName, addonName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckAddonExists(ctx, addonResourceName, &addon),
					resource.TestCheckResourceAttr(addonResourceName, "addon_name", addonName),
					resource.TestCheckResourceAttrSet(addonResourceName, "addon_version"),
					acctest.MatchResourceAttrRegionalARN(ctx, addonResourceName, names.AttrARN, "eks", regexache.MustCompile(fmt.Sprintf("addon/%s/%s/.+$", rName, addonName))),
					resource.TestCheckResourceAttrPair(addonResourceName, names.AttrClusterName, clusterResourceName, names.AttrName),
					resource.TestCheckResourceAttr(addonResourceName, "configuration_values", ""),
					resource.TestCheckResourceAttr(addonResourceName, "pod_identity_association.#", "0"),
					resource.TestCheckNoResourceAttr(addonResourceName, "preserve"),
					resource.TestCheckResourceAttr(addonResourceName, acctest.CtTagsPercent, "0"),
				),
			},
			{
				ResourceName:      addonResourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccEKSAddon_disappears(t *testing.T) {
	ctx := acctest.Context(t)
	var addon types.Addon
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_eks_addon.test"
	addonName := "vpc-cni"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheck(ctx, t); testAccPreCheckAddon(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.EKSServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckAddonDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccAddonConfig_basic(rName, addonName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon),
					acctest.CheckResourceDisappears(ctx, acctest.Provider, tfeks.ResourceAddon(), resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccEKSAddon_Disappears_cluster(t *testing.T) {
	ctx := acctest.Context(t)
	var addon types.Addon
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_eks_addon.test"
	clusterResourceName := "aws_eks_cluster.test"
	addonName := "vpc-cni"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheck(ctx, t); testAccPreCheckAddon(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.EKSServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckAddonDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccAddonConfig_basic(rName, addonName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon),
					acctest.CheckResourceDisappears(ctx, acctest.Provider, tfeks.ResourceCluster(), clusterResourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccEKSAddon_addonVersion(t *testing.T) {
	ctx := acctest.Context(t)
	var addon1, addon2 types.Addon
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_eks_addon.test"
	dataSourceNameDefault := "data.aws_eks_addon_version.default"
	dataSourceNameLatest := "data.aws_eks_addon_version.latest"
	addonName := "vpc-cni"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheck(ctx, t); testAccPreCheckAddon(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.EKSServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckAddonDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccAddonConfig_version(rName, addonName, dataSourceNameDefault),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon1),
					resource.TestCheckResourceAttrPair(resourceName, "addon_version", dataSourceNameDefault, names.AttrVersion),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"resolve_conflicts_on_create", "resolve_conflicts_on_update"},
			},
			{
				Config: testAccAddonConfig_version(rName, addonName, dataSourceNameLatest),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon2),
					resource.TestCheckResourceAttrPair(resourceName, "addon_version", dataSourceNameLatest, names.AttrVersion),
				),
			},
		},
	})
}

func TestAccEKSAddon_preserve(t *testing.T) {
	ctx := acctest.Context(t)
	var addon types.Addon
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_eks_addon.test"
	addonName := "vpc-cni"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheck(ctx, t); testAccPreCheckAddon(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.EKSServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckAddonDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccAddonConfig_preserve(rName, addonName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon),
					resource.TestCheckResourceAttr(resourceName, "preserve", acctest.CtTrue),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"preserve"},
			},
		},
	})
}

func TestAccEKSAddon_resolveConflicts(t *testing.T) {
	ctx := acctest.Context(t)
	var addon1, addon2, addon3 types.Addon
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_eks_addon.test"
	addonName := "vpc-cni"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheck(ctx, t); testAccPreCheckAddon(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.EKSServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckAddonDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccAddonConfig_resolveConflicts(rName, addonName, string(types.ResolveConflictsNone), string(types.ResolveConflictsNone)),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon1),
					resource.TestCheckResourceAttr(resourceName, "resolve_conflicts_on_create", string(types.ResolveConflictsNone)),
					resource.TestCheckResourceAttr(resourceName, "resolve_conflicts_on_update", string(types.ResolveConflictsNone)),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"resolve_conflicts_on_create", "resolve_conflicts_on_update"},
			},
			{
				Config: testAccAddonConfig_resolveConflicts(rName, addonName, string(types.ResolveConflictsOverwrite), string(types.ResolveConflictsOverwrite)),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon2),
					resource.TestCheckResourceAttr(resourceName, "resolve_conflicts_on_create", string(types.ResolveConflictsOverwrite)),
					resource.TestCheckResourceAttr(resourceName, "resolve_conflicts_on_update", string(types.ResolveConflictsOverwrite)),
				),
			},
			{
				Config: testAccAddonConfig_resolveConflicts(rName, addonName, string(types.ResolveConflictsOverwrite), string(types.ResolveConflictsPreserve)),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon3),
					resource.TestCheckResourceAttr(resourceName, "resolve_conflicts_on_create", string(types.ResolveConflictsOverwrite)),
					resource.TestCheckResourceAttr(resourceName, "resolve_conflicts_on_update", string(types.ResolveConflictsPreserve)),
				),
			},
		},
	})
}

func TestAccEKSAddon_serviceAccountRoleARN(t *testing.T) {
	ctx := acctest.Context(t)
	var addon types.Addon
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_eks_addon.test"
	serviceRoleResourceName := "aws_iam_role.test_service_role"
	addonName := "vpc-cni"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheck(ctx, t); testAccPreCheckAddon(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.EKSServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckAddonDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccAddonConfig_serviceAccountRoleARN(rName, addonName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon),
					resource.TestCheckResourceAttrPair(resourceName, "service_account_role_arn", serviceRoleResourceName, names.AttrARN),
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

func TestAccEKSAddon_configurationValues(t *testing.T) {
	ctx := acctest.Context(t)
	var addon types.Addon
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_eks_addon.test"
	configurationValues := "{\"env\": {\"WARM_ENI_TARGET\":\"2\",\"ENABLE_POD_ENI\":\"true\"},\"resources\": {\"limits\":{\"cpu\":\"100m\",\"memory\":\"100Mi\"},\"requests\":{\"cpu\":\"100m\",\"memory\":\"100Mi\"}}}"
	updateConfigurationValues := "{\"env\": {\"WARM_ENI_TARGET\":\"2\",\"ENABLE_POD_ENI\":\"true\"},\"resources\": {\"limits\":{\"cpu\":\"200m\",\"memory\":\"150Mi\"},\"requests\":{\"cpu\":\"200m\",\"memory\":\"150Mi\"}}}"
	emptyConfigurationValues := "{}"
	invalidConfigurationValues := "{\"env\": {\"INVALID_FIELD\":\"2\"}}"
	addonName := "vpc-cni"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheck(ctx, t); testAccPreCheckAddon(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.EKSServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckAddonDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccAddonConfig_configurationValues(rName, addonName, configurationValues),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon),
					resource.TestCheckResourceAttr(resourceName, "configuration_values", configurationValues),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"resolve_conflicts_on_create", "resolve_conflicts_on_update"},
			},
			{
				Config: testAccAddonConfig_configurationValues(rName, addonName, updateConfigurationValues),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon),
					resource.TestCheckResourceAttr(resourceName, "configuration_values", updateConfigurationValues),
				),
			},
			{
				Config: testAccAddonConfig_configurationValues(rName, addonName, emptyConfigurationValues),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon),
					resource.TestCheckResourceAttr(resourceName, "configuration_values", emptyConfigurationValues),
				),
			},
			{
				Config:      testAccAddonConfig_configurationValues(rName, addonName, invalidConfigurationValues),
				ExpectError: regexache.MustCompile(`InvalidParameterException: ConfigurationValue provided in request is not supported`),
			},
		},
	})
}

func TestAccEKSAddon_podIdentityAssociation(t *testing.T) {
	ctx := acctest.Context(t)
	var addon types.Addon
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_eks_addon.test"
	podIdentityRoleResourceName := "aws_iam_role.test_pod_identity"
	addonName := "vpc-cni"
	serviceAccount := "aws-node"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheck(ctx, t); testAccPreCheckAddon(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.EKSServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckAddonDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccAddonConfig_podIdentityAssociation(rName, addonName, serviceAccount),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon),
					resource.TestCheckResourceAttr(resourceName, "pod_identity_association.#", "1"),
					resource.TestCheckResourceAttrPair(resourceName, "pod_identity_association.0.role_arn", podIdentityRoleResourceName, names.AttrARN),
					resource.TestCheckResourceAttr(resourceName, "pod_identity_association.0.service_account", serviceAccount),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccAddonConfig_basic(rName, addonName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon),
					resource.TestCheckResourceAttr(resourceName, "pod_identity_association.#", "0"),
				),
			},
			{
				Config: testAccAddonConfig_podIdentityAssociation(rName, addonName, serviceAccount),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon),
					resource.TestCheckResourceAttr(resourceName, "pod_identity_association.#", "1"),
					resource.TestCheckResourceAttrPair(resourceName, "pod_identity_association.0.role_arn", podIdentityRoleResourceName, names.AttrARN),
					resource.TestCheckResourceAttr(resourceName, "pod_identity_association.0.service_account", serviceAccount),
				),
			},
		},
	})
}

func TestAccEKSAddon_tags(t *testing.T) {
	ctx := acctest.Context(t)
	var addon1, addon2, addon3 types.Addon
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_eks_addon.test"
	addonName := "vpc-cni"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheck(ctx, t); testAccPreCheckAddon(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.EKSServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckAddonDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccAddonConfig_tags1(rName, addonName, acctest.CtKey1, acctest.CtValue1),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon1),
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
				Config: testAccAddonConfig_tags2(rName, addonName, acctest.CtKey1, acctest.CtValue1Updated, acctest.CtKey2, acctest.CtValue2),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon2),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsPercent, "2"),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsKey1, acctest.CtValue1Updated),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsKey2, acctest.CtValue2),
				),
			},
			{
				Config: testAccAddonConfig_tags1(rName, addonName, acctest.CtKey2, acctest.CtValue2),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAddonExists(ctx, resourceName, &addon3),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsPercent, "1"),
					resource.TestCheckResourceAttr(resourceName, acctest.CtTagsKey2, acctest.CtValue2),
				),
			},
		},
	})
}

func TestAccEKSAddon_supportedAddons(t *testing.T) {
	ctx := acctest.Context(t)

	// List of core EKS addons that are reliable and commonly used
	supportedAddons := []string{
		// "vpc-cni", // Already installed by default
		"coredns",
		"kube-proxy",
		"aws-ebs-csi-driver",
		"eks-pod-identity-agent",
		"amazon-cloudwatch-observability",
		"eks-node-monitoring-agent",
		// "amazon-sagemaker-hyperpod-observability",
		// "amazon-sagemaker-hyperpod-taskgovernance",
		"aws-guardduty-agent",
		"aws-efs-csi-driver",
		"aws-network-flow-monitoring-agent",
		"snapshot-controller",
		"sriov-network-metrics-exporter",
		"aws-privateca-connector-for-kubernetes",
		"aws-fsx-csi-driver",
		"aws-mountpoint-s3-csi-driver",
	}

	for _, addonName := range supportedAddons {
		t.Run(addonName, func(t *testing.T) {
			var addonResource types.Addon
			rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
			clusterResourceName := "aws_eks_cluster.test"
			addonResourceName := "aws_eks_addon.test"

			resource.ParallelTest(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(ctx, t); testAccPreCheck(ctx, t); testAccPreCheckAddon(ctx, t) },
				ErrorCheck:               acctest.ErrorCheck(t, names.EKSServiceID),
				ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
				CheckDestroy:             testAccCheckAddonDestroy(ctx),
				Steps: []resource.TestStep{
					{
						Config: testAccAddonConfig_supportedAddon(rName, addonName),
						Check: resource.ComposeAggregateTestCheckFunc(
							testAccCheckAddonExists(ctx, addonResourceName, &addonResource),
							resource.TestCheckResourceAttr(addonResourceName, "addon_name", addonName),
							resource.TestCheckResourceAttrSet(addonResourceName, "addon_version"),
							acctest.MatchResourceAttrRegionalARN(ctx, addonResourceName, names.AttrARN, "eks", regexache.MustCompile(fmt.Sprintf("addon/%s/%s/.+$", rName, addonName))),
							resource.TestCheckResourceAttrPair(addonResourceName, names.AttrClusterName, clusterResourceName, names.AttrName),
							resource.TestCheckResourceAttr(clusterResourceName, names.AttrVersion, clusterVersion133),
						),
					},
					{
						ResourceName:            addonResourceName,
						ImportState:             true,
						ImportStateVerify:       true,
						ImportStateVerifyIgnore: []string{"resolve_conflicts_on_create", "resolve_conflicts_on_update"},
					},
				},
			})
		})
	}
}

func testAccCheckAddonExists(ctx context.Context, n string, v *types.Addon) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		clusterName, addonName, err := tfeks.AddonParseResourceID(rs.Primary.ID)
		if err != nil {
			return err
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).EKSClient(ctx)

		output, err := tfeks.FindAddonByTwoPartKey(ctx, conn, clusterName, addonName)

		if err != nil {
			return err
		}

		*v = *output

		return nil
	}
}

func testAccCheckAddonDestroy(ctx context.Context) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.Provider.Meta().(*conns.AWSClient).EKSClient(ctx)

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "aws_eks_addon" {
				continue
			}

			clusterName, addonName, err := tfeks.AddonParseResourceID(rs.Primary.ID)
			if err != nil {
				return err
			}

			_, err = tfeks.FindAddonByTwoPartKey(ctx, conn, clusterName, addonName)

			if tfresource.NotFound(err) {
				continue
			}

			if err != nil {
				return err
			}

			return fmt.Errorf("EKS Add-On %s still exists", rs.Primary.ID)
		}

		return nil
	}
}

func testAccPreCheckAddon(ctx context.Context, t *testing.T) {
	conn := acctest.Provider.Meta().(*conns.AWSClient).EKSClient(ctx)

	input := &eks.DescribeAddonVersionsInput{}

	_, err := conn.DescribeAddonVersions(ctx, input)

	if acctest.PreCheckSkipError(err) {
		t.Skipf("skipping acceptance testing: %s", err)
	}

	if err != nil {
		t.Fatalf("unexpected PreCheck error: %s", err)
	}
}

func testAccAddonConfig_base(rName string, eksVersion string) string {
	return acctest.ConfigCompose(acctest.ConfigAvailableAZsNoOptIn(), fmt.Sprintf(`
data "aws_partition" "current" {}

data "aws_service_principal" "eks" {
  service_name = "eks"
}

resource "aws_iam_role" "test" {
  name = %[1]q

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "${data.aws_service_principal.eks.name}"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "test-AmazonEKSClusterPolicy" {
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.test.name
}

resource "aws_vpc" "test" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name                          = %[1]q
    "kubernetes.io/cluster/%[1]s" = "shared"
  }
}

resource "aws_subnet" "test" {
  count = 2

  availability_zone = data.aws_availability_zones.available.names[count.index]
  cidr_block        = "10.0.${count.index}.0/24"
  vpc_id            = aws_vpc.test.id

  tags = {
    Name                          = %[1]q
    "kubernetes.io/cluster/%[1]s" = "shared"
  }
}

resource "aws_eks_cluster" "test" {
  name     = %[1]q
  role_arn = aws_iam_role.test.arn
  version  = %[2]q

  vpc_config {
    subnet_ids = aws_subnet.test[*].id
  }

  depends_on = [aws_iam_role_policy_attachment.test-AmazonEKSClusterPolicy]
}
`, rName, eksVersion))
}

func testAccAddonConfig_basic(rName, addonName string) string {
	return acctest.ConfigCompose(testAccAddonConfig_base(rName, clusterVersion133), fmt.Sprintf(`
resource "aws_eks_addon" "test" {
  cluster_name = aws_eks_cluster.test.name
  addon_name   = %[2]q
}
`, rName, addonName))
}

func testAccAddonConfig_version(rName, addonName, addonVersionDataSourceName string) string {
	return acctest.ConfigCompose(testAccAddonConfig_base(rName, clusterVersion133), fmt.Sprintf(`
data "aws_eks_addon_version" "default" {
  addon_name         = %[2]q
  kubernetes_version = aws_eks_cluster.test.version
}

data "aws_eks_addon_version" "latest" {
  addon_name         = %[2]q
  kubernetes_version = aws_eks_cluster.test.version
  most_recent        = true
}

resource "aws_eks_addon" "test" {
  cluster_name                = aws_eks_cluster.test.name
  addon_name                  = %[2]q
  addon_version               = %[3]s.version
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
}
`, rName, addonName, addonVersionDataSourceName))
}

func testAccAddonConfig_preserve(rName, addonName string) string {
	return acctest.ConfigCompose(testAccAddonConfig_base(rName, clusterVersion133), fmt.Sprintf(`
resource "aws_eks_addon" "test" {
  cluster_name = aws_eks_cluster.test.name
  addon_name   = %[2]q
  preserve     = true
}
`, rName, addonName))
}

func testAccAddonConfig_podIdentityAssociation(rName, addonName, serviceAccount string) string {
	return acctest.ConfigCompose(
		testAccAddonConfig_base(rName, clusterVersion133),
		fmt.Sprintf(`
data "aws_iam_policy_document" "test_assume_role" {
  statement {
    effect = "Allow"
    actions = [
      "sts:AssumeRole",
      "sts:TagSession",
    ]
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "test_pod_identity" {
  name               = "%1s-pod-identity"
  assume_role_policy = data.aws_iam_policy_document.test_assume_role.json
}

resource "aws_iam_role_policy_attachment" "test-AmazonEKS_CNI_Policy" {
  role       = aws_iam_role.test_pod_identity.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_eks_addon" "test" {
  depends_on = [aws_iam_role_policy_attachment.test-AmazonEKS_CNI_Policy]

  cluster_name = aws_eks_cluster.test.name
  addon_name   = %[2]q

  pod_identity_association {
    role_arn        = aws_iam_role.test_pod_identity.arn
    service_account = %[3]q
  }
}
`, rName, addonName, serviceAccount))
}

func testAccAddonConfig_resolveConflicts(rName, addonName, resolveConflictsOnCreate, resolveConflictsOnUpdate string) string {
	return acctest.ConfigCompose(testAccAddonConfig_base(rName, clusterVersion133), fmt.Sprintf(`
resource "aws_eks_addon" "test" {
  cluster_name                = aws_eks_cluster.test.name
  addon_name                  = %[2]q
  resolve_conflicts_on_create = %[3]q
  resolve_conflicts_on_update = %[4]q
}
`, rName, addonName, resolveConflictsOnCreate, resolveConflictsOnUpdate))
}

func testAccAddonConfig_serviceAccountRoleARN(rName, addonName string) string {
	return acctest.ConfigCompose(testAccAddonConfig_base(rName, clusterVersion133), fmt.Sprintf(`
resource "aws_iam_role" "test_service_role" {
  name               = "test-service-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_eks_addon" "test" {
  cluster_name             = aws_eks_cluster.test.name
  addon_name               = %[2]q
  service_account_role_arn = aws_iam_role.test_service_role.arn
}
`, rName, addonName))
}

func testAccAddonConfig_tags1(rName, addonName, tagKey1, tagValue1 string) string {
	return acctest.ConfigCompose(testAccAddonConfig_base(rName, clusterVersion133), fmt.Sprintf(`
resource "aws_eks_addon" "test" {
  cluster_name = aws_eks_cluster.test.name
  addon_name   = %[2]q

  tags = {
    %[3]q = %[4]q
  }
}
`, rName, addonName, tagKey1, tagValue1))
}

func testAccAddonConfig_tags2(rName, addonName, tagKey1, tagValue1, tagKey2, tagValue2 string) string {
	return acctest.ConfigCompose(testAccAddonConfig_base(rName, clusterVersion133), fmt.Sprintf(`
resource "aws_eks_addon" "test" {
  cluster_name = aws_eks_cluster.test.name
  addon_name   = %[2]q

  tags = {
    %[3]q = %[4]q
    %[5]q = %[6]q
  }
}
`, rName, addonName, tagKey1, tagValue1, tagKey2, tagValue2))
}

func testAccAddonConfig_configurationValues(rName, addonName, configurationValues string) string {
	return acctest.ConfigCompose(testAccAddonConfig_base(rName, clusterVersion133), fmt.Sprintf(`
resource "aws_eks_addon" "test" {
  cluster_name                = aws_eks_cluster.test.name
  addon_name                  = %[2]q
  configuration_values        = %[3]q
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
}
`, rName, addonName, configurationValues))
}

func testAccAddonConfig_supportedAddons(rName string, addons []struct {
	name             string
	resolveConflicts string
}) string {
	var addonConfigs []string

	addonConfigs = append(addonConfigs, `
resource "aws_internet_gateway" "test" {
  vpc_id = aws_vpc.test.id
  tags = {
    Name = %[1]q
  }
}
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.test.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.test.id
  }
  tags = {
    Name = %[1]q
  }
}

resource "aws_subnet" "public" {
  count = 2
  # make the cidr block bigger number to not conflict with the base ones
  cidr_block        = "10.0.${sum([count.index,10])}.0/24"
  vpc_id            = aws_vpc.test.id
  map_public_ip_on_launch = true

  tags = {
    Name                          = %[1]q
    "kubernetes.io/cluster/%[1]s" = "shared"
  }
}

resource "aws_route_table_association" "public" {
  count = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}
  
resource "aws_eks_node_group" "test_node_group" {
  cluster_name    = aws_eks_cluster.test.name
  node_group_name = "test_node_group"
  node_role_arn   = aws_iam_role.node_group.arn
  subnet_ids      = aws_subnet.public[*].id
  scaling_config {
    desired_size = 1
    max_size     = 2
    min_size     = 1
  }
  update_config {
    max_unavailable = 1
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.node_group-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.node_group-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.node_group-AmazonEC2ContainerRegistryReadOnly,
  ]
}

data "aws_service_principal" "ec2" {
  service_name = "ec2"
}

resource "aws_iam_role" "node_group" {
  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "${data.aws_service_principal.ec2.name}"
      }
    }]
    Version = "2012-10-17"
  })
}
resource "aws_iam_role_policy_attachment" "node_group-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node_group.name
}
resource "aws_iam_role_policy_attachment" "node_group-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node_group.name
}
resource "aws_iam_role_policy_attachment" "node_group-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node_group.name
}

resource "aws_eks_addon" "test_vpc_cni" {
  cluster_name = aws_eks_cluster.test.name
  addon_name   = "vpc-cni"
}

`)

	for _, addon := range addons {
		resourceName := strings.ReplaceAll(addon.name, "-", "_")
		addonConfig := fmt.Sprintf(`
	resource "aws_eks_addon" "test_%s" {
	  cluster_name                = aws_eks_cluster.test.name
	  addon_name                  = %q

	  depends_on = [
		aws_eks_node_group.test_node_group,
	  ]
	}
	  `, resourceName, addon.name)
		addonConfigs = append(addonConfigs, addonConfig)
	}

	return acctest.ConfigCompose(testAccAddonConfig_base(rName, clusterVersion133), fmt.Sprintf(strings.Join(addonConfigs, "\n"), rName, clusterVersion133))
}
func testAccAddonConfig_supportedAddon(rName, addonName string) string {
	return acctest.ConfigCompose(testAccAddonConfig_base(rName, clusterVersion133), fmt.Sprintf(`
resource "aws_internet_gateway" "test" {
  vpc_id = aws_vpc.test.id
  tags = {
    Name = %[1]q
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.test.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.test.id
  }
  tags = {
    Name = %[1]q
  }
}

resource "aws_subnet" "public" {
  count = 2
  # Use higher CIDR blocks to avoid conflicts with base subnets
  cidr_block              = "10.0.${sum([count.index, 10])}.0/24"
  vpc_id                  = aws_vpc.test.id
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name                          = %[1]q
    "kubernetes.io/cluster/%[1]s" = "shared"
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

data "aws_service_principal" "ec2" {
  service_name = "ec2"
}

resource "aws_iam_role" "node_group" {
  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = data.aws_service_principal.ec2.name
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "node_group-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node_group.name
}

resource "aws_iam_role_policy_attachment" "node_group-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node_group.name
}

resource "aws_iam_role_policy_attachment" "node_group-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node_group.name
}

resource "aws_eks_node_group" "test_node_group" {
  cluster_name    = aws_eks_cluster.test.name
  node_group_name = "test-node-group"
  node_role_arn   = aws_iam_role.node_group.arn
  subnet_ids      = aws_subnet.public[*].id

  scaling_config {
    desired_size = 1
    max_size     = 2
    min_size     = 1
  }

  update_config {
    max_unavailable = 1
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.node_group-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.node_group-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.node_group-AmazonEC2ContainerRegistryReadOnly,
  ]
}

resource "aws_eks_addon" "test_vpc_cni" {
  cluster_name = aws_eks_cluster.test.name
  addon_name   = "vpc-cni"
}

resource "aws_eks_addon" "test" {
  cluster_name                = aws_eks_cluster.test.name
  addon_name                  = %[2]q
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  depends_on = [
    aws_eks_node_group.test_node_group,
  ]
}
`, rName, addonName))
}
