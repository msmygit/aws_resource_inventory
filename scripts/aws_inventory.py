#!/usr/bin/env python3
"""
AWS Resource Inventory Utility (Read-Only)

Description:
  Scans active AWS regions and global services in the authenticated account
  to generate a structured inventory of cloud resources with creator/owner details,
  region identifier, resource name, resource type, creation date, and tags.

Safety:
  - STRICTLY READ-ONLY: Does not create, modify, alter, or delete any resource.
  - NO CREDENTIALS STORED: Relies solely on active local AWS CLI authentication (e.g. `aws sso login` or env vars).

Usage:
  python3 scripts/aws_inventory.py [--output output.csv] [--regions us-east-1,us-east-2]
"""

import argparse
import csv
import json
import subprocess
import sys
from datetime import datetime


def run_aws_cmd(args):
    """Executes an AWS CLI command safely and returns parsed JSON or empty dict/list."""
    try:
        res = subprocess.run(args, capture_output=True, text=True, check=False)
        if res.returncode == 0 and res.stdout.strip():
            return json.loads(res.stdout)
        return {}
    except Exception as e:
        return {}


def verify_authentication():
    """Verifies that the user has an active, authenticated AWS CLI session."""
    print("[*] Checking AWS CLI authentication...")
    identity = run_aws_cmd(["aws", "sts", "get-caller-identity", "--output", "json"])
    if not identity or "Arn" not in identity:
        print("\n[ERROR] AWS CLI session is not authenticated or expired.")
        print("Please authenticate to your AWS CLI session locally prior to running this script.")
        print("Example: 'aws sso login' or configure your AWS environment variables.")
        sys.exit(1)
    
    account_id = identity.get("Account", "Unknown")
    caller_arn = identity.get("Arn", "Unknown")
    print(f"[+] Authenticated successfully!")
    print(f"    Account ID: {account_id}")
    print(f"    Caller ARN: {caller_arn}\n")
    return account_id


def extract_creator_info(tags):
    """Heuristic extraction of creator / owner / author from tags."""
    if isinstance(tags, dict):
        tag_items = tags.items()
    elif isinstance(tags, list):
        tag_items = [(t.get("Key", ""), t.get("Value", "")) for t in tags if isinstance(t, dict)]
    else:
        tag_items = []

    # Direct keyword matches
    for k, v in tag_items:
        k_lower = k.lower()
        if k_lower in ["owner_email", "owner", "createdby", "creator", "user", "author"]:
            return v
    # Substring matches
    for k, v in tag_items:
        k_lower = k.lower()
        if any(sub in k_lower for sub in ["email", "owner", "creator"]):
            return v
    return "N/A (Untagged)"


def normalize_tags(tags):
    """Converts various tag formats into a consistent dictionary."""
    if isinstance(tags, dict):
        return tags
    if isinstance(tags, list):
        result = {}
        for t in tags:
            if isinstance(t, dict) and "Key" in t and "Value" in t:
                result[t["Key"]] = t["Value"]
        return result
    return {}


def scan_ec2_instances(region):
    """Discovers EC2 instances in a region."""
    data = run_aws_cmd(["aws", "ec2", "describe-instances", "--region", region, "--output", "json"])
    items = []
    for res in data.get("Reservations", []):
        for i in res.get("Instances", []):
            state = i.get("State", {}).get("Name", "unknown")
            if state == "terminated":
                continue
            tags = normalize_tags(i.get("Tags", []))
            name = tags.get("Name", i.get("InstanceId"))
            items.append({
                "Region": region,
                "Type": f"EC2 Instance ({i.get('InstanceType', '')}, {state})",
                "Name": name,
                "ID": i.get("InstanceId"),
                "Created": i.get("LaunchTime", "N/A"),
                "Creator": extract_creator_info(tags),
                "Tags": tags
            })
    return items


def scan_vpcs(region):
    """Discovers VPCs in a region."""
    data = run_aws_cmd(["aws", "ec2", "describe-vpcs", "--region", region, "--output", "json"])
    items = []
    for v in data.get("Vpcs", []):
        tags = normalize_tags(v.get("Tags", []))
        name = tags.get("Name", v.get("VpcId"))
        items.append({
            "Region": region,
            "Type": f"VPC ({v.get('CidrBlock', '')})",
            "Name": name,
            "ID": v.get("VpcId"),
            "Created": "N/A",
            "Creator": extract_creator_info(tags),
            "Tags": tags
        })
    return items


def scan_nat_gateways(region):
    """Discovers NAT Gateways in a region."""
    data = run_aws_cmd(["aws", "ec2", "describe-nat-gateways", "--region", region, "--output", "json"])
    items = []
    for n in data.get("NatGateways", []):
        if n.get("State") == "deleted":
            continue
        tags = normalize_tags(n.get("Tags", []))
        name = tags.get("Name", n.get("NatGatewayId"))
        items.append({
            "Region": region,
            "Type": f"NAT Gateway ({n.get('State', '')})",
            "Name": name,
            "ID": n.get("NatGatewayId"),
            "Created": str(n.get("CreateTime", "N/A")),
            "Creator": extract_creator_info(tags),
            "Tags": tags
        })
    return items


def scan_load_balancers(region):
    """Discovers ALB/NLBs in a region."""
    data = run_aws_cmd(["aws", "elbv2", "describe-load-balancers", "--region", region, "--output", "json"])
    items = []
    for lb in data.get("LoadBalancers", []):
        arn = lb.get("LoadBalancerArn")
        tag_data = run_aws_cmd(["aws", "elbv2", "describe-tags", "--resource-arns", arn, "--region", region, "--output", "json"])
        raw_tags = tag_data.get("TagDescriptions", [{}])[0].get("Tags", []) if tag_data.get("TagDescriptions") else []
        tags = normalize_tags(raw_tags)
        items.append({
            "Region": region,
            "Type": f"Load Balancer ({lb.get('Type', '')})",
            "Name": lb.get("LoadBalancerName"),
            "ID": lb.get("DNSName"),
            "Created": str(lb.get("CreatedTime", "N/A")),
            "Creator": extract_creator_info(tags),
            "Tags": tags
        })
    return items


def scan_opensearch(region):
    """Discovers AWS OpenSearch domains."""
    data = run_aws_cmd(["aws", "opensearch", "list-domain-names", "--region", region, "--output", "json"])
    items = []
    for d in data.get("DomainNames", []):
        dname = d.get("DomainName")
        items.append({
            "Region": region,
            "Type": "AWS OpenSearch Domain",
            "Name": dname,
            "ID": dname,
            "Created": "N/A",
            "Creator": "N/A",
            "Tags": {}
        })
    return items


def scan_eks_clusters(region):
    """Discovers EKS clusters in a region."""
    data = run_aws_cmd(["aws", "eks", "list-clusters", "--region", region, "--output", "json"])
    items = []
    for c in data.get("clusters", []):
        desc = run_cmd_cluster = run_aws_cmd(["aws", "eks", "describe-cluster", "--name", c, "--region", region, "--output", "json"]).get("cluster", {})
        tags = desc.get("tags", {})
        items.append({
            "Region": region,
            "Type": f"EKS Cluster (v{desc.get('version', '')})",
            "Name": c,
            "ID": desc.get("arn", c),
            "Created": str(desc.get("createdAt", "N/A")),
            "Creator": extract_creator_info(tags),
            "Tags": tags
        })
    return items


def scan_lambda_functions(region):
    """Discovers Lambda functions in a region."""
    data = run_aws_cmd(["aws", "lambda", "list-functions", "--region", region, "--output", "json"])
    items = []
    for fn in data.get("Functions", []):
        tags = fn.get("Tags", {})
        items.append({
            "Region": region,
            "Type": f"Lambda Function ({fn.get('Runtime', '')})",
            "Name": fn.get("FunctionName"),
            "ID": fn.get("FunctionArn"),
            "Created": fn.get("LastModified", "N/A"),
            "Creator": extract_creator_info(tags),
            "Tags": tags
        })
    return items


def scan_s3_buckets():
    """Discovers S3 buckets (Global)."""
    print("[*] Scanning S3 Buckets...")
    data = run_aws_cmd(["aws", "s3api", "list-buckets", "--output", "json"])
    items = []
    for b in data.get("Buckets", []):
        bname = b.get("Name")
        tag_res = run_aws_cmd(["aws", "s3api", "get-bucket-tagging", "--bucket", bname, "--output", "json"])
        tags = normalize_tags(tag_res.get("TagSet", []))
        
        loc_res = run_aws_cmd(["aws", "s3api", "get-bucket-location", "--bucket", bname, "--output", "json"])
        loc = loc_res.get("LocationConstraint")
        region = loc if loc else "us-east-1"

        items.append({
            "Region": region,
            "Type": "S3 Bucket",
            "Name": bname,
            "ID": bname,
            "Created": str(b.get("CreationDate", "N/A")),
            "Creator": extract_creator_info(tags),
            "Tags": tags
        })
    return items


def scan_route53_hosted_zones():
    """Discovers Route53 Hosted Zones (Global)."""
    print("[*] Scanning Route53 Hosted Zones...")
    data = run_aws_cmd(["aws", "route53", "list-hosted-zones", "--output", "json"])
    items = []
    for z in data.get("HostedZones", []):
        zid = z.get("Id", "").split("/")[-1]
        tag_res = run_aws_cmd(["aws", "route53", "list-tags-for-resource", "--resource-type", "hostedzone", "--resource-id", zid, "--output", "json"])
        raw_tags = tag_res.get("ResourceTagSet", {}).get("Tags", []) if tag_res.get("ResourceTagSet") else []
        tags = normalize_tags(raw_tags)
        is_private = z.get("Config", {}).get("PrivateZone", False)
        items.append({
            "Region": "Global",
            "Type": f"Route53 Hosted Zone (Private: {is_private})",
            "Name": z.get("Name"),
            "ID": zid,
            "Created": "N/A",
            "Creator": extract_creator_info(tags),
            "Tags": tags
        })
    return items


def main():
    parser = argparse.ArgumentParser(description="AWS Resource Inventory Utility (Read-Only)")
    parser.add_argument("--output", default="aws_cloud_resources_inventory.csv", help="Output CSV path (default: aws_cloud_resources_inventory.csv)")
    parser.add_argument("--regions", default="us-east-1,us-east-2,us-west-1,us-west-2", help="Comma-separated list of AWS regions to scan")
    args = parser.parse_args()

    # Verify authentication
    verify_authentication()

    target_regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    inventory = []

    # 1. Scan Global Resources
    inventory.extend(scan_s3_buckets())
    inventory.extend(scan_route53_hosted_zones())

    # 2. Scan Regional Resources
    for r in target_regions:
        print(f"[*] Scanning region: {r} ...")
        inventory.extend(scan_ec2_instances(r))
        inventory.extend(scan_vpcs(r))
        inventory.extend(scan_nat_gateways(r))
        inventory.extend(scan_load_balancers(r))
        inventory.extend(scan_opensearch(r))
        inventory.extend(scan_eks_clusters(r))
        inventory.extend(scan_lambda_functions(r))

    print(f"\n[+] Total cloud resources discovered: {len(inventory)}")

    # Write to CSV
    fields = [
        "Region",
        "Resource Type",
        "Resource Name",
        "Resource ID / ARN",
        "Date Created / Launched",
        "Creator / Owner",
        "Tags Summary"
    ]

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(fields)
        for item in inventory:
            tags_summary = "; ".join(f"{k}={v}" for k, v in item.get("Tags", {}).items())
            writer.writerow([
                item.get("Region"),
                item.get("Type"),
                item.get("Name"),
                item.get("ID"),
                item.get("Created"),
                item.get("Creator"),
                tags_summary
            ])

    print(f"[+] Inventory successfully saved to: {args.output}")


if __name__ == "__main__":
    main()
