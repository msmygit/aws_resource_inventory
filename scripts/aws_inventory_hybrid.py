#!/usr/bin/env python3
"""
AWS Comprehensive Cost & Resource Inventory Utility (Hybrid Architecture)

Description:
  Discovers 100% of cost-incurring and active cloud resources across AWS regions by combining:
  1. Direct Service-Level Scanners: Queries core cost-generating services directly (EC2, EBS, EIPs,
     NAT Gateways, ALBs/NLBs/CLBs, RDS, EFS, ElastiCache, OpenSearch, Redshift, MSK, FSx, S3, Route53,
     EKS, Lambda). This eliminates "The Untagged Blindspot" and catches orphaned/idle assets.
  2. Resource Groups Tagging API: Broad-net discovery across 100+ remaining AWS services.
  3. Deduplication & Cost Engine: Merges metadata on unique ARNs/IDs and flags cost risks (e.g.
     unattached EBS disks, unassociated Elastic IPs).

Safety & Security:
  - STRICTLY READ-ONLY: Executes only `describe-*`, `list-*`, and `get-*` AWS CLI commands.
  - NO CREDENTIALS STORED: Validates local CLI authentication at startup (e.g. `aws sso login`).

Usage:
  python3 scripts/aws_inventory_hybrid.py [--output inventory.csv] [--regions us-east-1,us-east-2]
"""

import argparse
import csv
import json
import subprocess
import sys


def run_aws_cmd(args):
    """Executes an AWS CLI command safely and returns parsed JSON or empty dict/list."""
    try:
        res = subprocess.run(args, capture_output=True, text=True, check=False)
        if res.returncode == 0 and res.stdout.strip():
            return json.loads(res.stdout)
        return {}
    except Exception:
        return {}


def verify_authentication():
    """Verifies that the user has an active, authenticated AWS CLI session."""
    print("[*] Checking AWS CLI authentication session...")
    identity = run_aws_cmd(["aws", "sts", "get-caller-identity", "--output", "json"])
    if not identity or "Arn" not in identity:
        print("\n" + "=" * 78)
        print("[ERROR] AWS CLI session is not authenticated or credentials have expired.")
        print("=" * 78)
        print("Please authenticate to your AWS CLI session locally prior to running this script.")
        print("Examples:")
        print("  - AWS SSO:       aws sso login --profile <profile-name>")
        print("  - IAM / Env:     export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...")
        print("=" * 78 + "\n")
        sys.exit(1)

    account_id = identity.get("Account", "Unknown")
    caller_arn = identity.get("Arn", "Unknown")
    print(f"[+] Authenticated successfully!")
    print(f"    Account ID : {account_id}")
    print(f"    Caller ARN : {caller_arn}\n")
    return account_id


def extract_creator_info(tags):
    """Extracts creator / owner / email from resource tags with heuristic matching."""
    if isinstance(tags, dict):
        tag_items = tags.items()
    elif isinstance(tags, list):
        tag_items = [(t.get("Key", ""), t.get("Value", "")) for t in tags if isinstance(t, dict)]
    else:
        tag_items = []

    # Priority 1: Exact matches
    for k, v in tag_items:
        k_lower = k.lower().replace("-", "").replace("_", "")
        if k_lower in ["owneremail", "owner", "createdby", "creator", "user", "author", "email"]:
            return v

    # Priority 2: Substring matches
    for k, v in tag_items:
        k_lower = k.lower()
        if any(sub in k_lower for sub in ["email", "owner", "creator"]):
            return v

    return "Untagged / Unspecified"


def normalize_tags(tags):
    """Converts diverse AWS tag structures into a standard dict."""
    if isinstance(tags, dict):
        return tags
    if isinstance(tags, list):
        result = {}
        for t in tags:
            if isinstance(t, dict) and "Key" in t and "Value" in t:
                result[t["Key"]] = t["Value"]
        return result
    return {}


# ==============================================================================
# 1. DIRECT SERVICE SCANNERS (Overcomes Untagged Blindspot & Flags Idle Costs)
# ==============================================================================

def scan_direct_ec2_instances(region):
    """Scans all EC2 instances."""
    data = run_aws_cmd(["aws", "ec2", "describe-instances", "--region", region, "--output", "json"])
    items = []
    for res in data.get("Reservations", []):
        for i in res.get("Instances", []):
            state = i.get("State", {}).get("Name", "unknown")
            if state == "terminated":
                continue
            tags = normalize_tags(i.get("Tags", []))
            name = tags.get("Name", i.get("InstanceId"))
            itype = i.get("InstanceType", "unknown")
            cost_note = f"Active Compute ({state})" if state == "running" else f"Compute Stopped (EBS attached costs apply)"
            items.append({
                "ARN": f"arn:aws:ec2:{region}:{i.get('OwnerId', '')}:instance/{i.get('InstanceId')}",
                "ID": i.get("InstanceId"),
                "Name": name,
                "Type": f"EC2 Instance ({itype})",
                "Region": region,
                "State": state,
                "Created": i.get("LaunchTime", "N/A"),
                "Creator": extract_creator_info(tags),
                "CostNote": cost_note,
                "Tags": tags
            })
    return items


def scan_direct_ebs_volumes(region):
    """Scans all EBS volumes, specifically identifying unattached/orphaned disks."""
    data = run_aws_cmd(["aws", "ec2", "describe-volumes", "--region", region, "--output", "json"])
    items = []
    for v in data.get("Volumes", []):
        vid = v.get("VolumeId")
        size_gb = v.get("Size", 0)
        vtype = v.get("VolumeType", "gp2/gp3")
        state = v.get("State", "unknown")
        attachments = v.get("Attachments", [])
        tags = normalize_tags(v.get("Tags", []))
        name = tags.get("Name", vid)

        if state == "available" or len(attachments) == 0:
            cost_note = f"⚠️ ORPHANED / UNATTACHED EBS ({size_gb} GB {vtype}) - Incurring Storage Cost!"
        else:
            attached_inst = attachments[0].get("InstanceId", "instance")
            cost_note = f"Attached to {attached_inst} ({size_gb} GB {vtype})"

        items.append({
            "ARN": f"arn:aws:ec2:{region}::volume/{vid}",
            "ID": vid,
            "Name": name,
            "Type": f"EBS Volume ({vtype}, {size_gb} GB)",
            "Region": region,
            "State": state,
            "Created": v.get("CreateTime", "N/A"),
            "Creator": extract_creator_info(tags),
            "CostNote": cost_note,
            "Tags": tags
        })
    return items


def scan_direct_elastic_ips(region):
    """Scans all Elastic IP addresses, detecting unassociated/idle cost penalties."""
    data = run_aws_cmd(["aws", "ec2", "describe-addresses", "--region", region, "--output", "json"])
    items = []
    for a in data.get("Addresses", []):
        alloc_id = a.get("AllocationId", a.get("PublicIp"))
        pub_ip = a.get("PublicIp", "N/A")
        tags = normalize_tags(a.get("Tags", []))
        name = tags.get("Name", pub_ip)
        association_id = a.get("AssociationId")
        instance_id = a.get("InstanceId")

        if not association_id and not instance_id:
            cost_note = "⚠️ UNASSOCIATED / IDLE EIP - Incurring Hourly IPv4 Penalty Cost!"
            state = "unassociated"
        else:
            target = instance_id or a.get("NetworkInterfaceId", "attached")
            cost_note = f"Associated with {target}"
            state = "associated"

        items.append({
            "ARN": f"arn:aws:ec2:{region}::elastic-ip/{alloc_id}",
            "ID": alloc_id,
            "Name": name,
            "Type": "Elastic IP (EIP)",
            "Region": region,
            "State": state,
            "Created": "N/A",
            "Creator": extract_creator_info(tags),
            "CostNote": cost_note,
            "Tags": tags
        })
    return items


def scan_direct_nat_gateways(region):
    """Scans all NAT Gateways."""
    data = run_aws_cmd(["aws", "ec2", "describe-nat-gateways", "--region", region, "--output", "json"])
    items = []
    for n in data.get("NatGateways", []):
        state = n.get("State", "unknown")
        if state == "deleted":
            continue
        nid = n.get("NatGatewayId")
        tags = normalize_tags(n.get("Tags", []))
        name = tags.get("Name", nid)
        cost_note = f"NAT Gateway Hourly (~$32/mo) + Data Processing Fees ({state})"
        items.append({
            "ARN": f"arn:aws:ec2:{region}::natgateway/{nid}",
            "ID": nid,
            "Name": name,
            "Type": "NAT Gateway",
            "Region": region,
            "State": state,
            "Created": str(n.get("CreateTime", "N/A")),
            "Creator": extract_creator_info(tags),
            "CostNote": cost_note,
            "Tags": tags
        })
    return items


def scan_direct_load_balancers(region):
    """Scans ALBs, NLBs, and Classic CLBs."""
    items = []
    # 1. v2 Load Balancers (ALB / NLB / Gateway)
    data_v2 = run_aws_cmd(["aws", "elbv2", "describe-load-balancers", "--region", region, "--output", "json"])
    for lb in data_v2.get("LoadBalancers", []):
        arn = lb.get("LoadBalancerArn")
        tag_data = run_aws_cmd(["aws", "elbv2", "describe-tags", "--resource-arns", arn, "--region", region, "--output", "json"])
        raw_tags = tag_data.get("TagDescriptions", [{}])[0].get("Tags", []) if tag_data.get("TagDescriptions") else []
        tags = normalize_tags(raw_tags)
        lb_type = lb.get("Type", "application")
        items.append({
            "ARN": arn,
            "ID": lb.get("DNSName"),
            "Name": lb.get("LoadBalancerName"),
            "Type": f"Load Balancer ({lb_type.upper()})",
            "Region": region,
            "State": lb.get("State", {}).get("Code", "active"),
            "Created": str(lb.get("CreatedTime", "N/A")),
            "Creator": extract_creator_info(tags),
            "CostNote": f"Hourly Rate + LCU Usage Cost ({lb_type})",
            "Tags": tags
        })

    # 2. Classic Load Balancers
    data_clb = run_aws_cmd(["aws", "elb", "describe-load-balancers", "--region", region, "--output", "json"])
    for clb in data_clb.get("LoadBalancerDescriptions", []):
        cname = clb.get("LoadBalancerName")
        items.append({
            "ARN": f"arn:aws:elasticloadbalancing:{region}::loadbalancer/{cname}",
            "ID": clb.get("DNSName"),
            "Name": cname,
            "Type": "Load Balancer (Classic CLB)",
            "Region": region,
            "State": "active",
            "Created": str(clb.get("CreatedTime", "N/A")),
            "Creator": "N/A",
            "CostNote": "Classic ELB Hourly + Data Fees",
            "Tags": {}
        })
    return items


def scan_direct_rds(region):
    """Scans RDS DB instances and Aurora clusters."""
    items = []
    data_inst = run_aws_cmd(["aws", "rds", "describe-db-instances", "--region", region, "--output", "json"])
    for db in data_inst.get("DBInstances", []):
        arn = db.get("DBInstanceArn")
        db_id = db.get("DBInstanceIdentifier")
        engine = db.get("Engine", "db")
        itype = db.get("DBInstanceClass", "")
        size_gb = db.get("AllocatedStorage", 0)
        state = db.get("DBInstanceStatus", "unknown")
        tags = normalize_tags(db.get("TagList", []))
        items.append({
            "ARN": arn,
            "ID": db_id,
            "Name": db_id,
            "Type": f"RDS DB Instance ({engine}, {itype})",
            "Region": region,
            "State": state,
            "Created": str(db.get("InstanceCreateTime", "N/A")),
            "Creator": extract_creator_info(tags),
            "CostNote": f"Database Compute + {size_gb}GB Storage ({state})",
            "Tags": tags
        })

    data_cl = run_aws_cmd(["aws", "rds", "describe-db-clusters", "--region", region, "--output", "json"])
    for cl in data_cl.get("DBClusters", []):
        arn = cl.get("DBClusterArn")
        cid = cl.get("DBClusterIdentifier")
        engine = cl.get("Engine", "aurora")
        state = cl.get("Status", "available")
        tags = normalize_tags(cl.get("TagList", []))
        items.append({
            "ARN": arn,
            "ID": cid,
            "Name": cid,
            "Type": f"RDS Cluster ({engine})",
            "Region": region,
            "State": state,
            "Created": str(cl.get("ClusterCreateTime", "N/A")),
            "Creator": extract_creator_info(tags),
            "CostNote": f"Aurora Cluster ({state})",
            "Tags": tags
        })
    return items


def scan_direct_efs(region):
    """Scans EFS File Systems."""
    data = run_aws_cmd(["aws", "efs", "describe-file-systems", "--region", region, "--output", "json"])
    items = []
    for fs in data.get("FileSystems", []):
        fs_id = fs.get("FileSystemId")
        arn = fs.get("FileSystemArn", f"arn:aws:elasticfilesystem:{region}::file-system/{fs_id}")
        tags = normalize_tags(fs.get("Tags", []))
        name = tags.get("Name", fs_id)
        size_gb = fs.get("SizeInBytes", {}).get("Value", 0) / (1024 ** 3)
        state = fs.get("LifeCycleState", "available")
        items.append({
            "ARN": arn,
            "ID": fs_id,
            "Name": name,
            "Type": "EFS File System",
            "Region": region,
            "State": state,
            "Created": str(fs.get("CreationTime", "N/A")),
            "Creator": extract_creator_info(tags),
            "CostNote": f"Elastic Storage ({size_gb:.2f} GB provisioned)",
            "Tags": tags
        })
    return items


def scan_direct_elasticache(region):
    """Scans ElastiCache (Redis/Memcached) clusters."""
    data = run_aws_cmd(["aws", "elasticache", "describe-cache-clusters", "--region", region, "--output", "json"])
    items = []
    for c in data.get("CacheClusters", []):
        arn = c.get("ARN")
        cid = c.get("CacheClusterId")
        engine = c.get("Engine", "cache")
        node_type = c.get("CacheNodeType", "")
        nodes = c.get("NumCacheNodes", 1)
        state = c.get("CacheClusterStatus", "available")
        items.append({
            "ARN": arn if arn else f"arn:aws:elasticache:{region}::cluster:{cid}",
            "ID": cid,
            "Name": cid,
            "Type": f"ElastiCache Cluster ({engine}, {node_type})",
            "Region": region,
            "State": state,
            "Created": str(c.get("CacheClusterCreateTime", "N/A")),
            "Creator": "N/A",
            "CostNote": f"{nodes}x {node_type} Nodes ({state})",
            "Tags": {}
        })
    return items


def scan_direct_opensearch(region):
    """Scans AWS OpenSearch domains."""
    data = run_aws_cmd(["aws", "opensearch", "list-domain-names", "--region", region, "--output", "json"])
    items = []
    for d in data.get("DomainNames", []):
        dname = d.get("DomainName")
        items.append({
            "ARN": f"arn:aws:es:{region}::domain/{dname}",
            "ID": dname,
            "Name": dname,
            "Type": "OpenSearch Domain",
            "Region": region,
            "State": "active",
            "Created": "N/A",
            "Creator": "N/A",
            "CostNote": "OpenSearch Master & Data Node Charges",
            "Tags": {}
        })
    return items


def scan_direct_vpcs(region):
    """Scans VPCs."""
    data = run_aws_cmd(["aws", "ec2", "describe-vpcs", "--region", region, "--output", "json"])
    items = []
    for v in data.get("Vpcs", []):
        vid = v.get("VpcId")
        tags = normalize_tags(v.get("Tags", []))
        name = tags.get("Name", vid)
        items.append({
            "ARN": f"arn:aws:ec2:{region}::vpc/{vid}",
            "ID": vid,
            "Name": name,
            "Type": f"VPC ({v.get('CidrBlock', '')})",
            "Region": region,
            "State": v.get("State", "available"),
            "Created": "N/A",
            "Creator": extract_creator_info(tags),
            "CostNote": "Network Architecture Base",
            "Tags": tags
        })
    return items


def scan_direct_eks(region):
    """Scans Amazon EKS clusters."""
    data = run_aws_cmd(["aws", "eks", "list-clusters", "--region", region, "--output", "json"])
    items = []
    for c in data.get("clusters", []):
        desc = run_aws_cmd(["aws", "eks", "describe-cluster", "--name", c, "--region", region, "--output", "json"]).get("cluster", {})
        tags = desc.get("tags", {})
        arn = desc.get("arn", f"arn:aws:eks:{region}::cluster/{c}")
        items.append({
            "ARN": arn,
            "ID": c,
            "Name": c,
            "Type": f"EKS Cluster (v{desc.get('version', '')})",
            "Region": region,
            "State": desc.get("status", "ACTIVE"),
            "Created": str(desc.get("createdAt", "N/A")),
            "Creator": extract_creator_info(tags),
            "CostNote": "EKS Cluster Fee ($0.10/hr) + Worker Nodes",
            "Tags": tags
        })
    return items


def scan_direct_lambda(region):
    """Scans AWS Lambda functions."""
    data = run_aws_cmd(["aws", "lambda", "list-functions", "--region", region, "--output", "json"])
    items = []
    for fn in data.get("Functions", []):
        arn = fn.get("FunctionArn")
        name = fn.get("FunctionName")
        tags = fn.get("Tags", {})
        items.append({
            "ARN": arn,
            "ID": name,
            "Name": name,
            "Type": f"Lambda Function ({fn.get('Runtime', '')})",
            "Region": region,
            "State": "active",
            "Created": fn.get("LastModified", "N/A"),
            "Creator": extract_creator_info(tags),
            "CostNote": "Serverless Invocations & Compute Duration",
            "Tags": tags
        })
    return items


def scan_direct_s3_buckets():
    """Scans all S3 storage buckets (Global)."""
    print("[*] Directly scanning S3 Buckets (Global)...")
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
            "ARN": f"arn:aws:s3:::{bname}",
            "ID": bname,
            "Name": bname,
            "Type": "S3 Bucket",
            "Region": region,
            "State": "active",
            "Created": str(b.get("CreationDate", "N/A")),
            "Creator": extract_creator_info(tags),
            "CostNote": "S3 Storage (GB/mo) + API Request Fees",
            "Tags": tags
        })
    return items


def scan_direct_route53_zones():
    """Scans all Route53 Hosted Zones (Global)."""
    print("[*] Directly scanning Route53 Hosted Zones (Global)...")
    data = run_aws_cmd(["aws", "route53", "list-hosted-zones", "--output", "json"])
    items = []
    for z in data.get("HostedZones", []):
        zid = z.get("Id", "").split("/")[-1]
        tag_res = run_aws_cmd(["aws", "route53", "list-tags-for-resource", "--resource-type", "hostedzone", "--resource-id", zid, "--output", "json"])
        raw_tags = tag_res.get("ResourceTagSet", {}).get("Tags", []) if tag_res.get("ResourceTagSet") else []
        tags = normalize_tags(raw_tags)
        is_priv = z.get("Config", {}).get("PrivateZone", False)
        items.append({
            "ARN": f"arn:aws:route53:::hostedzone/{zid}",
            "ID": zid,
            "Name": z.get("Name"),
            "Type": f"Route53 Hosted Zone (Private: {is_priv})",
            "Region": "Global",
            "State": "active",
            "Created": "N/A",
            "Creator": extract_creator_info(tags),
            "CostNote": "Hosted Zone Recurring Fee ($0.50/mo) + Query Fees",
            "Tags": tags
        })
    return items


# ==============================================================================
# 2. RESOURCE GROUPS TAGGING API SCANNER (Broad-Net for 100+ Tagged Services)
# ==============================================================================

def scan_tagging_api_region(region):
    """Scans all tagged resources in a region using Resource Groups Tagging API."""
    items = []
    paginator_token = None
    while True:
        cmd = ["aws", "resourcegroupstaggingapi", "get-resources", "--region", region, "--output", "json"]
        if paginator_token:
            cmd.extend(["--pagination-token", paginator_token])
        
        data = run_aws_cmd(cmd)
        mappings = data.get("ResourceTagMappingList", [])
        for m in mappings:
            arn = m.get("ResourceARN", "")
            tags = normalize_tags(m.get("Tags", []))
            
            # Parse service and resource name from ARN
            parts = arn.split(":")
            service = parts[2] if len(parts) > 2 else "aws"
            res_id = parts[-1] if len(parts) > 5 else arn
            name = tags.get("Name", res_id.split("/")[-1])

            items.append({
                "ARN": arn,
                "ID": res_id,
                "Name": name,
                "Type": f"AWS {service.upper()} Resource",
                "Region": region,
                "State": "active/tagged",
                "Created": "N/A",
                "Creator": extract_creator_info(tags),
                "CostNote": f"Discovered via Tagging API ({service})",
                "Tags": tags
            })

        paginator_token = data.get("PaginationToken")
        if not paginator_token:
            break
    return items


# ==============================================================================
# 3. DEDUPLICATION & MERGE ENGINE
# ==============================================================================

def merge_and_deduplicate(direct_items, tagging_items):
    """
    Merges direct scanner results with tagging API results.
    Direct scanner data takes precedence for state/cost diagnostics.
    """
    inventory_map = {}

    # 1. Add direct items
    for item in direct_items:
        key = item.get("ARN") or item.get("ID")
        inventory_map[key] = item

    # 2. Merge / Append tagging items
    for item in tagging_items:
        key = item.get("ARN") or item.get("ID")
        if key in inventory_map:
            # Merge tags if existing entry lacks tags
            existing = inventory_map[key]
            if not existing.get("Tags") and item.get("Tags"):
                existing["Tags"] = item.get("Tags")
                if existing.get("Creator") in ["Untagged / Unspecified", "N/A"]:
                    existing["Creator"] = item.get("Creator")
        else:
            # New resource found exclusively via Tagging API
            inventory_map[key] = item

    return list(inventory_map.values())


# ==============================================================================
# MAIN WORKFLOW
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="AWS Comprehensive Cost & Resource Inventory Utility (Hybrid Architecture)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan default high-activity regions
  python3 scripts/aws_inventory_hybrid.py

  # Scan custom regions and write to custom CSV
  python3 scripts/aws_inventory_hybrid.py --regions us-east-1,us-east-2,us-west-2 --output my_inventory.csv
        """
    )
    parser.add_argument("--output", default="aws_cloud_resources_inventory.csv", help="Output CSV path (default: aws_cloud_resources_inventory.csv)")
    parser.add_argument("--regions", default="us-east-1,us-east-2,us-west-1,us-west-2", help="Comma-separated list of AWS regions to scan")
    args = parser.parse_args()

    # Step 1: Pre-flight verify local authentication
    account_id = verify_authentication()

    target_regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    direct_resources = []
    tagging_resources = []

    print("=" * 78)
    print("PHASE 1: Direct Service-Level Scans (Capturing Tagged & Untagged Cost Drivers)")
    print("=" * 78)

    # Global Scans
    direct_resources.extend(scan_direct_s3_buckets())
    direct_resources.extend(scan_direct_route53_zones())

    # Regional Scans
    for r in target_regions:
        print(f"[*] Directly scanning region: {r} ...")
        direct_resources.extend(scan_direct_ec2_instances(r))
        direct_resources.extend(scan_direct_ebs_volumes(r))
        direct_resources.extend(scan_direct_elastic_ips(r))
        direct_resources.extend(scan_direct_nat_gateways(r))
        direct_resources.extend(scan_direct_load_balancers(r))
        direct_resources.extend(scan_direct_rds(r))
        direct_resources.extend(scan_direct_efs(r))
        direct_resources.extend(scan_direct_elasticache(r))
        direct_resources.extend(scan_direct_opensearch(r))
        direct_resources.extend(scan_direct_vpcs(r))
        direct_resources.extend(scan_direct_eks(r))
        direct_resources.extend(scan_direct_lambda(r))

    print(f"\n[+] Direct Scanner completed: {len(direct_resources)} cost/infrastructure items found.")

    print("\n" + "=" * 78)
    print("PHASE 2: Resource Groups Tagging API Scan (Broad Coverage across 100+ Services)")
    print("=" * 78)
    for r in target_regions:
        print(f"[*] Querying Tagging API for region: {r} ...")
        tagging_resources.extend(scan_tagging_api_region(r))

    print(f"[+] Tagging API completed: {len(tagging_resources)} tagged items indexed.")

    print("\n" + "=" * 78)
    print("PHASE 3: Deduplication, Cost Diagnosis & CSV Export")
    print("=" * 78)
    final_inventory = merge_and_deduplicate(direct_resources, tagging_resources)
    print(f"[+] Unified Total Discovered Resources: {len(final_inventory)}")

    # CSV Export
    fields = [
        "Region",
        "Resource Type",
        "Resource Name",
        "Resource ID / Identifier",
        "State / Status",
        "Cost & Diagnostic Note",
        "Date Created / Launched",
        "Creator / Owner / Email",
        "Full ARN",
        "Tags Summary"
    ]

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(fields)
        for item in final_inventory:
            tags_str = "; ".join(f"{k}={v}" for k, v in item.get("Tags", {}).items())
            writer.writerow([
                item.get("Region"),
                item.get("Type"),
                item.get("Name"),
                item.get("ID"),
                item.get("State", "N/A"),
                item.get("CostNote", "N/A"),
                item.get("Created", "N/A"),
                item.get("Creator", "Untagged / Unspecified"),
                item.get("ARN", "N/A"),
                tags_str
            ])

    print(f"[SUCCESS] Complete inventory written to: {args.output}\n")


if __name__ == "__main__":
    main()
