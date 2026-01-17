#!/usr/bin/env python3
import json
import sys
from tabulate import tabulate

def usage():
    print(f"Usage: {sys.argv[0]} <json-file>")
    sys.exit(1)


def mapAccessTypes(withAccesses):
    accesses = [access["type"] for access in withAccesses.get("accesses", [])]
    if 'all' in accesses:
        return 'all'
    return ', '.join(accesses)


def create_tables(json_file):
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.loads(f.read())
        access_list = []
        row_filter_list = []
        data_mask_list = []
        for policy in data["policies"]:
            row = []
            row.append(policy['id'])
            row.append(policy['name'])
            resource = policy["resources"]
            resources = [];
            if 'url' in resource:
                row.append(', '.join(resource['url']['values']))
            else:
                row.append("")
            if 'database' in resource:
                row.append(', '.join(resource['database']['values']))
            else:
                row.append("")
            if 'table' in resource:
                row.append(', '.join(resource['table']['values']))
            else:
                row.append("")
            if 'column' in resource:
                row.append(', '.join(resource['column']['values']))
            else:
                row.append("")
            if 'udf' in resource:
                row.append(', '.join(resource['udf']['values']))
            else:
                row.append("")
            if 'policyItems' in policy:
                for policy_item in policy["policyItems"]:
                    users = policy_item.get("users", [])
                    row.append(', '.join(users))
                    row.append(mapAccessTypes(policy_item))
                    access_list.append(row)
            if 'rowFilterPolicyItems' in policy:
                for policy_item in policy["rowFilterPolicyItems"]:
                    users = policy_item.get("users", [])
                    row.append(', '.join(users))
                    row.append(mapAccessTypes(policy_item))
                    row.append(policy_item['rowFilterInfo']['filterExpr'])
                    row_filter_list.append(row)
            if 'dataMaskPolicyItems' in policy:
                for policy_item in policy["dataMaskPolicyItems"]:
                    users = policy_item.get("users", [])
                    row.append(', '.join(users))
                    row.append(mapAccessTypes(policy_item))
                    row.append(policy_item['dataMaskInfo']['dataMaskType'])
                    data_mask_list.append(row)

        common_headers = ["ID", "Name", "URL", "DB", "Table", "Column", "UDF", "Users", "Accesses"]
        print("Access Policies:")
        print(tabulate(access_list, headers=common_headers, tablefmt="grid"))
        print()
        print("Row Filter Policies:")
        print(tabulate(row_filter_list, headers=common_headers + ["Row Filter Expression"], tablefmt="grid"))
        print()
        print("Data Mask Policies:")
        print(tabulate(data_mask_list, headers=common_headers + ["Data Mask Expression"], tablefmt="grid"))


def main():
    if len(sys.argv) == 2:
        json_file = sys.argv[1]
        create_tables(json_file)
    elif len(sys.argv) != 2:
        usage()


if __name__ == "__main__":
    main()
