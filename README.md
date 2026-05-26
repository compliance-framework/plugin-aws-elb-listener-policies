# AWS RDS policies for use in Compliance Framework plugins

## Testing


```shell
opa test policies
```

## Bundling

Policies are built into bundle to make distribution easier. 

You can easily build the policies by running 
```shell
make build
```

## Implemented RDS policy packages

This bundle includes focused, document-aligned policies:

- `compliance_framework.rds_database_storage_encryption`
- `compliance_framework.rds_snapshot_encryption`
- `compliance_framework.rds_network_boundary`
- `compliance_framework.rds_iam_database_auth`
- `compliance_framework.rds_tls_enforcement`
- `compliance_framework.rds_deletion_protection`
- `compliance_framework.rds_deletion_audit_events`
- `compliance_framework.rds_backup_retention`
- `compliance_framework.rds_snapshot_coverage`
- `compliance_framework.rds_pitr_freshness`
- `compliance_framework.rds_multi_az_redundancy`
- `compliance_framework.rds_snapshot_restore_access`
- `compliance_framework.rds_snapshot_status`
- `compliance_framework.rds_log_exports`
- `compliance_framework.rds_capacity_monitoring`
- `compliance_framework.rds_backup_restore_events`
- `compliance_framework.rds_management_audit_events`

Each policy package reads the normalized `aws-rds-aurora-psql` plugin input
schema. Every package has a resource-aware `title` and a package-level
`description` that explains the observed state for the current RDS instance,
cluster, or snapshot context.

Snapshot encryption, status, and restore-access policies evaluate standalone
snapshot records only. The collector is expected to emit every manual snapshot
as its own record and only the latest automated snapshot for each database
source, so retained older automated snapshots do not create stale policy
results. Snapshot coverage is evaluated on the parent database resource using
the selected snapshot list attached to that resource.

Common optional `policy_inputs`:

- `minimum_backup_retention_days`, default `1`
- `maximum_personal_information_retention_days`, default `365`
- `maximum_pitr_lag_hours`, default `24`
- `approved_snapshot_accounts`, default `[]`
- `fail_on_unknown_snapshot_sharing`, default `true`
- `required_log_exports`, default `["postgresql"]`
- `require_multi_az`, default `true`
- `require_snapshot_history`, default `true`
- `require_automated_snapshot`, default `false`
- `require_access_removal_events`, `require_rds_management_audit_events`,
  `require_backup_events`, `require_restore_events`,
  `require_capacity_metrics`, `require_enhanced_monitoring`,
  `require_deletion_audit_events`, and `require_disposal_audit_events`,
  all default `false`

## Running policies locally

```shell
opa eval -I -b policies -f pretty data.compliance_framework.rds_database_storage_encryption.violation <<EOF
{
  "resource": {"type": "db-instance"},
  "config": {
    "storage_encrypted": false,
    "kms_key_id": "",
    "publicly_accessible": true,
    "vpc_security_groups": [],
    "iam_database_authentication_enabled": false,
    "ssl_enforcement": {},
    "deletion_protection": false
  },
  "policy_inputs": {}
}
EOF
```

## Writing policies.

Policies are written in the [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) language.

```rego
package ssh.deny_password_auth

import future.keywords.in

violation[{
    "title": "Host SSH is using password authentication.",
    "description": "Host SSH should not use password, as this is insecure to brute force attacks from external sources.",
    "remarks": "Migrate to using SSH Public Keys, and switch off password authentication."
}] {
	"yes" in input.passwordauthentication
}
```

## Metadata

Plugins expect policies to contain a metadata section as comments, with a `# METADATA` line to indicate it. This metadata should be in a YAML format, and contain a title and description of the policy. Other configuration can be set also, like the schedule that a policy should run on, or the control that it is linked to.

Any other comments can be added as normal (before and after) with a line separator between them and the metadata.

Here is an example metadata:
```opa
# your custom comment

# METADATA
# title: <your-title>
# description: <your-description>
# custom:
#   controls:
#     - <control-id>
#   schedule: "<cron-string>"

# your custom comment
```
