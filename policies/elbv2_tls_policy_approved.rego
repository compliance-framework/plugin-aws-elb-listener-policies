package compliance_framework.elbv2_tls_policy_approved

# METADATA
# title: ELBv2 listener uses approved TLS policy
# description: Checks whether HTTPS/TLS listeners use an approved AWS SSL policy.
# custom:
#   metric_ids:
#     - ACM_TLS_ENDPOINTS
#   controls:
#     - ctrl-cc6-7-007
#     - ctrl-cc6-7-008
#     - ctrl-cc6-7-010
#     - ctrl-cc6-7-011
risk_templates := [{
	"name": "Load balancer listener uses an unapproved TLS policy",
	"title": "Weak TLS Policy May Permit Inadequate Encryption",
	"statement": "A listener using an unapproved SSL policy can negotiate weak protocol versions or cipher suites. Weak cryptography increases the likelihood that protected traffic can be decrypted, downgraded, or otherwise exposed in transit.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-326",
		"title": "Inadequate Encryption Strength",
		"url": "https://cwe.mitre.org/data/definitions/326.html",
	}],
	"remediation": {
		"title": "Use an approved ELB SSL policy",
		"description": "Configure HTTPS and TLS listeners with an SSL policy from the approved allow-list maintained for this environment.",
		"tasks": [
			{"title": "Identify the listener using the unapproved SSL policy"},
			{"title": "Select an approved AWS ELB SSL policy"},
			{"title": "Update the listener and verify clients can negotiate successfully"},
		],
	},
}]

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
listener_arn := object.get(config, "listener_arn", "unknown")
protocol := upper(object.get(config, "protocol", ""))
ssl_policy := object.get(config, "ssl_policy", "")
approved_ssl_policy_names := data.approved_ssl_policies

skip_reason := sprintf("Resource type %q is not a listener; this policy only applies to listener records.", [resource_type]) if {
	resource_type != "listener"
}

is_tls_listener if {
	resource_type == "listener"
	protocol in {"HTTPS", "TLS"}
}

approved_tls_policy if {
	ssl_policy in approved_ssl_policy_names
}

title := sprintf("Validate TLS policy for listener %s", [listener_arn])
description := sprintf("Listener %s uses SSL policy %q.", [listener_arn, ssl_policy])

violation[{"id": "weak_tls_policy"}] if {
	is_tls_listener
	not approved_tls_policy
}
