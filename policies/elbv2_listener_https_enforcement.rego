package compliance_framework.elbv2_listener_https_enforcement

import future.keywords.in

# METADATA
# title: ELBv2 listener enforces HTTPS/TLS
# description: Checks whether a client-facing listener uses an encrypted protocol.
# custom:
#   metric_ids:
#     - ACM_TLS_ENDPOINTS
#   controls:
#     - ctrl-cc6-2-014
#     - ctrl-cc6-2-018
#     - ctrl-cc6-3-004
#     - ctrl-cc6-7-001
#     - ctrl-cc6-7-004
#     - ctrl-cc6-7-007
#     - ctrl-cc6-7-009
#     - ctrl-cc6-7-010
risk_templates := [{
	"name": "Load balancer listener accepts unencrypted client traffic",
	"title": "Plaintext Listener Exposes Data In Transit to Interception",
	"statement": "A listener serving HTTP, TCP, or UDP terminates client connections without TLS. Credentials and sensitive data can traverse the network in cleartext, allowing an on-path attacker to read or modify traffic and compromise confidentiality and integrity.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-319",
		"title": "Cleartext Transmission of Sensitive Information",
		"url": "https://cwe.mitre.org/data/definitions/319.html",
	}],
	"remediation": {
		"title": "Require HTTPS/TLS on client-facing listeners",
		"description": "Replace plaintext listeners with HTTPS or TLS listeners using an approved SSL policy and a valid certificate, or record an explicit time-bound exception.",
		"tasks": [
			{"title": "Create an HTTPS or TLS listener with an approved SSL policy"},
			{"title": "Attach a valid ACM certificate to the listener"},
			{"title": "Redirect or remove the plaintext listener"},
		],
	},
}]

config := object.get(input, "config", {})
policy_inputs := object.get(input, "policy_inputs", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
listener_arn := object.get(config, "listener_arn", "unknown")
protocol := upper(object.get(config, "protocol", ""))
allowed_plaintext := object.get(policy_inputs, "allowed_plaintext_listener_arns", [])

skip_reason := sprintf("Resource type %q is not a listener; this policy only applies to listener records.", [resource_type]) if {
	resource_type != "listener"
}

is_evaluable if {
	resource_type == "listener"
	protocol != "GENEVE"
}

plaintext_protocol if {
	protocol in {"HTTP", "TCP", "UDP"}
}

plaintext_allowed if {
	listener_arn in allowed_plaintext
}

title := sprintf("Validate HTTPS enforcement for listener %s", [listener_arn])
description := sprintf("Listener %s uses protocol %q.", [listener_arn, protocol])

violation[{"id": "plaintext_listener"}] if {
	is_evaluable
	plaintext_protocol
	not plaintext_allowed
}
