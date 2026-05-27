package compliance_framework.elbv2_information_movement

# METADATA
# title: ELBv2 listener uses approved protocols and ports
# description: Checks whether listener protocols and ports match approved information movement constraints.
# custom:
#   metric_ids:
#     - ACM_TLS_ENDPOINTS
#   controls:
#     - ctrl-cc6-7-002
#     - ctrl-cc6-7-005
#     - ctrl-cc6-7-008
#     - ctrl-cc6-7-011
risk_templates := [{
	"name": "Load balancer listener allows unapproved information movement",
	"title": "Unapproved Listener Protocol or Port Can Expose Unauthorized Data Paths",
	"statement": "A listener using an unapproved protocol or port can create data movement paths outside the intended architecture. Unreviewed paths reduce visibility, complicate monitoring, and may bypass expected encryption, filtering, or routing controls.",
	"likelihood_hint": "medium",
	"impact_hint": "medium",
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-200",
		"title": "Exposure of Sensitive Information to an Unauthorized Actor",
		"url": "https://cwe.mitre.org/data/definitions/200.html",
	}],
	"remediation": {
		"title": "Restrict listeners to approved protocols and ports",
		"description": "Update listener protocol and port configuration to match the approved allow-lists, or document an approved exception through policy inputs.",
		"tasks": [
			{"title": "Review the listener protocol and port against approved architecture"},
			{"title": "Update the listener to an approved protocol or port"},
			{"title": "Remove stale listeners that are no longer required"},
		],
	},
}]

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
listener_arn := object.get(config, "listener_arn", "unknown")
protocol := upper(object.get(config, "protocol", ""))
port := object.get(config, "port", 0)
approved_listener_protocol_values := data.compliance_framework.elbv2_information_movement.approved_listener_protocols
approved_listener_port_values := data.compliance_framework.elbv2_information_movement.approved_listener_ports
approved_listener_protocols_normalized := {upper(p) | p := approved_listener_protocol_values[_]}

skip_reason := sprintf("Resource type %q is not a listener; this policy only applies to listener records.", [resource_type]) if {
	resource_type != "listener"
}

is_evaluable if {
	resource_type == "listener"
	protocol != "GENEVE"
}

protocol_check_enabled if {
	count(approved_listener_protocol_values) > 0
}

port_check_enabled if {
	count(approved_listener_port_values) > 0
}

protocol_approved if {
	protocol in approved_listener_protocols_normalized
}

port_approved if {
	port in approved_listener_port_values
}

title := sprintf("Validate information movement controls for listener %s", [listener_arn])
description := sprintf("Listener %s uses protocol %q on port %v.", [listener_arn, protocol, port])

violation[{"id": "protocol_not_approved"}] if {
	is_evaluable
	protocol_check_enabled
	not protocol_approved
}

violation[{"id": "port_not_approved"}] if {
	is_evaluable
	port_check_enabled
	not port_approved
}
