package compliance_framework.elbv2_information_movement_test

import data.compliance_framework.elbv2_information_movement as policy

base_input := {
	"schema_version": "v1",
	"source": "aws-elbv2",
	"account": {"account_id": "123456789012"},
	"region": {"name": "us-east-1"},
	"resource": {
		"id": "listener/app/my-alb/abc/def",
		"arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/my-alb/abc/def",
		"type": "listener",
	},
	"config": {
		"listener_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/my-alb/abc/def",
		"load_balancer_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc",
		"protocol": "HTTPS",
		"port": 443,
		"ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
		"certificate_arn": "arn:aws:acm:us-east-1:123456789012:certificate/abc",
	},
	"policy_inputs": {
		"approved_listener_protocols": ["HTTPS", "TLS"],
		"approved_listener_ports": [443],
	},
}

test_https_listener_compliant if {
	count(policy.violation) == 0 with input as base_input
}

test_http_listener_violates if {
	inp := object.union_n([base_input, {"config": object.union(base_input.config, {"protocol": "HTTP", "port": 80})}])
	count(policy.violation) >= 1 with input as inp
}

test_geneve_listener_skipped if {
	inp := object.union_n([base_input, {"config": object.union(base_input.config, {"protocol": "GENEVE", "port": 6081})}])
	count(policy.violation) == 0 with input as inp
}

test_non_listener_record_skipped if {
	inp := object.union_n([base_input, {"resource": object.union(base_input.resource, {"type": "load-balancer"})}])
	count(policy.violation) == 0 with input as inp
}

test_empty_approved_lists_pass if {
	inp := object.union_n([
		object.remove(base_input, ["policy_inputs"]),
		{"config": object.union(base_input.config, {"protocol": "HTTP", "port": 80})},
		{"policy_inputs": {"approved_listener_protocols": [], "approved_listener_ports": []}},
	])
	count(policy.violation) == 0 with input as inp
}

test_missing_approved_lists_pass if {
	inp := object.union_n([
		object.remove(base_input, ["policy_inputs"]),
		{"config": object.union(base_input.config, {"protocol": "HTTP", "port": 80})},
	])
	count(policy.violation) == 0 with input as inp
}

test_lowercase_approved_protocol_matches_normalized_listener_protocol if {
	inp := object.union_n([
		base_input,
		{"policy_inputs": object.union(base_input.policy_inputs, {"approved_listener_protocols": ["https"]})},
	])
	count(policy.violation) == 0 with input as inp
}
