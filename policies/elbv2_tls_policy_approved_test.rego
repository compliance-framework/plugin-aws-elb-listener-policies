package compliance_framework.elbv2_tls_policy_approved_test

import data.compliance_framework.elbv2_tls_policy_approved as policy

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
	"policy_inputs": {"approved_ssl_policies": ["ELBSecurityPolicy-TLS13-1-2-2021-06"]},
}

test_https_listener_compliant if {
	count(policy.violation) == 0 with input as base_input
}

test_unapproved_tls_policy_violates if {
	inp := object.union_n([base_input, {"config": object.union(base_input.config, {"ssl_policy": "ELBSecurityPolicy-TLS-1-0-2015-04"})}])
	count(policy.violation) >= 1 with input as inp
}

test_http_listener_skipped if {
	inp := object.union_n([base_input, {"config": object.union(base_input.config, {"protocol": "HTTP", "port": 80, "ssl_policy": ""})}])
	count(policy.violation) == 0 with input as inp
}

test_empty_tls_policy_violates if {
	inp := object.union_n([base_input, {"config": object.union(base_input.config, {"ssl_policy": ""})}])
	count(policy.violation) >= 1 with input as inp
}

test_geneve_listener_skipped if {
	inp := object.union_n([base_input, {"config": object.union(base_input.config, {"protocol": "GENEVE", "port": 6081, "ssl_policy": ""})}])
	count(policy.violation) == 0 with input as inp
}

test_non_listener_record_skipped if {
	inp := object.union_n([base_input, {"resource": object.union(base_input.resource, {"type": "load-balancer"})}])
	count(policy.violation) == 0 with input as inp
}
