package compliance_framework.elbv2_listener_https_enforcement_test

import data.compliance_framework.elbv2_listener_https_enforcement as policy

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

test_allowed_plaintext_listener_compliant if {
	arn := base_input.config.listener_arn
	inp := object.union_n([
		base_input,
		{"config": object.union(base_input.config, {"protocol": "HTTP", "port": 80})},
	])
	count(policy.violation) == 0 with input as inp
		with data.allowed_plaintext_listener_arns as [arn]
}

test_tcp_udp_listener_violates if {
	inp := object.union_n([base_input, {"config": object.union(base_input.config, {"protocol": "TCP_UDP", "port": 443})}])
	count(policy.violation) >= 1 with input as inp
}
