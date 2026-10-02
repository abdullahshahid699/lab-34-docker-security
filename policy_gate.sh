#!/usr/bin/env bash

run_policy_gate() {
    local trivy_json="$1"
    local policy_yaml="$2"

    local critical_limit
    local high_limit
    local medium_limit
    local label

    critical_limit=$(yq '.fail_on.critical_count_exceeds' "$policy_yaml")
    high_limit=$(yq '.fail_on.high_count_exceeds' "$policy_yaml")
    medium_limit=$(yq '.warn_on.medium_count_exceeds' "$policy_yaml")
    label=$(yq -r '.report_label' "$policy_yaml")

    local critical
    local high
    local medium

    critical=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$trivy_json")
    high=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$trivy_json")
    medium=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$trivy_json")

    echo "CRITICAL=$critical HIGH=$high MEDIUM=$medium"

    if [ "$critical" -gt "$critical_limit" ]; then
        echo "FAIL: $label — CRITICAL count exceeds threshold"
        return 1
    fi

    if [ "$high" -gt "$high_limit" ]; then
        echo "FAIL: $label — HIGH count exceeds threshold"
        return 1
    fi

    if [ "$medium" -gt "$medium_limit" ]; then
        echo "WARNING: MEDIUM count exceeds threshold"
    fi

    echo "PASS: $label"
    return 0
}

run_policy_gate "$@"
