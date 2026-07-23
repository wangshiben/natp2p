package billingadversary

import (
	"slices"
	"testing"
)

func TestProductionComponentProbeCoversEveryScenario(t *testing.T) {
	for _, scenario := range Scenarios {
		t.Run(scenario, func(t *testing.T) {
			result := Run(Request{
				Scenario: scenario,
				Nonce:    "component-probe-" + scenario,
				StateDir: t.TempDir(),
			})
			if result.Status != "PASS" || result.FailureCode != "" {
				t.Fatalf("result=%+v", result)
			}
			if result.SchemaVersion != probeSchemaVersion || result.Scenario != scenario {
				t.Fatalf("unexpected result identity: %+v", result)
			}
			if len(result.Checks) < 3 || !slices.Contains(result.ProductionPackages, "billingrecord") ||
				!slices.Contains(result.ProductionPackages, "billingvoucher") {
				t.Fatalf("production coverage missing: %+v", result)
			}
			if len(result.Limitations) != len(probeLimitations) {
				t.Fatalf("limitations=%v", result.Limitations)
			}
		})
	}
}

func TestProductionComponentProbeRejectsInvalidRequest(t *testing.T) {
	for _, request := range []Request{
		{Scenario: "unknown", Nonce: "valid", StateDir: t.TempDir()},
		{Scenario: Scenarios[0], Nonce: "contains spaces", StateDir: t.TempDir()},
		{Scenario: Scenarios[0], Nonce: "valid"},
	} {
		result := Run(request)
		if result.Status != "FAIL" || result.FailureCode != "component_probe_invalid_request" {
			t.Fatalf("invalid request result=%+v", result)
		}
	}
}
