package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	devicemanager "xvertile/akamai-bmp/dm"
)

func post(t *testing.T, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/akamai/bmp", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handleBmpRequest(rec, req)
	return rec
}

func baseRequest(version string) map[string]interface{} {
	return map[string]interface{}{"app": "com.example", "lang": "en_US", "version": version}
}

func pinnedDevice() devicemanager.Device {
	d := devicemanager.TestDevice()
	d.Build.Model = "SM-PINNED"
	d.Build.ID = "PIN1.000000.001"
	return d
}

// The server's own database holds a DIFFERENT device, so an echo of the pinned
// one proves the request's device won rather than the -devicepath one.
func setUp() {
	deviceManager = devicemanager.Single(devicemanager.TestDevice())
}

func TestRequestDeviceOverridesServerDatabase(t *testing.T) {
	setUp()
	for _, version := range []string{"4.2.1", "3.3.4"} {
		body := baseRequest(version)
		body["device"] = pinnedDevice()
		rec := post(t, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", version, rec.Code, rec.Body.String())
		}
		var resp AkamaiResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Model != "SM-PINNED" || resp.BuildID != "PIN1.000000.001" || resp.SdkInt != 31 {
			t.Fatalf("%s: sensor built from %+v, want the pinned device", version, resp)
		}
		if resp.SensorData == "" {
			t.Fatalf("%s: empty sensor", version)
		}
	}
}

func TestEchoesEffectiveDeviceIDAndAppVersion(t *testing.T) {
	setUp()
	body := baseRequest("4.2.1")
	body["deviceId"] = "0123456789abcdef"
	body["appVersion"] = "2.3.4"
	body["appVersionCode"] = 20304
	rec := post(t, body)
	var resp AkamaiResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(rec.Body.String())
	}
	if resp.DeviceID != "0123456789abcdef" || resp.AppVersion != "2.3.4" {
		t.Fatalf("got deviceId=%q appVersion=%q", resp.DeviceID, resp.AppVersion)
	}
}

func TestDefaultAppVersionIsReported(t *testing.T) {
	setUp()
	rec := post(t, baseRequest("4.2.1"))
	var resp AkamaiResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(rec.Body.String())
	}
	if resp.AppVersion != "1.0.0" || resp.DeviceID == "" {
		t.Fatalf("got deviceId=%q appVersion=%q", resp.DeviceID, resp.AppVersion)
	}
}

func TestRejects(t *testing.T) {
	setUp()
	incomplete := pinnedDevice()
	incomplete.Build.Fingerprint = ""
	incomplete.Build.ID = ""

	cases := map[string]struct {
		body map[string]interface{}
		want string
	}{
		"incomplete device": {
			body: map[string]interface{}{"device": incomplete},
			want: "BUILD.ID, BUILD.FINGERPRINT",
		},
		"appVersion without code": {
			body: map[string]interface{}{"appVersion": "2.3.4"},
			want: "set together",
		},
		"appVersionCode without name": {
			body: map[string]interface{}{"appVersionCode": 1},
			want: "set together",
		},
	}
	for name, c := range cases {
		body := baseRequest("4.2.1")
		for k, v := range c.body {
			body[k] = v
		}
		rec := post(t, body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: got %d %q", name, rec.Code, rec.Body.String())
		}
	}

	// A version that cannot honour a knob refuses it instead of silently
	// sending a sensor that disagrees with the caller's headers.
	for _, knob := range []string{"deviceId", "appVersion"} {
		body := baseRequest("3.3.4")
		body[knob] = "x"
		if knob == "appVersion" {
			body["appVersionCode"] = 1
		}
		rec := post(t, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("3.3.4 with %s: got %d", knob, rec.Code)
		}
	}
}
