package bmp421

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
	"testing"

	"xvertile/akamai-bmp/dm"
)

// decryptPayload opens the sensor's encrypted field with the generator's own key:
// the header is "6,a,<rsa aes>,<rsa hmac>$<b64 iv|ct|hmac>$<timing>$...$<metadata>".
func decryptPayload(t *testing.T, sensor string, ctx *CryptoContext) string {
	t.Helper()
	parts := strings.Split(sensor, "$")
	if len(parts) != 7 {
		t.Fatalf("sensor has %d $-fields, want 7", len(parts))
	}
	raw, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload is not base64: %v", err)
	}
	iv, ct := raw[:16], raw[16:len(raw)-32]
	block, _ := aes.NewCipher(ctx.AESKey)
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	return string(pt[:len(pt)-int(pt[len(pt)-1])])
}

// deviceFP is the -100 pair: the device fingerprint, which carries the Android id.
func deviceFP(t *testing.T, plaintext string) string {
	t.Helper()
	for _, field := range strings.Split(plaintext, Separator) {
		if strings.HasPrefix(field, "-100,") {
			return strings.TrimPrefix(field, "-100,")
		}
	}
	t.Fatal("no -100 device fingerprint in the payload")
	return ""
}

func metadataDeviceID(sensor string) string {
	parts := strings.Split(sensor, "$")
	return strings.Split(parts[6], "&&&")[1]
}

func newBM(t *testing.T) *BotManager {
	t.Helper()
	var d dm.Device
	d.Screen.WidthPixels, d.Screen.HeightPixels = 1080, 2400
	d.Build.Model, d.Build.Brand, d.Build.Manufacturer = "SM-A515F", "samsung", "samsung"
	d.Build.Version.Release, d.Build.Version.SdkInt = "12", 31
	d.Build.ID, d.Build.Fingerprint = "SP1A.210812.016", "samsung/a51nsxx/a51:12/SP1A.210812.016/x:user/release-keys"
	devices := dm.Single(d)
	return NewStable("com.example.app", "en_IN", false, "", devices)
}

// The override must reach the ENCRYPTED fingerprint, not only the plaintext
// metadata: Akamai decrypts the payload, so two different ids in one sensor are a
// contradiction it can see.
func TestDeviceIDOverrideReachesTheEncryptedFingerprint(t *testing.T) {
	bm := newBM(t)
	original := bm.GetAndroidId()
	const pinned = "0123456789abcdef"
	bm.SetDeviceID(pinned)

	sensor, err := bm.GenerateSensorData()
	if err != nil {
		t.Fatal(err)
	}
	fp := deviceFP(t, decryptPayload(t, sensor, bm.Ctx))

	if got := metadataDeviceID(sensor); got != pinned {
		t.Fatalf("metadata device id = %q, want %q", got, pinned)
	}
	if !strings.Contains(fp, ","+pinned+",") {
		t.Errorf("encrypted fingerprint does not carry the pinned id %q:\n%s", pinned, fp)
	}
	if strings.Contains(fp, ","+original+",") {
		t.Errorf("encrypted fingerprint still carries the random id %q", original)
	}
	if bm.EffectiveDeviceID() != pinned {
		t.Errorf("EffectiveDeviceID() = %q, want %q", bm.EffectiveDeviceID(), pinned)
	}
}

// Without an override, both copies are the profile's own id -- unchanged behaviour.
func TestWithoutAnOverrideBothCopiesAreTheProfileID(t *testing.T) {
	bm := newBM(t)
	id := bm.GetAndroidId()
	sensor, err := bm.GenerateSensorData()
	if err != nil {
		t.Fatal(err)
	}
	if got := metadataDeviceID(sensor); got != id {
		t.Fatalf("metadata device id = %q, want %q", got, id)
	}
	if fp := deviceFP(t, decryptPayload(t, sensor, bm.Ctx)); !strings.Contains(fp, ","+id+",") {
		t.Errorf("encrypted fingerprint does not carry the profile id %q", id)
	}
}

// Generate is exported, so a direct caller passing GenerateOpts.DeviceID must get
// the same single id -- and the Generator's own profile must not be mutated by it.
func TestGenerateOptsDeviceIDIsAppliedWithoutMutatingTheProfile(t *testing.T) {
	bm := newBM(t)
	before := bm.Generator.Device.AndroidID
	sensor := bm.Generate(GenerateOpts{DeviceID: "fedcba9876543210"})
	if fp := deviceFP(t, decryptPayload(t, sensor, bm.Ctx)); !strings.Contains(fp, ",fedcba9876543210,") {
		t.Errorf("GenerateOpts.DeviceID did not reach the encrypted fingerprint")
	}
	if bm.Generator.Device.AndroidID != before {
		t.Errorf("Generate mutated the profile: AndroidID %q -> %q", before, bm.Generator.Device.AndroidID)
	}
}
