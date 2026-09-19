package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	bmp212 "xvertile/akamai-bmp/bm/2.1.2"
	bmp222 "xvertile/akamai-bmp/bm/2.2.2"
	bmp223 "xvertile/akamai-bmp/bm/2.2.3"
	bmp310 "xvertile/akamai-bmp/bm/3.1.0"
	bmp323 "xvertile/akamai-bmp/bm/3.2.3"
	bmp330 "xvertile/akamai-bmp/bm/3.3.0"
	bmp331 "xvertile/akamai-bmp/bm/3.3.1"
	bmp334 "xvertile/akamai-bmp/bm/3.3.4"
	bmp421 "xvertile/akamai-bmp/bm/4.2.1"
	"xvertile/akamai-bmp/dm"
	devicemanager "xvertile/akamai-bmp/dm"
)

type AkamaiRequest struct {
	App          string `json:"app"`
	Lang         string `json:"lang"`
	Version      string `json:"version"`
	Challenge    bool   `json:"challenge"`
	ChallengeUrl string `json:"powUrl"`
	// ServerSignal is the `serversidesignal` from the target's
	// /_bm/get_params?type=sdk-dci. Optional; only BMP 4.2.1 consumes it today.
	ServerSignal string `json:"serverSignal"`
	// DeviceID pins the sensor's device id so it can match the caller's headers.
	DeviceID string `json:"deviceId"`
	// NumTouchTaps / NumSensorEvents raise the sensor's behavioural density from the
	// sparse default (3 / 32). 0 keeps the default. BMP 4.2.1 only.
	NumTouchTaps    int `json:"numTouchTaps"`
	NumSensorEvents int `json:"numSensorEvents"`
	// Device, when set, is the ONE handset this sensor is built from, in the same
	// shape as a db/devices.json entry. Without it the device is picked at random
	// from -devicepath, which is right for callers that follow the sensor's device
	// and wrong for callers whose headers already name one: the caller cannot
	// control which -devicepath the running server was started with, but it can
	// control this. Honoured by every BMP version.
	Device *devicemanager.Device `json:"device"`
	// AppVersion / AppVersionCode are the host app's versionName / versionCode the
	// sensor reports (default "1.0.0" / 1). Set both or neither. BMP 4.2.1 only.
	AppVersion     string `json:"appVersion"`
	AppVersionCode int    `json:"appVersionCode"`
}

// sensorTuning is implemented by the BMP versions that can take a server-side
// signal. Applied via type assertion so the other versions keep working untouched.
type sensorTuning interface {
	SetServerSignal(string)
	SetDeviceID(string)
	SetBehaviour(taps, events int)
	SetAppVersion(name string, code int)
	EffectiveDeviceID() string
	EffectiveAppVersion() string
}

type AkamaiResponse struct {
	SensorData     string `json:"sensor"`
	AndroidVersion string `json:"androidVersion"`
	Model          string `json:"model"`
	Brand          string `json:"brand"`
	ScreenSize     string `json:"screenSize"`
	// The rest let a caller check the sensor against what it sends beside it,
	// rather than trusting that the server was started with the right devices.
	BuildID    string `json:"buildId"`
	SdkInt     int    `json:"sdkInt"`
	DeviceID   string `json:"deviceId,omitempty"`
	AppVersion string `json:"appVersion,omitempty"`
}

// validateDevice rejects a caller-supplied device missing a field the sensor
// embeds. An empty field would not fail generation; it would ship a sensor with
// a hole in it, which is a different anomaly rather than a fixed one.
func validateDevice(d *devicemanager.Device) error {
	var missing []string
	if d.Build.Model == "" {
		missing = append(missing, "BUILD.MODEL")
	}
	if d.Build.Brand == "" {
		missing = append(missing, "BUILD.BRAND")
	}
	if d.Build.Manufacturer == "" {
		missing = append(missing, "BUILD.MANUFACTURER")
	}
	if d.Build.Version.Release == "" {
		missing = append(missing, "BUILD.VERSION.RELEASE")
	}
	if d.Build.Version.SdkInt <= 0 {
		missing = append(missing, "BUILD.VERSION.SDK_INT")
	}
	if d.Build.ID == "" {
		missing = append(missing, "BUILD.ID")
	}
	if d.Build.Fingerprint == "" {
		missing = append(missing, "BUILD.FINGERPRINT")
	}
	if d.Screen.WidthPixels <= 0 || d.Screen.HeightPixels <= 0 {
		missing = append(missing, "SCREEN")
	}
	if len(missing) > 0 {
		return fmt.Errorf("device is missing %s", strings.Join(missing, ", "))
	}
	return nil
}

type AkamaiBmpGen interface {
	GetAndroidId() string
	GenerateSensorData() (string, error)
	GetDevice() devicemanager.Device
}

var deviceManager devicemanager.DeviceManager

var akamaiBmpVersions = map[string]interface{}{
	"4.2.1": bmp421.NewStable,
	"3.3.4": bmp334.NewStable,
	"3.3.1": bmp331.NewStable,
	"3.3.0": bmp330.NewStable,
	"3.2.3": bmp323.NewStable,
	"3.1.0": bmp310.NewStable,
	"2.2.3": bmp223.NewStable,
	"2.2.2": bmp222.NewStable,
	"2.1.2": bmp212.NewStable,
}

func Call(funcName string, params ...interface{}) (result interface{}, err error) {
	f := reflect.ValueOf(akamaiBmpVersions[funcName])
	if len(params) != f.Type().NumIn() {
		fmt.Println(len(params), f.Type().NumIn())
		err = errors.New("The number of params is out of index.")
		return
	}
	in := make([]reflect.Value, len(params))
	for k, param := range params {
		in[k] = reflect.ValueOf(param)
	}
	var res []reflect.Value
	res = f.Call(in)
	result = res[0].Interface()
	return
}

func handleBmpRequest(w http.ResponseWriter, r *http.Request) {
	// Check if the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request body into an ExampleRequest struct
	var req AkamaiRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Error parsing request body", http.StatusBadRequest)
		return
	}

	if req.Challenge && len(req.ChallengeUrl) == 0 {
		http.Error(w, "Challenge set to true but no challenge url provided", http.StatusBadRequest)
		return
	}

	if (req.AppVersion == "") != (req.AppVersionCode == 0) {
		http.Error(w, "appVersion and appVersionCode must be set together", http.StatusBadRequest)
		return
	}
	devices := deviceManager
	if req.Device != nil {
		if err := validateDevice(req.Device); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		devices = devicemanager.Single(*req.Device)
	}

	if _, ok := akamaiBmpVersions[req.Version]; !ok {
		http.Error(w, "Bmp version not found", http.StatusBadRequest)
		return
	} else {
		result, err := Call(req.Version, req.App, req.Lang, req.Challenge, req.ChallengeUrl, devices)
		if err != nil {
			http.Error(w, "Error generating sensor data "+err.Error(), http.StatusBadRequest)
			return
		}
		//.(AkamaiBmpGen)
		gen := result.(AkamaiBmpGen)
		if t, ok := gen.(sensorTuning); ok {
			if req.ServerSignal != "" {
				t.SetServerSignal(req.ServerSignal)
			}
			if req.DeviceID != "" {
				t.SetDeviceID(req.DeviceID)
			}
			if req.NumTouchTaps != 0 || req.NumSensorEvents != 0 {
				t.SetBehaviour(req.NumTouchTaps, req.NumSensorEvents)
			}
			if req.AppVersion != "" {
				t.SetAppVersion(req.AppVersion, req.AppVersionCode)
			}
		} else if req.ServerSignal != "" || req.DeviceID != "" || req.AppVersion != "" ||
			req.NumTouchTaps != 0 || req.NumSensorEvents != 0 {
			// Refused rather than ignored: a caller that asked for a pinned device id
			// or app version and silently got the defaults would send a sensor that
			// contradicts its own headers, with nothing to say so.
			http.Error(w, "serverSignal, deviceId, appVersion and numTouchTaps/numSensorEvents are only supported by BMP 4.2.1", http.StatusBadRequest)
			return
		}
		sensor, err := gen.GenerateSensorData()
		if err != nil {
			http.Error(w, "Error generating sensor data "+err.Error(), http.StatusBadRequest)
			return
		}

		// Create a new ExampleResponse struct
		resp := AkamaiResponse{
			Brand:          gen.GetDevice().Build.Brand,
			SensorData:     sensor,
			AndroidVersion: gen.GetDevice().Build.Version.Release,
			Model:          gen.GetDevice().Build.Model,
			ScreenSize:     strconv.Itoa(gen.GetDevice().Screen.WidthPixels) + "x" + strconv.Itoa(gen.GetDevice().Screen.HeightPixels),
			BuildID:        gen.GetDevice().Build.ID,
			SdkInt:         gen.GetDevice().Build.Version.SdkInt,
			DeviceID:       gen.GetAndroidId(),
		}
		if t, ok := gen.(sensorTuning); ok {
			resp.DeviceID = t.EffectiveDeviceID()
			resp.AppVersion = t.EffectiveAppVersion()
		}

		// Marshal the ExampleResponse struct to JSON
		respJSON, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "Error encoding response", http.StatusInternalServerError)
			return
		}
		if req.App == "com.adidas.confirmed.app" {
			respJSON = respJSON[:len(respJSON)-1]
			respJSON = append(respJSON, []byte(`,"userAgent":"`+generateAdidasDevice(result.(AkamaiBmpGen).GetAndroidId(), result.(AkamaiBmpGen).GetDevice())+`"}`)...)
		}

		// Set the response content type to application/json
		w.Header().Set("Content-Type", "application/json")

		// Write the response JSON to the response writer
		w.Write(respJSON)
		return
	}

}

func generateAdidasDevice(androidId string, device dm.Device) string {
	hash := sha256.Sum256([]byte(androidId))
	hashHex := hex.EncodeToString(hash[:])

	return fmt.Sprintf("app/com.adidas.confirmed.app; os/Android; os-version/%v; app-version/4.23.0; buildnumber/42300291; type/%v/%v/%v/%vx%v; fingerprint/%v", device.Build.Version.SdkInt, device.Build.Device, device.Build.Model, "1.0", device.Screen.WidthPixels, device.Screen.HeightPixels, hashHex)
}

func main() {
	var (
		host       string
		port       int
		devicePath string
	)
	flag.StringVar(&host, "host", "localhost", "Specify the host on which the server will run")
	flag.IntVar(&port, "port", 1337, "Specify the port on which the server will run")
	flag.StringVar(&devicePath, "devicepath", "db/devices.json", "Specify the path to the device configuration file")
	help := flag.Bool("h", false, "Display help")
	flag.Parse()

	if *help {
		fmt.Println("Usage of Akamai BMP server:")
		flag.PrintDefaults()
		return
	}
	deviceManager = devicemanager.New(devicePath)
	httpAddr := fmt.Sprintf("%s:%d", host, port)
	http.HandleFunc("/akamai/bmp", handleBmpRequest)
	log.Printf("Starting server on %s with device config from %s\n", httpAddr, devicePath)
	log.Fatal(http.ListenAndServe(httpAddr, nil))
}
