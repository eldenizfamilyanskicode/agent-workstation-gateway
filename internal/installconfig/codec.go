package installconfig

import (
	"encoding/json"
	"errors"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/strictjson"
)

const MaxConfigBytes = 64 * 1024

func Decode(encoded []byte) (Config, error) {
	var configuration Config
	if err := strictjson.DecodeObject(encoded, MaxConfigBytes, &configuration); err != nil {
		var decodeFailure *strictjson.Error
		if errors.As(err, &decodeFailure) {
			return Config{}, configError("config", "json-"+decodeFailure.Rule)
		}
		return Config{}, configError("config", "json-decode")
	}
	if err := Validate(configuration); err != nil {
		return Config{}, err
	}
	return configuration, nil
}

func MarshalCanonical(configuration Config) ([]byte, error) {
	if err := Validate(configuration); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(configuration)
	if err != nil {
		return nil, configError("config", "canonical-encode")
	}
	if len(encoded) > MaxConfigBytes {
		return nil, configError("config", "canonical-size-limit")
	}
	return encoded, nil
}
