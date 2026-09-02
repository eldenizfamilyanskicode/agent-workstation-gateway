package installplan

import (
	"encoding/json"
	"errors"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/strictjson"
)

func Decode(encoded []byte) (Spec, error) {
	var specification Spec
	if err := strictjson.DecodeObject(encoded, MaxSpecBytes, &specification); err != nil {
		var decodeFailure *strictjson.Error
		if errors.As(err, &decodeFailure) {
			return Spec{}, planError("spec", "json-"+decodeFailure.Rule)
		}
		return Spec{}, planError("spec", "json-decode")
	}
	if err := Validate(specification); err != nil {
		return Spec{}, err
	}
	return specification, nil
}

func MarshalPlan(plan Plan) ([]byte, error) {
	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil, planError("plan", "canonical-encode")
	}
	if len(encoded) > MaxSpecBytes {
		return nil, planError("plan", "canonical-size-limit")
	}
	return encoded, nil
}
