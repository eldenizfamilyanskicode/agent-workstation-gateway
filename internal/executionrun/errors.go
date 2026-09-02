package executionrun

import "errors"

var ErrLauncherRequired = errors.New("native launcher is required")
var ErrInvalidOptions = errors.New("invalid execution lifecycle options")
var ErrInvalidLaunchPlan = errors.New("invalid authorized launch plan")
var ErrClockRegression = errors.New("execution clock moved backwards")
var ErrInvalidExecutionReport = errors.New("could not construct a valid execution report")
