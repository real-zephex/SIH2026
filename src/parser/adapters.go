// Adapters registering the function-style parsers behind the Parser
// interface. FortiGate (Detect/Parse) and Linux (DetectLinux/ParseLinux)
// were built with package-level funcs; these thin structs plug them into
// the registry without touching teammate logic.
package parser

import "sih/src/schema"

// FortiGate adapts the package-level FortiGate Detect/Parse funcs.
type FortiGate struct{}

func init() { Register(FortiGate{}) }

// Name returns the registry name.
func (FortiGate) Name() string { return "fortigate" }

// Detect delegates to the FortiGate Detect func.
func (FortiGate) Detect(line string) bool { return Detect(line) }

// Parse delegates to the FortiGate Parse func.
func (FortiGate) Parse(line string) (schema.Event, error) { return Parse(line) }

// Linux adapts the package-level Linux DetectLinux/ParseLinux funcs.
type Linux struct{}

func init() { Register(Linux{}) }

// Name returns the registry name.
func (Linux) Name() string { return "linux" }

// Detect delegates to DetectLinux.
func (Linux) Detect(line string) bool { return DetectLinux(line) }

// Parse delegates to ParseLinux.
func (Linux) Parse(line string) (schema.Event, error) { return ParseLinux(line) }
