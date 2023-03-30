package spf

import (
	"errors"
	"strings"
)

// A Qualifier can be
// -, +, ~, ?
const (
	PassQualifier     = iota // +
	FailQualifier            // -
	SoftFailQualifier        // ~
	NeutralQualifier         // ?
)

const (
	AllMechanism     = iota + 1 // all
	IPv4Mechanism               // ip4
	IPv6Mechanism               // ip6
	AMechanism                  // a
	MXMechanism                 // mx
	PTRMechanism                // ptr
	ExistsMechanism             // exists
	IncludeMechanism            // include
)

// An Argument in the SPF Record
// They are read from left to right (Left is the most powerful one)
// Qualifiers determine what should be done if the mechanism matches the client
type Mechanism struct {
	Qualifier int
	Mechanism int
	Value     string
}

type MechanismParseContext struct {
	Qualifier         int
	Mechanism         string
	Value             string
	WritingDescriptor bool
}

// The mechanisms which were found in an SPF Record.
// This Type is sorted from the most to the least powerful mechanism.
type Record []Mechanism

type Result string

func IsSPF(spf string) bool {
	return strings.HasPrefix(spf, "v=spf1")
}

func ParseSPF(spf string) (Record, error) {
	var spfRecord = []Mechanism{}

	if !IsSPF(spf) {
		return nil, errors.New("nospf")
	}

	spfContent := spf[len("v=spf "):]

	parseContext := MechanismParseContext{
		Qualifier:         PassQualifier,
		Mechanism:         "",
		Value:             "",
		WritingDescriptor: true,
	}

	writeValue := &parseContext.Mechanism

	for _, chr := range spfContent {
		switch chr {
		case '+', '-', '~', '?':
			if parseContext.Mechanism == "" && parseContext.Value == "" {
				qualifier, err := EvaluateQualifier(chr)

				if err != nil {
					return nil, err
				}

				parseContext.Qualifier = qualifier
			}
		case ':':
			if parseContext.Mechanism == "" {
				return nil, errors.New("syntax")
			}

			if parseContext.WritingDescriptor {
				writeValue = &parseContext.Value
				parseContext.WritingDescriptor = false
			} else {
				*writeValue += string(chr)
			}
		case ' ', '\n', '\r':
			if !parseContext.WritingDescriptor && parseContext.Value != "" {
				mechanism, err := EvaluateMechanism(&parseContext)
				if err != nil {
					return nil, err
				}

				spfRecord = append(spfRecord, mechanism)

				writeValue = &parseContext.Mechanism
				parseContext.Qualifier = PassQualifier
				parseContext.WritingDescriptor = true
				parseContext.Mechanism = ""
				parseContext.Value = ""
			}
		default:
			*writeValue += string(chr)
		}
	}

	if parseContext.Mechanism != "" {
		mechanism, err := EvaluateMechanism(&parseContext)

		if err != nil {
			return nil, err
		}

		spfRecord = append(spfRecord, mechanism)
	}

	return spfRecord, nil
}

func EvaluateQualifier(char rune) (int, error) {
	switch char {
	case '+':
		return PassQualifier, nil
	case '-':
		return FailQualifier, nil
	case '~':
		return SoftFailQualifier, nil
	case '?':
		return NeutralQualifier, nil
	default:
		return 0, errors.New("invalid qualifier")
	}
}

func EvaluateMechanism(context *MechanismParseContext) (Mechanism, error) {
	mechanism := Mechanism{Qualifier: context.Qualifier, Value: context.Value}
	switch strings.ToLower(context.Mechanism) {
	case "all":
		mechanism.Mechanism = AllMechanism
		return mechanism, nil
	case "ip4":
		mechanism.Mechanism = IPv4Mechanism
		return mechanism, nil
	case "ip6":
		mechanism.Mechanism = IPv6Mechanism
		return mechanism, nil
	case "a":
		mechanism.Mechanism = AMechanism
		return mechanism, nil
	case "mx":
		mechanism.Mechanism = MXMechanism
		return mechanism, nil
	case "ptr":
		mechanism.Mechanism = PTRMechanism
		return mechanism, nil
	case "exists":
		mechanism.Mechanism = ExistsMechanism
		return mechanism, nil
	case "include":
		mechanism.Mechanism = IncludeMechanism
		return mechanism, nil
	default:
		return Mechanism{}, errors.New("invalidmechanism")
	}
}
