package spf

import (
	"errors"
	"strings"
)

type Qualifier int

// A Qualifier can be
// -, +, ~, ?
const (
	PassQualifier     = iota // +
	FailQualifier            // -
	SoftFailQualifier        // ~
	NeutralQualifier         // ?
	NoneQualifier            // No Mechanism matched the current ip
)

// Caution! Modifiers are also called mechanisms in this library,
// but they get distinguished correctly
const (
	AllMechanism      = iota + 1 // all
	IPv4Mechanism                // ip4
	IPv6Mechanism                // ip6
	AMechanism                   // a
	MXMechanism                  // mx
	PTRMechanism                 // ptr
	ExistsMechanism              // exists
	IncludeMechanism             // include
	RedirectMechanism            // redirect
)

// An Argument in the SPF Record
// They are read from left to right (Left is the most powerful one)
// Qualifiers determine how the ip should be treated if the mechanism matches the address
type Mechanism struct {
	Qualifier Qualifier
	Mechanism int
	Value     string
}

type MechanismParseContext struct {
	Qualifier         Qualifier
	Mechanism         string
	Value             string
	WritingDescriptor bool
	Modifier          bool
}

// The mechanisms which were found in an SPF Record.
// This Type is sorted from the most to the least powerful mechanism.
type Record []Mechanism

type Result string

// Simple and fast check to validate SPF Record
func IsSPF(spf string) bool {
	return strings.HasPrefix(spf, "v=spf1")
}

// Informationful way to read out spf record
func ParseSPF(spf string) (Record, error) {
	var spfRecord = []Mechanism{}
	var spfModifiers = []Mechanism{} // Reversive, just gets appended after record

	if !IsSPF(spf) {
		return nil, errors.New("nospf")
	}

	spfContent := spf[len("v=spf "):]

	parseContext := MechanismParseContext{
		Qualifier:         PassQualifier,
		Mechanism:         "",
		Value:             "",
		WritingDescriptor: true,
		Modifier:          false,
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
				continue
			}

			*writeValue += string(chr)
		case ':':
			if parseContext.Mechanism == "" {
				return nil, ErrSyntax
			}

			if parseContext.WritingDescriptor {
				writeValue = &parseContext.Value
				parseContext.WritingDescriptor = false
			} else {
				*writeValue += string(chr)
			}
		case '=':
			if parseContext.Mechanism == "" {
				return nil, ErrSyntax
			}

			if parseContext.WritingDescriptor {
				writeValue = &parseContext.Value
				parseContext.WritingDescriptor = false
				parseContext.Modifier = true
			} else {
				*writeValue += string(chr)
			}

		case ' ', '\n', '\r':
			if parseContext.WritingDescriptor || parseContext.Value == "" {
				continue
			}

			if parseContext.Modifier {
				mechanism, err := EvaluateModifier(&parseContext)

				if err != nil {
					return nil, err
				}

				spfModifiers = append(spfModifiers, mechanism)
			} else {
				mechanism, err := EvaluateMechanism(&parseContext)

				if err != nil {
					return nil, err
				}

				spfRecord = append(spfRecord, mechanism)
			}

			writeValue = &parseContext.Mechanism
			parseContext.Qualifier = PassQualifier
			parseContext.WritingDescriptor = true
			parseContext.Mechanism = ""
			parseContext.Value = ""
			parseContext.Modifier = false
		default:
			*writeValue += string(chr)
		}
	}

	if parseContext.Mechanism != "" {
		if parseContext.Modifier {
			mechanism, err := EvaluateModifier(&parseContext)

			if err != nil {
				return nil, err
			}

			spfModifiers = append(spfModifiers, mechanism)
		} else {
			mechanism, err := EvaluateMechanism(&parseContext)

			if err != nil {
				return nil, err
			}

			spfRecord = append(spfRecord, mechanism)
		}
	}

	return append(spfRecord, spfModifiers...), nil
}

func EvaluateQualifier(char rune) (Qualifier, error) {
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
		return 0, ErrInvalidQualifier
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
		return Mechanism{}, ErrInvalidMechanism
	}
}

func EvaluateModifier(context *MechanismParseContext) (Mechanism, error) {
	modifier := Mechanism{Qualifier: PassQualifier, Value: context.Value}

	switch context.Mechanism {
	case "redirect":
		modifier.Mechanism = RedirectMechanism
		return modifier, nil
	default:
		return Mechanism{}, ErrInvalidModifier
	}
}
