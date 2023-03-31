package spf

import "errors"

var ErrSyntax error = errors.New("syntax")                     // Syntax error in ParseSPF
var ErrInvalidQualifier error = errors.New("invalidqualifier") // Other character than +, -, ~, ? for a qualifier received
var ErrInvalidMechanism error = errors.New("invalidmechanism") // Unknwon mechanism keyword received
var ErrInvalidModifier error = errors.New("invalidmodifier")   // Unknown modifier received
var ErrNotFound error = errors.New("notfound")                 // DNS entry not found
var ErrOutOfRecursions = errors.New("outofrecursions")         // Too many redirect or include mechanisms were called

// Most of the time it's the issuers fault an error occurs
// but this are sadly not the only errors ValidateIP can return
// DNS Errors (for example if lookup is not available) can also occur
