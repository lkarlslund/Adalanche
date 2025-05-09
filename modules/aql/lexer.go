package aql

import (
	"strconv"

	"github.com/timtadh/lexmachine"
	"github.com/timtadh/lexmachine/machines"
)

type TokenID int

var Literals []string       // The tokens representing literal strings
var Keywords []string       // The keyword tokens
var Tokens []string         // All of the tokens (including literals and keywords)
var TokenIds map[string]int // A map from the token names to their int ids
var Lexer *lexmachine.Lexer // The lexer object. Use this to construct a Scanner

//go:generate go tool github.com/dmarkham/enumer -type=TokenID -output tokenid_enums.go

const (
	Invalid TokenID = iota

	// ORDERING MATTERS!

	Star
	Slash
	Exclamation

	Dot
	Dotdot
	Comma
	Colon
	Equals
	Tilde
	LessThan
	LessThanEquals
	GreaterThan
	GreaterThanEquals

	And
	Or
	Xor
	Not

	BinaryAnd
	BinaryOr
	BinaryNot

	LParan // (
	RParan // )

	LBracket // [
	RBracket // ]

	LBrace // {
	RBrace // }

	EdgeAnyDirection // -
	EdgeIn           // <-
	EdgeOut          // ->

	Is
	Match
	Where
	Skip
	Offset
	Limit
	OrderBy
	Desc
	Union

	True
	False

	Literal
	Keyword

	Whitespace

	Integer
	Float

	UnquotedLDAPString
	QuotedString // Quoted string

	Identifier
	HashIdentifier
	AtIdentifier

	Comment

	MAXTOKEN = Comment
)

var StaticLexers = map[string]TokenID{
	"\\(": LParan,
	"\\)": RParan,

	"\\[": LBracket,
	"\\]": RBracket,

	"\\{": LBrace,
	"\\}": RBrace,

	// Comparison
	"\\~":    Tilde,
	"\\=":    Equals,
	"\\<":    LessThan,
	"\\<\\=": LessThanEquals,
	"\\>":    GreaterThan,
	"\\>\\=": GreaterThanEquals,
	// Binary
	"\\&": BinaryAnd,
	"\\|": BinaryOr,
	"\\^": BinaryNot,
	// Logical
	"AND": And,
	"OR":  Or,
	"NOT": Not,

	"TRUE":  True,
	"FALSE": False,

	"\\*":    Star,
	"\\/":    Slash,
	"\\!":    Exclamation,
	"\\.":    Dot,
	"\\.\\.": Dotdot,
	"\\,":    Comma,
	// "\\;\\":                Literal,
	"\\:":    Colon,
	"\\-":    EdgeAnyDirection,
	"\\-\\>": EdgeOut,
	"\\<\\-": EdgeIn,

	"MATCH":    Match,
	"IS":       Is,
	"WHERE":    Where,
	"SKIP":     Skip,
	"OFFSET":   Offset,
	"LIMIT":    Limit,
	"ORDER BY": OrderBy,
	"DESC":     Desc,
	"UNION":    Union,

	`//[^\n]*\n?`: Comment,
	`/\*([^*]|\r|\n|(\*+([^*/]|\r|\n)))*\*+/`: Comment,
	`([a-zA-Z]|_)([a-zA-Z0-9]|_|-)*`:          Identifier,
	`\\#([a-zA-Z]|_)([a-zA-Z0-9]|_)+`:         HashIdentifier,
	`\\@([a-zA-Z]|_)([a-zA-Z0-9]|_)+`:         AtIdentifier,

	`( |\t|\n|\r)+`: Whitespace,
}

// Creates the lexer object and compiles the NFA.
func getLexer() (*lexmachine.Lexer, error) {
	lexer := lexmachine.NewLexer()

	// Preserve ordering in the dumbest way possible
	for currentid := range MAXTOKEN {
		for autolex, id := range StaticLexers {
			if currentid+1 == id {
				lexer.Add([]byte(autolex), tokenid(id))
			}
		}
	}

	// lexer.Add([]byte(`([^)]|(\\.))+`),
	// 	func(scan *lexmachine.Scanner, match *machines.Match) (any, error) {
	// 		x, _ := tokenid(UnquotedLDAPString)(scan, match)
	// 		t := x.(*lexmachine.Token)
	// 		return t, nil
	// 	})

	// Regular integers
	lexer.Add([]byte("[0-9]+"),
		func(scan *lexmachine.Scanner, match *machines.Match) (result any, err error) {
			x, _ := tokenid(Integer)(scan, match)
			t := x.(Token)
			t.Native, err = strconv.ParseInt(t.Value, 10, 64)
			return t, err
		})

	// Hex formatted integer
	lexer.Add([]byte("0[xX][0-9a-fA-F]+"),
		func(scan *lexmachine.Scanner, match *machines.Match) (result any, err error) {
			x, _ := tokenid(Integer)(scan, match)
			t := x.(Token)
			t.Native, err = strconv.ParseInt(t.Value[2:], 16, 64)
			return t, err
		})

	// Octal formatted integer
	lexer.Add([]byte("0[0-7]+"),
		func(scan *lexmachine.Scanner, match *machines.Match) (result any, err error) {
			x, _ := tokenid(Integer)(scan, match)
			t := x.(Token)
			t.Native, err = strconv.ParseInt(t.Value, 8, 64)
			return t, err
		})

	lexer.Add([]byte("[1-9][0-9]+\\.[0-9]+"), func(scan *lexmachine.Scanner, match *machines.Match) (result any, err error) {
		x, _ := tokenid(Float)(scan, match)
		t := x.(Token)
		t.Native, err = strconv.ParseFloat(t.Value, 64)
		return t, err
	})

	lexer.Add([]byte(`"([^\\"]|(\\.))*"`),
		func(scan *lexmachine.Scanner, match *machines.Match) (any, error) {
			x, _ := tokenid(QuotedString)(scan, match)
			t := x.(Token)
			t.Value = t.Value[1 : len(t.Value)-1] // strip quotes
			return t, nil
		})

	// lexer.Add([]byte("( |\t|\n|\r)+"), skip) // skip tabs, linefeeds etc

	err := lexer.Compile()
	if err != nil {
		return nil, err
	}
	return lexer, nil
}

// a lexmachine.Action function which skips the match.
func skip(*lexmachine.Scanner, *machines.Match) (any, error) {
	return nil, nil
}

// a lexmachine.Action function with constructs a Token of the given token type by
// the token type's id.
func tokenid(id TokenID) lexmachine.Action {
	return func(s *lexmachine.Scanner, m *machines.Match) (any, error) {
		// m contains positions etc
		return Token{
			Type:     id,
			Value:    string(m.Bytes),
			Position: *m,
		}, nil
	}
}
