package aql

import (
	"errors"
)

type TokenStream struct {
	data     []Token
	position int
}

// Parse the input string into a TokenStream
func Parse(input string) (*TokenStream, error) {
	t, err := getLexer()
	if err != nil {
		return nil, err
	}
	tokens, err := t.Scanner([]byte(input))
	if err != nil {
		return nil, err
	}
	var result TokenStream
	for {
		t, err, eof := tokens.Next()
		if err != nil {
			return nil, err
		}
		if eof {
			break
		}
		token, ok := t.(Token)
		if !ok {
			return nil, errors.New("Unexpected token type from lexer")
		}
		result.data = append(result.data, token)
	}
	return &result, nil
}

// NextIfIs checks if the current token is of the given type, and if so, advances the stream
func (ts *TokenStream) NextIfIs(id TokenID) bool {
	result := ts.Token().Is(id)
	if result {
		ts.Next()
	}
	return result
}

// Token returns the current token, or an Invalid token if at EOF
func (ts *TokenStream) Token() Token {
	if ts.position < len(ts.data) {
		return ts.data[ts.position]
	}
	return Token{
		Type: Invalid,
	}
}

// Peek the next token, skipping any whitespace
func (ts *TokenStream) PeekNextToken() Token {
	pos := ts.position + 1
	for ts.data[pos].Is(Whitespace) {
		pos++
	}
	if pos < len(ts.data) {
		return ts.data[pos]
	}
	return Token{
		Type: Invalid,
	}
}

// Peek the next token, including whitespace
func (ts *TokenStream) PeekNextRawToken() Token {
	pos := ts.position + 1
	if pos < len(ts.data) {
		return ts.data[pos]
	}
	return Token{
		Type: Invalid,
	}
}

// Move to the next token, skipping any whitespace
func (ts *TokenStream) Prev() bool {
	if ts.position > 0 {
		ts.position--
		for ts.Token().Is(Whitespace) {
			ts.position--
		}
		return true
	}
	return false
}

// Move to the next token, skipping any whitespace
func (ts *TokenStream) Next() bool {
	ts.position++
	for ts.Token().Is(Whitespace) {
		ts.position++
	}
	return ts.position < len(ts.data)
}

// Snarf text until the next token of the given type is encountered.
func (ts *TokenStream) SnarfTextUntil(id TokenID) string {
	var result string
	for !ts.EOF() && !ts.Token().Is(id) {
		// we assume this is an unquoted string, so read until we hit a )
		result += ts.Token().Value
		ts.position++
	}
	return result
}

// EOF returns true if we are at the end of the token stream
func (ts *TokenStream) EOF() bool {
	return !(ts.position < len(ts.data))
}
