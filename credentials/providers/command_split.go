package providers

import (
	"fmt"
	"strings"
	"unicode"
)

// splitProcessCommand splits process_command into argv with quote support.
// Whitespace outside quotes separates arguments. Double/single quotes group a
// single argument so Windows paths like "C:\Program Files\tool.exe" work.
// Escape rules follow POSIX shlex: outside quotes, '\' escapes the next rune;
// inside double quotes, '\' only escapes '"', '\', '$', '`' and newline;
// inside single quotes, all characters are literal.
func splitProcessCommand(command string) ([]string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil, fmt.Errorf("process_command is empty")
	}

	var args []string
	var current strings.Builder
	inSingle := false
	inDouble := false

	flush := func() {
		if current.Len() > 0 {
			args = append(args, current.String())
			current.Reset()
		}
	}

	runes := []rune(command)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if inSingle {
			if r == '\'' {
				inSingle = false
			} else {
				current.WriteRune(r)
			}
			continue
		}
		if inDouble {
			if r == '"' {
				inDouble = false
				continue
			}
			if r == '\\' && i+1 < len(runes) {
				next := runes[i+1]
				if next == '"' || next == '\\' || next == '$' || next == '`' || next == '\n' {
					current.WriteRune(next)
					i++
					continue
				}
			}
			current.WriteRune(r)
			continue
		}
		// unquoted
		if r == '\\' {
			if i+1 >= len(runes) {
				return nil, fmt.Errorf("invalid process_command: trailing backslash")
			}
			current.WriteRune(runes[i+1])
			i++
			continue
		}
		if r == '\'' {
			inSingle = true
			continue
		}
		if r == '"' {
			inDouble = true
			continue
		}
		if unicode.IsSpace(r) {
			flush()
			continue
		}
		current.WriteRune(r)
	}

	if inSingle || inDouble {
		return nil, fmt.Errorf("invalid process_command: unclosed quote")
	}
	flush()
	if len(args) == 0 {
		return nil, fmt.Errorf("process_command is empty")
	}
	return args, nil
}
