package setup

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxAttempts bounds how often a question is repeated after invalid answers,
// so a script feeding wrong input does not loop forever.
const maxAttempts = 5

// Prompter asks questions on a line-oriented input.
type Prompter struct {
	in  *bufio.Reader
	out io.Writer
}

// NewPrompter reads answers from in and writes questions to out.
func NewPrompter(in *bufio.Reader, out io.Writer) *Prompter {
	return &Prompter{in: in, out: out}
}

// Ask shows q with the default def and returns the answer passed through
// check. An empty answer selects def. Invalid answers are explained and the
// question is asked again.
func (p *Prompter) Ask(q, def string, check func(string) (string, error)) (string, error) {
	for range maxAttempts {
		if def != "" {
			fmt.Fprintf(p.out, "%s [%s]: ", q, def)
		} else {
			fmt.Fprintf(p.out, "%s: ", q)
		}
		line, err := p.line()
		if err != nil {
			return "", err
		}
		if line == "" {
			line = def
		}
		v, err := check(line)
		if err == nil {
			return v, nil
		}
		fmt.Fprintf(p.out, "  → %v\n", err)
	}
	return "", errors.New("올바른 값을 입력받지 못해 중단합니다")
}

// Confirm asks a yes/no question. An empty answer selects def.
func (p *Prompter) Confirm(q string, def bool) (bool, error) {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	for range maxAttempts {
		fmt.Fprintf(p.out, "%s %s: ", q, hint)
		line, err := p.line()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(line) {
		case "":
			return def, nil
		case "y", "yes", "예", "네", "ㅇ":
			return true, nil
		case "n", "no", "아니오", "아니요", "ㄴ":
			return false, nil
		}
		fmt.Fprintln(p.out, "  → y 또는 n으로 답해 주세요")
	}
	return false, errors.New("올바른 값을 입력받지 못해 중단합니다")
}

// Reader is the underlying input, for reading a password from a pipe
// without losing buffered lines.
func (p *Prompter) Reader() *bufio.Reader { return p.in }

func (p *Prompter) line() (string, error) {
	line, err := p.in.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		if errors.Is(err, io.EOF) {
			return "", errors.New("입력이 끝나 설정을 중단합니다")
		}
		return "", fmt.Errorf("read answer: %w", err)
	}
	return strings.TrimSpace(line), nil
}
