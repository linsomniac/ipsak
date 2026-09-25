//go:build !unix

package stream

import "os"

func pollableOutput(original *os.File) (*os.File, func(), error) {
	return original, func() {}, nil
}
