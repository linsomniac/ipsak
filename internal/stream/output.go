package stream

import (
	"fmt"
	"os"
	"path/filepath"
)

// Output streams into a same-directory private temporary file. Abort removes
// only that temporary file, never an existing or already committed destination.
type Output struct {
	File             *os.File
	path, temporary  string
	force, committed bool
}

func NewOutput(path string, force bool) (*Output, error) {
	if path == "" || path == "-" {
		return nil, fmt.Errorf("output requires a filename")
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing symlink destination %q", path)
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("destination is not a regular file")
		}
		if !force {
			return nil, fmt.Errorf("destination exists; use --force to replace it")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".ipsak-*")
	if err != nil {
		return nil, err
	}
	return &Output{File: f, path: path, temporary: f.Name(), force: force}, nil
}

func (o *Output) Commit() error {
	if o.committed {
		return fmt.Errorf("output already committed")
	}
	if err := o.File.Sync(); err != nil {
		return err
	}
	if err := o.File.Close(); err != nil {
		return err
	}
	if o.force {
		if err := os.Rename(o.temporary, o.path); err != nil {
			return err
		}
	} else {
		// Link fails if any destination entry appeared after the preflight check.
		if err := os.Link(o.temporary, o.path); err != nil {
			return err
		}
		_ = os.Remove(o.temporary)
	}
	o.committed = true
	return nil
}

func (o *Output) Abort() {
	_ = o.File.Close()
	_ = os.Remove(o.temporary)
}
