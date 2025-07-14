package main

import (
	"compress/gzip"
	"io"
	"os"
)

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer ignore(in.Close())

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer ignore(out.Close())

	_, err = io.Copy(out, in)
	return err
}

func gzipFile(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		ignore(in.Close())
	}()

	out, err := os.Create(path + ".gz")
	if err != nil {
		return err
	}
	defer func() {
		ignore(out.Close())
	}()

	gz := gzip.NewWriter(out)
	defer ignore(gz.Close())

	_, err = io.Copy(gz, in)
	return err
}
