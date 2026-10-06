package egress

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// Cache caps (egress.md §4). Go refuses module zips over 500 MiB, so a larger object is not a module.
const (
	DefaultObjectCap = 512 << 20
	DefaultWorkerCap = 2 << 30
)

// cache is one worker's namespace <cachedir>/<P>.<W>/: immutable objects only (a version's .info, .mod and .zip,
// sumdb tiles), stored under the sha256 of their upstream path once a 200 response was read completely.
// Nothing in it is shared with another worker (G5). tmp/ holds responses being read.
type cache struct {
	dir string
	max int64

	mu   sync.Mutex
	used int64
}

func openCache(dir string, max int64) (*cache, error) {
	c := &cache{dir: dir, max: max}
	for _, d := range []string{"obj", "tmp"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return nil, err
		}
	}
	// Responses left by a crash are garbage.
	if ents, err := os.ReadDir(filepath.Join(dir, "tmp")); err == nil {
		for _, e := range ents {
			os.Remove(filepath.Join(dir, "tmp", e.Name()))
		}
	}
	err := filepath.WalkDir(filepath.Join(dir, "obj"), func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if fi, err := d.Info(); err == nil {
			c.used += fi.Size()
		}
		return nil
	})
	return c, err
}

func (c *cache) path(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.dir, "obj", hex.EncodeToString(sum[:]))
}

// open returns the cached object for key, or nil.
func (c *cache) open(key string) (*os.File, int64) {
	f, err := os.Open(c.path(key))
	if err != nil {
		return nil, 0
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, 0
	}
	return f, fi.Size()
}

// temp creates a file for a response being read.
func (c *cache) temp() (*os.File, error) { return os.CreateTemp(filepath.Join(c.dir, "tmp"), "r-") }

// store moves a completely read 200 response into the cache, unless the worker's total cap would be exceeded.
// It reports whether the object was stored; the temporary file is the caller's either way.
func (c *cache) store(key, tmp string, size int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.used+size > c.max {
		return false
	}
	dst := c.path(key)
	if _, err := os.Lstat(dst); err == nil {
		return false
	}
	if err := os.Link(tmp, dst); err != nil {
		return false
	}
	c.used += size
	return true
}

// removeCache deletes a worker's namespace. dir must be a namespace under the cache root.
func removeCache(dir string) error {
	err := os.RemoveAll(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
