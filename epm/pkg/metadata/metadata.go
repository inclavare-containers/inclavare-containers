package metadata

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/boltdb/bolt"
	"github.com/inclavare-containers/epm/pkg/epm-api/v1alpha1"
)

// Metadata containers the DB used to store the cache metadata
type Metadata struct {
	db *bolt.DB
}

// NewMetadataServer open a DB connection
func NewMetadataServer(DBPath string, timeout time.Duration) (*Metadata, error) {
	db, err := bolt.Open(DBPath, 0600, &bolt.Options{Timeout: timeout})
	if err != nil {
		return nil, err
	}
	return &Metadata{db: db}, nil
}

// SaveCache saves the cache metadata to DB
func (m *Metadata) SaveCache(bucket, key string, cache *v1alpha1.Cache) error {
	return m.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		value, err := json.Marshal(cache)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), value)
	})
}

// DeleteCache deletes the cache metadata from DB
func (m *Metadata) DeleteCache(bucket, key string) error {
	return m.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		return b.Delete([]byte(key))
	})
}

// GetCache gets the cache metadata from DB
func (m *Metadata) GetCache(bucket, key string) (*v1alpha1.Cache, error) {
	cache := &v1alpha1.Cache{}
	err := m.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			cache = nil
			return nil
		}
		value := b.Get([]byte(key))
		return json.Unmarshal(value, cache)
	})
	if err != nil {
		return nil, err
	}
	return cache, nil
}

// ListCache lists the cache metadata from DB
func (m *Metadata) ListCache(bucket, subType string, lastKey string, limit int32) ([]*v1alpha1.Cache, error) {
	caches := make([]*v1alpha1.Cache, 0)
	err := m.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		var k, v []byte
		if lastKey != "" {
			k, v = c.Seek([]byte(lastKey))
		} else {
			k, v = c.First()
		}
		var count int32
		for ; k != nil && count < limit; k, v = c.Next() {
			cache := &v1alpha1.Cache{}
			if err := json.Unmarshal(v, cache); err != nil {
				return err
			}
			if cache.SubType != subType {
				continue
			}
			caches = append(caches, cache)
			count++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return caches, nil
}

// Close closes the DB connections
func (m *Metadata) Close() error {
	return m.db.Close()
}

// GetAncestorCaches get the ancestor caches
func (m *Metadata) GetAncestorCaches(cache *v1alpha1.Cache) ([]*v1alpha1.Cache, error) {
	p := cache.Parent
	caches := make([]*v1alpha1.Cache, 0)
	for p != nil {
		c, err := m.GetCache(p.Type, p.ID)
		if err != nil {
			return nil, err
		}
		if c == nil {
			return nil, fmt.Errorf("parent cache is not exit. type: %s, id: %s", p.Type, p.ID)
		}
		caches = append(caches, c)
		p = c.Parent
	}
	return caches, nil
}
