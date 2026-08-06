// Copyright 2026 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build integration

package storage

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// This file integration-tests the driven/storage <-> mongo-driver/v2 boundary against a real,
// disposable MongoDB instance (via testcontainers-go). It targets exactly the operations and
// edge cases that changed behavior or API shape during the v1 -> v2 migration, since the
// storage package previously had zero automated test coverage of its own.
//
// Requires a local Docker daemon. Gated behind the "integration" build tag so `go test ./...`
// (and `make`, which runs it as part of the Docker image build) does not try to start a
// container in environments with no Docker access. Run with:
//
//	go test -tags=integration ./driven/storage/...

var testMongoURI string

func TestMain(m *testing.M) {
	ctx := context.Background()

	// PerformTransaction (sessions/transactions) and Watch (change streams) both require a
	// replica set - a plain standalone mongod rejects both.
	container, err := mongodb.Run(ctx, "mongo:7", mongodb.WithReplicaSet("rs0"))
	if err != nil {
		panic("failed to start mongodb test container: " + err.Error())
	}
	defer func() {
		_ = testcontainers.TerminateContainer(container)
	}()

	uri, err := container.ConnectionString(ctx)
	if err != nil {
		panic("failed to get mongodb test container connection string: " + err.Error())
	}
	testMongoURI = uri

	m.Run()
}

func testLogger() *logs.Logger {
	return logs.NewLogger("storage-migration-test", &logs.LoggerOpts{})
}

// newTestDatabase connects a lightweight *database (no collection provisioning) to the shared
// test container, using the same client options as database.start() so the DefaultDocumentMap
// fix is exercised identically to production.
func newTestDatabase(t *testing.T) *database {
	t.Helper()

	timeout := 5 * time.Second
	clientOptions := options.Client().ApplyURI(testMongoURI).
		SetConnectTimeout(timeout).
		SetBSONOptions(&options.BSONOptions{DefaultDocumentMap: true})

	client, err := mongo.Connect(clientOptions)
	if err != nil {
		t.Fatalf("connect: %s", err)
	}
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })

	if err := client.Ping(context.Background(), nil); err != nil {
		t.Fatalf("ping: %s", err)
	}

	db := &database{mongoDBName: "migration_test", mongoTimeout: timeout, logger: testLogger(), listeners: []Listener{}}
	db.db = client.Database(db.mongoDBName)
	db.dbClient = client
	return db
}

// freshCollection returns a collectionWrapper over a brand-new, uniquely named collection so
// tests don't interfere with each other or with any indexes/constraints from production schema.
func freshCollection(t *testing.T, db *database, name string) *collectionWrapper {
	t.Helper()
	coll := &collectionWrapper{database: db, coll: db.db.Collection(name + "_" + uniqueSuffix())}
	t.Cleanup(func() { _ = coll.Drop() })
	return coll
}

var suffixCounter int64

func uniqueSuffix() string {
	return fmt.Sprintf("%d", atomic.AddInt64(&suffixCounter, 1))
}

type testDoc struct {
	ID    string `bson:"_id"`
	Name  string `bson:"name"`
	Group string `bson:"group"`
}

// TestAdapterStart exercises the real production startup path (mongo.Connect with
// SetBSONOptions/SetConnectTimeout, all ~20 applyXChecks/AddIndex calls, and launching the
// change-stream Watch goroutines) against a real MongoDB instance.
func TestAdapterStart(t *testing.T) {
	logger := testLogger()
	sa := NewStorageAdapter("test-host", testMongoURI, "migration_test_start", "5000", logger)

	if err := sa.Start(); err != nil {
		t.Fatalf("adapter start: %s", err)
	}
}

func TestFindAndFindOne(t *testing.T) {
	db := newTestDatabase(t)
	coll := freshCollection(t, db, "find")

	_, err := coll.InsertOne(testDoc{ID: "1", Name: "alice", Group: "a"})
	if err != nil {
		t.Fatalf("insert: %s", err)
	}
	_, err = coll.InsertOne(testDoc{ID: "2", Name: "bob", Group: "a"})
	if err != nil {
		t.Fatalf("insert: %s", err)
	}

	var all []testDoc
	if err := coll.Find(bson.M{"group": "a"}, &all, nil); err != nil {
		t.Fatalf("find: %s", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 docs, got %d", len(all))
	}

	var one testDoc
	if err := coll.FindOne(bson.M{"_id": "1"}, &one); err != nil {
		t.Fatalf("find one: %s", err)
	}
	if one.Name != "alice" {
		t.Fatalf("expected alice, got %s", one.Name)
	}

	findOpts := options.Find().SetLimit(1)
	var limited []testDoc
	if err := coll.Find(bson.M{"group": "a"}, &limited, []options.Lister[options.FindOptions]{findOpts}); err != nil {
		t.Fatalf("find with options: %s", err)
	}
	if len(limited) != 1 {
		t.Fatalf("expected 1 doc with limit, got %d", len(limited))
	}
}

// TestReplaceOne covers the guard logic that had to change under v2 (options.ReplaceOptions no
// longer exposes an Upsert field to read back): matched, not-matched, and upsert paths.
func TestReplaceOne(t *testing.T) {
	db := newTestDatabase(t)
	coll := freshCollection(t, db, "replace")

	if _, err := coll.InsertOne(testDoc{ID: "1", Name: "alice", Group: "a"}); err != nil {
		t.Fatalf("insert: %s", err)
	}

	// matched -> no error
	if err := coll.ReplaceOne(bson.M{"_id": "1"}, testDoc{ID: "1", Name: "alice2", Group: "a"}, nil); err != nil {
		t.Fatalf("replace matched: %s", err)
	}
	var updated testDoc
	if err := coll.FindOne(bson.M{"_id": "1"}, &updated); err != nil {
		t.Fatalf("find after replace: %s", err)
	}
	if updated.Name != "alice2" {
		t.Fatalf("expected alice2, got %s", updated.Name)
	}

	// not matched, no upsert -> error
	err := coll.ReplaceOne(bson.M{"_id": "does-not-exist"}, testDoc{ID: "does-not-exist", Name: "x"}, nil)
	if err == nil {
		t.Fatal("expected error for no-match replace without upsert")
	}

	// not matched, upsert -> no error
	upsertOpts := options.Replace().SetUpsert(true)
	err = coll.ReplaceOne(bson.M{"_id": "2"}, testDoc{ID: "2", Name: "carol", Group: "b"}, upsertOpts)
	if err != nil {
		t.Fatalf("replace upsert: %s", err)
	}
	var upserted testDoc
	if err := coll.FindOne(bson.M{"_id": "2"}, &upserted); err != nil {
		t.Fatalf("find upserted: %s", err)
	}
	if upserted.Name != "carol" {
		t.Fatalf("expected carol, got %s", upserted.Name)
	}
}

func TestInsertUpdateDelete(t *testing.T) {
	db := newTestDatabase(t)
	coll := freshCollection(t, db, "crud")

	docs := []interface{}{
		testDoc{ID: "1", Name: "alice", Group: "a"},
		testDoc{ID: "2", Name: "bob", Group: "a"},
		testDoc{ID: "3", Name: "carol", Group: "b"},
	}
	if _, err := coll.InsertMany(docs, nil); err != nil {
		t.Fatalf("insert many: %s", err)
	}

	count, err := coll.CountDocuments(bson.M{"group": "a"})
	if err != nil {
		t.Fatalf("count: %s", err)
	}
	if count != 2 {
		t.Fatalf("expected 2, got %d", count)
	}

	updateRes, err := coll.UpdateOne(bson.M{"_id": "1"}, bson.M{"$set": bson.M{"name": "alice-updated"}}, nil)
	if err != nil {
		t.Fatalf("update one: %s", err)
	}
	if updateRes.ModifiedCount != 1 {
		t.Fatalf("expected 1 modified, got %d", updateRes.ModifiedCount)
	}

	updateManyRes, err := coll.UpdateMany(bson.M{"group": "a"}, bson.M{"$set": bson.M{"group": "a2"}}, nil)
	if err != nil {
		t.Fatalf("update many: %s", err)
	}
	if updateManyRes.ModifiedCount != 2 {
		t.Fatalf("expected 2 modified, got %d", updateManyRes.ModifiedCount)
	}

	delOneRes, err := coll.DeleteOne(bson.M{"_id": "3"}, nil)
	if err != nil {
		t.Fatalf("delete one: %s", err)
	}
	if delOneRes.DeletedCount != 1 {
		t.Fatalf("expected 1 deleted, got %d", delOneRes.DeletedCount)
	}

	delManyRes, err := coll.DeleteMany(bson.M{"group": "a2"}, nil)
	if err != nil {
		t.Fatalf("delete many: %s", err)
	}
	if delManyRes.DeletedCount != 2 {
		t.Fatalf("expected 2 deleted, got %d", delManyRes.DeletedCount)
	}
}

// TestUpdateManyArrayFilters mirrors the two real ArrayFilters call sites in adapter.go
// (UpdateAppOrgRole / UpdateAppOrgGroup), which had to move from options.ArrayFilters{Filters:
// []interface{}{...}} to a plain []any passed to options.UpdateMany().SetArrayFilters(...).
func TestUpdateManyArrayFilters(t *testing.T) {
	db := newTestDatabase(t)
	coll := freshCollection(t, db, "arrayfilters")

	doc := bson.M{
		"_id": "1",
		"items": bson.A{
			bson.M{"id": "a", "value": 1},
			bson.M{"id": "b", "value": 1},
		},
	}
	if _, err := coll.InsertOne(doc); err != nil {
		t.Fatalf("insert: %s", err)
	}

	arrayFilters := []interface{}{bson.M{"element.id": "b"}}
	updateOpts := options.UpdateOne().SetArrayFilters(arrayFilters)
	res, err := coll.UpdateOne(bson.M{"_id": "1"}, bson.M{"$set": bson.M{"items.$[element].value": 2}}, updateOpts)
	if err != nil {
		t.Fatalf("update with array filters: %s", err)
	}
	if res.ModifiedCount != 1 {
		t.Fatalf("expected 1 modified, got %d", res.ModifiedCount)
	}

	var result bson.M
	if err := coll.FindOne(bson.M{"_id": "1"}, &result); err != nil {
		t.Fatalf("find: %s", err)
	}
	items, ok := result["items"].(bson.A)
	if !ok {
		t.Fatalf("expected items to be bson.A, got %T", result["items"])
	}
	// items[1] is decoded through an `any` destination (bson.A element type), so it's subject to
	// the same DefaultDocumentMap fix as the rest of this test file - it comes back as
	// map[string]interface{}, not bson.M.
	updatedItem, ok := items[1].(map[string]interface{})
	if !ok {
		t.Fatalf("expected item to be map[string]interface{}, got %T", items[1])
	}
	if v, _ := updatedItem["value"].(int32); v != 2 {
		t.Fatalf("expected element b value 2, got %v", updatedItem["value"])
	}
}

func TestIndexes(t *testing.T) {
	db := newTestDatabase(t)
	coll := freshCollection(t, db, "indexes")

	if err := coll.AddIndex(bson.D{{Key: "name", Value: 1}}, true); err != nil {
		t.Fatalf("add unique index: %s", err)
	}

	indexOpts := options.Index().SetUnique(false).SetName("group_idx")
	if err := coll.AddIndexWithOptions(bson.D{{Key: "group", Value: 1}}, indexOpts); err != nil {
		t.Fatalf("add index with options: %s", err)
	}

	list, err := coll.ListIndexes(db.logger)
	if err != nil {
		t.Fatalf("list indexes: %s", err)
	}
	// _id index + the two we created
	if len(list) != 3 {
		t.Fatalf("expected 3 indexes, got %d: %+v", len(list), list)
	}

	if err := coll.DropIndex("group_idx"); err != nil {
		t.Fatalf("drop index: %s", err)
	}
	list, err = coll.ListIndexes(db.logger)
	if err != nil {
		t.Fatalf("list indexes after drop: %s", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 indexes after drop, got %d", len(list))
	}

	// uniqueness should now be enforced
	if _, err := coll.InsertOne(testDoc{ID: "1", Name: "dup", Group: "a"}); err != nil {
		t.Fatalf("insert: %s", err)
	}
	_, err = coll.InsertOne(testDoc{ID: "2", Name: "dup", Group: "a"})
	if err == nil {
		t.Fatal("expected duplicate key error on unique name index")
	}
}

func TestAggregate(t *testing.T) {
	db := newTestDatabase(t)
	coll := freshCollection(t, db, "aggregate")

	docs := []interface{}{
		testDoc{ID: "1", Name: "alice", Group: "a"},
		testDoc{ID: "2", Name: "bob", Group: "a"},
		testDoc{ID: "3", Name: "carol", Group: "b"},
	}
	if _, err := coll.InsertMany(docs, nil); err != nil {
		t.Fatalf("insert many: %s", err)
	}

	pipeline := bson.A{
		bson.M{"$group": bson.M{"_id": "$group", "count": bson.M{"$sum": 1}}},
		bson.M{"$sort": bson.M{"_id": 1}},
	}
	var result []bson.M
	if err := coll.Aggregate(pipeline, &result, nil); err != nil {
		t.Fatalf("aggregate: %s", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(result))
	}
	if result[0]["_id"] != "a" || result[0]["count"] != int32(2) {
		t.Fatalf("unexpected group a result: %+v", result[0])
	}
}

// TestPerformTransaction covers both the commit and abort paths of the transaction/session
// rewrite, the single biggest structural API change in the v1 -> v2 migration.
func TestPerformTransaction(t *testing.T) {
	db := newTestDatabase(t)
	coll := freshCollection(t, db, "tx")
	sa := &Adapter{db: db, logger: db.logger}

	// commit path
	err := sa.PerformTransaction(func(ctx TransactionContext) error {
		_, err := coll.InsertOneWithContext(ctx, testDoc{ID: "1", Name: "alice", Group: "a"})
		return err
	})
	if err != nil {
		t.Fatalf("perform transaction (commit): %s", err)
	}
	count, err := coll.CountDocuments(nil)
	if err != nil {
		t.Fatalf("count: %s", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 doc after commit, got %d", count)
	}

	// abort path: the transaction function returns an error, so the insert must be rolled back
	sentinel := errors.New("induced failure")
	err = sa.PerformTransaction(func(ctx TransactionContext) error {
		if _, err := coll.InsertOneWithContext(ctx, testDoc{ID: "2", Name: "bob", Group: "a"}); err != nil {
			return err
		}
		return sentinel
	})
	if err == nil {
		t.Fatal("expected error from aborted transaction")
	}
	count, err = coll.CountDocuments(nil)
	if err != nil {
		t.Fatalf("count: %s", err)
	}
	if count != 1 {
		t.Fatalf("expected abort to roll back insert, still expected 1 doc, got %d", count)
	}
}

// TestNestedDocumentDecode is the most important regression test from the previous migration
// attempt: nested BSON sub-documents decoded through an interface{}-typed destination came back
// as bson.D in v2 by default instead of map[string]interface{} as in v1, silently breaking any
// code that does a `.(map[string]interface{})` type assertion (e.g. account privacy/field
// visibility handling). The fix is a single client-level option (SetBSONOptions with
// DefaultDocumentMap: true, set in database.go's start() and mirrored in newTestDatabase above).
// This test proves that option restores v1-identical decoding.
func TestNestedDocumentDecode(t *testing.T) {
	db := newTestDatabase(t)
	coll := freshCollection(t, db, "nested")

	doc := bson.M{
		"_id": "1",
		"field_visibility": bson.M{
			"profile": bson.M{
				"first_name": "public",
				"last_name":  "private",
			},
		},
	}
	if _, err := coll.InsertOne(doc); err != nil {
		t.Fatalf("insert: %s", err)
	}

	var result struct {
		ID              string                  `bson:"_id"`
		FieldVisibility *map[string]interface{} `bson:"field_visibility"`
	}
	if err := coll.FindOne(bson.M{"_id": "1"}, &result); err != nil {
		t.Fatalf("find one: %s", err)
	}
	if result.FieldVisibility == nil {
		t.Fatal("expected field visibility to be decoded")
	}

	profileRaw, ok := (*result.FieldVisibility)["profile"]
	if !ok {
		t.Fatal("expected nested 'profile' key")
	}

	// This is the exact assertion pattern used in core/model/user.go's
	// Privacy.ValidateFieldVisibility and utils/utils.go's GetMapEntryFromPath. Without
	// DefaultDocumentMap, profileRaw's concrete type would be bson.D and this assertion would
	// fail, exactly reproducing the suspected class of production regression.
	profile, ok := profileRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("expected nested value to decode as map[string]interface{}, got %T", profileRaw)
	}
	if profile["first_name"] != "public" {
		t.Fatalf("expected first_name=public, got %v", profile["first_name"])
	}
}

// TestWatchOnDataChanged is an end-to-end smoke test of the change-stream pipeline
// (collectionWrapper.Watch -> cur.Decode -> database.onDataChanged -> Listener), which was the
// area that needed the most iteration ("Fix on data changed", "Fix watch issue") in the previous
// migration attempt. The collection must be named "configs" to match one of the switch cases in
// onDataChanged.
func TestWatchOnDataChanged(t *testing.T) {
	db := newTestDatabase(t)
	configs := &collectionWrapper{database: db, coll: db.db.Collection("configs")}
	t.Cleanup(func() { _ = configs.Drop() })
	db.configs = configs

	notified := make(chan struct{}, 1)
	listener := &testListener{onConfigsUpdated: func() { notified <- struct{}{} }}
	db.listeners = append(db.listeners, listener)

	go configs.Watch(nil, db.logger)
	// give the change stream a moment to establish before writing
	time.Sleep(2 * time.Second)

	if _, err := configs.InsertOne(bson.M{"_id": "1", "type": "test", "app_id": "app1", "org_id": "org1"}); err != nil {
		t.Fatalf("insert: %s", err)
	}

	select {
	case <-notified:
		// success - onDataChanged decoded the change stream document and dispatched to the listener
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for OnConfigsUpdated notification")
	}
}

type testListener struct {
	DefaultListenerImpl
	onConfigsUpdated func()
}

func (l *testListener) OnConfigsUpdated() {
	if l.onConfigsUpdated != nil {
		l.onConfigsUpdated()
	}
}
