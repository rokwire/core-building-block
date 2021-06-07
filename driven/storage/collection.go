package storage

import (
	"context"
	"errors"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type collectionWrapper struct {
	database *database
	coll     *mongo.Collection
}

func (collWrapper *collectionWrapper) Find(filter interface{}, result interface{}, findOptions *options.FindOptions) error {
	return collWrapper.FindWithContext(context.Background(), filter, result, findOptions)
}

func (collWrapper *collectionWrapper) FindWithContext(ctx context.Context, filter interface{}, result interface{}, findOptions *options.FindOptions) error {
	ctx, cancel := context.WithTimeout(ctx, collWrapper.database.mongoTimeout)
	defer cancel()

	if filter == nil {
		// Passing bson.D{} as the filter matches all documents in the collection
		filter = bson.D{}
	}

	cur, err := collWrapper.coll.Find(ctx, filter, findOptions)

	if err == nil {
		err = cur.All(ctx, result)
	}

	return err
}

func (collWrapper *collectionWrapper) FindOne(filter interface{}, result interface{}, findOptions *options.FindOneOptions) error {
	return collWrapper.FindOneWithContext(context.Background(), filter, result, findOptions)
}

func (collWrapper *collectionWrapper) FindOneWithContext(ctx context.Context, filter interface{}, result interface{}, findOptions *options.FindOneOptions) error {
	ctx, cancel := context.WithTimeout(ctx, collWrapper.database.mongoTimeout)
	defer cancel()

	if findOptions == nil {
		findOptions = options.FindOne() // crash if not added!
	}

	singleResult := collWrapper.coll.FindOne(ctx, filter, findOptions)
	if singleResult.Err() != nil {
		return singleResult.Err()
	}
	err := singleResult.Decode(result)
	if err != nil {
		return err
	}
	return nil
}

func (collWrapper *collectionWrapper) ReplaceOne(filter interface{}, replacement interface{}, replaceOptions *options.ReplaceOptions) error {
	return collWrapper.ReplaceOneWithContext(context.Background(), filter, replacement, replaceOptions)
}

func (collWrapper *collectionWrapper) ReplaceOneWithContext(ctx context.Context, filter interface{}, replacement interface{}, replaceOptions *options.ReplaceOptions) error {
	ctx, cancel := context.WithTimeout(ctx, collWrapper.database.mongoTimeout)
	defer cancel()

	if replacement == nil {
		return errors.New("replace one - input parameters cannot be nil")
	}
	if replaceOptions == nil {
		replaceOptions = options.Replace() // crash if not added!
	}

	res, err := collWrapper.coll.ReplaceOne(ctx, filter, replacement, replaceOptions)
	if err != nil {
		return err
	}
	if res == nil {
		return errors.New("replace one - res is nil")
	}
	matchedCount := res.MatchedCount
	if matchedCount == 0 {
		return errors.New("replace one - no record replaced")
	}
	return nil
}

func (collWrapper *collectionWrapper) InsertOne(data interface{}) (interface{}, error) {
	return collWrapper.InsertOneWithContext(context.Background(), data)
}

func (collWrapper *collectionWrapper) InsertOneWithContext(ctx context.Context, data interface{}) (interface{}, error) {
	ctx, cancel := context.WithTimeout(ctx, collWrapper.database.mongoTimeout)

	ins, err := collWrapper.coll.InsertOne(ctx, data)
	cancel()

	if err == nil {
		if id, ok := ins.InsertedID.(interface{}); ok {
			return id, nil
		}
	}

	return nil, err
}

func (collWrapper *collectionWrapper) InsertMany(documents []interface{}, opts *options.InsertManyOptions) (*mongo.InsertManyResult, error) {
	return collWrapper.InsertManyWithContext(context.Background(), documents, opts)
}

func (collWrapper *collectionWrapper) InsertManyWithContext(ctx context.Context, documents []interface{}, opts *options.InsertManyOptions) (*mongo.InsertManyResult, error) {
	ctx, cancel := context.WithTimeout(ctx, collWrapper.database.mongoTimeout)
	defer cancel()

	result, err := collWrapper.coll.InsertMany(ctx, documents, opts)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (collWrapper *collectionWrapper) DeleteMany(filter interface{}, opts *options.DeleteOptions) (*mongo.DeleteResult, error) {
	return collWrapper.DeleteManyWithContext(context.Background(), filter, opts)
}

func (collWrapper *collectionWrapper) DeleteManyWithContext(ctx context.Context, filter interface{}, opts *options.DeleteOptions) (*mongo.DeleteResult, error) {
	ctx, cancel := context.WithTimeout(ctx, collWrapper.database.mongoTimeout)
	defer cancel()

	result, err := collWrapper.coll.DeleteMany(ctx, filter, opts)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (collWrapper *collectionWrapper) DeleteOne(filter interface{}, opts *options.DeleteOptions) (*mongo.DeleteResult, error) {
	return collWrapper.DeleteOneWithContext(context.Background(), filter, opts)
}

func (collWrapper *collectionWrapper) DeleteOneWithContext(ctx context.Context, filter interface{}, opts *options.DeleteOptions) (*mongo.DeleteResult, error) {
	ctx, cancel := context.WithTimeout(ctx, collWrapper.database.mongoTimeout)
	defer cancel()

	result, err := collWrapper.coll.DeleteOne(ctx, filter, opts)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (collWrapper *collectionWrapper) UpdateOne(filter interface{}, update interface{}, opts *options.UpdateOptions) (*mongo.UpdateResult, error) {
	return collWrapper.UpdateOneWithContext(context.Background(), filter, update, opts)
}

func (collWrapper *collectionWrapper) UpdateOneWithContext(ctx context.Context, filter interface{}, update interface{}, opts *options.UpdateOptions) (*mongo.UpdateResult, error) {
	ctx, cancel := context.WithTimeout(ctx, collWrapper.database.mongoTimeout)
	defer cancel()

	updateResult, err := collWrapper.coll.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return nil, err
	}

	return updateResult, nil
}

func (collWrapper *collectionWrapper) CountDocuments(filter interface{}) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), collWrapper.database.mongoTimeout)
	defer cancel()

	if filter == nil {
		filter = bson.D{}
	}

	count, err := collWrapper.coll.CountDocuments(ctx, filter)

	if err != nil {
		return -1, err
	}
	return count, nil
}

func (collWrapper *collectionWrapper) Watch(pipeline interface{}) error {
	if pipeline == nil {
		pipeline = []bson.M{}
	}

	var opts *options.ChangeStreamOptions
	opts = options.ChangeStream()
	opts.SetFullDocument(options.UpdateLookup)

	ctx := context.Background()
	cur, err := collWrapper.coll.Watch(ctx, pipeline, opts)
	if err != nil {
		log.Printf("error watching: %s\n", err)
		return err
	}
	defer cur.Close(ctx)

	var changeDoc map[string]interface{}
	log.Println("waiting for changes")
	for cur.Next(ctx) {
		if e := cur.Decode(&changeDoc); e != nil {
			log.Printf("error decoding: %s\n", e)
		}
		collWrapper.database.onDataChanged(changeDoc)
	}

	if err := cur.Err(); err != nil {
		log.Printf("error cur.Err(): %s\n", err)
		return err
	}
	return nil
}

func (collWrapper *collectionWrapper) ListIndexes() ([]bson.M, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*15000)
	defer cancel()

	indexes, err := collWrapper.coll.Indexes().List(ctx, nil)
	if err != nil {
		log.Printf("error getting indexes list: %s\n", err)
		return nil, err
	}

	var list []bson.M
	err = indexes.All(ctx, &list)
	if err != nil {
		log.Printf("error iterating indexes list: %s\n", err)
		return nil, err
	}
	return list, nil
}

func (collWrapper *collectionWrapper) AddIndex(keys interface{}, unique bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*15000)
	defer cancel()

	index := mongo.IndexModel{Keys: keys}

	if unique {
		index.Options = options.Index()
		index.Options.Unique = &unique
	}

	_, err := collWrapper.coll.Indexes().CreateOne(ctx, index, nil)

	return err
}

func (collWrapper *collectionWrapper) AddIndexWithOptions(keys interface{}, opt *options.IndexOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*15000)
	defer cancel()

	index := mongo.IndexModel{Keys: keys}
	index.Options = opt

	_, err := collWrapper.coll.Indexes().CreateOne(ctx, index, nil)

	return err
}

func (collWrapper *collectionWrapper) DropIndex(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*15000)
	defer cancel()

	_, err := collWrapper.coll.Indexes().DropOne(ctx, name, nil)

	return err
}

func (collWrapper *collectionWrapper) Aggregate(pipeline interface{}, result interface{}, ops *options.AggregateOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*15000)
	defer cancel()

	cursor, err := collWrapper.coll.Aggregate(ctx, pipeline, ops)

	if err == nil {
		err = cursor.All(ctx, result)
	}

	return err
}

func (collWrapper *collectionWrapper) Drop() error {
	ctx, cancel := context.WithTimeout(context.Background(), collWrapper.database.mongoTimeout)
	defer cancel()

	err := collWrapper.coll.Drop(ctx)
	if err != nil {
		return err
	}
	return nil
}
