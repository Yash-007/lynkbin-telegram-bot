package main

import (
	"context"

	"github.com/redis/go-redis/v9"
)

func NewRedisClient(addr string) redis.Client {
	options, err := redis.ParseURL(addr)
	if err != nil {
		panic(err)
	}
	client := redis.NewClient(options)
	_, err = client.Ping(context.Background()).Result()
	if err != nil {
		panic(err)
	}

	return *client
}
