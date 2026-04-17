// Package store provides implementations of the idproxy.Store interface
// for session, authorization code, and access token persistence.
//
// # MemoryStore
//
// The default implementation is MemoryStore, an in-memory store suitable
// for single-instance deployments and testing. State is lost when the process
// restarts and is not shared across multiple instances.
//
// # DynamoDBStore
//
// DynamoDBStore provides a DynamoDB-backed persistent store for multi-instance
// deployments such as AWS Lambda with multiple concurrent containers.
//
// Use DynamoDBStore when:
//   - Running on AWS Lambda with multiple concurrent executions
//   - State must survive process restarts (cold starts)
//   - Multiple instances must share session, authorization code, and token state
//
// Use MemoryStore when:
//   - Single-instance deployments (e.g. a single container or VM)
//   - Testing and local development
//   - State does not need to persist across restarts
//
// Example (DynamoDBStore):
//
//	s, err := store.NewDynamoDBStore("my-idproxy-table", "ap-northeast-1")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer s.Close()
//
//	cfg := idproxy.Config{
//	    Store: s,
//	    // ...
//	}
package store
