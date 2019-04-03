package elasticsearch

import (
	"fmt"
	"testing"
)

// TODO actually end-to-end test the plugin with a working client
// TODO write backend tests that can be toggled to hit a real docker

// TODO this needs a fake client
func TestClientFactory_Raciness(t *testing.T) {
	factory := &clientFactory{
		clientConfig: &ClientConfig{},
	}
	start := make(chan struct{})

	for i := 0; i < 100; i++ {
		go func() {
			conf := &ClientConfig{}
			<-start
			factory.UpdateConfig(conf)
		}()
	}

	for i := 0; i < 100; i++ {
		go func() {
			<-start
			client, err := factory.GetClient()
			if err != nil {
				t.Fatal(err)
			}
			fmt.Sprintf("%+v\n", client)
		}()
	}

	for i := 0; i < 100; i++ {
		done := make(chan struct{})
		go func() {
			<-start
			if err := factory.UpdatePassword(done, "new"); err != nil {
				t.Fatal(err)
			}
		}()
	}

	close(start)
}
