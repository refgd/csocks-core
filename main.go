package csocks

import (
	"context"
	"errors"
)

var (
	logger *customLogger
)

type ListenConfig struct {
	ListenPort     string
	ServerAddress  string
	ServerCertFile string
	ServerKeyFile  string
	Secret         string
	WithHttp       bool
	PublicKeyFile  string
}

func NewListenConfig() *ListenConfig {
	return &ListenConfig{
		ListenPort:     "1080",
		ServerAddress:  "",
		ServerCertFile: "",
		ServerKeyFile:  "",
		Secret:         "anonymous",
		WithHttp:       false,
		PublicKeyFile:  "",
	}
}

func StartServer(ctx context.Context, listenConfig *ListenConfig, quiet bool) error {
	logger = newCustomLogger()
	logger.quiet = quiet

	if listenConfig.ServerAddress != "" {
		err := forward(ctx, listenConfig)
		if err != nil {
			return err
		}
	} else if listenConfig.ServerCertFile != "" {
		err := proxy(ctx, listenConfig)
		if err != nil {
			return err
		}
	} else {
		return errors.New("miss config")
	}

	return nil
}
