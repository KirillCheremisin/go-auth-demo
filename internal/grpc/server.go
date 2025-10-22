package grpc

import (
	"log"
	"net"

	"auth-demo/internal/config"
	"auth-demo/internal/grpc/proto"
	"auth-demo/internal/grpc/service"
	"auth-demo/internal/storage"

	"google.golang.org/grpc"
)

type Server struct {
	server   *grpc.Server
	grpcPort string
}

func NewServer(cfg *config.Config, userStorage storage.Storage) *Server {
	// Создаем gRPC сервер
	grpcServer := grpc.NewServer()

	// Регистрируем сервисы
	userService := service.NewUserService(userStorage)
	proto.RegisterUserServiceServer(grpcServer, userService)

	return &Server{
		server:   grpcServer,
		grpcPort: cfg.GRPCPort,
	}
}

func (s *Server) Start() error {
	lis, err := net.Listen("tcp", ":"+s.grpcPort)
	if err != nil {
		return err
	}

	log.Printf("🚀 gRPC server starting on port %s", s.grpcPort)

	return s.server.Serve(lis)
}

func (s *Server) Stop() {
	log.Println("🛑 Stopping gRPC server...")
	s.server.GracefulStop()
}
