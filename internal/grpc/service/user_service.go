package service

import (
	"auth-demo/internal/grpc/proto"
	"auth-demo/internal/storage"
	"context"
	"log"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type UserService struct {
	proto.UnimplementedUserServiceServer
	userStorage storage.Storage
}

func NewUserService(userStorage storage.Storage) *UserService {
	return &UserService{
		userStorage: userStorage,
	}
}

func (s *UserService) GetUserProfile(ctx context.Context, req *proto.GetUserRequest) (*proto.UserProfile, error) {
	// TODO: Добавим JWT валидацию позже
	log.Printf("gRPC GetUserProfile called for user: %s", req.UserId)

	user, err := s.userStorage.GetUserByID(req.UserId)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	// Конвертируем время в Timestamp
	createdAt, _ := time.Parse(time.RFC3339, user.CreatedAt.Format(time.RFC3339))

	return &proto.UserProfile{
		Id:          user.ID,
		Email:       user.Email,
		DisplayName: user.Email, // Пока используем email как display name
		CreatedAt:   timestamppb.New(createdAt),
		LastLogin:   timestamppb.New(time.Now()), // TODO: Добавить поле last_login в модель
	}, nil
}

func (s *UserService) ListUsers(ctx context.Context, req *proto.ListUsersRequest) (*proto.ListUsersResponse, error) {
	// TODO: Добавим JWT валидацию позже
	log.Printf("gRPC ListUsers called, page: %d, limit: %d", req.Page, req.Limit)

	users, err := s.userStorage.GetAllUsers()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get users")
	}

	// Простая пагинация
	page := int(req.Page)
	if page < 1 {
		page = 1
	}
	limit := int(req.Limit)
	if limit < 1 || limit > 100 {
		limit = 10
	}

	start := (page - 1) * limit
	end := start + limit
	if end > len(users) {
		end = len(users)
	}

	var userProfiles []*proto.UserProfile
	for i := start; i < end && i < len(users); i++ {
		user := users[i]
		createdAt, _ := time.Parse(time.RFC3339, user.CreatedAt.Format(time.RFC3339))

		userProfiles = append(userProfiles, &proto.UserProfile{
			Id:          user.ID,
			Email:       user.Email,
			DisplayName: user.Email,
			CreatedAt:   timestamppb.New(createdAt),
			LastLogin:   timestamppb.New(time.Now()),
		})
	}

	return &proto.ListUsersResponse{
		Users:      userProfiles,
		TotalCount: int32(len(users)),
		Page:       int32(page),
		TotalPages: int32((len(users) + limit - 1) / limit),
	}, nil
}

func (s *UserService) UpdateUserProfile(ctx context.Context, req *proto.UpdateUserRequest) (*proto.UserProfile, error) {
	// TODO: Добавим JWT валидацию и реальное обновление позже
	log.Printf("gRPC UpdateUserProfile called for user: %s", req.UserId)

	// Собираем обновления
	updates := make(map[string]interface{})
	if req.Email != nil {
		updates["email"] = *req.Email
	}
	if req.DisplayName != nil {
		updates["display_name"] = *req.DisplayName
	}

	// Если нет полей для обновления
	if len(updates) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no fields to update")
	}

	// Обновляем пользователя
	user, err := s.userStorage.UpdateUser(req.UserId, updates)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to update user")
	}

	// Конвертируем время
	createdAt, _ := time.Parse(time.RFC3339, user.CreatedAt.Format(time.RFC3339))

	return &proto.UserProfile{
		Id:          user.ID,
		Email:       user.Email,
		DisplayName: user.Email, // Пока используем email как display name
		CreatedAt:   timestamppb.New(createdAt),
		LastLogin:   timestamppb.New(time.Now()),
	}, nil
}
