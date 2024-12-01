package service

import (
	"github.com/google/uuid"
	"go-auth/src/model"
	"gorm.io/gorm"
	"log"
)

type TokenService struct {
	DB gorm.DB
}

func (s *TokenService) GetTokensByGuid(guid string) ([]model.RefreshTokenModel, error) {
	var tokens []model.RefreshTokenModel
	_uuid, err := uuid.FromBytes([]byte(guid))
    if err != nil {
		log.Printf("GUID %s length is not 16", guid)
        return nil, err
    }
	err = s.DB.Where("guid = ?", _uuid).Find(&tokens).Error
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

func (s *TokenService) CreateRefreshToken(guid string, hash string) error {
	_uuid, err := uuid.FromBytes([]byte(guid))
    if err != nil {
		log.Printf("GUID %s length is not 16", guid)
        return err
    }
    token := model.RefreshTokenModel{Guid: _uuid, RefreshTokenHash: hash}
	return s.DB.Create(&token).Error
}