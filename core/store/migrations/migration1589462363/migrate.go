package migration1589462363

import (
	"github.com/jinzhu/gorm"
)

// Migrate adds the requisite tables for the BulletproofTxManager
// I have tried to make an intelligent guess at the required indexes and
// constraints but this will need revisiting after the system has been finished
func Migrate(tx *gorm.DB) error {
	return tx.Exec(`
	  	ALTER TABLE keys ADD COLUMN nonce BIGINT NOT NULL DEFAULT 0;
	`).Error
}
