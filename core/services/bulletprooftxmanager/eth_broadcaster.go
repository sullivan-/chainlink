package bulletprooftxmanager

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink/core/eth"
	"github.com/smartcontractkit/chainlink/core/logger"
	"github.com/smartcontractkit/chainlink/core/store"
	"github.com/smartcontractkit/chainlink/core/store/models"
	"github.com/smartcontractkit/chainlink/core/store/orm"
	"github.com/smartcontractkit/chainlink/core/utils"

	gethCommon "github.com/ethereum/go-ethereum/common"
	gethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/jinzhu/gorm"
)

const (
	// databasePollInterval indicates how long to wait each time before polling
	// the database for new eth_transactions to send
	databasePollInterval = 1 * time.Second
)

type EthBroadcaster interface {
	Start() error
	Stop() error

	ProcessUnbroadcastEthTransactions() error
}

// ethBroadcaster monitors eth_transactions for transactions that need to
// be broadcast, assigns nonces and ensures that at least one eth node
// somewhere has received the transaction successfully.
//
// This does not guarantee delivery! A whole host of other things can
// subsequently go wrong such as transctions being evicted from the mempool,
// eth nodes going offline etc. Responsibility for ensuring eventual inclusion
// into the chain falls on the shoulders of the ethConfirmer.
//
// What ethBroadcaster does guarantee is:
// - a finalised nonce
// - existence of a saved eth_transaction_attempt
// - that the transaction is valid and can be accepted by an eth node (and if not, it is saved with an error)
type ethBroadcaster struct {
	store             *store.Store
	gethClientWrapper store.GethClientWrapper
	config            orm.ConfigReader

	started    bool
	stateMutex sync.RWMutex

	chStop chan struct{}
	chDone chan struct{}
}

func NewEthBroadcaster(store *store.Store, gethClientWrapper store.GethClientWrapper, config orm.ConfigReader) EthBroadcaster {
	return &ethBroadcaster{
		store:             store,
		gethClientWrapper: gethClientWrapper,
		config:            config,
		chStop:            make(chan struct{}),
		chDone:            make(chan struct{}),
	}
}

func (eb *ethBroadcaster) Start() error {
	if !eb.config.EnableBulletproofTxManager() {
		return nil
	}

	eb.stateMutex.Lock()
	defer eb.stateMutex.Unlock()
	if eb.started {
		return errors.New("already started")
	}
	go eb.monitorEthTransactions()
	eb.started = true

	return nil
}

func (eb *ethBroadcaster) Stop() error {
	eb.stateMutex.Lock()
	defer eb.stateMutex.Unlock()
	if !eb.started {
		return nil
	}
	eb.started = false
	close(eb.chStop)
	<-eb.chDone

	return nil
}

func (eb *ethBroadcaster) monitorEthTransactions() {
	defer close(eb.chDone)
	for {
		if err := eb.ProcessUnbroadcastEthTransactions(); err != nil {
			logger.Error(err)
		}

		pollDatabaseTimer := time.NewTimer(databasePollInterval)

		select {
		case <-eb.chStop:
			return
		case <-pollDatabaseTimer.C:
			continue
		}
	}
}

// TODO: write this doc
// NOTE: First version of this MUST NOT be run concurrently or it will break things!
// Multiple stages of concurrency handling, first is to manage distributed system between one singleton process and the eth network.
// Next stage will be to allow multiple insances of the eb to be run
func (eb *ethBroadcaster) ProcessUnbroadcastEthTransactions() error {
	defaultAddress, err := GetDefaultAddress(eb.store)
	if err != nil {
		return err
	}

	for {
		// TODO: Add total attempts count for transactions and maybe mark as error if some limit is exceeded?
		ethTransaction, err := nextUnbroadcastTransactionWithNonce(eb.store, defaultAddress)
		if err != nil {
			// Unexpected fatal error
			return err
		}
		if ethTransaction == nil {
			// Finished
			return nil
		}

		gasPrice := eb.config.EthGasPriceDefault()
		ethTransactionAttempt, unretryableError := eb.send(*ethTransaction, gasPrice)

		if unretryableError != nil {
			errString := unretryableError.Error()
			ethTransaction.Nonce = nil
			ethTransaction.Error = &errString
			err := eb.store.RawDB(func(db *gorm.DB) error {
				return db.Save(ethTransaction).Error
			})
			if err != nil {
				// Unexpected fatal error
				return err
			}
			continue
		}

		now := time.Now()
		ethTransaction.BroadcastAt = &now

		err = saveBroadcastTransaction(eb.store, *ethTransaction, ethTransactionAttempt)
		if err != nil {
			// Unexpected fatal error
			return err
		}
	}
}

// TODO: Write short doc
func nextUnbroadcastTransactionWithNonce(store *store.Store, defaultAddress gethCommon.Address) (*models.EthTransaction, error) {
	ethTransaction := &models.EthTransaction{}
	err := store.Transaction(func(tx *gorm.DB) error {
		if err := findNextUnbroadcastTransaction(tx, ethTransaction); err != nil {
			// rollback
			return err
		}

		if ethTransaction.FromAddress == nil {
			ethTransaction.FromAddress = &defaultAddress
		}
		if ethTransaction.Nonce == nil {
			nonce, err := GetAndIncrementNonce(tx, *ethTransaction.FromAddress)
			if err != nil {
				// rollback
				return err
			}
			ethTransaction.Nonce = &nonce
			if err := tx.Save(ethTransaction).Error; err != nil {
				// rollback
				return err
			}
		}
		return nil
	})
	if gorm.IsRecordNotFoundError(err) {
		// Finish. No more unbroadcasted transactions left to process. Hoorah!
		return nil, nil
	}
	return ethTransaction, err
}

// TODO: Needs indexing optimization
func findNextUnbroadcastTransaction(tx *gorm.DB, ethTransaction *models.EthTransaction) error {
	return tx.
		Where("error IS NULL AND broadcast_at IS NULL").
		Order("nonce ASC NULLS LAST, created_at ASC, id ASC").
		First(ethTransaction).
		Error
}

func saveBroadcastTransaction(store *store.Store, ethTransaction models.EthTransaction, attempt models.EthTransactionAttempt) error {
	if ethTransaction.BroadcastAt == nil {
		return errors.New("broadcastAt must be set")
	}
	return store.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(&ethTransaction).Error; err != nil {
			return err
		}
		return tx.Save(&attempt).Error
	})
}

// TODO: Write this doc with concurrency notes
func GetAndIncrementNonce(tx *gorm.DB, address gethCommon.Address) (int64, error) {
	var nonce *int64
	row := tx.Raw("UPDATE keys SET nonce = nonce + 1 WHERE address = ? RETURNING nonce - 1", address).Row()
	if err := row.Scan(&nonce); err != nil {
		logger.Error(err)
		return 0, err
	}
	return *nonce, nil

}

// TODO: Write this doc
// If this function returns an error, that error is in the class of FATAL
// UNCONFIRMED and will not ever give a different result on retry.
// TODO: convert transaction / attempt to pointers and return only error
func (eb *ethBroadcaster) send(ethTransaction models.EthTransaction, gasPrice *big.Int) (models.EthTransactionAttempt, error) {
	attempt := models.EthTransactionAttempt{}
	if ethTransaction.Nonce == nil {
		return attempt, errors.New("cannot send transaction without nonce")
	}
	if ethTransaction.FromAddress == nil {
		return attempt, errors.New("transaction missing from address")
	}
	account, err := eb.store.KeyStore.GetAccountByAddress(*ethTransaction.FromAddress)
	if err != nil {
		return attempt, err
	}

	transaction := gethTypes.NewTransaction(uint64(*ethTransaction.Nonce), ethTransaction.ToAddress, ethTransaction.Value.ToInt(), ethTransaction.GasLimit, gasPrice, ethTransaction.EncodedPayload)
	signedTransaction, err := eb.store.KeyStore.SignTx(account, transaction, eb.config.ChainID())
	if err != nil {
		return attempt, err
	}
	rlp := new(bytes.Buffer)
	if err := signedTransaction.EncodeRLP(rlp); err != nil {
		return attempt, err
	}
	attempt.SignedRawTx = rlp.Bytes()

	attempt.EthTransactionID = ethTransaction.ID
	attempt.GasPrice = *utils.NewBig(gasPrice)

	err = sendTransactionWithRetry(eb.gethClientWrapper, signedTransaction)

	if isNonceTooLowError(err) {
		logger.Error("nonce of %v was too low, it appears that address %s has been used by another wallet", *ethTransaction.Nonce, ethTransaction.FromAddress.String())

		newNonce, err := ReloadNonceFromEthClient(eb.store, eb.gethClientWrapper, *ethTransaction.FromAddress)
		if err != nil {
			// Something really went wrong here, maybe the eth node is offline?
			// Let the transaction fall through and catch it on the next round
			logger.Error(err)
			return attempt, nil
		}
		nonce := int64(newNonce)
		// TODO: Does it save the nonce correctly?
		if nonce > *ethTransaction.Nonce {
			// Retry it with the higher nonce
			ethTransaction.Nonce = &nonce
			return eb.send(ethTransaction, gasPrice)
		}
		return attempt, nil
	} else if isUnderpriced(err) {
		// TODO: Bump gas immediately
	}
	// TODO: What if it was an http error or context timeout?
	unretryableError := eb.handleError(err, ethTransaction)
	// TODO: Enter retry loop here if didnt get response back from client due to network failure etc
	return attempt, unretryableError
}

func sendTransactionWithRetry(gethClientWrapper store.GethClientWrapper, signedTransaction *gethTypes.Transaction) error {
	// TODO: Write some retry logic here, what if client is not connected?
	// TODO: Add timeout to context
	ctx := context.Background()
	return gethClientWrapper.GethClient(func(gethClient eth.GethClient) error {
		return gethClient.SendTransaction(ctx, signedTransaction)
	})
}

func (eb *ethBroadcaster) handleError(err error, ethTransaction models.EthTransaction) error {
	if err == nil {
		return nil
	} else if isAlreadyInMempool(err) {
		logger.Debugw("transaction was already submitted", "err", err, "ethTransactionID", ethTransaction.ID)
		return nil
	} else if isAlreadyMined(err) {
		// TODO: Get receipt and write hash/block details here?
		logger.Debugw("transaction was already mined in block with hash", "err", err, "ethTransactionID", ethTransaction.ID)
		return nil
	} else if isUnretryableError(err) {
		return err
	}
	logger.Errorw("transaction errored but it wasn't terminal. It may or may not have been sent. Assuming it has been sent and handing off to the confirmer", "err", err, "ethTransactionID", ethTransaction.ID)
	return nil
}

// Geth/parity returns this error if the transaction is already in the node's mempool
func isAlreadyInMempool(err error) bool {
	// TODO
	return false
}

// Geth/parity returns this error if the transaction is already included in a block
func isAlreadyMined(err error) bool {
	// TODO
	return false
}

// Geth/parity returns this error if a transaction with this nonce already
// exists either on-chain or in the mempool.
//
// This can NEVER happen if the ethereum wallet is only used by the chainlink
// node and BulletproofTxManager is enabled.
//
// If it does happen, it means the node operator manually sent a transaction
// from another wallet using the same key.
//
// Since our local nonce tracking is now useless, we have no choice but to
// reset to the geth node's view of the world no matter how unreliable that may
// be.
func isNonceTooLowError(err error) bool {
	// TODO: Add parity error
	fmt.Println("err", err)
	fmt.Printf("err: %#v\n", err)
	return err.Error() == "nonce too low" || err.Error() == "replacement transaction underpriced"
}

// Geth/parity returns these errors if the transaction failed in such a way that:
// 1. It can NEVER be included into a block
// 2. Resending the transaction will never change that outcome
func isUnretryableError(err error) bool {
	switch err.Error() {
	// Geth errors
	// See: https://github.com/ethereum/go-ethereum/blob/b9df7ecdc3d3685180ceb29665bab59e9f614da5/core/tx_pool.go#L516
	case "exceeds block gas limit", "invalid sender", "negative value", "oversized data", "gas uint64 overflow", "intrinsic gas too low":
		return true
	// TODO: Add parity here, and can we use error codes?
	// See: https://github.com/openethereum/openethereum/blob/master/rpc/src/v1/helpers/errors.rs#L420
	default:
		return false
	}
}

// GetDefaultAddress queries the database for the address of the primary default ethereum key
func GetDefaultAddress(store *store.Store) (gethCommon.Address, error) {
	defaultKey, err := getDefaultKey(store)
	if err != nil {
		return gethCommon.Address{}, err
	}
	return defaultKey.Address.Address(), err
}

// NOTE: We can add more advanced logic here later such as sorting by priority
// etc
func getDefaultKey(store *store.Store) (models.Key, error) {
	availableKeys, err := store.Keys()
	if err != nil {
		return models.Key{}, err
	}
	if len(availableKeys) == 0 {
		return models.Key{}, errors.New("no keys available")
	}
	return *availableKeys[0], nil
}

// ReloadNonceFromEthClient queries the eth node for the latest nonce including
// transactions in the mempool.
//
// This should almost never be necessary in normal operation unless the node
// operator has re-used their account somewhere else.
//
// It is generally safe to call this method as many times as you like because
// it can only ever increase the nonce, never decrease it.
func ReloadNonceFromEthClient(store *store.Store, gethClientWrapper store.GethClientWrapper, address gethCommon.Address) (uint64, error) {
	var nonce uint64
	err := gethClientWrapper.GethClient(func(c eth.GethClient) error {
		var err error
		// TODO: Probably need to add a timeout or something
		ctx := context.Background()
		nonce, err = c.PendingNonceAt(ctx, address)
		return err
	})
	if err != nil {
		return nonce, err
	}
	return nonce, store.RawDB(func(db *gorm.DB) error {
		res := db.Exec("UPDATE keys SET nonce = ? WHERE address = ? AND nonce < ?", nonce, address, nonce)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			logger.Warnf("new nonce of %v for account %s did not update any rows", nonce, address.String())
		} else {
			logger.Debugf("updated account %s with new nonce %v", address.String(), nonce)
		}
		return nil
	})
}
