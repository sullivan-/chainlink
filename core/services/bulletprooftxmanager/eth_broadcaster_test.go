package bulletprooftxmanager_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink/core/assets"
	"github.com/smartcontractkit/chainlink/core/internal/cltest"
	"github.com/smartcontractkit/chainlink/core/internal/mocks"
	"github.com/smartcontractkit/chainlink/core/services/bulletprooftxmanager"
	"github.com/smartcontractkit/chainlink/core/store/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	gethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethTypes "github.com/ethereum/go-ethereum/core/types"
)

func TestTxBroadcaster_NewBulletproofTxManager(t *testing.T) {
	// TODO: write this test
}

func TestBulletproofTxManager_ProcessUnbroadcastEthTransactions_Success(t *testing.T) {
	t.Parallel()

	store, cleanup := cltest.NewStore(t)
	defer cleanup()
	// Use the real KeyStore loaded from database fixtures
	store.KeyStore.Unlock(cltest.Password)

	config, cleanup := cltest.NewConfig(t)
	gethClient := new(mocks.GethClient)
	gethWrapper := cltest.NewSimpleGethWrapper(gethClient)
	eb := bulletprooftxmanager.NewEthBroadcaster(store, gethWrapper, config)

	keys, err := store.Keys()
	require.NoError(t, err)
	defaultFromAddress := keys[0].Address.Address()
	toAddress := gethCommon.HexToAddress("0x6C03DDA95a2AEd917EeCc6eddD4b9D16E6380411")
	timeNow := time.Now()
	fmt.Println(cltest.NewAddress().String())
	fmt.Println(cltest.NewAddress().String())
	fmt.Println(cltest.NewAddress().String())

	encodedPayload := []byte{1, 2, 3}
	value := assets.NewEthValue(142)
	gasLimit := uint64(242)

	t.Run("no eth_transactions at all", func(t *testing.T) {
		require.NoError(t, eb.ProcessUnbroadcastEthTransactions())
	})

	t.Run("existing eth_transactions with broadcast_at or error", func(t *testing.T) {
		nonce := int64(342)
		errStr := "some error"

		ethTransactionWithNonce := models.EthTransaction{
			Nonce:          &nonce,
			FromAddress:    &defaultFromAddress,
			ToAddress:      toAddress,
			EncodedPayload: encodedPayload,
			Value:          value,
			GasLimit:       gasLimit,
			BroadcastAt:    &timeNow,
			Error:          nil,
		}
		ethTransactionWithError := models.EthTransaction{
			Nonce:          nil,
			FromAddress:    &defaultFromAddress,
			ToAddress:      toAddress,
			EncodedPayload: encodedPayload,
			Value:          value,
			GasLimit:       gasLimit,
			Error:          &errStr,
		}

		require.NoError(t, store.GetRawDB().Save(&ethTransactionWithNonce).Error)
		require.NoError(t, store.GetRawDB().Save(&ethTransactionWithError).Error)

		require.NoError(t, eb.ProcessUnbroadcastEthTransactions())
	})

	t.Run("sends two EthTransactions in order starting from the earliest", func(t *testing.T) {
		// Earlier
		ethTransactionWithoutFromAddress := models.EthTransaction{
			ToAddress:      toAddress,
			EncodedPayload: []byte{42, 42, 0},
			Value:          value,
			GasLimit:       gasLimit,
			CreatedAt:      time.Unix(0, 0),
		}
		gethClient.On("SendTransaction", mock.Anything, mock.MatchedBy(func(tx *gethTypes.Transaction) bool {
			if tx.Nonce() != uint64(0) {
				return false
			}
			require.Equal(t, config.ChainID(), tx.ChainId())
			require.Equal(t, gasLimit, tx.Gas())
			require.Equal(t, config.EthGasPriceDefault(), tx.GasPrice())
			require.Equal(t, toAddress, *tx.To())
			require.Equal(t, value.ToInt().String(), tx.Value().String())
			require.Equal(t, ethTransactionWithoutFromAddress.EncodedPayload, tx.Data())

			// They must be set to something to indicate that the transaction is signed
			v, r, s := tx.RawSignatureValues()
			require.Equal(t, "41", v.String())
			require.Equal(t, "100125404117036954913117369048685056327836806830110180962458866833256017916154", r.String())
			require.Equal(t, "13748121423502857499887005034545879393991949882113605371398299275605825415634", s.String())
			return true
		})).Return(nil)

		// Later
		ethTransactionWithFromAddress := models.EthTransaction{
			FromAddress:    &defaultFromAddress,
			ToAddress:      toAddress,
			EncodedPayload: []byte{42, 42, 1},
			Value:          value,
			GasLimit:       gasLimit,
			CreatedAt:      time.Unix(1, 0),
		}
		// TODO: Test context has correct timeout set here
		gethClient.On("SendTransaction", mock.Anything, mock.MatchedBy(func(tx *gethTypes.Transaction) bool {
			if tx.Nonce() != uint64(1) {
				return false
			}
			require.Equal(t, config.ChainID(), tx.ChainId())
			require.Equal(t, gasLimit, tx.Gas())
			require.Equal(t, config.EthGasPriceDefault(), tx.GasPrice())
			require.Equal(t, toAddress, *tx.To())
			require.Equal(t, value.ToInt().String(), tx.Value().String())
			require.Equal(t, ethTransactionWithFromAddress.EncodedPayload, tx.Data())

			// They must be set to something to indicate that the transaction is signed
			v, r, s := tx.RawSignatureValues()
			require.Equal(t, "42", v.String())
			require.Equal(t, "39363214223465398755579021511352119350941428292598621771180906281886401763946", r.String())
			require.Equal(t, "13319764116922590262026344403688458878732413946946573942114704806995618455150", s.String())
			return true
		})).Return(nil)

		require.NoError(t, store.GetRawDB().Save(&ethTransactionWithoutFromAddress).Error)
		require.NoError(t, store.GetRawDB().Save(&ethTransactionWithFromAddress).Error)

		// Do the thing
		require.NoError(t, eb.ProcessUnbroadcastEthTransactions())

		// check for EthTransactionWithoutFromAddress and it's attempt
		// This was the earlier one sent so it has the lower nonce
		earlierTransaction, err := store.FindEthTransactionWithAttempts(ethTransactionWithoutFromAddress.ID)
		require.NoError(t, err)
		assert.Nil(t, earlierTransaction.Error)
		require.NotNil(t, earlierTransaction.FromAddress)
		assert.Equal(t, defaultFromAddress, *earlierTransaction.FromAddress)
		require.NotNil(t, earlierTransaction.Nonce)
		assert.Equal(t, int64(0), *earlierTransaction.Nonce)
		assert.NotNil(t, earlierTransaction.BroadcastAt)
		assert.Len(t, earlierTransaction.EthTransactionAttempts, 1)

		attempt := earlierTransaction.EthTransactionAttempts[0]

		assert.Equal(t, earlierTransaction.ID, attempt.EthTransactionID)
		assert.Equal(t, config.EthGasPriceDefault().String(), attempt.GasPrice.String())
		assert.Nil(t, attempt.Hash)
		assert.Nil(t, attempt.Error)
		assert.Nil(t, attempt.ConfirmedInBlockNum)
		assert.Nil(t, attempt.ConfirmedInBlockHash)
		assert.Nil(t, attempt.ConfirmedAt)

		assert.Equal(t, "0xf867808504a817c80081f2946c03dda95a2aed917eecc6eddd4b9d16e6380411818e832a2a0029a0dd5cf86fe8e6c6c863c5cc4feb2cbfa5a87b289d8f74b8d82a599931629970faa01e65293571cd92fb96398dfd22362e76cacb527ff9472c5aa14439ae3381e9d2", hexutil.Encode(attempt.SignedRawTx))

		// check for EthTransactionWithFromAddress and it's attempt
		// This was the later one sent so it has the higher nonce
		laterTransaction, err := store.FindEthTransactionWithAttempts(ethTransactionWithFromAddress.ID)
		require.NoError(t, err)
		assert.Nil(t, laterTransaction.Error)
		require.NotNil(t, laterTransaction.FromAddress)
		assert.Equal(t, defaultFromAddress, *laterTransaction.FromAddress)
		require.NotNil(t, laterTransaction.Nonce)
		assert.Equal(t, int64(1), *laterTransaction.Nonce)
		assert.NotNil(t, laterTransaction.BroadcastAt)
		assert.Len(t, laterTransaction.EthTransactionAttempts, 1)

		attempt = laterTransaction.EthTransactionAttempts[0]

		assert.Equal(t, laterTransaction.ID, attempt.EthTransactionID)
		assert.Equal(t, config.EthGasPriceDefault().String(), attempt.GasPrice.String())
		assert.Nil(t, attempt.Hash)
		assert.Nil(t, attempt.Error)
		assert.Nil(t, attempt.ConfirmedInBlockNum)
		assert.Nil(t, attempt.ConfirmedInBlockHash)
		assert.Nil(t, attempt.ConfirmedAt)

		assert.Equal(t, "0xf867018504a817c80081f2946c03dda95a2aed917eecc6eddd4b9d16e6380411818e832a2a012aa05706ca2b15c5796218fc602be65cca821d28310135407889fa40bf409c891a6aa01d72b825e1c765c8a3368cbef7ce3c249ceceadc36aa17c60294c4c959545e6e", hexutil.Encode(attempt.SignedRawTx))

		gethClient.AssertExpectations(t)
	})
}

func TestBulletproofTxManager_ProcessUnbroadcastEthTransactions_ResumingFromCrash(t *testing.T) {
	t.Parallel()

	store, cleanup := cltest.NewStore(t)
	defer cleanup()
	// Use the real KeyStore loaded from database fixtures
	store.KeyStore.Unlock(cltest.Password)

	config, cleanup := cltest.NewConfig(t)
	gethClient := new(mocks.GethClient)
	gethWrapper := cltest.NewSimpleGethWrapper(gethClient)
	eb := bulletprooftxmanager.NewEthBroadcaster(store, gethWrapper, config)

	keys, err := store.Keys()
	require.NoError(t, err)
	defaultFromAddress := keys[0].Address.Address()
	toAddress := gethCommon.HexToAddress("0x6C03DDA95a2AEd917EeCc6eddD4b9D16E6380411")
	// timeNow := time.Now()

	value := assets.NewEthValue(142)
	gasLimit := uint64(242)
	encodedPayload := []byte{0, 1}
	initialNonce := int64(916714082576372858)

	t.Run("previous run assigned nonce but never broadcast", func(t *testing.T) {
		nonce := initialNonce
		unbroadcastEthTransactionWithNonce := models.EthTransaction{
			FromAddress:    &defaultFromAddress,
			Nonce:          &nonce,
			ToAddress:      toAddress,
			EncodedPayload: encodedPayload,
			Value:          value,
			GasLimit:       gasLimit,
			BroadcastAt:    nil,
			CreatedAt:      time.Unix(1, 0),
		}

		require.NoError(t, store.GetRawDB().Create(&unbroadcastEthTransactionWithNonce).Error)

		gethClient.On("SendTransaction", mock.Anything, mock.MatchedBy(func(tx *gethTypes.Transaction) bool {
			return tx.Nonce() == uint64(nonce)
		})).Return(nil)

		// Do the thing
		require.NoError(t, eb.ProcessUnbroadcastEthTransactions())

		// Check it was saved correctly with its attempt
		ethTransaction, err := store.FindEthTransactionWithAttempts(unbroadcastEthTransactionWithNonce.ID)
		require.NoError(t, err)

		assert.NotNil(t, ethTransaction.BroadcastAt)
		assert.Nil(t, ethTransaction.Error)
		assert.Len(t, ethTransaction.EthTransactionAttempts, 1)

		gethClient.AssertExpectations(t)
	})

	t.Run("previous run assigned nonce and broadcast but it unretryably errored before we could save", func(t *testing.T) {
		nonce := initialNonce + 1
		unbroadcastEthTransactionWithNonce := models.EthTransaction{
			FromAddress:    &defaultFromAddress,
			Nonce:          &nonce,
			ToAddress:      toAddress,
			EncodedPayload: encodedPayload,
			Value:          value,
			GasLimit:       gasLimit,
			BroadcastAt:    nil,
			CreatedAt:      time.Unix(1, 0),
		}

		require.NoError(t, store.GetRawDB().Create(&unbroadcastEthTransactionWithNonce).Error)

		gethClient.On("SendTransaction", mock.Anything, mock.MatchedBy(func(tx *gethTypes.Transaction) bool {
			return tx.Nonce() == uint64(nonce)
		})).Return(errors.New("exceeds block gas limit"))

		// Do the thing
		require.NoError(t, eb.ProcessUnbroadcastEthTransactions())

		// Check it was saved correctly with its attempt
		ethTransaction, err := store.FindEthTransactionWithAttempts(unbroadcastEthTransactionWithNonce.ID)
		require.NoError(t, err)

		assert.Nil(t, ethTransaction.BroadcastAt)
		assert.NotNil(t, ethTransaction.Error)
		assert.Equal(t, "exceeds block gas limit", *ethTransaction.Error)
		assert.Len(t, ethTransaction.EthTransactionAttempts, 0)

		gethClient.AssertExpectations(t)
	})

	t.Run("previous run assigned nonce and broadcast and is now in mempool", func(t *testing.T) {
		nonce := initialNonce + 2
		unbroadcastEthTransactionWithNonce := models.EthTransaction{
			FromAddress:    &defaultFromAddress,
			Nonce:          &nonce,
			ToAddress:      toAddress,
			EncodedPayload: encodedPayload,
			Value:          value,
			GasLimit:       gasLimit,
			BroadcastAt:    nil,
			CreatedAt:      time.Unix(1, 0),
		}

		require.NoError(t, store.GetRawDB().Create(&unbroadcastEthTransactionWithNonce).Error)

		gethClient.On("SendTransaction", mock.Anything, mock.MatchedBy(func(tx *gethTypes.Transaction) bool {
			return tx.Nonce() == uint64(nonce)
		})).Return(errors.New("already known"))

		// Do the thing
		require.NoError(t, eb.ProcessUnbroadcastEthTransactions())

		// Check it was saved correctly with its attempt
		ethTransaction, err := store.FindEthTransactionWithAttempts(unbroadcastEthTransactionWithNonce.ID)
		require.NoError(t, err)

		assert.NotNil(t, ethTransaction.BroadcastAt)
		assert.Nil(t, ethTransaction.Error)
		assert.Len(t, ethTransaction.EthTransactionAttempts, 1)

		gethClient.AssertExpectations(t)
	})
	// t.Run("previous run assigned nonce and broadcast and is now confirmed")
}

func TestBulletproofTxManager_ProcessUnbroadcastEthTransactions_Errors(t *testing.T) {
	t.Parallel()

	store, cleanup := cltest.NewStore(t)
	defer cleanup()
	// Use the real KeyStore loaded from database fixtures
	store.KeyStore.Unlock(cltest.Password)

	config, cleanup := cltest.NewConfig(t)
	gethClient := new(mocks.GethClient)
	gethWrapper := cltest.NewSimpleGethWrapper(gethClient)
	eb := bulletprooftxmanager.NewEthBroadcaster(store, gethWrapper, config)

	keys, err := store.Keys()
	require.NoError(t, err)
	defaultFromAddress := keys[0].Address.Address()
	toAddress := gethCommon.HexToAddress("0x6C03DDA95a2AEd917EeCc6eddD4b9D16E6380411")
	// timeNow := time.Now()

	value := assets.NewEthValue(142)
	gasLimit := uint64(242)
	encodedPayload := []byte{0, 1}
	initialNonce := int64(916714082576372858)

	t.Run("external wallet messed with the account and now the nonce has already been used giving 'nonce too low' error", func(t *testing.T) {
		ethTransaction := models.EthTransaction{
			ToAddress:      toAddress,
			EncodedPayload: []byte{42, 42, 0},
			Value:          value,
			GasLimit:       gasLimit,
			CreatedAt:      time.Unix(0, 0),
		}
		require.NoError(t, store.GetRawDB().Save(&ethTransaction).Error)
		gethClient.On("SendTransaction", mock.Anything, mock.MatchedBy(func(tx *gethTypes.Transaction) bool {
			return tx.Nonce() == uint64(0)
		})).Return(errors.New("nonce too low"))

		// Do the thing
		require.NoError(t, eb.ProcessUnbroadcastEthTransactions())

	})

	// - key is gone from database (no matching address) - mock keystore to return error "authentication needed: password or unlock"
	// - keystore does not have the unlocked key
	// - tx signing fails
	// - gethClient fails with FATAL UNCONFIRMED (various types)
	// - gethClient failes with RETRYABLE UNCONFIRMED (various types)
	// - does it send successful one after failed?
	// - external client sent something which is in mempool and now we get "replacement transaction underpriced"
	// - reloading nonce fails
	// - TODO: Check what error we get if we resubmit an identical transaction that is in mempool
	// - TODO: Check what error we get if we resubmit an identical transaction that is confirmed
}

func TestBulletproofTxManager_ProcessUnbroadcastEthTransactions_ComplexTest(t *testing.T) {
	// Multiple tx's, some of which fail with different errors on multiple occasions over multiple calls
}

func TestBulletproofTxManager_GetDefaultAddress(t *testing.T) {
	// Test cases:
	// -
}

func TestBulletproofTxManager_GetAndIncrementNonce(t *testing.T) {
	store, cleanup := cltest.NewStore(t)
	defer cleanup()

	// Fixture key has nonce 0
	var key models.Key
	require.NoError(t, store.GetRawDB().First(&key).Error)
	require.Equal(t, int64(0), key.Nonce)

	nonce, err := bulletprooftxmanager.GetAndIncrementNonce(store.GetRawDB(), key.Address.Address())
	assert.NoError(t, err)
	assert.Equal(t, int64(0), nonce)

	// It incremented the nonce
	require.NoError(t, store.GetRawDB().First(&key).Error)
	require.Equal(t, int64(1), key.Nonce)
}

func TestBulletproofTxManager_ReloadNonceFromEthClient(t *testing.T) {
	store, cleanup := cltest.NewStore(t)
	defer cleanup()

	localAddress := gethCommon.HexToAddress("0x3cb8e3FD9d27e39a5e9e6852b0e96160061fd4ea")
	localNonce := int64(10)
	require.NoError(t, store.GetRawDB().Exec(`UPDATE keys SET nonce = ? WHERE address = ?`, localNonce, localAddress).Error)

	t.Run("does nothing if account is not in keys table", func(t *testing.T) {
		missingLocalAddress := cltest.NewAddress()

		gethClient := new(mocks.GethClient)
		gethWrapper := cltest.NewSimpleGethWrapper(gethClient)
		gethClient.On("PendingNonceAt", mock.Anything, mock.MatchedBy(func(a gethCommon.Address) bool {
			return a == missingLocalAddress
		})).Return(uint64(42), nil)
		require.NoError(t, bulletprooftxmanager.ReloadNonceFromEthClient(store, gethWrapper, missingLocalAddress))

		gethClient.AssertExpectations(t)
	})

	t.Run("does nothing if eth node's nonce is less than the current one", func(t *testing.T) {
		remoteNonce := uint64(5)

		gethClient := new(mocks.GethClient)
		gethWrapper := cltest.NewSimpleGethWrapper(gethClient)
		gethClient.On("PendingNonceAt", mock.Anything, mock.MatchedBy(func(a gethCommon.Address) bool {
			return a == localAddress
		})).Return(uint64(remoteNonce), nil)
		require.NoError(t, bulletprooftxmanager.ReloadNonceFromEthClient(store, gethWrapper, localAddress))

		// Database nonce was not updated
		var key models.Key
		require.NoError(t, store.GetRawDB().First(&key).Error)
		require.Equal(t, localNonce, key.Nonce)

		gethClient.AssertExpectations(t)
	})

	t.Run("does nothing if eth node's nonce is the same as the current one", func(t *testing.T) {
		remoteNonce := localNonce

		gethClient := new(mocks.GethClient)
		gethWrapper := cltest.NewSimpleGethWrapper(gethClient)
		gethClient.On("PendingNonceAt", mock.Anything, mock.MatchedBy(func(a gethCommon.Address) bool {
			return a == localAddress
		})).Return(uint64(remoteNonce), nil)
		require.NoError(t, bulletprooftxmanager.ReloadNonceFromEthClient(store, gethWrapper, localAddress))

		// Database nonce was not updated
		var key models.Key
		require.NoError(t, store.GetRawDB().First(&key).Error)
		require.Equal(t, localNonce, key.Nonce)

		gethClient.AssertExpectations(t)
	})

	t.Run("does nothing and returns error if eth node returns error", func(t *testing.T) {
		remoteNonce := uint64(1589808404872494000)

		gethClient := new(mocks.GethClient)
		gethWrapper := cltest.NewSimpleGethWrapper(gethClient)
		gethClient.On("PendingNonceAt", mock.Anything, mock.MatchedBy(func(a gethCommon.Address) bool {
			return a == localAddress
		})).Return(uint64(remoteNonce), errors.New("something exploded"))
		require.EqualError(t, bulletprooftxmanager.ReloadNonceFromEthClient(store, gethWrapper, localAddress), "something exploded")

		// Database nonce was NOT updated
		var key models.Key
		require.NoError(t, store.GetRawDB().First(&key).Error)
		require.Equal(t, localNonce, key.Nonce)

		gethClient.AssertExpectations(t)
	})

	t.Run("updates local nonce if eth node's nonce is higher than the current one", func(t *testing.T) {
		remoteNonce := uint64(1589808404872494000)

		gethClient := new(mocks.GethClient)
		gethWrapper := cltest.NewSimpleGethWrapper(gethClient)
		gethClient.On("PendingNonceAt", mock.Anything, mock.MatchedBy(func(a gethCommon.Address) bool {
			return a == localAddress
		})).Return(uint64(remoteNonce), nil)
		require.NoError(t, bulletprooftxmanager.ReloadNonceFromEthClient(store, gethWrapper, localAddress))

		// Database nonce was updated
		var key models.Key
		require.NoError(t, store.GetRawDB().First(&key).Error)
		require.Equal(t, int64(remoteNonce), key.Nonce)

		gethClient.AssertExpectations(t)
	})

}
