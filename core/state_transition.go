// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"fmt"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	cmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// ExecutionResult includes all output after executing given evm
// message no matter the execution itself is successful or not.
type ExecutionResult struct {
	UsedGas     uint64 // Total used gas, not including the refunded gas
	RefundedGas uint64 // Total gas refunded after execution
	Err         error  // Any error encountered during the execution(listed in core/vm/errors.go)
	ReturnData  []byte // Returned data from evm(function result or data supplied with revert opcode)
}

// Unwrap returns the internal evm error which allows us for further
// analysis outside.
func (result *ExecutionResult) Unwrap() error {
	return result.Err
}

// Failed returns the indicator whether the execution is successful or not
func (result *ExecutionResult) Failed() bool { return result.Err != nil }

// Return is a helper function to help caller distinguish between revert reason
// and function return. Return returns the data after execution if no error occurs.
func (result *ExecutionResult) Return() []byte {
	if result.Err != nil {
		return nil
	}
	return common.CopyBytes(result.ReturnData)
}

// Revert returns the concrete revert reason if the execution is aborted by `REVERT`
// opcode. Note the reason can be nil if no data supplied with revert opcode.
func (result *ExecutionResult) Revert() []byte {
	if result.Err != vm.ErrExecutionReverted {
		return nil
	}
	return common.CopyBytes(result.ReturnData)
}

// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
func IntrinsicGas(data []byte, accessList types.AccessList, isContractCreation, isHomestead, isEIP2028, isEIP3860 bool) (uint64, error) {
	// Set the starting gas for the raw transaction
	var gas uint64
	if isContractCreation && isHomestead {
		gas = params.TxGasContractCreation
	} else {
		gas = params.TxGas
	}
	dataLen := uint64(len(data))
	// Bump the required gas by the amount of transactional data
	if dataLen > 0 {
		// Zero and non-zero bytes are priced differently
		var nz uint64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		// Make sure we don't exceed uint64 for all data combinations
		nonZeroGas := params.TxDataNonZeroGasFrontier
		if isEIP2028 {
			nonZeroGas = params.TxDataNonZeroGasEIP2028
		}
		if (math.MaxUint64-gas)/nonZeroGas < nz {
			return 0, ErrGasUintOverflow
		}
		gas += nz * nonZeroGas

		z := dataLen - nz
		if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
			return 0, ErrGasUintOverflow
		}
		gas += z * params.TxDataZeroGas

		if isContractCreation && isEIP3860 {
			lenWords := toWordSize(dataLen)
			if (math.MaxUint64-gas)/params.InitCodeWordGas < lenWords {
				return 0, ErrGasUintOverflow
			}
			gas += lenWords * params.InitCodeWordGas
		}
	}
	if accessList != nil {
		gas += uint64(len(accessList)) * params.TxAccessListAddressGas
		gas += uint64(accessList.StorageKeys()) * params.TxAccessListStorageKeyGas
	}
	return gas, nil
}

// toWordSize returns the ceiled word size required for init code payment calculation.
func toWordSize(size uint64) uint64 {
	if size > math.MaxUint64-31 {
		return math.MaxUint64/32 + 1
	}

	return (size + 31) / 32
}

// A Message contains the data derived from a single transaction that is relevant to state
// processing.
type Message struct {
	To            *common.Address
	From          common.Address
	Nonce         uint64
	Value         *big.Int
	GasLimit      uint64
	GasPrice      *big.Int
	GasFeeCap     *big.Int
	GasTipCap     *big.Int
	Data          []byte
	AccessList    types.AccessList
	BlobGasFeeCap *big.Int
	BlobHashes    []common.Hash

	// When SkipNonceChecks is true, the message nonce is not checked against the
	// account nonce in state.
	// This field will be set to true for operations like RPC eth_call.
	SkipNonceChecks bool

	// When SkipFromEOACheck is true, the message sender is not checked to be an EOA.
	SkipFromEOACheck bool

	IsSystemTx     bool                 // IsSystemTx indicates the message, if also a deposit, does not emit gas usage.
	IsDepositTx    bool                 // IsDepositTx indicates the message is force-included and can persist a mint.
	Mint           *big.Int             // Mint is the amount to mint before EVM processing, or nil if there is no minting.
	RollupCostData types.RollupCostData // RollupCostData caches data to compute the fee we charge for data availability
}

// TransactionToMessage converts a transaction into a Message.
func TransactionToMessage(tx *types.Transaction, s types.Signer, baseFee *big.Int) (*Message, error) {
	msg := &Message{
		Nonce:            tx.Nonce(),
		GasLimit:         tx.Gas(),
		GasPrice:         new(big.Int).Set(tx.GasPrice()),
		GasFeeCap:        new(big.Int).Set(tx.GasFeeCap()),
		GasTipCap:        new(big.Int).Set(tx.GasTipCap()),
		To:               tx.To(),
		Value:            tx.Value(),
		Data:             tx.Data(),
		AccessList:       tx.AccessList(),
		SkipNonceChecks:  false,
		SkipFromEOACheck: false,
		BlobHashes:       tx.BlobHashes(),
		BlobGasFeeCap:    tx.BlobGasFeeCap(),

		IsSystemTx:     tx.IsSystemTx(),
		IsDepositTx:    tx.IsDepositTx(),
		Mint:           tx.Mint(),
		RollupCostData: tx.RollupCostData(),
	}
	// If baseFee provided, set gasPrice to effectiveGasPrice.
	if baseFee != nil {
		msg.GasPrice = cmath.BigMin(msg.GasPrice.Add(msg.GasTipCap, baseFee), msg.GasFeeCap)
	}
	var err error
	msg.From, err = types.Sender(s, tx)
	return msg, err
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
func ApplyMessage(evm *vm.EVM, msg *Message, gp *GasPool) (*ExecutionResult, error) {
	return NewStateTransition(evm, msg, gp).TransitionDb()
}

// StateTransition represents a state transition.
//
// == The State Transitioning Model
//
// A state transition is a change made when a transaction is applied to the current world
// state. The state transitioning model does all the necessary work to work out a valid new
// state root.
//
//  1. Nonce handling
//  2. Pre pay gas
//  3. Create a new state object if the recipient is nil
//  4. Value transfer
//
// == If contract creation ==
//
//	4a. Attempt to run transaction data
//	4b. If valid, use result as code for the new state object
//
// == end ==
//
//  5. Run Script section
//  6. Derive new state root
type StateTransition struct {
	gp           *GasPool
	msg          *Message
	gasRemaining uint64
	initialGas   uint64
	state        vm.StateDB
	evm          *vm.EVM

	// nil means SGT is not used at all
	usedSGTBalance *uint256.Int
	// should not be used if usedSGTBalance is nil;
	// only set when: 1. usedSGTBalance is non-nil 2. used native balance is gt 0
	usedNativeBalance *uint256.Int

	// these are set once for checking gas formula only
	boughtGas   *uint256.Int
	refundedGas *uint256.Int
	tipFee      *uint256.Int
	baseFee     *uint256.Int
	l1Fee       *uint256.Int
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(evm *vm.EVM, msg *Message, gp *GasPool) *StateTransition {
	return &StateTransition{
		gp:    gp,
		evm:   evm,
		msg:   msg,
		state: evm.StateDB,
	}
}

func (st *StateTransition) checkGasFormula() error {
	if st.boughtGas.Cmp(
		new(uint256.Int).Add(
			st.refundedGas, new(uint256.Int).Add(
				st.tipFee, new(uint256.Int).Add(
					st.baseFee, st.l1Fee)))) != 0 {
		return fmt.Errorf("gas formula doesn't hold: boughtGas(%v) != refundedGas(%v) + tipFee(%v) + baseFee(%v) + l1Fee(%v)", st.boughtGas, st.refundedGas, st.tipFee, st.baseFee, st.l1Fee)
	}
	return nil
}

func (st *StateTransition) collectableNativeBalance(amount *uint256.Int) *uint256.Int {
	// we burn the token if gas is from SoulGasToken which is not backed by native
	if st.usedSGTBalance != nil && st.evm.ChainConfig().IsOptimism() && !st.evm.ChainConfig().Optimism.IsSoulBackedByNative {
		_, amount = st.distributeGas(amount, st.usedSGTBalance, st.usedNativeBalance)
	}
	return amount
}

// distributeGas distributes the gas according to the priority:
//
//	first pool1, then pool2
//
// note: the returned values are always non-nil.
func (st *StateTransition) distributeGas(amount, pool1, pool2 *uint256.Int) (quota1, quota2 *uint256.Int) {
	if amount == nil {
		panic("amount should not be nil")
	}
	if st.usedSGTBalance == nil {
		panic("should not happen when usedSGTBalance is nil")
	}
	if pool1 == nil {
		// pool1 empty, all to pool2
		quota1 = new(uint256.Int)
		quota2 = amount.Clone()

		pool2.Sub(pool2, quota2)
		return
	}
	if pool2 == nil {
		// pool2 empty, all to pool1
		quota1 = amount.Clone()
		quota2 = new(uint256.Int)

		pool1.Sub(pool1, quota1)
		return
	}

	// from here, both pool1 and pool2 are non-nil

	if amount.Cmp(pool1) >= 0 {
		// partial pool1, remaining to pool2
		quota1 = pool1.Clone()
		quota2 = new(uint256.Int).Sub(amount, quota1)

		pool1.Clear()
		pool2.Sub(pool2, quota2)
	} else {
		// all to pool1
		quota1 = amount.Clone()
		quota2 = new(uint256.Int)

		pool1.Sub(pool1, quota1)
	}

	return
}

// to returns the recipient of the message.
func (st *StateTransition) to() common.Address {
	if st.msg == nil || st.msg.To == nil /* contract creation */ {
		return common.Address{}
	}
	return *st.msg.To
}

const (
	// should keep it in sync with the balances field of SoulGasToken contract
	BalancesSlot = uint64(51)
)

var (
	slotArgs abi.Arguments
)

func init() {
	uint64Ty, _ := abi.NewType("uint64", "", nil)
	addressTy, _ := abi.NewType("address", "", nil)
	slotArgs = abi.Arguments{{Name: "addr", Type: addressTy, Indexed: false}, {Name: "slot", Type: uint64Ty, Indexed: false}}
}

func TargetSGTBalanceSlot(account common.Address) (slot common.Hash) {
	data, _ := slotArgs.Pack(account, BalancesSlot)
	slot = crypto.Keccak256Hash(data)
	return
}

func (st *StateTransition) GetSoulBalance(account common.Address) *uint256.Int {
	slot := TargetSGTBalanceSlot(account)
	value := st.state.GetState(types.SoulGasTokenAddr, slot)
	balance := new(uint256.Int)
	balance.SetBytes(value[:])
	return balance
}

// Get the effective balance to pay gas
func GetEffectiveGasBalance(state vm.StateDB, chainconfig *params.ChainConfig, account common.Address, value *big.Int) (*big.Int, error) {
	bal, sgtBal := GetGasBalancesInBig(state, chainconfig, account)
	if value == nil {
		value = big.NewInt(0)
	}
	if bal.Cmp(value) < 0 {
		return nil, ErrInsufficientFundsForTransfer
	}
	bal.Sub(bal, value)
	if bal.Cmp(sgtBal) < 0 {
		return sgtBal, nil
	}

	return bal, nil
}

func GetGasBalances(state vm.StateDB, chainconfig *params.ChainConfig, account common.Address) (*uint256.Int, *uint256.Int) {
	balance := state.GetBalance(account)
	if chainconfig != nil && chainconfig.IsOptimism() && chainconfig.Optimism.UseSoulGasToken {
		sgtBalanceSlot := TargetSGTBalanceSlot(account)
		sgtBalanceValue := state.GetState(types.SoulGasTokenAddr, sgtBalanceSlot)
		sgtBalance := new(uint256.Int).SetBytes(sgtBalanceValue[:])

		return balance, sgtBalance
	}

	return balance, uint256.NewInt(0)
}

func GetGasBalancesInBig(state vm.StateDB, chainconfig *params.ChainConfig, account common.Address) (*big.Int, *big.Int) {
	bal, sgtBal := GetGasBalances(state, chainconfig, account)
	return bal.ToBig(), sgtBal.ToBig()
}

// called by buyGas
func (st *StateTransition) subSoulBalance(account common.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) (err error) {
	current := st.GetSoulBalance(account)
	if current.Cmp(amount) < 0 {
		return fmt.Errorf("soul balance not enough, current:%v, expect:%v", current, amount)
	}

	value := current.Sub(current, amount).Bytes32()
	st.state.SetState(types.SoulGasTokenAddr, TargetSGTBalanceSlot(account), value)

	if st.evm.ChainConfig().IsOptimism() && st.evm.ChainConfig().Optimism.IsSoulBackedByNative {
		st.state.SubBalance(types.SoulGasTokenAddr, amount, reason)
	}

	// subSoulBalance is only called by buyGas once
	st.usedSGTBalance = amount
	return
}

// called by refundGas
func (st *StateTransition) addSoulBalance(account common.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) {
	current := st.GetSoulBalance(account)
	value := current.Add(current, amount).Bytes32()
	st.state.SetState(types.SoulGasTokenAddr, TargetSGTBalanceSlot(account), value)

	if st.evm.ChainConfig().IsOptimism() && st.evm.ChainConfig().Optimism.IsSoulBackedByNative {
		st.state.AddBalance(types.SoulGasTokenAddr, amount, reason)
	}
	st.usedSGTBalance.Sub(st.usedSGTBalance, amount)
}

func (st *StateTransition) buyGas() error {
	mgval := new(big.Int).SetUint64(st.msg.GasLimit)
	mgval.Mul(mgval, st.msg.GasPrice)
	var l1Cost *big.Int
	if st.evm.Context.L1CostFunc != nil && !st.msg.SkipNonceChecks && !st.msg.SkipFromEOACheck {
		l1Cost = st.evm.Context.L1CostFunc(st.msg.RollupCostData, st.evm.Context.Time)
		if l1Cost != nil {
			mgval = mgval.Add(mgval, l1Cost)
		}
	}
	balanceCheck := new(big.Int).Set(mgval)
	if st.msg.GasFeeCap != nil {
		balanceCheck.SetUint64(st.msg.GasLimit)
		balanceCheck = balanceCheck.Mul(balanceCheck, st.msg.GasFeeCap)
	}
	balanceCheck.Add(balanceCheck, st.msg.Value)
	if l1Cost != nil {
		balanceCheck.Add(balanceCheck, l1Cost)
	}

	if st.evm.ChainConfig().IsCancun(st.evm.Context.BlockNumber, st.evm.Context.Time) {
		if blobGas := st.blobGasUsed(); blobGas > 0 {
			// Check that the user has enough funds to cover blobGasUsed * tx.BlobGasFeeCap
			blobBalanceCheck := new(big.Int).SetUint64(blobGas)
			blobBalanceCheck.Mul(blobBalanceCheck, st.msg.BlobGasFeeCap)
			balanceCheck.Add(balanceCheck, blobBalanceCheck)
			// Pay for blobGasUsed * actual blob fee
			blobFee := new(big.Int).SetUint64(blobGas)
			blobFee.Mul(blobFee, st.evm.Context.BlobBaseFee)
			mgval.Add(mgval, blobFee)
		}
	}

	balanceCheckU256, overflow := uint256.FromBig(balanceCheck)
	if overflow {
		return fmt.Errorf("%w: address %v required balance exceeds 256 bits", ErrInsufficientFunds, st.msg.From.Hex())
	}

	nativeBalance := st.state.GetBalance(st.msg.From)
	var soulBalance *uint256.Int
	if st.evm.ChainConfig().IsOptimism() && st.evm.ChainConfig().Optimism.UseSoulGasToken {
		if have, want := nativeBalance.ToBig(), st.msg.Value; have.Cmp(want) < 0 {
			return fmt.Errorf("%w: address %v have native balance %v want %v", ErrInsufficientFunds, st.msg.From.Hex(), have, want)
		}

		soulBalance = st.GetSoulBalance(st.msg.From)
		if have, want := new(uint256.Int).Add(nativeBalance, soulBalance), balanceCheckU256; have.Cmp(want) < 0 {
			return fmt.Errorf("%w: address %v have total balance %v want %v", ErrInsufficientFunds, st.msg.From.Hex(), have, want)
		}
	} else {
		if have, want := st.state.GetBalance(st.msg.From), balanceCheckU256; have.Cmp(want) < 0 {
			return fmt.Errorf("%w: address %v have %v want %v", ErrInsufficientFunds, st.msg.From.Hex(), have, want)
		}
	}

	if err := st.gp.SubGas(st.msg.GasLimit); err != nil {
		return err
	}

	if st.evm.Config.Tracer != nil && st.evm.Config.Tracer.OnGasChange != nil {
		st.evm.Config.Tracer.OnGasChange(0, st.msg.GasLimit, tracing.GasChangeTxInitialBalance)
	}
	st.gasRemaining = st.msg.GasLimit

	st.initialGas = st.msg.GasLimit

	mgvalU256, _ := uint256.FromBig(mgval)
	st.boughtGas = mgvalU256.Clone()
	if soulBalance == nil {
		st.state.SubBalance(st.msg.From, mgvalU256, tracing.BalanceDecreaseGasBuy)
	} else {
		if mgvalU256.Cmp(soulBalance) <= 0 {
			return st.subSoulBalance(st.msg.From, mgvalU256, tracing.BalanceDecreaseGasBuy)
		} else {
			err := st.subSoulBalance(st.msg.From, soulBalance, tracing.BalanceDecreaseGasBuy)
			if err != nil {
				return err
			}
			// when both SGT and native balance are used, we record both amounts for refund.
			// the priority for refund is: first native, then SGT
			usedNativeBalance := new(uint256.Int).Sub(mgvalU256, soulBalance)
			if usedNativeBalance.Sign() > 0 {
				st.state.SubBalance(st.msg.From, usedNativeBalance, tracing.BalanceDecreaseGasBuy)
				st.usedNativeBalance = usedNativeBalance
			}
		}
	}

	return nil
}

func (st *StateTransition) preCheck() error {
	if st.msg.IsDepositTx {
		// No fee fields to check, no nonce to check, and no need to check if EOA (L1 already verified it for us)
		// Gas is free, but no refunds!
		st.initialGas = st.msg.GasLimit
		st.gasRemaining += st.msg.GasLimit // Add gas here in order to be able to execute calls.
		// Don't touch the gas pool for system transactions
		if st.msg.IsSystemTx {
			if st.evm.ChainConfig().IsOptimismRegolith(st.evm.Context.Time) {
				return fmt.Errorf("%w: address %v", ErrSystemTxNotSupported,
					st.msg.From.Hex())
			}
			return nil
		}
		return st.gp.SubGas(st.msg.GasLimit) // gas used by deposits may not be used by other txs
	}
	// Only check transactions that are not fake
	msg := st.msg
	if !msg.SkipNonceChecks {
		// Make sure this transaction's nonce is correct.
		stNonce := st.state.GetNonce(msg.From)
		if msgNonce := msg.Nonce; stNonce < msgNonce {
			return fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooHigh,
				msg.From.Hex(), msgNonce, stNonce)
		} else if stNonce > msgNonce {
			return fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooLow,
				msg.From.Hex(), msgNonce, stNonce)
		} else if stNonce+1 < stNonce {
			return fmt.Errorf("%w: address %v, nonce: %d", ErrNonceMax,
				msg.From.Hex(), stNonce)
		}
	}
	if !msg.SkipFromEOACheck {
		// Make sure the sender is an EOA
		codeHash := st.state.GetCodeHash(msg.From)
		if codeHash != (common.Hash{}) && codeHash != types.EmptyCodeHash {
			return fmt.Errorf("%w: address %v, codehash: %s", ErrSenderNoEOA,
				msg.From.Hex(), codeHash)
		}
	}
	// Make sure that transaction gasFeeCap is greater than the baseFee (post london)
	if st.evm.ChainConfig().IsLondon(st.evm.Context.BlockNumber) {
		// Skip the checks if gas fields are zero and baseFee was explicitly disabled (eth_call)
		skipCheck := st.evm.Config.NoBaseFee && msg.GasFeeCap.BitLen() == 0 && msg.GasTipCap.BitLen() == 0
		if !skipCheck {
			if l := msg.GasFeeCap.BitLen(); l > 256 {
				return fmt.Errorf("%w: address %v, maxFeePerGas bit length: %d", ErrFeeCapVeryHigh,
					msg.From.Hex(), l)
			}
			if l := msg.GasTipCap.BitLen(); l > 256 {
				return fmt.Errorf("%w: address %v, maxPriorityFeePerGas bit length: %d", ErrTipVeryHigh,
					msg.From.Hex(), l)
			}
			if msg.GasFeeCap.Cmp(msg.GasTipCap) < 0 {
				return fmt.Errorf("%w: address %v, maxPriorityFeePerGas: %s, maxFeePerGas: %s", ErrTipAboveFeeCap,
					msg.From.Hex(), msg.GasTipCap, msg.GasFeeCap)
			}
			// This will panic if baseFee is nil, but basefee presence is verified
			// as part of header validation.
			if msg.GasFeeCap.Cmp(st.evm.Context.BaseFee) < 0 {
				return fmt.Errorf("%w: address %v, maxFeePerGas: %s, baseFee: %s", ErrFeeCapTooLow,
					msg.From.Hex(), msg.GasFeeCap, st.evm.Context.BaseFee)
			}
		}
	}
	// Check the blob version validity
	if msg.BlobHashes != nil {
		// The to field of a blob tx type is mandatory, and a `BlobTx` transaction internally
		// has it as a non-nillable value, so any msg derived from blob transaction has it non-nil.
		// However, messages created through RPC (eth_call) don't have this restriction.
		if msg.To == nil {
			return ErrBlobTxCreate
		}
		if len(msg.BlobHashes) == 0 {
			return ErrMissingBlobHashes
		}
		for i, hash := range msg.BlobHashes {
			if !kzg4844.IsValidVersionedHash(hash[:]) {
				return fmt.Errorf("blob %d has invalid hash version", i)
			}
		}
	}
	// Check that the user is paying at least the current blob fee
	if st.evm.ChainConfig().IsCancun(st.evm.Context.BlockNumber, st.evm.Context.Time) {
		if st.blobGasUsed() > 0 {
			// Skip the checks if gas fields are zero and blobBaseFee was explicitly disabled (eth_call)
			skipCheck := st.evm.Config.NoBaseFee && msg.BlobGasFeeCap.BitLen() == 0
			if !skipCheck {
				// This will panic if blobBaseFee is nil, but blobBaseFee presence
				// is verified as part of header validation.
				if msg.BlobGasFeeCap.Cmp(st.evm.Context.BlobBaseFee) < 0 {
					return fmt.Errorf("%w: address %v blobGasFeeCap: %v, blobBaseFee: %v", ErrBlobFeeCapTooLow,
						msg.From.Hex(), msg.BlobGasFeeCap, st.evm.Context.BlobBaseFee)
				}
			}
		}
	}
	return st.buyGas()
}

// TransitionDb will transition the state by applying the current message and
// returning the evm execution result with following fields.
//
//   - used gas: total gas used (including gas being refunded)
//   - returndata: the returned data from evm
//   - concrete execution error: various EVM errors which abort the execution, e.g.
//     ErrOutOfGas, ErrExecutionReverted
//
// However if any consensus issue encountered, return the error directly with
// nil evm execution result.
func (st *StateTransition) TransitionDb() (*ExecutionResult, error) {
	if mint := st.msg.Mint; mint != nil {
		mintU256, overflow := uint256.FromBig(mint)
		if overflow {
			return nil, fmt.Errorf("mint value exceeds uint256: %d", mintU256)
		}
		st.state.AddBalance(st.msg.From, mintU256, tracing.BalanceMint)
	}
	snap := st.state.Snapshot()

	result, err := st.innerTransitionDb()
	// Failed deposits must still be included. Unless we cannot produce the block at all due to the gas limit.
	// On deposit failure, we rewind any state changes from after the minting, and increment the nonce.
	if err != nil && err != ErrGasLimitReached && st.msg.IsDepositTx {
		if st.evm.Config.Tracer != nil && st.evm.Config.Tracer.OnEnter != nil {
			st.evm.Config.Tracer.OnEnter(0, byte(vm.STOP), common.Address{}, common.Address{}, nil, 0, nil)
		}

		st.state.RevertToSnapshot(snap)
		// Even though we revert the state changes, always increment the nonce for the next deposit transaction
		st.state.SetNonce(st.msg.From, st.state.GetNonce(st.msg.From)+1)
		// Record deposits as using all their gas (matches the gas pool)
		// System Transactions are special & are not recorded as using any gas (anywhere)
		// Regolith changes this behaviour so the actual gas used is reported.
		// In this case the tx is invalid so is recorded as using all gas.
		gasUsed := st.msg.GasLimit
		if st.msg.IsSystemTx && !st.evm.ChainConfig().IsRegolith(st.evm.Context.Time) {
			gasUsed = 0
		}
		result = &ExecutionResult{
			UsedGas:    gasUsed,
			Err:        fmt.Errorf("failed deposit: %w", err),
			ReturnData: nil,
		}
		err = nil
	}
	return result, err
}

func (st *StateTransition) innerTransitionDb() (*ExecutionResult, error) {
	// First check this message satisfies all consensus rules before
	// applying the message. The rules include these clauses
	//
	// 1. the nonce of the message caller is correct
	// 2. caller has enough balance to cover transaction fee(gaslimit * gasprice)
	// 3. the amount of gas required is available in the block
	// 4. the purchased gas is enough to cover intrinsic usage
	// 5. there is no overflow when calculating intrinsic gas
	// 6. caller has enough balance to cover asset transfer for **topmost** call

	// Check clauses 1-3, buy gas if everything is correct
	if err := st.preCheck(); err != nil {
		return nil, err
	}

	var (
		msg              = st.msg
		sender           = vm.AccountRef(msg.From)
		rules            = st.evm.ChainConfig().Rules(st.evm.Context.BlockNumber, st.evm.Context.Random != nil, st.evm.Context.Time)
		contractCreation = msg.To == nil
	)

	// Check clauses 4-5, subtract intrinsic gas if everything is correct
	gas, err := IntrinsicGas(msg.Data, msg.AccessList, contractCreation, rules.IsHomestead, rules.IsIstanbul, rules.IsShanghai)
	if err != nil {
		return nil, err
	}
	if st.gasRemaining < gas {
		return nil, fmt.Errorf("%w: have %d, want %d", ErrIntrinsicGas, st.gasRemaining, gas)
	}
	if t := st.evm.Config.Tracer; t != nil && t.OnGasChange != nil {
		if st.msg.IsDepositTx {
			t.OnGasChange(st.gasRemaining, 0, tracing.GasChangeTxIntrinsicGas)
		} else {
			t.OnGasChange(st.gasRemaining, st.gasRemaining-gas, tracing.GasChangeTxIntrinsicGas)
		}
	}
	st.gasRemaining -= gas

	if rules.IsEIP4762 {
		st.evm.AccessEvents.AddTxOrigin(msg.From)

		if targetAddr := msg.To; targetAddr != nil {
			st.evm.AccessEvents.AddTxDestination(*targetAddr, msg.Value.Sign() != 0)
		}
	}

	// Check clause 6
	value, overflow := uint256.FromBig(msg.Value)
	if overflow {
		return nil, fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, msg.From.Hex())
	}
	if !value.IsZero() && !st.evm.Context.CanTransfer(st.state, msg.From, value) {
		return nil, fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, msg.From.Hex())
	}

	// Check whether the init code size has been exceeded.
	if rules.IsShanghai && contractCreation && len(msg.Data) > params.MaxInitCodeSize {
		return nil, fmt.Errorf("%w: code size %v limit %v", ErrMaxInitCodeSizeExceeded, len(msg.Data), params.MaxInitCodeSize)
	}

	// Execute the preparatory steps for state transition which includes:
	// - prepare accessList(post-berlin)
	// - reset transient storage(eip 1153)
	st.state.Prepare(rules, msg.From, st.evm.Context.Coinbase, msg.To, vm.ActivePrecompiles(rules), msg.AccessList)

	var (
		ret   []byte
		vmerr error // vm errors do not effect consensus and are therefore not assigned to err
	)
	if contractCreation {
		ret, _, st.gasRemaining, vmerr = st.evm.Create(sender, msg.Data, st.gasRemaining, value)
	} else {
		// Increment the nonce for the next transaction
		st.state.SetNonce(msg.From, st.state.GetNonce(sender.Address())+1)
		ret, st.gasRemaining, vmerr = st.evm.Call(sender, st.to(), msg.Data, st.gasRemaining, value)
	}

	// if deposit: skip refunds, skip tipping coinbase
	// Regolith changes this behaviour to report the actual gasUsed instead of always reporting all gas used.
	if st.msg.IsDepositTx && !rules.IsOptimismRegolith {
		// Record deposits as using all their gas (matches the gas pool)
		// System Transactions are special & are not recorded as using any gas (anywhere)
		gasUsed := st.msg.GasLimit
		if st.msg.IsSystemTx {
			gasUsed = 0
		}
		return &ExecutionResult{
			UsedGas:    gasUsed,
			Err:        vmerr,
			ReturnData: ret,
		}, nil
	}
	// Note for deposit tx there is no ETH refunded for unused gas, but that's taken care of by the fact that gasPrice
	// is always 0 for deposit tx. So calling refundGas will ensure the gasUsed accounting is correct without actually
	// changing the sender's balance
	var gasRefund uint64
	if !rules.IsLondon {
		// Before EIP-3529: refunds were capped to gasUsed / 2
		gasRefund = st.refundGas(params.RefundQuotient)
	} else {
		// After EIP-3529: refunds are capped to gasUsed / 5
		gasRefund = st.refundGas(params.RefundQuotientEIP3529)
	}
	if st.msg.IsDepositTx && rules.IsOptimismRegolith {
		// Skip coinbase payments for deposit tx in Regolith
		return &ExecutionResult{
			UsedGas:     st.gasUsed(),
			RefundedGas: gasRefund,
			Err:         vmerr,
			ReturnData:  ret,
		}, nil
	}
	effectiveTip := msg.GasPrice
	if rules.IsLondon {
		effectiveTip = cmath.BigMin(msg.GasTipCap, new(big.Int).Sub(msg.GasFeeCap, st.evm.Context.BaseFee))
	}
	effectiveTipU256, _ := uint256.FromBig(effectiveTip)

	shouldCheckGasFormula := true
	if st.evm.Config.NoBaseFee && msg.GasFeeCap.Sign() == 0 && msg.GasTipCap.Sign() == 0 {
		// Skip fee payment when NoBaseFee is set and the fee fields
		// are 0. This avoids a negative effectiveTip being applied to
		// the coinbase when simulating calls.
		shouldCheckGasFormula = false
	} else {

		fee := new(uint256.Int).SetUint64(st.gasUsed())
		fee.Mul(fee, effectiveTipU256)

		st.tipFee = fee.Clone()

		fee = st.collectableNativeBalance(fee)
		st.state.AddBalance(st.evm.Context.Coinbase, fee, tracing.BalanceIncreaseRewardTransactionFee)

		// add the coinbase to the witness iff the fee is greater than 0
		if rules.IsEIP4762 && fee.Sign() != 0 {
			st.evm.AccessEvents.AddAccount(st.evm.Context.Coinbase, true)
		}
	}

	// Check that we are post bedrock to enable op-geth to be able to create pseudo pre-bedrock blocks (these are pre-bedrock, but don't follow l2 geth rules)
	// Note optimismConfig will not be nil if rules.IsOptimismBedrock is true
	if optimismConfig := st.evm.ChainConfig().Optimism; optimismConfig != nil && rules.IsOptimismBedrock && !st.msg.IsDepositTx {
		gasCost := new(big.Int).Mul(new(big.Int).SetUint64(st.gasUsed()), st.evm.Context.BaseFee)

		if st.evm.ChainConfig().IsCancun(st.evm.Context.BlockNumber, st.evm.Context.Time) {
			gasCost.Add(gasCost, new(big.Int).Mul(new(big.Int).SetUint64(st.blobGasUsed()), st.evm.Context.BlobBaseFee))
		}

		amtU256, overflow := uint256.FromBig(gasCost)
		if overflow {
			return nil, fmt.Errorf("optimism gas cost overflows U256: %d", gasCost)
		}
		if shouldCheckGasFormula {
			st.baseFee = amtU256.Clone()
		}

		amtU256 = st.collectableNativeBalance(amtU256)
		st.state.AddBalance(params.OptimismBaseFeeRecipient, amtU256, tracing.BalanceIncreaseRewardTransactionFee)
		if l1Cost := st.evm.Context.L1CostFunc(st.msg.RollupCostData, st.evm.Context.Time); l1Cost != nil {
			amtU256, overflow = uint256.FromBig(l1Cost)
			if overflow {
				return nil, fmt.Errorf("optimism l1 cost overflows U256: %d", l1Cost)
			}

			if shouldCheckGasFormula {
				st.l1Fee = amtU256.Clone()
			}

			amtU256 = st.collectableNativeBalance(amtU256)
			st.state.AddBalance(params.OptimismL1FeeRecipient, amtU256, tracing.BalanceIncreaseRewardTransactionFee)
		}

		if shouldCheckGasFormula {
			if st.l1Fee == nil {
				st.l1Fee = new(uint256.Int)
			}
			if err := st.checkGasFormula(); err != nil {
				return nil, err
			}
		}
	}

	return &ExecutionResult{
		UsedGas:     st.gasUsed(),
		RefundedGas: gasRefund,
		Err:         vmerr,
		ReturnData:  ret,
	}, nil
}

func (st *StateTransition) refundGas(refundQuotient uint64) uint64 {
	// Apply refund counter, capped to a refund quotient
	refund := st.gasUsed() / refundQuotient
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund()
	}

	if st.evm.Config.Tracer != nil && st.evm.Config.Tracer.OnGasChange != nil && refund > 0 {
		st.evm.Config.Tracer.OnGasChange(st.gasRemaining, st.gasRemaining+refund, tracing.GasChangeTxRefunds)
	}

	st.gasRemaining += refund

	// Return ETH for remaining gas, exchanged at the original rate.
	remaining := uint256.NewInt(st.gasRemaining)
	remaining.Mul(remaining, uint256.MustFromBig(st.msg.GasPrice))
	st.refundedGas = remaining.Clone()
	if st.usedSGTBalance == nil {
		st.state.AddBalance(st.msg.From, remaining, tracing.BalanceIncreaseGasReturn)
	} else {
		native, sgt := st.distributeGas(remaining, st.usedNativeBalance, st.usedSGTBalance)
		if native.Sign() > 0 {
			st.state.AddBalance(st.msg.From, remaining, tracing.BalanceIncreaseGasReturn)
		}
		if sgt.Sign() > 0 {
			st.addSoulBalance(st.msg.From, sgt, tracing.BalanceIncreaseGasReturn)
		}
	}

	if st.evm.Config.Tracer != nil && st.evm.Config.Tracer.OnGasChange != nil && st.gasRemaining > 0 {
		st.evm.Config.Tracer.OnGasChange(st.gasRemaining, 0, tracing.GasChangeTxLeftOverReturned)
	}

	// Also return remaining gas to the block gas counter so it is
	// available for the next transaction.
	st.gp.AddGas(st.gasRemaining)

	return refund
}

// gasUsed returns the amount of gas used up by the state transition.
func (st *StateTransition) gasUsed() uint64 {
	return st.initialGas - st.gasRemaining
}

// blobGasUsed returns the amount of blob gas used by the message.
func (st *StateTransition) blobGasUsed() uint64 {
	return uint64(len(st.msg.BlobHashes) * params.BlobTxBlobGasPerBlob)
}
