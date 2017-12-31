package dcrwallet

import (
	"fmt"
	"strings"
	"path/filepath"
	"encoding/json"

	pb "github.com/decred/dcrwallet/rpc/walletrpc"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)
//var certificateFile = filepath.Join(dcrutil.AppDataDir("dcrwallet", false), "rpc.cert")
var certificateFile = filepath.Join("/data/data/com.decrediton/files/dcrwallet", "rpc.cert")
type Balance struct{
	Total					int64
	Spendable				int64
	ImmatureReward			int64
	ImmatureStakeGeneration	int64
	LockedByTickets			int64
	VotingAuthority			int64
	UnConfirmed				int64
}
type Account struct{
	Number				int32
	Name				string
	Balance				*Balance
	External_key_count	int32
	Internal_key_count	int32
	Imported_key_count	int32
}
type Accounts struct{
	Count					int
	ErrorMessage			string
	ErrorCode				int
	ErrorOccurred			bool
	Acc						*[]Account
	Current_block_hash		[]byte
	Current_block_height	int32
}
/* 
	Error Codes
	// OK is returned on success.
	OK Code = 0

	// Canceled indicates the operation was canceled (typically by the caller).
	Canceled Code = 1

	// Unknown error.  An example of where this error may be returned is
	// if a Status value received from another address space belongs to
	// an error-space that is not known in this address space.  Also
	// errors raised by APIs that do not return enough error information
	// may be converted to this error.
	Unknown Code = 2

	// InvalidArgument indicates client specified an invalid argument.
	// Note that this differs from FailedPrecondition. It indicates arguments
	// that are problematic regardless of the state of the system
	// (e.g., a malformed file name).
	InvalidArgument Code = 3

	// DeadlineExceeded means operation expired before completion.
	// For operations that change the state of the system, this error may be
	// returned even if the operation has completed successfully. For
	// example, a successful response from a server could have been delayed
	// long enough for the deadline to expire.
	DeadlineExceeded Code = 4

	// NotFound means some requested entity (e.g., file or directory) was
	// not found.
	NotFound Code = 5

	// AlreadyExists means an attempt to create an entity failed because one
	// already exists.
	AlreadyExists Code = 6

	// PermissionDenied indicates the caller does not have permission to
	// execute the specified operation. It must not be used for rejections
	// caused by exhausting some resource (use ResourceExhausted
	// instead for those errors).  It must not be
	// used if the caller cannot be identified (use Unauthenticated
	// instead for those errors).
	PermissionDenied Code = 7

	// Unauthenticated indicates the request does not have valid
	// authentication credentials for the operation.
	Unauthenticated Code = 16

	// ResourceExhausted indicates some resource has been exhausted, perhaps
	// a per-user quota, or perhaps the entire file system is out of space.
	ResourceExhausted Code = 8

	// FailedPrecondition indicates operation was rejected because the
	// system is not in a state required for the operation's execution.
	// For example, directory to be deleted may be non-empty, an rmdir
	// operation is applied to a non-directory, etc.
	FailedPrecondition Code = 9

	// Aborted indicates the operation was aborted, typically due to a
	// concurrency issue like sequencer check failures, transaction aborts,
	// etc.
	//
	// See litmus test above for deciding between FailedPrecondition,
	// Aborted, and Unavailable.
	Aborted Code = 10

	// OutOfRange means operation was attempted past the valid range.
	// E.g., seeking or reading past end of file.
	//
	// Unlike InvalidArgument, this error indicates a problem that may
	// be fixed if the system state changes. For example, a 32-bit file
	// system will generate InvalidArgument if asked to read at an
	// offset that is not in the range [0,2^32-1], but it will generate
	// OutOfRange if asked to read from an offset past the current
	// file size.
	//
	// There is a fair bit of overlap between FailedPrecondition and
	// OutOfRange.  We recommend using OutOfRange (the more specific
	// error) when it applies so that callers who are iterating through
	// a space can easily look for an OutOfRange error to detect when
	// they are done.
	OutOfRange Code = 11

	// Unimplemented indicates operation is not implemented or not
	// supported/enabled in this service.
	Unimplemented Code = 12

	// Internal errors.  Means some invariants expected by underlying
	// system has been broken.  If you see one of these errors,
	// something is very broken.
	Internal Code = 13

	// Unavailable indicates the service is currently unavailable.
	// This is a most likely a transient condition and may be corrected
	// by retrying with a backoff.
	//
	// See litmus test above for deciding between FailedPrecondition,
	// Aborted, and Unavailable.
	Unavailable Code = 14

	// DataLoss indicates unrecoverable data loss or corruption.
	DataLoss Code = 15
	//Still working on the error codes
*/

func connect() (*grpc.ClientConn, error){
	creds, err := credentials.NewClientTLSFromFile(certificateFile, "127.0.0.1")
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	conn, err := grpc.Dial("127.0.0.1:9111", grpc.WithTransportCredentials(creds))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return conn,nil	
}

func RestoreWallet(passPhrase string, userInput string) string {
	connection, err := connect()
	if err != nil{
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	defer connection.Close()
	seedsService := pb.NewSeedServiceClient(connection);
	decodeSeedRequest := &pb.DecodeSeedRequest{UserInput : userInput}
	decodeSeedResponse, err := seedsService.DecodeSeed(context.Background(), decodeSeedRequest);
	if err != nil{
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "Error while trying to decode seed"}}`
	}
	seed := decodeSeedResponse.DecodedSeed
	privatePassphrase := []byte(passPhrase)
	publicPassPhrase := []byte("public")
	walletLoader := pb.NewWalletLoaderServiceClient(connection)
	createWallet := &pb.CreateWalletRequest{
		PublicPassphrase: publicPassPhrase,
	 	PrivatePassphrase: privatePassphrase,
	 	Seed: seed,
	}
	createWalletResponse, err := walletLoader.CreateWallet(context.Background(), createWallet)
	if err != nil{
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	createWalletResponse.Reset();
	if err != nil{
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	return `{"ErrorOccurred" : "false", "Success" : {"content": "true"}}`
}

func GenerateSeed() string{
	connection, err := connect()
	if err != nil{
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	defer connection.Close()
	seedsService := pb.NewSeedServiceClient(connection);
	generateSeedRequest := &pb.GenerateRandomSeedRequest{
		SeedLength : 0 }
	generateSeedResponse, err := seedsService.GenerateRandomSeed(context.Background(), generateSeedRequest);
	if err != nil{
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	seedMnemonic := generateSeedResponse.GetSeedMnemonic();
	return `{"ErrorOccurred" : "false", "Success" : {"content": "`+seedMnemonic+`"}}`
}

func VerifySeed(seedMnemonic string) string{
	connection, err := connect()
	if err != nil{
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	defer connection.Close()
	seedsService := pb.NewSeedServiceClient(connection);
	decodeSeedRequest := &pb.DecodeSeedRequest{
		UserInput: seedMnemonic }
	_, err = seedsService.DecodeSeed(context.Background(), decodeSeedRequest);
	if err != nil{
		fmt.Println(err)
		if(strings.Contains(err.Error(), "InvalidArgument")){
			return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "The seed you entered is not valid"}}`
		}
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	return `{"ErrorOccurred" : "false", "Success" : {"content": "true"}}`
}

func CreateWallet(passPhrase string,seedMnemonic string) string {
	connection, err := connect()
	if err != nil{
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	defer connection.Close()
	seedsService := pb.NewSeedServiceClient(connection);
	decodeSeedRequest := &pb.DecodeSeedRequest{
		UserInput: seedMnemonic }
	decodeSeedResponse, err := seedsService.DecodeSeed(context.Background(), decodeSeedRequest);
	if err != nil{
		fmt.Println(err)
		if(strings.Contains(err.Error(), "InvalidArgument")){
			return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "The seed you entered is not valid"}}`
		}
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	seed := decodeSeedResponse.DecodedSeed
	privatePassphrase := []byte(passPhrase)
	publicPassPhrase := []byte("public")
	walletLoader := pb.NewWalletLoaderServiceClient(connection)
	createWallet := &pb.CreateWalletRequest{
		PublicPassphrase: publicPassPhrase,
	 	PrivatePassphrase: privatePassphrase,
	 	Seed: seed,
	}
	_, err = walletLoader.CreateWallet(context.Background(), createWallet)
	if err != nil{
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	if err != nil{
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	return `{"ErrorOccurred" : "false", "Success" : {"content": "`+seedMnemonic+`"}}`
}

func WalletExists() string{
	connection, err := connect()
	if err != nil{
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	defer connection.Close()
	walletLoader := pb.NewWalletLoaderServiceClient(connection)
	walletExistsRequest := &pb.WalletExistsRequest{}
	walletExistsResponse, err := walletLoader.WalletExists(context.Background(), walletExistsRequest);
	if err != nil{
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "Error while checking for existence of wallet"}}`
	}
	exists := "false"
	if walletExistsResponse.GetExists(){
		exists = "true"
	}else{
		exists = "false"
	}
	return `{"ErrorOccurred" : "false", "Success" : {"content": "`+exists+`"}}`
}

func OpenWallet() string{
	connection, err := connect()
	if err != nil{
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "Error while connecting to dcrwallet"}}`
	}
	defer connection.Close()
	publicPassPhrase := []byte("public")
	walletLoader := pb.NewWalletLoaderServiceClient(connection)
	openWalletRequest := &pb.OpenWalletRequest{
		PublicPassphrase: publicPassPhrase}
	_, err = walletLoader.OpenWallet(context.Background(), openWalletRequest)
	if err != nil{
		if(strings.Contains(err.Error(), "FailedPrecondition")){
			return `{"ErrorOccurred" : "false", "Success" : {"content": "true"}}`
		}else if(strings.Contains(err.Error(), "NotFound")){
			return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "Wallet does not exists"}}`
		}else if(strings.Contains(err.Error(), "InvalidArgument")){
			return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "Incorrect public passphrase"}}`
		}
	}
	return `{"ErrorOccurred" : "false", "Success" : {"content": "true"}}`
}

func CloseWallet() string{
	connection, err := connect()
	if err != nil{
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "Error while connecting to dcrwallet"}}`
	}
	defer connection.Close()
	walletLoader := pb.NewWalletLoaderServiceClient(connection)
	closeWalletRequest := &pb.CloseWalletRequest{}
	_, err =  walletLoader.CloseWallet(context.Background(), closeWalletRequest)
	if err != nil{
		fmt.Printf("%v", err)
		if(strings.Contains(err.Error(), "FailedPrecondition")){
			return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "No wallet is currently open"}}`
		}
	}
	return `{"ErrorOccurred" : "false", "Success" : {"content": "true"}}`
}

func GetAccounts() string{
	accounts := &Accounts{}
	connection, err := connect()
	if err != nil{
		fmt.Println(err)
		accounts.ErrorOccurred = true
		accounts.ErrorMessage = "Error while connecting to dcrwallet"
		result,_ := json.Marshal(accounts)
		return string(result)
	}
	defer connection.Close()
	walletService := pb.NewWalletServiceClient(connection)
	accountsRequest := &pb.AccountsRequest{}
	accountResponse, err := walletService.Accounts(context.Background(), accountsRequest)
	if err != nil{
		fmt.Printf("%v", err)
		accounts.ErrorOccurred = true
		accounts.ErrorMessage = "Error while connecting to getting accounts"
		result,_ := json.Marshal(accounts)
		return string(result)
	}
	accountArray := make([] Account, len(accountResponse.Accounts))
	for index, value := range accountResponse.Accounts{
		balanceRequest := &pb.BalanceRequest{
			AccountNumber: value.AccountNumber,
			RequiredConfirmations: 3}
		balanceResponse,_ := walletService.Balance(context.Background(), balanceRequest)
		balance := Balance{
			Total: balanceResponse.GetTotal(),
			Spendable: balanceResponse.GetSpendable(),
			ImmatureReward: balanceResponse.GetImmatureReward(),
			ImmatureStakeGeneration: balanceResponse.GetImmatureStakeGeneration(),
			LockedByTickets: balanceResponse.GetLockedByTickets(),
			VotingAuthority: balanceResponse.GetVotingAuthority(),
			UnConfirmed: balanceResponse.GetUnconfirmed()}
		accountArray[index] = Account{
			Name: value.GetAccountName(),
			Number: int32(value.GetAccountNumber()),
			External_key_count: int32(value.GetExternalKeyCount()),
			Internal_key_count: int32(value.GetInternalKeyCount()),
			Imported_key_count: int32(value.GetImportedKeyCount()),
			Balance: &balance}
	}
	accounts = &Accounts{
		Count: len(accountResponse.Accounts),
		Current_block_hash: accountResponse.GetCurrentBlockHash(),
		Current_block_height: accountResponse.GetCurrentBlockHeight(),
		Acc: &accountArray,
		ErrorOccurred: false,
	}
	result,_ := json.Marshal(accounts)
	return string(result)
}

// func GetBalance(num int) string{
// 	connection, err := connect()
// 	if err != nil{
// 		fmt.Println(err)
// 		//return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "Error while connecting to dcrwallet"}}`
// 	}
// 	defer connection.Close()
// 	walletService := pb.NewWalletServiceClient(connection)
// 	balanceRequest := &pb.BalanceRequest{
// 		AccountNumber: uint32(num),
// 		RequiredConfirmations: 3}
// 	balanceResponse,_ := walletService.Balance(context.Background(), balanceRequest)
// 	balance := &Balance{
// 		Total: balanceResponse.GetTotal(),
// 		Spendable: balanceResponse.GetSpendable(),
// 		ImmatureReward: balanceResponse.GetImmatureReward(),
// 		ImmatureStakeGeneration: balanceResponse.GetImmatureStakeGeneration(),
// 		LockedByTickets: balanceResponse.GetLockedByTickets(),
// 		VotingAuthority: balanceResponse.GetVotingAuthority(),
// 		UnConfirmed: balanceResponse.GetUnconfirmed()}
// 	result,_ := json.Marshal(balance);
// 	return string(result)
// }

// // func (accounts *Accounts) AddAccount(account Account) []Account{
// // 	accounts.Acc = append(accounts.Acc, account);
// // 	return accounts.Acc
// // }