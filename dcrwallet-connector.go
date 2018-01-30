package dcrwallet

import (
	"encoding/json"

	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"

	dcrctl "github.com/decred/dcrctl"
	pb "github.com/decred/dcrwallet/rpc/walletrpc"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	//"github.com/decred/dcrd/dcrutil"
)

//var certificateFile = filepath.Join(dcrutil.AppDataDir("dcrwallet", false), "rpc.cert")
var certificateFile = filepath.Join("/data/data/com.decrediton/files/dcrwallet", "rpc.cert")

type Balance struct {
	Total                   int64
	Spendable               int64
	ImmatureReward          int64
	ImmatureStakeGeneration int64
	LockedByTickets         int64
	VotingAuthority         int64
	UnConfirmed             int64
}

type Account struct {
	Number             int32
	Name               string
	Balance            *Balance
	External_key_count int32
	Internal_key_count int32
	Imported_key_count int32
}

type Accounts struct {
	Count                int
	ErrorMessage         string
	ErrorCode            int
	ErrorOccurred        bool
	Acc                  *[]Account
	Current_block_hash   []byte
	Current_block_height int32
}

type Transaction struct {
	Hash        string
	Transaction []byte
	Fee         int64
	Timestamp   int64
	Type        string
	Amount      int64
	Status      string
	Debits      *[]TransactionDebit
	Credits     *[]TransactionCredit
}

type TransactionDebit struct {
	Index           int32
	PreviousAccount int32
	PreviousAmount  int64
	AccountName     string
}

type TransactionCredit struct {
	Index    int32
	Account  int32
	Internal bool
	Amount   int64
	Address  string
}

type BlockScanResponse interface {
	OnScan(rescanned_through int)
	OnEnd(height int)
}

type getTransactionsResponse struct {
	Mined         []Transaction
	UnMined       []Transaction
	ErrorOccurred bool
	ErrorMessage  string
}

type ConstructTxResponse struct {
	EstimatedSignedSize       int32
	TotalOutputAmount         int64
	TotalPreviousOutputAmount int64
	UnsignedTransaction       []byte
	ErrorOccurred             bool
	ErrorMessage              string
	ErrorCode                 int32
}

func connect() (*grpc.ClientConn, error) {
	creds, err := credentials.NewClientTLSFromFile(certificateFile, "127.0.0.1")
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	tcfg, _, err := loadConfig(context.Background())
	if err != nil {
		return nil, err
	}
	cfg = tcfg
	rpcAddress := "127.0.0.1:9111"
	if cfg.TestNet {
		rpcAddress = "127.0.0.1:19111"
	}
	conn, err := grpc.Dial(rpcAddress, grpc.WithTransportCredentials(creds))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return conn, nil
}

func TestConnect() bool {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer connection.Close()
	return true
}

func Ping() bool {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer connection.Close()
	walletService := pb.NewWalletServiceClient(connection)
	_, err = walletService.Ping(context.Background(), &pb.PingRequest{})
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

func IsTestNet() bool {
	tcfg, _, err := loadConfig(context.Background())
	if err != nil {
		return false
	}
	cfg = tcfg
	return cfg.TestNet
}

func RestoreWallet(passPhrase string, userInput string) string {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	defer connection.Close()
	seedsService := pb.NewSeedServiceClient(connection)
	decodeSeedRequest := &pb.DecodeSeedRequest{UserInput: userInput}
	decodeSeedResponse, err := seedsService.DecodeSeed(context.Background(), decodeSeedRequest)
	if err != nil {
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "Error while trying to decode seed"}}`
	}
	seed := decodeSeedResponse.DecodedSeed
	privatePassphrase := []byte(passPhrase)
	publicPassPhrase := []byte("public")
	walletLoader := pb.NewWalletLoaderServiceClient(connection)
	createWallet := &pb.CreateWalletRequest{
		PublicPassphrase:  publicPassPhrase,
		PrivatePassphrase: privatePassphrase,
		Seed:              seed,
	}
	createWalletResponse, err := walletLoader.CreateWallet(context.Background(), createWallet)
	if err != nil {
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	createWalletResponse.Reset()
	if err != nil {
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	return `{"ErrorOccurred" : "false", "Success" : {"content": "true"}}`
}

func GenerateSeed() string {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	defer connection.Close()
	seedsService := pb.NewSeedServiceClient(connection)
	generateSeedRequest := &pb.GenerateRandomSeedRequest{
		SeedLength: 0}
	generateSeedResponse, err := seedsService.GenerateRandomSeed(context.Background(), generateSeedRequest)
	if err != nil {
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	seedMnemonic := generateSeedResponse.GetSeedMnemonic()
	return `{"ErrorOccurred" : "false", "Success" : {"content": "` + seedMnemonic + `"}}`
}

func VerifySeed(seedMnemonic string) string {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	defer connection.Close()
	seedsService := pb.NewSeedServiceClient(connection)
	decodeSeedRequest := &pb.DecodeSeedRequest{
		UserInput: seedMnemonic}
	_, err = seedsService.DecodeSeed(context.Background(), decodeSeedRequest)
	if err != nil {
		fmt.Println(err)
		if strings.Contains(err.Error(), "InvalidArgument") {
			return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "The seed you entered is not valid"}}`
		}
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	return `{"ErrorOccurred" : "false", "Success" : {"content": "true"}}`
}

func CreateWallet(passPhrase string, seedMnemonic string) string {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	defer connection.Close()
	seedsService := pb.NewSeedServiceClient(connection)
	decodeSeedRequest := &pb.DecodeSeedRequest{
		UserInput: seedMnemonic}
	decodeSeedResponse, err := seedsService.DecodeSeed(context.Background(), decodeSeedRequest)
	if err != nil {
		fmt.Println(err)
		if strings.Contains(err.Error(), "InvalidArgument") {
			return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "The seed you entered is not valid"}}`
		}
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	seed := decodeSeedResponse.DecodedSeed
	privatePassphrase := []byte(passPhrase)
	publicPassPhrase := []byte("public")
	walletLoader := pb.NewWalletLoaderServiceClient(connection)
	createWallet := &pb.CreateWalletRequest{
		PublicPassphrase:  publicPassPhrase,
		PrivatePassphrase: privatePassphrase,
		Seed:              seed,
	}
	_, err = walletLoader.CreateWallet(context.Background(), createWallet)
	if err != nil {
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	//ConnectToDcrd("192.168.43.203:9109")
	return `{"ErrorOccurred" : "false", "Success" : {"content": "` + seedMnemonic + `"}}`
}

func WalletExists() string {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	defer connection.Close()
	walletLoader := pb.NewWalletLoaderServiceClient(connection)
	walletExistsRequest := &pb.WalletExistsRequest{}
	walletExistsResponse, err := walletLoader.WalletExists(context.Background(), walletExistsRequest)
	if err != nil {
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "Error while checking for existence of wallet"}}`
	}
	exists := "false"
	if walletExistsResponse.GetExists() {
		exists = "true"
	} else {
		exists = "false"
	}
	return `{"ErrorOccurred" : "false", "Success" : {"content": "` + exists + `"}}`
}

func OpenWallet() string {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : ""}}`
	}
	defer connection.Close()
	publicPassPhrase := []byte("public")
	walletLoader := pb.NewWalletLoaderServiceClient(connection)
	openWalletRequest := &pb.OpenWalletRequest{
		PublicPassphrase: publicPassPhrase}
	_, err = walletLoader.OpenWallet(context.Background(), openWalletRequest)
	if err != nil {
		if strings.Contains(err.Error(), "FailedPrecondition") {
			return `{"ErrorOccurred" : "false", "Success" : {"content": "true"}}`
		} else if strings.Contains(err.Error(), "NotFound") {
			return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "Wallet does not exists"}}`
		} else if strings.Contains(err.Error(), "InvalidArgument") {
			return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "Incorrect public passphrase"}}`
		}
	}
	//ConnectToDcrd("127.0.0.1:9109")
	//ConnectToDcrd("192.168.43.203:9109")
	return `{"ErrorOccurred" : "false", "Success" : {"content": "true"}}`
}

func CloseWallet() string {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "Error while connecting to dcrwallet"}}`
	}
	defer connection.Close()
	walletLoader := pb.NewWalletLoaderServiceClient(connection)
	closeWalletRequest := &pb.CloseWalletRequest{}
	_, err = walletLoader.CloseWallet(context.Background(), closeWalletRequest)
	if err != nil {
		fmt.Printf("%v", err)
		if strings.Contains(err.Error(), "FailedPrecondition") {
			return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "No wallet is currently open"}}`
		}
	}
	return `{"ErrorOccurred" : "false", "Success" : {"content": "true"}}`
}

func GetAccounts() string {
	accounts := &Accounts{}
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		accounts.ErrorOccurred = true
		accounts.ErrorMessage = "Error while connecting to dcrwallet"
		result, _ := json.Marshal(accounts)
		return string(result)
	}
	defer connection.Close()
	walletService := pb.NewWalletServiceClient(connection)
	accountsRequest := &pb.AccountsRequest{}
	accountResponse, err := walletService.Accounts(context.Background(), accountsRequest)
	if err != nil {
		fmt.Printf("%v", err)
		accounts.ErrorOccurred = true
		accounts.ErrorMessage = "Error while connecting to getting accounts"
		result, _ := json.Marshal(accounts)
		return string(result)
	}
	accountArray := make([]Account, len(accountResponse.Accounts))
	for index, value := range accountResponse.Accounts {
		balanceRequest := &pb.BalanceRequest{
			AccountNumber:         value.AccountNumber,
			RequiredConfirmations: 3}
		balanceResponse, _ := walletService.Balance(context.Background(), balanceRequest)
		balance := Balance{
			Total:                   balanceResponse.GetTotal(),
			Spendable:               balanceResponse.GetSpendable(),
			ImmatureReward:          balanceResponse.GetImmatureReward(),
			ImmatureStakeGeneration: balanceResponse.GetImmatureStakeGeneration(),
			LockedByTickets:         balanceResponse.GetLockedByTickets(),
			VotingAuthority:         balanceResponse.GetVotingAuthority(),
			UnConfirmed:             balanceResponse.GetUnconfirmed()}
		accountArray[index] = Account{
			Name:               value.GetAccountName(),
			Number:             int32(value.GetAccountNumber()),
			External_key_count: int32(value.GetExternalKeyCount()),
			Internal_key_count: int32(value.GetInternalKeyCount()),
			Imported_key_count: int32(value.GetImportedKeyCount()),
			Balance:            &balance}
	}
	accounts = &Accounts{
		Count:                len(accountResponse.Accounts),
		Current_block_hash:   accountResponse.GetCurrentBlockHash(),
		Current_block_height: accountResponse.GetCurrentBlockHeight(),
		Acc:                  &accountArray,
		ErrorOccurred:        false,
	}
	result, _ := json.Marshal(accounts)
	return string(result)
}

func CreateAccount(accountName string, passPhrase string) string {
	connection, _ := connect()
	defer connection.Close()
	walletService := pb.NewWalletServiceClient(connection)
	nextAccountRequest := &pb.NextAccountRequest{
		AccountName: accountName,
		Passphrase:  []byte(passPhrase)}
	_, _ = walletService.NextAccount(context.Background(), nextAccountRequest)
	return `{"ErrorOccurred" : "false", "Success" : {"content": "true"}}`
}

func NextAddress(accountNumber int) string {
	connection, _ := connect()
	defer connection.Close()
	walletService := pb.NewWalletServiceClient(connection)
	nextAddressRequest := &pb.NextAddressRequest{
		Account:   uint32(accountNumber),
		Kind:      pb.NextAddressRequest_BIP0044_EXTERNAL,
		GapPolicy: pb.NextAddressRequest_GAP_POLICY_WRAP}
	nextAddressResponse, err := walletService.NextAddress(context.Background(), nextAddressRequest)
	if err != nil {
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "Error while checking for address"}}`
	}
	fmt.Println("PUBLIC KEY:", nextAddressResponse.GetAddress())

	return `{"ErrorOccurred" : "false", "Success" : {"content": "` + nextAddressResponse.Address + `"}}`
}

func GetBalance(num int) *Balance {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		//return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "Error while connecting to dcrwallet"}}`
	}
	defer connection.Close()
	walletService := pb.NewWalletServiceClient(connection)
	balanceRequest := &pb.BalanceRequest{
		AccountNumber:         uint32(num),
		RequiredConfirmations: 3}
	balanceResponse, _ := walletService.Balance(context.Background(), balanceRequest)
	balance := &Balance{
		Total:                   balanceResponse.GetTotal(),
		Spendable:               balanceResponse.GetSpendable(),
		ImmatureReward:          balanceResponse.GetImmatureReward(),
		ImmatureStakeGeneration: balanceResponse.GetImmatureStakeGeneration(),
		LockedByTickets:         balanceResponse.GetLockedByTickets(),
		VotingAuthority:         balanceResponse.GetVotingAuthority(),
		UnConfirmed:             balanceResponse.GetUnconfirmed()}
	//result,_ := json.Marshal(balance);
	return balance
}

func GetAccount(num int, connection *grpc.ClientConn) string {
	walletService := pb.NewWalletServiceClient(connection)
	accountResponse, err := walletService.Accounts(context.Background(), &pb.AccountsRequest{})
	if err != nil {
		fmt.Println(err)
		return ""
	}
	for _, account := range accountResponse.Accounts {
		if account.AccountNumber == uint32(num) {
			return account.AccountName
		}
	}
	return "Account Not Found"
}

func GetTransaction(txHash []byte) (string, error) {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	defer connection.Close()
	walletService := pb.NewWalletServiceClient(connection)
	transactionRequest := &pb.GetTransactionRequest{
		TransactionHash: txHash,
	}
	transactionResponse, err := walletService.GetTransaction(context.Background(), transactionRequest)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	transaction := transactionResponse.Transaction
	var amount int64
	tempCredits := make([]TransactionCredit, len(transaction.Credits))
	for index, credit := range transaction.Credits {
		if IsAddressMine(credit.Address, connection) {
			amount += credit.Amount
		}
		tempCredits[index] = TransactionCredit{
			Index:    int32(credit.Index),
			Account:  int32(credit.Account),
			Internal: credit.Internal,
			Amount:   credit.Amount,
			Address:  credit.Address}
	}
	tempDebits := make([]TransactionDebit, len(transaction.Debits))
	for index, debit := range transaction.Debits {
		tempDebits[index] = TransactionDebit{
			Index:           int32(debit.Index),
			PreviousAccount: int32(debit.PreviousAccount),
			PreviousAmount:  debit.PreviousAmount,
			AccountName:     GetAccount(int(debit.PreviousAccount), connection)}
	}
	tempTransaction := Transaction{
		Fee:       transaction.Fee,
		Hash:      fmt.Sprintf("%02x", transaction.Hash),
		Timestamp: transaction.Timestamp,
		Type:      transaction.TransactionType.String(),
		Credits:   &tempCredits,
		Amount:    amount,
		Status:    "pending",
		Debits:    &tempDebits}
	result, _ := json.Marshal(tempTransaction)
	return string(result), nil
}

func reverse(hash []byte) []byte {
	for i := 0; i < len(hash)/2; i++ {
		j := len(hash) - i - 1
		hash[i], hash[j] = hash[j], hash[i]
	}
	return hash
}

func GetTransactions(blockHeight int32, startHeight int32) string {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		result, _ := json.Marshal(getTransactionsResponse{ErrorOccurred: true})
		return string(result)
	}
	defer connection.Close()
	walletService := pb.NewWalletServiceClient(connection)
	transactionRequest := &pb.GetTransactionsRequest{
		StartingBlockHeight:    startHeight,
		EndingBlockHeight:      blockHeight,
		TargetTransactionCount: 0}
	transactionResponse, err := walletService.GetTransactions(context.Background(), transactionRequest)
	if err != nil {
		fmt.Println(err)
		result, _ := json.Marshal(getTransactionsResponse{ErrorOccurred: true})
		return string(result)
	}
	minedTransactions := make([]Transaction, 0)
	unMinedTransactions := make([]Transaction, 0)
	for {
		response, err := transactionResponse.Recv()
		if err == io.EOF {
			fmt.Println(err)
			break
		}
		if response.MinedTransactions != nil {
			blockDetails := response.GetMinedTransactions()
			transactionDetails := blockDetails.Transactions
			for _, transaction := range transactionDetails {
				var amount int64
				tempCredits := make([]TransactionCredit, len(transaction.Credits))
				for index, credit := range transaction.Credits {
					if IsAddressMine(credit.Address, connection) {
						amount += credit.Amount
					}
					tempCredits[index] = TransactionCredit{
						Index:    int32(credit.Index),
						Account:  int32(credit.Account),
						Internal: credit.Internal,
						Amount:   credit.Amount,
						Address:  credit.Address}
				}
				tempDebits := make([]TransactionDebit, len(transaction.Debits))
				for index, debit := range transaction.Debits {
					tempDebits[index] = TransactionDebit{
						Index:           int32(debit.Index),
						PreviousAccount: int32(debit.PreviousAccount),
						PreviousAmount:  debit.PreviousAmount,
						AccountName:     GetAccount(int(debit.PreviousAccount), connection)}
				}
				///fmt.Printf("Hash: %02x \n", reverse(transaction.Hash))
				tempTransaction := Transaction{
					Fee:       transaction.Fee,
					Hash:      fmt.Sprintf("%02x", transaction.Hash),
					Timestamp: transaction.Timestamp,
					Type:      transaction.TransactionType.String(),
					Credits:   &tempCredits,
					Amount:    amount,
					Status:    "confirmed",
					Debits:    &tempDebits}
				minedTransactions = append(minedTransactions, tempTransaction)
			}
		}
		if response.UnminedTransactions != nil {
			transactionDetails := response.UnminedTransactions
			for _, transaction := range transactionDetails {
				var amount int64
				tempCredits := make([]TransactionCredit, len(transaction.Credits))
				for index, credit := range transaction.Credits {
					if IsAddressMine(credit.Address, connection) {
						amount += credit.Amount
					}
					tempCredits[index] = TransactionCredit{
						Index:    int32(credit.Index),
						Account:  int32(credit.Account),
						Internal: credit.Internal,
						Amount:   credit.Amount,
						Address:  credit.Address}
				}
				tempDebits := make([]TransactionDebit, len(transaction.Debits))
				for index, debit := range transaction.Debits {
					tempDebits[index] = TransactionDebit{
						Index:           int32(debit.Index),
						PreviousAccount: int32(debit.PreviousAccount),
						PreviousAmount:  debit.PreviousAmount,
						AccountName:     GetAccount(int(debit.PreviousAccount), connection)}
				}
				tempTransaction := Transaction{
					Fee:       transaction.Fee,
					Hash:      fmt.Sprintf("%02x", transaction.Hash),
					Timestamp: transaction.Timestamp,
					Type:      transaction.TransactionType.String(),
					Credits:   &tempCredits,
					Amount:    amount,
					Status:    "pending",
					Debits:    &tempDebits}
				unMinedTransactions = append(unMinedTransactions, tempTransaction)
			}
		}
	}
	result, _ := json.Marshal(getTransactionsResponse{ErrorOccurred: false, Mined: minedTransactions, UnMined: unMinedTransactions})
	return string(result)
}

func IsAddressMine(address string, connection *grpc.ClientConn) bool {
	walletService := pb.NewWalletServiceClient(connection)
	validateResponse, err := walletService.ValidateAddress(context.Background(), &pb.ValidateAddressRequest{Address: address})
	if err != nil {
		fmt.Println(err)
		return false
	}
	return validateResponse.IsMine
}

func ConnectToDcrd(address string) bool {
	//cert, err := ioutil.ReadFile(filepath.Join(dcrutil.AppDataDir("dcrd", false), "rpc.cert"))
	cert, err := ioutil.ReadFile("/data/data/com.decrediton/files/dcrd/rpc.cert")
	//fmt.Println("CERT: ",string(cert))
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer connection.Close()
	walletLoader := pb.NewWalletLoaderServiceClient(connection)
	rpcRequest := &pb.StartConsensusRpcRequest{
		Certificate:    cert,
		Password:       []byte("dcrwallet"),
		Username:       "dcrwallet",
		NetworkAddress: address}
	_, err = walletLoader.StartConsensusRpc(context.Background(), rpcRequest)
	if err != nil {
		fmt.Println(err)
		return false
		//return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "RPC ERROR"}}`
	}
	//return `{"ErrorOccurred" : "false", "Success" : {"content": "true"}}`
	return true
}

func SubscibeToBlockNotifications() string {
	connection, err := connect()

	if err != nil {
		fmt.Println(err)
	}
	defer connection.Close()
	walletLoader := pb.NewWalletLoaderServiceClient(connection)
	_, err = walletLoader.SubscribeToBlockNotifications(context.Background(), &pb.SubscribeToBlockNotificationsRequest{})
	if err != nil {
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "SUBSCRIBE ERROR"}}`
	}
	return `{"ErrorOccurred" : "false", "Success" : {"content": "true"}}`
}

func DiscoverAddresses(privPass string) string {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
	}
	defer connection.Close()
	walletLoader := pb.NewWalletLoaderServiceClient(connection)
	discoverRequest := &pb.DiscoverAddressesRequest{
		DiscoverAccounts:  true,
		PrivatePassphrase: []byte(privPass),
	}
	_, err = walletLoader.DiscoverAddresses(context.Background(), discoverRequest)
	if err != nil {
		fmt.Println(err)
		return `{"ErrorOccurred" : "true", "Error" : {"Code": 0, "Message" : "DISCOVER ERROR"}}`
	}
	return `{"ErrorOccurred" : "false", "Success" : {"content": "true"}}`
}

func RunUtil() (string, error) {
	info, err := dcrctl.RunCommand("getpeerinfo")
	if err != nil {
		return "", err
	}
	return info, nil
}

func RunDcrCommands(string) (string, error) {
	info, err := dcrctl.RunCommand("getpeerinfo")
	if err != nil {
		return "", err
	}
	return info, nil
}

func ReScanBlocks(callback BlockScanResponse) {
	LoadActiveDataFilters()
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
	}

	defer connection.Close()
	walletService := pb.NewWalletServiceClient(connection)
	rescanRequest := &pb.RescanRequest{
		BeginHeight: 1,
	}
	rescanResponse, err := walletService.Rescan(context.Background(), rescanRequest)
	if err != nil {
		fmt.Println(err)
		return
	}
	var scanThrough int32
	for {
		response, err := rescanResponse.Recv()
		if err != nil {
			callback.OnEnd(int(scanThrough))
			return
		}
		scanThrough = response.RescannedThrough
		callback.OnScan(int(scanThrough))
	}
}

func FetchHeaders() int32 {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return -1
	}
	defer connection.Close()
	walletLoader := pb.NewWalletLoaderServiceClient(connection)
	fetchRequest := &pb.FetchHeadersRequest{}
	fetchResponse, err := walletLoader.FetchHeaders(context.Background(), fetchRequest)
	if err != nil {
		fmt.Println(err)
		return -1
	}
	return fetchResponse.MainChainTipBlockHeight
}

func LoadActiveDataFilters() {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
	}
	defer connection.Close()
	walletService := pb.NewWalletServiceClient(connection)
	loadRequest := &pb.LoadActiveDataFiltersRequest{}
	_, _ = walletService.LoadActiveDataFilters(context.Background(), loadRequest)
}

func ConstructTransaction(address string, amount int64, account int32) *ConstructTxResponse {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return &ConstructTxResponse{ErrorOccurred: true, ErrorMessage: "", ErrorCode: 0}
	}
	defer connection.Close()
	walletService := pb.NewWalletServiceClient(connection)
	outputDestination := pb.ConstructTransactionRequest_OutputDestination{
		Address: address,
	}
	//var output [1]pb.ConstructTransactionRequest_Output
	output := make([]*pb.ConstructTransactionRequest_Output, 1)
	output[0] = &pb.ConstructTransactionRequest_Output{
		Amount:      amount,
		Destination: &outputDestination,
	}
	constructRequest := &pb.ConstructTransactionRequest{
		SourceAccount:            uint32(account),
		RequiredConfirmations:    0,
		FeePerKb:                 100000,
		NonChangeOutputs:         output,
		OutputSelectionAlgorithm: pb.ConstructTransactionRequest_UNSPECIFIED,
	}
	constructResponse, err := walletService.ConstructTransaction(context.Background(), constructRequest)
	if err != nil {
		fmt.Println(err)
		return &ConstructTxResponse{ErrorOccurred: true, ErrorMessage: "", ErrorCode: 0}
	}

	return &ConstructTxResponse{ErrorOccurred: true, EstimatedSignedSize: int32(constructResponse.EstimatedSignedSize),
		TotalOutputAmount:         constructResponse.TotalOutputAmount,
		TotalPreviousOutputAmount: constructResponse.TotalPreviousOutputAmount,
		UnsignedTransaction:       constructResponse.UnsignedTransaction,
	}
}

func SignTransaction(tx []byte, passphrase string) ([]byte, error) {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer connection.Close()
	walletService := pb.NewWalletServiceClient(connection)
	signRequest := &pb.SignTransactionRequest{
		SerializedTransaction: tx,
		Passphrase:            []byte(passphrase),
	}
	signResponse, err := walletService.SignTransaction(context.Background(), signRequest)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return signResponse.Transaction, nil
}

func PublishTransaction(tx []byte) ([]byte, error) {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer connection.Close()
	walletService := pb.NewWalletServiceClient(connection)
	publishRequest := &pb.PublishTransactionRequest{
		SignedTransaction: tx,
	}
	publishResponse, err := walletService.PublishTransaction(context.Background(), publishRequest)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return publishResponse.TransactionHash, nil
}

func PublishUnminedTransactions() error {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer connection.Close()
	walletService := pb.NewWalletServiceClient(connection)
	_, err = walletService.PublishUnminedTransactions(context.Background(), &pb.PublishUnminedTransactionsRequest{})
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func DecodeRawTransaction(tx []byte) (string, error) {
	connection, err := connect()
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	defer connection.Close()
	decodeMessageService := pb.NewDecodeMessageServiceClient(connection)
	decodeRequest := &pb.DecodeRawTransactionRequest{
		SerializedTransaction: tx,
	}
	decodeResponse, err := decodeMessageService.DecodeRawTransaction(context.Background(), decodeRequest)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	decodedTx := decodeResponse.Transaction
	return string(decodedTx.TransactionHash), nil
}
