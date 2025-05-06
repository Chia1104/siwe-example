package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spruceid/siwe-go"
)

func TestWeb3Login(t *testing.T) {
	// 設置環境變數
	os.Setenv("JWT_SECRET", "test_secret")

	// 生成一個私鑰用於測試
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("無法生成私鑰: %v", err)
	}

	// 使用私鑰生成地址
	walletAddress := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

	// 直接創建一個 SIWE 消息字符串
	domain := "example.com"
	uri := "https://example.com/login"
	version := "1"
	chainId := "1"
	nonce := "1234567890"
	issuedAt := time.Now().UTC().Format(time.RFC3339)

	messageStr := fmt.Sprintf(
		"%s wants you to sign in with your Ethereum account:\n%s\n\nI accept the Terms of Service: %s\n\nURI: %s\nVersion: %s\nChain ID: %s\nNonce: %s\nIssued At: %s",
		domain,
		walletAddress,
		domain,
		uri,
		version,
		chainId,
		nonce,
		issuedAt,
	)

	// 解析消息
	_, err = siwe.ParseMessage(messageStr)
	if err != nil {
		t.Fatalf("無法解析 SIWE 消息: %v", err)
	}

	// 使用私鑰簽名消息
	messageBytes := []byte(messageStr)
	messageHash := crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(messageBytes), messageBytes)))
	signature, err := crypto.Sign(messageHash, privateKey)
	if err != nil {
		t.Fatalf("無法簽名消息: %v", err)
	}

	// 將簽名格式轉換為 EIP-191 格式
	signature[64] += 27
	signatureHex := hexutil.Encode(signature)

	// 創建請求體
	reqBody := LoginRequest{
		Message:   messageStr,
		Signature: signatureHex,
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("無法創建JSON請求體: %v", err)
	}

	// 創建一個測試請求
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/web3:login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// 創建一個 ResponseRecorder 來記錄響應
	w := httptest.NewRecorder()

	// 調用 Web3Login 函數
	err = Web3Login(w, req)

	// 檢查響應狀態
	if err != nil {
		t.Errorf("Web3Login 返回錯誤: %v", err)
	} else {
		t.Log("Web3Login 成功執行")

		// 檢查響應頭中是否存在 Cookie
		if cookies := w.Result().Cookies(); len(cookies) == 0 {
			t.Error("未在響應中找到 Cookie")
		} else {
			found := false
			for _, cookie := range cookies {
				if cookie.Name == "jwt_token" && cookie.Value != "" {
					found = true
					t.Logf("找到 jwt_token Cookie: %s", cookie.Value)
					break
				}
			}
			if !found {
				t.Error("未找到名為 jwt_token 的 Cookie 或 Cookie 值為空")
			}
		}
	}
}
