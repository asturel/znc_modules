#define REQUIRESSL	1

#include "Chan.h"
#include "User.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>

#ifndef wget
#include <curl/curl.h>
#endif

static const char magic[] = "Salted__";
	
class CNotifierMod : public CModule {


public:
	
	MODCONSTRUCTOR(CNotifierMod) { 	}
	virtual ~CNotifierMod() {}


	virtual EModRet OnPrivMsg(CNick& Nick, CString& sMessage) {
		FilterIncoming(/*Nick.GetNick()*/ "!PRIVATE", Nick, sMessage);
		return CONTINUE;
	}

	virtual EModRet OnChanMsg(CNick& Nick, CChan& Channel, CString& sMessage) {
		if (sMessage.find(m_pUser->GetNick()) != CString::npos ) FilterIncoming(Channel.GetName(), Nick, sMessage);
		return CONTINUE;
	}

	void FilterIncoming(const CString& sTarget, CNick& Nick, CString& sMessage) {
		if ((m_pUser->IsIRCAway() || !m_pUser->IsUserAttached()) && !GetNV("token").empty() && !GetNV("password").empty()) {
			notif_send(Nick.GetNick(),sTarget,sMessage,GetNV("token"),GetNV("password"));
		}
	}

	virtual void OnModCommand(const CString& sCommand) {
		CString sCmd = sCommand.Token(0);
		
		if (sCmd.Equals("settoken")) {
			CString sToken = sCommand.Token(1,true);
			if (!sToken.empty()) {
				if (SetNV("token",sToken)) {
					PutModule("Token [" + sToken + "] setted");
				} else {
					PutModule("Token set error (?)");
				}
				
			} else {
				//PutModule("Usage SetToken <token>");
				if (DelNV("token")) PutModule("Token deleted.");
			}
		} else if (sCmd.Equals("setpassword")) {
			CString sPassw = sCommand.Token(1,true);
			if (!sPassw.empty()) {
				if (SetNV("password",sPassw)) {
					PutModule("Password setted");
				} else {
					PutModule("Password set error (?)");
				}

			} else {
				//PutModule("Usage SetPassword <password>");
				if (DelNV("password")) PutModule("Passwored deleted.");
			}
		} else if (sCmd.Equals("show")) {

			PutModule("Token: [" + GetNV("token") + "]");
			PutModule("Password: [" + GetNV("password") + "]");

		} else if (sCmd.Equals("HELP")) {
			PutModule("Try: Show, SetToken, SetPassword");

		} else {
			PutModule("Unknown command, try 'Help'");
		}
	}
	
private:
	unsigned char salt[PKCS5_SALT_LEN];
	
	int aes_init(const unsigned char *key_data, int key_data_len, unsigned char *ssalt, EVP_CIPHER_CTX *e_ctx)
	{
		unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
		if (EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), ssalt, key_data, key_data_len, 1, key, iv) != 16) {
			return -1;
		}
		
		EVP_CIPHER_CTX_init(e_ctx);
		EVP_EncryptInit_ex(e_ctx, EVP_aes_128_cbc(), NULL, key, iv);
		return 0;
	}
	
	unsigned char *aes_encrypt(EVP_CIPHER_CTX *e,  const unsigned char* plaintext, int *len)
	{
		int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
		unsigned char *ciphertext = (unsigned char*) malloc(c_len);

		EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);
		EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);
		EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

		*len = c_len + f_len;
		return ciphertext;
	}

	char *base64(const unsigned char *input, int length)
	{
		BIO *bmem, *b64;
		BUF_MEM *bptr;

		b64 = BIO_new(BIO_f_base64());
		BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);

		bmem = BIO_new(BIO_s_mem());
		b64 = BIO_push(b64, bmem);
		BIO_write(b64, magic, sizeof(magic)-1);
		BIO_write(b64, (char*)salt, sizeof(salt));

		BIO_write(b64, input, length);
		BIO_flush(b64);
		BIO_get_mem_ptr(b64, &bptr);

		char *buff = (char *)malloc(bptr->length);
//		memcpy(buff, bptr->data, bptr->length-1);

		int chars = 0;
		for (unsigned int i = 0; i < bptr->length-1; i++) {
			if (bptr->data[i] == '+') { buff[chars] = '-'; chars++;}
			else if (bptr->data[i] == '/') { buff[chars] = '_'; chars++; }
			else if (bptr->data[i] != '=') { buff[chars] = bptr->data[i]; chars++; }
		}

		buff[chars] = 0;
		
		BIO_free_all(b64);


		return buff;
	}

	void notif_send(CString nick, CString channel, CString message, CString token, CString pass)
	{
		EVP_CIPHER_CTX en;
//        unsigned char salt[PKCS5_SALT_LEN];


		RAND_pseudo_bytes(salt, sizeof salt);
		
		if (aes_init( (unsigned char*)pass.c_str(), pass.length(), (unsigned char*)&salt, &en)) return;

		
		int nicklen = nick.length()+1;
		unsigned char* sNick = aes_encrypt(&en, (unsigned char*)nick.c_str(), &nicklen );
		
		int chanlen = channel.length()+1;
		unsigned char* sChannel = aes_encrypt(&en, (unsigned char*)channel.c_str(), &chanlen);
		
		int msgclen = message.length()+1;
		unsigned char* sMessage = aes_encrypt(&en, (unsigned char*)message.c_str(), &msgclen);

		#ifdef wget
		char cmd[message.length() + 1024];
		snprintf(cmd,sizeof(cmd),"wget --no-check-certificate -qO- /dev/null --post-data=\"apiToken=%s&message=%s&channel=%s&nick=%s&version=12\" https://irssinotifier.appspot.com/API/Message",token.c_str(),base64(sMessage,msgclen),base64(sChannel,chanlen),base64(sNick,nicklen));
		notif_exec(cmd);
		#else
		CURL *curl;
		CURLcode res;
		curl_global_init(CURL_GLOBAL_DEFAULT);
		curl = curl_easy_init();
		if (curl) {
			char cmd[message.length() + 1024];
			snprintf(cmd,sizeof(cmd),"apiToken=%s&message=%s&channel=%s&nick=%s&version=12",token.c_str(),base64(sMessage,msgclen),base64(sChannel,chanlen),base64(sNick,nicklen));

			curl_easy_setopt(curl, CURLOPT_URL, "https://irssinotifier.appspot.com/API/Message");
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cmd);

			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
			res = curl_easy_perform(curl);
			/* Check for errors */ 
			if(res != CURLE_OK) //PutModule("curl_easy_perform() failed: " + curl_easy_strerror(res));
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
			curl_easy_strerror(res));
			

			/* always cleanup */ 
			curl_easy_cleanup(curl);
		}

		curl_global_cleanup();		
		#endif

	}

};

template<> void TModInfo<CNotifierMod>(CModInfo& Info) {
	Info.SetWikiPage("notifier");
}

MODULEDEFS(CNotifierMod, "irssi notifier")
