#include "Chan.h"
#include "User.h"

#define REQUIRESSL	1

CString notif_exec(char* cmd) {
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return "ERROR";
    char buffer[128];
    CString result;

    while(!feof(pipe)) {
        if(fgets(buffer, 128, pipe) != NULL)
                result += buffer;
    }
    pclose(pipe);
    return result;
}


CString notif_encrypt(CString &text, CString &pass)
{
        char cmd[text.length() + 500];
        snprintf(cmd,sizeof(cmd),"echo '%s' | openssl enc -aes-128-cbc -salt -base64 -A -pass pass:%s | sed \"s/=//g\" | tr \"+\" \"-\" | tr \"/\" \"_\" ",text.c_str(),pass.c_str());
        return notif_exec(cmd);
}

void notif_send(CString nick, CString channel, CString message, CString token, CString pass)
{
	CString sNick = notif_encrypt(nick,pass);
	CString sChannel = notif_encrypt(channel,pass);
	CString sMessage = notif_encrypt(message,pass);

        char cmd[message.length() + 1024];
        snprintf(cmd,sizeof(cmd),"wget --no-check-certificate -qO- /dev/null --post-data=\"apiToken=%s&message=%s&channel=%s&nick=%s&version=12\" https://irssinotifier.appspot.com/API/Message",token.c_str(),sMessage.c_str(),sChannel.c_str(),sNick.c_str());
        notif_exec(cmd);
}


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
};

template<> void TModInfo<CNotifierMod>(CModInfo& Info) {
	Info.SetWikiPage("notifier");
}

MODULEDEFS(CNotifierMod, "irssi notifier")
