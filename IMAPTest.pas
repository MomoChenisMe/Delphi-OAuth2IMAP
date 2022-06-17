unit IMAPTest;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs,
  FMX.Controls.Presentation, FMX.StdCtrls,
  sgcBase_Classes, sgcHTTP_Classes, sgcHTTP_OAuth2_Client,
  sgcHTTP,
  FMX.ScrollBox, FMX.Memo,
  IdTCPClient, IdExplicitTLSClientServerBase, IdMessageClient, IdIMAP4,
  IdBaseComponent, IdComponent, IdIOHandler, IdIOHandlerSocket, IdSASLCollection,
  IdIOHandlerStack, IdSSL, IdSSLOpenSSL, sgcHTTP_OAuth_Client,
  IdTCPConnection,
  IdSASLXOAUTH,
  DeviceAuthFlow,
  ROPCFlow,
  Global;

type
  TFormIMAPTest = class(TForm)
    OAuth2_Authorization_Code: TsgcHTTP_OAuth2_Client;
    btn_Authorization_Code_Flow: TButton;
    Memo1: TMemo;
    btn_Test_outlook_IMAP: TButton;
    IdSSLIOHandlerSocketOpenSSL1: TIdSSLIOHandlerSocketOpenSSL;
    IdIMAP4: TIdIMAP4;
    btn_Device_Auth_Flow: TButton;
    Button1: TButton;
    procedure btn_Authorization_Code_FlowClick(Sender: TObject);
    procedure OAuth2_Authorization_CodeAfterAuthorizeCode(Sender: TObject;
      const Code, State, Scope, RawParams: string; var Handled: Boolean);
    procedure OAuth2_Authorization_CodeAfterAccessToken(Sender: TObject;
      const Access_Token, Token_Type, Expires_In, Refresh_Token, Scope,
      RawParams: string; var Handled: Boolean);
    procedure FormCreate(Sender: TObject);
    procedure btn_Test_outlook_IMAPClick(Sender: TObject);
    procedure btn_Device_Auth_FlowClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure Button1Click(Sender: TObject);
  private
    { Private declarations }
    xOAuthSASL: TIdSASLListEntry;
    FDevice_Authorization_Flow: TDevice_Authorization_Flow;
    FROPC_Flow: TROPC_Flow;
    procedure DoLog(logText: string);
  public
    { Public declarations }
  end;

var
  FormIMAPTest: TFormIMAPTest;

implementation

{$R *.fmx}

procedure TFormIMAPTest.btn_Authorization_Code_FlowClick(Sender: TObject);
begin
  DoLog('Start Authorization Code Flow');
  OAuth2_Authorization_Code.Start;
end;

procedure TFormIMAPTest.btn_Device_Auth_FlowClick(Sender: TObject);
begin
  DoLog('Start Device Authorization Flow');
  FDevice_Authorization_Flow.Start;
end;

procedure TFormIMAPTest.btn_Test_outlook_IMAPClick(Sender: TObject);
begin
  try
    try
      if TIdSASLXOAuth(xOAuthSASL.SASL).Token <> '' then begin
        if not TIdSASLXOAuth(xOAuthSASL.SASL).IsTokenExpired then begin
          DoLog('Start Connect Outlook');
          IdIMAP4.Connect;
          DoLog('Connected Outlook');
          IdIMAP4.SelectMailBox('INBOX');
          DoLog('Your Outlook TotalMsgs: ' + IdIMAP4.MailBox.TotalMsgs.ToString);
          IdIMAP4.Disconnect;
          DoLog('Disconnected Outlook');
        end else begin
          DoLog('Access Token is expired!!');
        end;
      end else begin
        DoLog('Access Token is empty!!');
      end;
    except
      on E: Exception do begin
        DoLog('IMAP Exception: ' + E.ToString);
      end;
    end;
  finally
    if TIdSASLXOAuth(xOAuthSASL.SASL).IsTokenExpired then TIdSASLXOAuth(xOAuthSASL.SASL).Token := '';
  end;
end;

procedure TFormIMAPTest.Button1Click(Sender: TObject);
begin
  DoLog('Start ROPC Flow');
  FROPC_Flow.Start;
end;

procedure TFormIMAPTest.DoLog(logText: string);
begin
  Memo1.Lines.Add(logText);
end;

procedure TFormIMAPTest.FormCreate(Sender: TObject);
begin
  xOAuthSASL := IdIMAP4.SASLMechanisms.Add;
  xOAuthSASL.SASL := TIdSASLXOAuth.Create(Self);
  // Authorization Code Flow
  OAuth2_Authorization_Code.AuthorizationServerOptions.Scope.Add(SCOPE);
  OAuth2_Authorization_Code.OAuth2Options.ClientId := CLIENTID;

  //Device Authorization Flow
  FDevice_Authorization_Flow := TDevice_Authorization_Flow.Create;
  FDevice_Authorization_Flow.TenantID := TENANTID;
  FDevice_Authorization_Flow.ClientID := CLIENTID;
  FDevice_Authorization_Flow.Scope := SCOPE;
  FDevice_Authorization_Flow.OnAfterAuthorizeCode := procedure(AuthCode: string)
  begin
    btn_Device_Auth_Flow.Enabled := False;
    DoLog('Your Auth Code: ' + AuthCode);
  end;
  FDevice_Authorization_Flow.OnAfterAuthorizeGetExpireTime := procedure(ExpireTime: Integer)
  begin
    btn_Device_Auth_Flow.Text := 'Use Device Authorization Flow - ' + IntToStr(ExpireTime) + 's';
  end;
  FDevice_Authorization_Flow.OnAfterAccessToken := procedure(Device_ID, Access_Token, Token_Type: string; Expires_In: Integer; Scope: string)
  begin
    btn_Device_Auth_Flow.Enabled := True;
    btn_Device_Auth_Flow.Text := 'Use Device Authorization Flow';
    DoLog('Device_ID: ' + Device_ID + CRLF +
          'AccessToken: ' + Access_Token + CRLF +
          'Token_Type: ' + Token_Type + CRLF +
          'Expires_In: ' + IntToStr(Expires_In) + CRLF +
          'Scope: ' + Scope);
    TIdSASLXOAuth(xOAuthSASL.SASL).Token := Access_Token;
    TIdSASLXOAuth(xOAuthSASL.SASL).ExpireTime := IntToStr(Expires_In);
    TIdSASLXOAuth(xOAuthSASL.SASL).User := EMAILACCOUNT; // outlook email account
  end;
  FDevice_Authorization_Flow.OnErrorAccessToken := procedure(Error, ErrorDescription: string)
  begin
    btn_Device_Auth_Flow.Text := 'Use Device Authorization Flow';
    DoLog('Error: ' + Error + CRLF +
          'Error_Description: ' + ErrorDescription);
    btn_Device_Auth_Flow.Enabled := True;
  end;

  //ROPC Flow
  FROPC_Flow := TROPC_Flow.Create;
  FROPC_Flow.TenantID := TENANTID;
  FROPC_Flow.ClientID := CLIENTID;
  FROPC_Flow.ClientSecret := CLIENTSECRET;
  FROPC_Flow.Scope := SCOPE;
  FROPC_Flow.Username := EMAILACCOUNT;
  FROPC_Flow.Password := EMAILPASSWORD;
  FROPC_Flow.OnAfterAccessToken := procedure(Access_Token, Token_Type: string; Expires_In: Integer; Scope: string)
  begin
    DoLog('AccessToken: ' + Access_Token + CRLF +
          'Token_Type: ' + Token_Type + CRLF +
          'Expires_In: ' + IntToStr(Expires_In) + CRLF +
          'Scope: ' + Scope);
    TIdSASLXOAuth(xOAuthSASL.SASL).Token := Access_Token;
    TIdSASLXOAuth(xOAuthSASL.SASL).ExpireTime := IntToStr(Expires_In);
    TIdSASLXOAuth(xOAuthSASL.SASL).User := EMAILACCOUNT; // outlook email account
  end;
  FROPC_Flow.OnErrorAccessToken := procedure(Error, ErrorDescription: string)
  begin
    DoLog('Error: ' + Error + CRLF +
          'Error_Description: ' + ErrorDescription);
  end;
end;

procedure TFormIMAPTest.FormDestroy(Sender: TObject);
begin
  if Assigned(FDevice_Authorization_Flow) then FreeAndNil(FDevice_Authorization_Flow);
  if Assigned(FROPC_Flow) then FreeAndNil(FROPC_Flow);
end;

procedure TFormIMAPTest.OAuth2_Authorization_CodeAfterAccessToken(Sender: TObject;
  const Access_Token, Token_Type, Expires_In, Refresh_Token, Scope,
  RawParams: string; var Handled: Boolean);
begin
  DoLog('AccessToken: ' + Access_Token + CRLF +
        'Token_Type: ' + Token_Type + CRLF +
        'Expires_In: ' + Expires_In + CRLF +
        'Refresh_Token: ' + Refresh_Token + CRLF +
        'Scope: ' + Scope);
  TIdSASLXOAuth(xOAuthSASL.SASL).Token := Access_Token;
  TIdSASLXOAuth(xOAuthSASL.SASL).ExpireTime := Expires_In;
  TIdSASLXOAuth(xOAuthSASL.SASL).User := ''; // outlook email account
end;

procedure TFormIMAPTest.OAuth2_Authorization_CodeAfterAuthorizeCode(Sender: TObject;
  const Code, State, Scope, RawParams: string; var Handled: Boolean);
begin
  DoLog('Code: ' + Code + CRLF +
        'State: ' + State + CRLF +
        'Scope: ' + Scope);
end;

end.
