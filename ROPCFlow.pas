unit ROPCFlow;

interface

uses System.Classes, System.SysUtils, System.JSON, System.Threading, System.Net.URLClient, Winapi.ShellAPI, IdHTTP, IdSSLOpenSSL;

type
  TOnErrorAccessToken = reference to procedure(Error, ErrorDescription: string);
  TOnAfterAccessToken = reference to procedure(Access_Token, Token_Type: string; Expires_In: Integer; Scope: string);

  TROPC_Flow = class
  const
    ROPCURL = 'https://login.microsoftonline.com/%s/oauth2/v2.0/token'; // ROPC Access Token URL
    CLIENTIDSTRING = 'client_id=%s'; // ROPC Access Token post data -> client id
    CLIENTSECRETSTRING = 'client_secret=%s'; // ROPC Access Token post data -> client secret
    SCOPESTRING = 'scope=%s'; // ROPC Access Token -> scope
    USERNAMESTRING = 'username=%s'; // Device Code Token post data -> username
    PAWWORDSTRING = 'password=%s'; // Device Code Token post data -> password
    GRANTTYPESTRING = 'grant_type=password'; // Device Code Token post data -> grant type
  strict private
    FTenantID: string;
    FScope: string;
    FClientID: string;
    FClientSecret: string;
    FPassword: string;
    FUsername: string;

    FVerification_URI: string;
    FExpire_In: Integer;
    FInterval: Integer;
    IdHTTP_ROPC: TIdHTTP;
    LHandler: TIdSSLIOHandlerSocketOpenSSL;
    FOnAfterAccessToken: TOnAfterAccessToken;
    FOnErrorAccessToken: TOnErrorAccessToken;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Start;
    property TenantID: string read FTenantID write FTenantID;
    property ClientID: string read FClientID write FClientID;
    property ClientSecret: string read FClientSecret write FClientSecret;
    property Scope: string read FScope write FScope;
    property Username: string read FUsername write FUsername;
    property Password: string read FPassword write FPassword;
    property OnAfterAccessToken: TOnAfterAccessToken read FOnAfterAccessToken write FOnAfterAccessToken;
    property OnErrorAccessToken: TOnErrorAccessToken read FOnErrorAccessToken write FOnErrorAccessToken;
  end;

implementation

{ TROPC_Flow }
constructor TROPC_Flow.Create;
begin
  FClientID := '';
  FClientSecret := '';
  FTenantID := '';
  FScope := '';
  FUsername := '';
  FPassword := '';
  LHandler := TIdSSLIOHandlerSocketOpenSSL.Create(nil);
  LHandler.SSLOptions.SSLVersions := [sslvTLSv1_2];
  LHandler.SSLOptions.Mode := sslmClient;
  LHandler.SSLOptions.VerifyMode := [];
  LHandler.SSLOptions.VerifyDepth := 0;

  IdHTTP_ROPC := TIdHTTP.Create(nil);
  IdHTTP_ROPC.IOHandler := LHandler;
  IdHTTP_ROPC.Request.ContentEncoding := 'UTF-8';
  IdHTTP_ROPC.Request.ContentType := 'application/x-www-form-urlencoded';
end;

destructor TROPC_Flow.Destroy;
begin
  if Assigned(LHandler) then FreeAndNil(LHandler);
  if Assigned(IdHTTP_ROPC) then FreeAndNil(IdHTTP_ROPC);
  inherited;
end;

procedure TROPC_Flow.Start;
var
  postData: TStrings;
  FResponseString: string;
  FResponseJSON: TJSONObject;
  FErrResponseJSON: TJSONObject;
begin
  if (FClientID <> '') and
     (FClientSecret <> '') and
     (FTenantID <> '') and
     (FScope <> '') and
     (FUsername <> '') and
     (FPassword <> '') then begin
    try
      try
        // Post Data
        postData := TStringList.Create;
        postData.Add(Format(CLIENTIDSTRING, [FClientID]));
        postData.Add(Format(CLIENTSECRETSTRING, [FClientSecret]));
        postData.Add(Format(SCOPESTRING, [FScope]));
        postData.Add(Format(USERNAMESTRING, [FUsername]));
        postData.Add(Format(PAWWORDSTRING, [FPassword]));
        postData.Add(GRANTTYPESTRING);
        // Call Device Auth API
        FResponseString := IdHTTP_ROPC.Post(Format(ROPCURL, [FTenantID]), postData);
        // Response JSON
        FResponseJSON := TJSONObject.ParseJSONValue(FResponseString) as TJSONObject;
        // Callback Auth Code
        if Assigned(FOnAfterAccessToken) then FOnAfterAccessToken(FResponseJSON.GetValue('access_token').AsType<string>,
                                                                  FResponseJSON.GetValue('token_type').AsType<string>,
                                                                  FResponseJSON.GetValue('expires_in').AsType<Integer>,
                                                                  FResponseJSON.GetValue('scope').AsType<string>);
      except
        on E: EIdHTTPProtocolException do begin
          // Http Error
          FErrResponseJSON := TJSONObject.ParseJSONValue(E.ErrorMessage) as TJSONObject;
          if Assigned(OnErrorAccessToken) then OnErrorAccessToken(FResponseJSON.GetValue('error').AsType<string>, FResponseJSON.GetValue('error_description').AsType<string>);
          if Assigned(FErrResponseJSON) then FreeAndNil(FErrResponseJSON);
        end;
      end;
    finally
      if Assigned(postData) then FreeAndNil(postData);
      if Assigned(FResponseJSON) then FreeAndNil(FResponseJSON);
    end;
  end else begin
    raise Exception.Create('Not set Client ID or Client Secret or Tenant ID or Scope or Username or Password');
  end;
end;
end.
