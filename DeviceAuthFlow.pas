unit DeviceAuthFlow;

interface

uses System.Classes, System.SysUtils, System.JSON, System.Threading, System.Net.URLClient, Winapi.ShellAPI, FMX.Types, IdHTTP;

type
  TOnAfterAuthorizeCode = reference to procedure(AuthCode: string);
  TOnAfterAuthorizeGetExpireTime = reference to procedure(ExpireTime: Integer);
  TOnErrorAccessToken = reference to procedure(Error, ErrorDescription: string);
  TOnAfterAccessToken = reference to procedure(Device_ID, Access_Token, Token_Type: string; Expires_In: Integer; Scope: string);

  TDevice_Authorization_Flow = class
  const
    DEVICECODEAUTHURL = 'https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode'; // Device Code Auth URL
    CLIENTIDSTRING = 'client_id=%s'; // Device Code Auth/Token post data -> client id
    SCOPESTRING = 'scope=%s'; // Device Code Auth post data -> scope
    DEVICECODETOKENURL = 'https://login.microsoftonline.com/%s/oauth2/v2.0/token'; // Device Code Token URL
    GRANTTYPESTRING = 'grant_type=urn:ietf:params:oauth:grant-type:device_code'; // Device Code Token post data -> grant type
    DEVICECODESTRING = 'device_code=%s'; // Device Code Token post data -> device code
  type
    TResponse = record
      ResponseCode: Integer;
      ResponseText: string;
    end;
  strict private
    FTenantID: string;
    FScope: string;
    FClientID: string;
    FDevice_Code: string;
    FVerification_URI: string;
    FExpire_In: Integer;
    FInterval: Integer;
    IdHTTP_Device_Authorization: TIdHTTP;
    FTimer_Device_Auth_Interval: TTimer;
    FOnAfterAuthorizeCode: TOnAfterAuthorizeCode;
    FOnAfterAuthorizeGetExpireTime: TOnAfterAuthorizeGetExpireTime;
    FOnAfterAccessToken: TOnAfterAccessToken;
    FOnErrorAccessToken: TOnErrorAccessToken;
    procedure OnCalExpireTimer(Sender: TObject);
    procedure OpenVerification_URI;
    procedure StartAuthLoop;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Start;
    property TenantID: string read FTenantID write FTenantID;
    property ClientID: string read FClientID write FClientID;
    property Scope: string read FScope write FScope;
    property OnAfterAuthorizeCode: TOnAfterAuthorizeCode read FOnAfterAuthorizeCode write FOnAfterAuthorizeCode;
    property OnAfterAuthorizeGetExpireTime: TOnAfterAuthorizeGetExpireTime read FOnAfterAuthorizeGetExpireTime write FOnAfterAuthorizeGetExpireTime;
    property OnAfterAccessToken: TOnAfterAccessToken read FOnAfterAccessToken write FOnAfterAccessToken;
    property OnErrorAccessToken: TOnErrorAccessToken read FOnErrorAccessToken write FOnErrorAccessToken;
  end;

implementation

{ TDevice_Authorization_Flow }
constructor TDevice_Authorization_Flow.Create;
begin
  FClientID := '';
  FTenantID := '';
  FScope := '';
  IdHTTP_Device_Authorization := TIdHTTP.Create(nil);
  IdHTTP_Device_Authorization.Request.ContentEncoding := 'UTF-8';
  IdHTTP_Device_Authorization.Request.ContentType := 'application/x-www-form-urlencoded';
  FTimer_Device_Auth_Interval := TTimer.Create(nil);
  FTimer_Device_Auth_Interval.Enabled := False;
  FTimer_Device_Auth_Interval.OnTimer := OnCalExpireTimer;
end;

destructor TDevice_Authorization_Flow.Destroy;
begin
  if Assigned(IdHTTP_Device_Authorization) then FreeAndNil(IdHTTP_Device_Authorization);
  if Assigned(FTimer_Device_Auth_Interval) then FreeAndNil(FTimer_Device_Auth_Interval);
  inherited;
end;

procedure TDevice_Authorization_Flow.OnCalExpireTimer(Sender: TObject);
begin
  if FExpire_In <> 0 then begin
    FExpire_In := FExpire_In - 1;
    if Assigned(FOnAfterAuthorizeGetExpireTime) then FOnAfterAuthorizeGetExpireTime(FExpire_In);
  end else begin
    FTimer_Device_Auth_Interval.Enabled := False;
  end;
end;

procedure TDevice_Authorization_Flow.OpenVerification_URI;
var
  FURI: TURI;
begin
  if FVerification_URI <> '' then begin
    FURI := TURI.Create(FVerification_URI);
    ShellExecute(0, 'open', PChar(FURI.ToString), nil, nil, 0);
  end;
end;

procedure TDevice_Authorization_Flow.Start;
var
  postData: TStrings;
  FResponseString: string;
  FResponseJSON: TJSONObject;
begin
  if (FClientID <> '') and
     (FTenantID <> '') and
     (FScope <> '') then begin
    try
      // Post Data
      postData := TStringList.Create;
      postData.Add(Format(CLIENTIDSTRING, [FClientID]));
      postData.Add(Format(SCOPESTRING, [FScope]));
      // Call Device Auth API
      FResponseString := IdHTTP_Device_Authorization.Post(Format(DEVICECODEAUTHURL, [FTenantID]), postData);
      // Response JSON
      FResponseJSON := TJSONObject.ParseJSONValue(FResponseString) as TJSONObject;
      FDevice_Code := FResponseJSON.GetValue('device_code').AsType<string>;
      FVerification_URI := FResponseJSON.GetValue('verification_uri').AsType<string>;
      FExpire_In := FResponseJSON.GetValue('expires_in').AsType<Integer>;
      FInterval := FResponseJSON.GetValue('interval').AsType<Integer>;
      // Callback Auth Code
      if Assigned(FOnAfterAuthorizeCode) then FOnAfterAuthorizeCode(FResponseJSON.GetValue('user_code').AsType<string>);
      // Start Cal Expire Time
      FTimer_Device_Auth_Interval.Enabled := True;
      // Open verification uri
      OpenVerification_URI;
      // Auth Loop
      StartAuthLoop;
    finally
      if Assigned(postData) then FreeAndNil(postData);
      if Assigned(FResponseJSON) then FreeAndNil(FResponseJSON);
    end;
  end else begin
    raise Exception.Create('Not set Client ID or Tenant ID or Scope');
  end;
end;

procedure TDevice_Authorization_Flow.StartAuthLoop;
var
  aTask: IFuture<TResponse>;
begin
  // Start Task
  aTask := TTask.Future<TResponse>(function: TResponse
  var
    IdHTTP_Device_Token: TIdHTTP;
    postData: TStrings;
    FErrResponseJSON: TJSONObject;
    FTID: string;
    FCID: string;
    FDCOD: string;
    FITT: Integer;
    FError: string;
  begin
    try
      Result.ResponseCode := 400;
      Result.ResponseText := '';
      FTID := FTenantID;
      FCID := FClientID;
      FDCOD := FDevice_Code;
      FITT := FInterval * 1000;
      IdHTTP_Device_Token := TIdHTTP.Create(nil);
      IdHTTP_Device_Token.Request.ContentEncoding := 'UTF-8';
      IdHTTP_Device_Token.Request.ContentType := 'application/x-www-form-urlencoded';
      // Post Data
      postData := TStringList.Create;
      postData.Add(GRANTTYPESTRING);
      postData.Add(Format(DEVICECODESTRING, [FDCOD]));
      postData.Add(Format(CLIENTIDSTRING, [FCID]));
      repeat
        Sleep(FITT);
        try
          // Call Device Auth API
          Result.ResponseText := IdHTTP_Device_Token.Post(Format(DEVICECODETOKENURL, [FTID]), postData);
          Result.ResponseCode := 200;
        except
          on E: EIdHTTPProtocolException do begin
            // Http Error
            FErrResponseJSON := TJSONObject.ParseJSONValue(E.ErrorMessage) as TJSONObject;
            FError := FErrResponseJSON.GetValue('error').AsType<string>;
            // Expired token or Authorization Declined
            if (FError = 'expired_token') or (FError = 'authorization_declined') then begin
              Result.ResponseText := E.ErrorMessage;
              break;
            end;
            if Assigned(FErrResponseJSON) then FreeAndNil(FErrResponseJSON);
          end;
        end;
      until Result.ResponseCode = 200;
    finally
      if Assigned(postData) then FreeAndNil(postData);
      if Assigned(IdHTTP_Device_Token) then FreeAndNil(IdHTTP_Device_Token);
    end;
  end);
  aTask.Start;

  // Get Task Result
  TTask.Run(procedure()
  var
    FResponseJSON: TJSONObject;
  begin
    try
      // Wait aTask For Access Token Response
      TTask.WaitForAny([aTask]);
      // Callback Access Token Response
      FTimer_Device_Auth_Interval.Enabled := False;
      FResponseJSON := TJSONObject.ParseJSONValue(aTask.Value.ResponseText) as TJSONObject;
      if aTask.Value.ResponseCode = 200 then begin
        TThread.Synchronize(nil, procedure begin if Assigned(FOnAfterAccessToken) then FOnAfterAccessToken(FDevice_Code,
                                                                                                           FResponseJSON.GetValue('access_token').AsType<string>,
                                                                                                           FResponseJSON.GetValue('token_type').AsType<string>,
                                                                                                           FResponseJSON.GetValue('expires_in').AsType<Integer>,
                                                                                                           FResponseJSON.GetValue('scope').AsType<string>) end);
      end else begin
        TThread.Synchronize(nil, procedure begin if Assigned(OnErrorAccessToken) then OnErrorAccessToken(FResponseJSON.GetValue('error').AsType<string>, FResponseJSON.GetValue('error_description').AsType<string>); end);
      end;
    finally
      if Assigned(FResponseJSON) then FreeAndNil(FResponseJSON);
    end;
  end);
end;
end.
