unit IdSASLXOAUTH;

interface

uses
  System.SysUtils,
  System.DateUtils,
  Classes,
  IdSASL
  ;

type
  TIdSASLXOAuth = class(TIdSASL)
  private
    FToken: string;
    FUser: string;
    FExpireTime: string;
    FGetTokenDateTime: TDateTime;
    procedure GetToken(const Value: string);
  public
    property Token: string read FToken write GetToken;
    property User: string read FUser write FUser;
    property ExpireTime: string read FExpireTime write FExpireTime;
    class function ServiceName: TIdSASLServiceName; override;
    constructor Create(AOwner: TComponent);
    destructor Destroy; override;
    function TryStartAuthenticate(const AHost, AProtocolName : String; var VInitialResponse: String): Boolean; override;
    function ContinueAuthenticate(const ALastResponse, AHost, AProtocolName : string): string; override;
    function StartAuthenticate(const AChallenge, AHost, AProtocolName: string): string; override;
    { For cleaning up after Authentication }
    procedure FinishAuthenticate; override;
    function IsTokenExpired: Boolean;
  end;

implementation

{ TIdSASLXOAuth }

class function TIdSASLXOAuth.ServiceName: TIdSASLServiceName;
begin
  Result := 'XOAUTH2';
end;

constructor TIdSASLXOAuth.Create(AOwner: TComponent);
begin
  inherited;
  FExpireTime := '3599';
end;

destructor TIdSASLXOAuth.Destroy;
begin
  inherited;
end;

function TIdSASLXOAuth.TryStartAuthenticate(const AHost, AProtocolName: String; var VInitialResponse: String): Boolean;
begin
  VInitialResponse := 'user=' + FUser + Chr($01) + 'auth=Bearer ' + FToken + Chr($01) + Chr($01);
  Result := True;
end;

function TIdSASLXOAuth.StartAuthenticate(const AChallenge, AHost, AProtocolName: string): string;
begin
  Result := 'user=' + FUser + Chr($01) + 'auth=Bearer ' + FToken + Chr($01) + Chr($01);
end;

function TIdSASLXOAuth.ContinueAuthenticate(const ALastResponse, AHost, AProtocolName: string): string;
begin
  // Nothing to do
end;

procedure TIdSASLXOAuth.FinishAuthenticate;
begin
  // Nothing to do
end;

procedure TIdSASLXOAuth.GetToken(const Value: string);
begin
  FToken := Value;
  FGetTokenDateTime := now;
end;

function TIdSASLXOAuth.IsTokenExpired: Boolean;
var
  FExpireDateTime: TDateTime;
begin
  FExpireDateTime := IncSecond(FGetTokenDateTime, StrToInt(FExpireTime));
  Result := FExpireDateTime <= Now
end;

end.

