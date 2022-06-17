program OAuth2IMAP;

uses
  System.StartUpCopy,
  FMX.Forms,
  IMAPTest in 'IMAPTest.pas' {FormIMAPTest},
  IdSASLXOAUTH in 'IdSASLXOAUTH.pas',
  DeviceAuthFlow in 'DeviceAuthFlow.pas',
  ROPCFlow in 'ROPCFlow.pas',
  Global in 'Global.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TFormIMAPTest, FormIMAPTest);
  Application.Run;
end.
