unit Global;

interface

const CRLF = #13#10;

//Setting
const
  TENANTID = '';
  CLIENTID = '';
  CLIENTSECRET = '';
  SCOPE = ''; //For Client Credentials Flow, Scope use [https://outlook.office365.com/.default]
  EMAILACCOUNT = '';
  EMAILPASSWORD = ''; // For ROPC flow
  CLIENTCREDENTIALSTOKENURL = 'https://login.microsoftonline.com/%s/oauth2/v2.0/token'; // For Client Credentials Flow, need TenantID

implementation

end.
