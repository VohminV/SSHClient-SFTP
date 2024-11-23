unit SSHClient;

interface

uses
  SysUtils, Windows, Classes, WinSock;

const
  LIBSSH2_CALLBACK_IGNORE = 0;
  LIBSSH2_CALLBACK_DEBUG = 1;
  LIBSSH2_CALLBACK_DISCONNECT = 2;
  LIBSSH2_CALLBACK_MACERROR = 3;
  LIBSSH2_CALLBACK_X11 = 4;

  LIBSSH2_METHOD_KEX = 0;
  LIBSSH2_METHOD_HOSTKEY = 1;
  LIBSSH2_METHOD_CRYPT_CS = 2;
  LIBSSH2_METHOD_CRYPT_SC = 3;
  LIBSSH2_METHOD_MAC_CS = 4;
  LIBSSH2_METHOD_MAC_SC = 5;
  LIBSSH2_METHOD_COMP_CS = 6;
  LIBSSH2_METHOD_COMP_SC = 7;
  LIBSSH2_METHOD_LANG_CS = 8;
  LIBSSH2_METHOD_LANG_SC = 9;
  LIBSSH2_ERROR_SFTP_PROTOCOL = -31;
  LIBSSH2_FXF_WRITE = $00000002;
  LIBSSH2_FXF_CREAT = $00000008;
  LIBSSH2_FXF_READ = $00000001;
  LIBSSH2_FXF_APPEND = $00000004;
  LIBSSH2_FXF_TRUNC = $00000010;
  LIBSSH2_FXF_EXCL = $00000020;

type
  LIBSSH2_PASSWD_CHANGEREQ_FUNC = procedure
    (session: Pointer; message: PAnsiChar; const len: Integer); cdecl;

  TSSHClient = class
    private
      FSession: Pointer;
      FSocket: TSocket;
      FHost: string;
      FUsername: string;
      FPassword: string;
      FPort: Integer;
      FLibSSH2: THandle;

      procedure LoadLibSSH2;
      procedure CheckError(ResultCode: Integer; const ErrorMessage: string);
      function CreateSocket: TSocket;
    public
      constructor Create(const Host, Username, Password: string;
        const Port: Integer = 22);
      destructor Destroy; override;
      function ConnectServer: Boolean;
      function Disconnect: Boolean;
      function CreateRemoteDirectory(const DirectoryPath: string): Boolean;
      function UploadFileToServer(const LocalFileName, RemoteFileName: string)
        : Boolean;
      procedure DownloadFileFromServer(const RemoteFileName,
        LocalFileName: string);
      procedure DeleteFileFromServer(const RemoteFileName: string);
  end;

implementation

type
  libssh2_init_func = function(flags: Integer): Integer; cdecl;
  libssh2_exit_func = procedure; cdecl;
  libssh2_session_init_ex_func = function(v1, v2, v3, v4: Pointer): Pointer;
    cdecl;
  libssh2_session_free_func = procedure(session: Pointer); cdecl;
  libssh2_session_handshake_func = function(session: Pointer; sock: TSocket)
    : Integer; cdecl;
  libssh2_userauth_password_ex_func = function(session: Pointer;
    Username: PAnsiChar; username_len: Integer; Password: PAnsiChar;
    password_len: Integer; passwd_change_cb: LIBSSH2_PASSWD_CHANGEREQ_FUNC)
    : Integer; cdecl;
  libssh2_session_method_pref_func = function(session: Pointer;
    method_type: Integer; const prefs: PAnsiChar): Integer; cdecl;
  libssh2_sftp_init_func = function(session: Pointer): Pointer; cdecl;
  libssh2_sftp_shutdown_func = function(sftp: Pointer): Integer; cdecl;
  libssh2_sftp_mkdir_ex_func = function(sftp: Pointer; const path: PAnsiChar;
    path_len: UInt; mode: LongInt): Integer; cdecl;

  libssh2_sftp_open_ex_func = function(sftp: Pointer;
    const filename: PAnsiChar; filename_len: UInt; flags: ULong; mode: LongInt;
    open_type: Integer): Pointer; cdecl;
  libssh2_sftp_write_func = function(handle: Pointer; const buffer: PAnsiChar;
    count: NativeInt): NativeInt; cdecl;
  libssh2_sftp_close_handle_func = function(handle: Pointer): Integer; cdecl;
  libssh2_sftp_read_func = function(handle: Pointer; buffer: PAnsiChar;
    buffer_maxlen: NativeInt): NativeInt; cdecl;
  libssh2_sftp_unlink_ex_func = function(sftp: Pointer;
                                         const filename: PAnsiChar;
                                         filename_len: UInt): Integer; cdecl;
var
  libssh2_init: libssh2_init_func;
  libssh2_exit: libssh2_exit_func;
  libssh2_session_init_ex: libssh2_session_init_ex_func;
  libssh2_session_free: libssh2_session_free_func;
  libssh2_session_handshake: libssh2_session_handshake_func;
  libssh2_userauth_password_ex: libssh2_userauth_password_ex_func;
  libssh2_session_method_pref: libssh2_session_method_pref_func;
  libssh2_sftp_init: libssh2_sftp_init_func;
  libssh2_sftp_shutdown: libssh2_sftp_shutdown_func;
  libssh2_sftp_mkdir_ex: libssh2_sftp_mkdir_ex_func;

  libssh2_sftp_open_ex: libssh2_sftp_open_ex_func;
  libssh2_sftp_write: libssh2_sftp_write_func;
  libssh2_sftp_close_handle: libssh2_sftp_close_handle_func;
  libssh2_sftp_read: libssh2_sftp_read_func;
  libssh2_sftp_unlink_ex: libssh2_sftp_unlink_ex_func;
constructor TSSHClient.Create(const Host, Username, Password: string;
  const Port: Integer = 22);
begin
  FHost := Host;
  FUsername := Username;
  FPassword := Password;
  FPort := Port;
  FLibSSH2 := 0;
  FSession := nil;
  FSocket := INVALID_SOCKET;
  LoadLibSSH2;
end;

destructor TSSHClient.Destroy;
begin
  if FSession <> nil then
    libssh2_session_free(FSession);
  if FSocket <> INVALID_SOCKET then
    closesocket(FSocket);
  if FLibSSH2 <> 0 then
    FreeLibrary(FLibSSH2);
  inherited;
end;

procedure TSSHClient.LoadLibSSH2;
begin
  FLibSSH2 := LoadLibrary('libssh2.dll');
  if FLibSSH2 = 0 then
    raise Exception.Create('Unable to load libssh2.dll');

  @libssh2_init := GetProcAddress(FLibSSH2, 'libssh2_init');
  @libssh2_exit := GetProcAddress(FLibSSH2, 'libssh2_exit');
  @libssh2_session_init_ex := GetProcAddress
    (FLibSSH2, 'libssh2_session_init_ex');
  @libssh2_session_free := GetProcAddress(FLibSSH2, 'libssh2_session_free');
  @libssh2_session_handshake := GetProcAddress(FLibSSH2,
    'libssh2_session_handshake');
  @libssh2_userauth_password_ex := GetProcAddress(FLibSSH2,
    'libssh2_userauth_password_ex');
  @libssh2_session_method_pref := GetProcAddress(FLibSSH2,
    'libssh2_session_method_pref');

  @libssh2_sftp_init := GetProcAddress(FLibSSH2, 'libssh2_sftp_init');
  @libssh2_sftp_shutdown := GetProcAddress(FLibSSH2, 'libssh2_sftp_shutdown');
  @libssh2_sftp_mkdir_ex := GetProcAddress(FLibSSH2, 'libssh2_sftp_mkdir_ex');

  @libssh2_sftp_open_ex := GetProcAddress(FLibSSH2, 'libssh2_sftp_open_ex');
  @libssh2_sftp_write := GetProcAddress(FLibSSH2, 'libssh2_sftp_write');
  @libssh2_sftp_close_handle := GetProcAddress(FLibSSH2,
    'libssh2_sftp_close_handle');
  @libssh2_sftp_read := GetProcAddress(FLibSSH2, 'libssh2_sftp_read');
  @libssh2_sftp_unlink_ex := GetProcAddress(FLibSSH2, 'libssh2_sftp_unlink_ex');
  if not Assigned(libssh2_userauth_password_ex) then
    raise Exception.Create('libssh2_userauth_password_ex function not found');
end;

procedure TSSHClient.CheckError(ResultCode: Integer;
  const ErrorMessage: string);
begin
  if ResultCode < 0 then
    raise Exception.CreateFmt('%s. Error code: %d', [ErrorMessage, ResultCode]);
end;

procedure TSSHClient.DeleteFileFromServer(const RemoteFileName: string);
var
  SFTPHandle: Pointer;
  ResultCode: Integer;
begin
  // Инициализируем SFTP-сессию
  SFTPHandle := libssh2_sftp_init(FSession);
  if SFTPHandle = nil then
    raise Exception.Create('Ошибка инициализации SFTP сессии');

  try
    // Удаляем файл
    ResultCode := libssh2_sftp_unlink_ex
      (SFTPHandle, PAnsiChar(AnsiString(RemoteFileName)), Length(RemoteFileName)
      );
    if ResultCode <> 0 then
      raise Exception.CreateFmt('Ошибка удаления файла %s (код: %d)',
        [RemoteFileName, ResultCode]);
  finally
    // Завершаем SFTP-сессию
    libssh2_sftp_shutdown(SFTPHandle);
  end;
end;

function TSSHClient.UploadFileToServer(const LocalFileName,
  RemoteFileName: string): Boolean;
var
  FileStream: TFileStream;
  SFTPHandle: Pointer;
  RemoteFile: Pointer;
  buffer: array [0 .. 1023] of Byte;
  BytesRead: Integer;
  ResultCode: Integer;
begin
  Result := False;

  // Открываем локальный файл для чтения
  FileStream := TFileStream.Create(LocalFileName, fmOpenRead);
  try
    // Открываем SFTP-сессию
    SFTPHandle := libssh2_sftp_init(FSession);
    if SFTPHandle = nil then
      raise Exception.Create('Failed to initialize SFTP session');

    // Открываем удаленный файл для записи
    RemoteFile := libssh2_sftp_open_ex
      (SFTPHandle, PAnsiChar(AnsiString(RemoteFileName)), Length(RemoteFileName)
        , LIBSSH2_FXF_WRITE or LIBSSH2_FXF_CREAT, $1A4, 0);
    if RemoteFile = nil then
      raise Exception.Create('Failed to open remote file for writing');

    // Чтение файла и запись в удаленный файл
    while FileStream.Position < FileStream.Size do
      begin
        BytesRead := FileStream.Read(buffer, SizeOf(buffer));
        if BytesRead > 0 then
          begin
            ResultCode := libssh2_sftp_write(RemoteFile, @buffer, BytesRead);
            if ResultCode < 0 then
              raise Exception.Create('Failed to write to remote file');
          end;
      end;

    // Закрытие удаленного файла
    if RemoteFile <> nil then
      begin
        libssh2_sftp_close_handle(RemoteFile); // Закрываем удаленный файл
        RemoteFile := nil; // Обнуляем указатель после закрытия
      end;

    Result := True;
  finally
    FileStream.Free;
  end;
end;

procedure TSSHClient.DownloadFileFromServer
  (const RemoteFileName, LocalFileName: string);
var
  FileStream: TFileStream;
  SFTPHandle: Pointer;
  RemoteFile: Pointer;
  buffer: array [0 .. 1023] of Byte;
  BytesRead: Integer;
  ResultCode: Integer;
begin
  // Открываем локальный файл для записи
  FileStream := TFileStream.Create(LocalFileName, fmCreate);
  try
    // Открываем SFTP-сессию
    SFTPHandle := libssh2_sftp_init(FSession);
    if SFTPHandle = nil then
      raise Exception.Create('Failed to initialize SFTP session');

    // Открываем удаленный файл для чтения
    RemoteFile := libssh2_sftp_open_ex
      (SFTPHandle, PAnsiChar(AnsiString(RemoteFileName)), Length(RemoteFileName)
        , LIBSSH2_FXF_READ, 0, 0);
    if RemoteFile = nil then
      raise Exception.Create('Failed to open remote file for reading');

    // Чтение удаленного файла и запись в локальный файл
    while True do
      begin
        ResultCode := libssh2_sftp_read(RemoteFile, @buffer, SizeOf(buffer));
        if ResultCode < 0 then
          raise Exception.Create('Failed to read from remote file');
        if ResultCode = 0 then
          Break; // Конец файла

        // Запись данных в локальный файл
        FileStream.WriteBuffer(buffer, ResultCode);
      end;

    // Закрытие удаленного файла
    libssh2_sftp_close_handle(RemoteFile);
  finally
    FileStream.Free;
  end;
end;

function TSSHClient.CreateRemoteDirectory(const DirectoryPath: string): Boolean;
var
  SFTPSession: Pointer;
  DirectoryPathAnsi: AnsiString;
  ResultCode: Integer;
begin
  Result := False;

  // Инициализация SFTP-сессии
  SFTPSession := libssh2_sftp_init(FSession);
  if SFTPSession = nil then
    raise Exception.Create('Failed to initialize SFTP session');

  try
    // Преобразование пути в AnsiString
    DirectoryPathAnsi := AnsiString(DirectoryPath);

    // Попытка создать директорию
    ResultCode := libssh2_sftp_mkdir_ex
      (SFTPSession, PAnsiChar(DirectoryPathAnsi), Length(DirectoryPathAnsi),
      $1FF);
    if ResultCode = 0 then
      begin
        // Успех
        Result := True;
      end
    else if ResultCode = LIBSSH2_ERROR_SFTP_PROTOCOL then
      begin
        // Директория, возможно, уже существует
        // Log('Directory might already exist: ' + DirectoryPath);
        Result := True;
      end
    else
      begin
        CheckError(ResultCode, 'Failed to create directory: ' + DirectoryPath);
      end;
  finally
    // Завершение SFTP-сессии
    libssh2_sftp_shutdown(SFTPSession);
  end;
end;

function TSSHClient.CreateSocket: TSocket;
var
  Addr: TSockAddrIn;
  HostEnt: PHostEnt;
begin
  Result := INVALID_SOCKET;

  HostEnt := gethostbyname(PAnsiChar(AnsiString(FHost)));
  if HostEnt = nil then
    raise Exception.Create('Failed to resolve host');

  Result := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if Result = INVALID_SOCKET then
    raise Exception.Create('Failed to create socket');

  Addr.sin_family := AF_INET;
  Addr.sin_port := htons(FPort);
  Addr.sin_addr.S_addr := PInAddr(HostEnt^.h_addr_list^)^.S_addr;

  if connect(Result, Addr, SizeOf(Addr)) <> 0 then
    begin
      closesocket(Result);
      raise Exception.Create('Failed to connect to remote host');
    end;
end;

function TSSHClient.ConnectServer: Boolean;
var
  ResultCode: Integer;
  Username, Password: AnsiString;
  ChangePasswdCallback: LIBSSH2_PASSWD_CHANGEREQ_FUNC;
begin
  Result := False;

  // Initialize libssh2
  ResultCode := libssh2_init(0);
  CheckError(ResultCode, 'libssh2 initialization failed');

  // Create the SSH session
  FSession := libssh2_session_init_ex(nil, nil, nil, nil);
  if FSession = nil then
    raise Exception.Create('libssh2 session initialization failed');

  // Create and connect the socket
  FSocket := CreateSocket;

  // Set preferred host key algorithm
  ResultCode := libssh2_session_method_pref(FSession, LIBSSH2_METHOD_HOSTKEY,
    PAnsiChar(AnsiString('ssh-rsa,ssh-dss')));
  CheckError(ResultCode, 'Failed to set preferred host key method');

  // Perform the handshake
  ResultCode := libssh2_session_handshake(FSession, FSocket);
  CheckError(ResultCode, 'SSH handshake failed');

  // Ensure the session is valid before proceeding
  if FSession = nil then
    raise Exception.Create('Session is invalid before authentication');

  // Ensure username and password are not empty
  Username := AnsiString(FUsername);
  Password := AnsiString(FPassword);

  if (Username = '') or (Password = '') then
    raise Exception.Create('Username or password is empty');

  // Set up the password change callback (pass nil for no change)
  ChangePasswdCallback := nil;

  // Authenticate using username and password with length arguments
  ResultCode := libssh2_userauth_password_ex
    (FSession, PAnsiChar(Username), Length(Username), PAnsiChar(Password),
    Length(Password), ChangePasswdCallback);
  CheckError(ResultCode, 'Authentication failed');

  Result := True;
end;

function TSSHClient.Disconnect: Boolean;
begin
  if FSession <> nil then
    begin
      libssh2_session_free(FSession);
      FSession := nil;
    end;

  if FSocket <> INVALID_SOCKET then
    begin
      closesocket(FSocket);
      FSocket := INVALID_SOCKET;
    end;

  Result := True;
end;

end.
