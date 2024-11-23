# SSHClient-SFTP for Delphi 2010

## Описание

Данный проект реализует базовый функционал работы с SFTP, используя библиотеку **libssh2**. Класс разработан для использования в Delphi 2010 и выше.

## Реализованный функционал

- **Создание сессий**:
  - Подключение к серверу с использованием логина и пароля.
- **Работа с файлами и директориями**:
  - Создание директории на сервере.
  - Загрузка файлов на сервер.
  - Удаление файлов с сервера.

## Установка

1. Убедитесь, что у вас установлен **Delphi 2010**.
2. Скачайте и подключите библиотеку **libssh2.dll** в ваш проект.
3. Импортируйте класс `TSSHClient` в ваш проект.

## Пример использования

```delphi
var
  SSH: TSSHClient;
begin
  try
    // Создание клиента SFTP
    SSH := TSSHClient.Create('192.168.1.1', 'username', 'password');
    
    // Подключение к серверу
    SSH.ConnectServer;

    // Создание директории
    if SSH.CreateRemoteDirectory('/new/directory') then
      ShowMessage('Директория успешно создана');

    // Загрузка файла
    if SSH.UploadFileToServer('C:\\local\\file.txt', '/remote/file.txt') then
      ShowMessage('Файл успешно загружен');

    // Удаление файла
    SSH.DeleteFileFromServer('/remote/file.txt');
    ShowMessage('Файл успешно удалён');

  except
    on E: Exception do
      ShowMessage('Ошибка: ' + E.Message);
  end;
end;
