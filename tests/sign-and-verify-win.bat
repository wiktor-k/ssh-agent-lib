rem del /F /Q Cargo.toml.sig id_rsa id_rsa.pub agent.pub

cmd /c "START /b cargo run --example key_storage"

@echo off
:waitloop
IF EXIST "server-started" GOTO waitloopend
rem timeout doesn't work in github actions so introduce delay some other way
rem see https://stackoverflow.com/a/75054929
ping localhost >nul
goto waitloop
:waitloopend
@echo on

ssh-keygen -t rsa -f id_rsa -N ""
set SSH_AUTH_SOCK=\\.\pipe\agent
ssh-add id_rsa
ssh-add -L | tee agent.pub

ssh-keygen -Y sign -f agent.pub -n file < Cargo.toml > Cargo.toml.sig
if %errorlevel% neq 0 exit /b %errorlevel%

ssh-keygen -Y check-novalidate -n file -f agent.pub -s Cargo.toml.sig < Cargo.toml
if %errorlevel% neq 0 exit /b %errorlevel%

rem del /F /Q Cargo.toml.sig id_rsa id_rsa.pub agent.pub
