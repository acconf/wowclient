# WoWClient beta

## Overview
WoWClient is a wireguard client for windows,work with wstunnel.  
Client configuration is encrypted and treated as PEM file.  

## Process
WoWClient----->Server(WSTUNNEL--->WireGuard Server)  
WoWClient controls to startup/shutdown wstunnel automatically.  

## Dependency

### 1. wintun.dll
Download dll from [wintun.net](https://www.wintun.net/builds/wintun-0.14.1.zip).  
Using amd64\wintun.dll ,MUST TO put this dll in the same directory of wowclient.exe.  

### 2. wstunnel.exe
Download from [erebe/wstunnel](https://github.com/erebe/wstunnel/releases).  
Using wstunnel_10.4.3_windows_amd64.tar.gz  


## Configuration
### 1. config for wowclient.exe
See wow_config_sample.json  
  - name      REQUIRED. The Name for creating tunnel.
  - pem       REQUIRED. PATH-TO-SECRET-PEMFILE.Such as [D:\\pems\\wow_secret_client1.pem]
  - proxy     OPTIONAL. Such as [http://user:pass@proxy-server-ip:port]
  - wstunnel  OPTIONAL. PATH-TO-wstunnel.exe. Default path is same to the wowclient.exe.

### 2. config for wireguard and wstunnel.
See plan_wireguard_wstunnel.conf.  
MUST TO ENCRYPT the raw-plantext config file, and rename encrypted file to PEM.  


## Build
go build -o wowclient.exe -ldflags "-s -w"


## USAGE
### 1. Install windows service
 - wowclient.exe install \<ServiceName\> \<Path-To-JSON-Config-File\>
### 2. Remove windows service
 - wowclient.exe remove \<ServiceName\>
### 3. Run CLI directly.
 - wowclient.exe run \<Path-To-JSON-Config-File\>
