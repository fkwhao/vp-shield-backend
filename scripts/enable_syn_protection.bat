@echo off
echo ========================================
echo TCP SYN Flood 防护配置
echo 需要管理员权限运行
echo ========================================

echo.
echo [1] 启用 SYN 攻击保护
netsh int tcp set global synattackprotection=enabled

echo.
echo [2] 配置注册表参数...

:: 设置 SYN 攻击检测阈值
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v SynAttackProtect /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxHalfOpen /t REG_DWORD /d 500 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxHalfOpenRetried /t REG_DWORD /d 400 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxPortsExhausted /t REG_DWORD /d 5 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxConnectResponseRetransmissions /t REG_DWORD /d 2 /f

:: 减少连接超时时间
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpTimedWaitDelay /t REG_DWORD /d 30 /f

echo.
echo [3] 当前配置:
netsh int tcp show global

echo.
echo ========================================
echo 配置完成！
echo SynAttackProtect=2 表示已启用最高级别保护
echo ========================================
echo.
echo 注意：部分参数需要重启系统才能生效
pause
