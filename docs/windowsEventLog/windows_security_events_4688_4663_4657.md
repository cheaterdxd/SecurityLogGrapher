# Windows Security Event Log — Field Reference
> **Mục đích:** Tài liệu kỹ thuật cho code agent phân tích cấu trúc log Windows Security Events 4688, 4663, 4657.

---

## Mục Lục
- [Event 4688 — Process Creation](#event-4688--process-creation)
- [Event 4663 — Object Access](#event-4663--object-access)
- [Event 4657 — Registry Value Modified](#event-4657--registry-value-modified)
- [Phụ lục A — AccessList / AccessMask Decoder](#phụ-lục-a--accesslist--accessmask-decoder)
- [Phụ lục B — Registry Persistence Keys](#phụ-lục-b--registry-persistence-keys)
- [Phụ lục C — Correlation Map](#phụ-lục-c--correlation-map)

---

## Event 4688 — Process Creation

```
Channel   : Security
Category  : Detailed Tracking
Subcategory: Audit Process Creation
GUID      : {0CCE922B-69AE-11D9-BED3-505054503030}
Trigger   : Mỗi khi một process mới được tạo ra trong hệ thống
Volume    : Rất cao
```

### Cấu trúc XML mẫu

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4688</EventID>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-111111111-222222222-333333333-1001</Data>
    <Data Name="SubjectUserName">john.doe</Data>
    <Data Name="SubjectDomainName">CORP.LOCAL</Data>
    <Data Name="SubjectLogonId">0x3E7</Data>
    <Data Name="NewProcessId">0x1ABC</Data>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="TokenElevationType">%%1936</Data>
    <Data Name="ProcessId">0x4F2</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">-</Data>
    <Data Name="TargetDomainName">-</Data>
    <Data Name="TargetLogonId">0x0</Data>
    <Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
    <Data Name="MandatoryLabel">S-1-16-8192</Data>
  </EventData>
</Event>
```

### Field Reference

| Field | Type | Mô tả | Ví dụ |
|---|---|---|---|
| `SubjectUserSid` | SID | SID của tài khoản tạo process. Định danh duy nhất của chủ thể. | `S-1-5-21-...-1001` |
| `SubjectUserName` | String | Tên tài khoản người dùng tạo process. `SYSTEM` = process tự khởi động từ service. | `john.doe` |
| `SubjectDomainName` | String | Domain/workgroup của tài khoản. `WORKGROUP` hoặc tên máy = local account. | `CORP.LOCAL` |
| `SubjectLogonId` | HEX | ID phiên đăng nhập của chủ thể. Dùng để correlate với Event 4624. | `0x3E7` |
| `NewProcessId` | HEX | PID của tiến trình mới. Unique tại thời điểm chạy. | `0x1ABC` |
| `NewProcessName` | String | **Đường dẫn đầy đủ** của file thực thi được tạo mới. Field quan trọng nhất để phát hiện malware. | `C:\Windows\System32\cmd.exe` |
| `TokenElevationType` | HEX | Loại token elevation. Xem bảng giải mã bên dưới. | `%%1936` |
| `ProcessId` | HEX | PID của tiến trình **cha** (Parent Process) tạo ra process mới. | `0x4F2` |
| `CommandLine` | String | **Toàn bộ command line** bao gồm arguments. Chỉ có khi bật policy `Include command line in process creation events`. | `cmd.exe /c whoami` |
| `TargetUserSid` | SID | SID của user mà process chạy dưới danh nghĩa khi dùng RunAs hoặc impersonation. Khác `SubjectUserSid` khi có elevation. | `S-1-5-18` |
| `TargetUserName` | String | Username của identity thực sự chạy process (RunAs / CreateProcessWithLogonW). | `SYSTEM` |
| `TargetDomainName` | String | Domain của `TargetUser`. | `NT AUTHORITY` |
| `TargetLogonId` | HEX | Logon Session ID của TargetUser. Correlate với Event 4624 của target session. | `0x3E4` |
| `ParentProcessName` | String | Đường dẫn đầy đủ của tiến trình cha. Có từ Windows 10/Server 2016. Dùng để xây dựng process chain. | `C:\Windows\explorer.exe` |
| `MandatoryLabel` | SID | Integrity Level của process. Xem bảng giải mã bên dưới. | `S-1-16-8192` |

### TokenElevationType Decoder

| Giá trị | Tên | Ý nghĩa | Cảnh báo |
|---|---|---|---|
| `%%1936` | `TokenElevationTypeDefault` | UAC không bật hoặc identity không thay đổi. | Bình thường với SYSTEM/Service accounts. |
| `%%1937` | `TokenElevationTypeFull` | Đang chạy với quyền Admin đầy đủ — đã vượt UAC hoặc UAC tắt. | ⚠️ Alert nếu kết hợp với process lạ. Có thể là UAC bypass. |
| `%%1938` | `TokenElevationTypeLimited` | Token bị giới hạn (filtered token) — UAC đã split token. | Bình thường — đây là cơ chế UAC split-token. |

### MandatoryLabel (Integrity Level) Decoder

| SID | Integrity Level | Ý nghĩa |
|---|---|---|
| `S-1-16-4096` | Low | Sandbox, Internet Explorer Protected Mode |
| `S-1-16-8192` | Medium | User-level processes (mặc định) |
| `S-1-16-12288` | High | Elevated (Admin) processes |
| `S-1-16-16384` | System | SYSTEM-level processes |

### Điều kiện bật log

```
# Group Policy
Computer Configuration
  -> Windows Settings
    -> Security Settings
      -> Advanced Audit Policy Configuration
        -> Detailed Tracking
          -> Audit Process Creation: SUCCESS

# Bật ghi CommandLine (Registry)
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
  ProcessCreationIncludeCmdLine_Enabled = 1 (DWORD)
```

### Detection Patterns

```yaml
# Pattern 1: Suspicious Encoded PowerShell
event_id: 4688
condition:
  NewProcessName|endswith: '\powershell.exe'
  CommandLine|contains_any:
    - '-enc '
    - '-EncodedCommand'
    - '-nop'
    - '-w hidden'
    - 'bypass'
severity: CRITICAL
mitre: T1059.001

# Pattern 2: Office Spawns Script Interpreter (Macro Malware)
event_id: 4688
condition:
  ParentProcessName|endswith_any:
    - '\WINWORD.EXE'
    - '\EXCEL.EXE'
    - '\POWERPNT.EXE'
  NewProcessName|endswith_any:
    - '\cmd.exe'
    - '\powershell.exe'
    - '\wscript.exe'
    - '\mshta.exe'
severity: CRITICAL
mitre: T1566.001

# Pattern 3: Process Running from Suspicious Path
event_id: 4688
condition:
  NewProcessName|contains_any:
    - '\Temp\'
    - '\AppData\Local\'
    - '\AppData\Roaming\'
    - '\Users\Public\'
  NewProcessName|endswith_any:
    - '.exe'
    - '.scr'
    - '.com'
severity: HIGH
mitre: T1204

# Pattern 4: LOLBins Abuse
event_id: 4688
condition:
  NewProcessName|endswith_any:
    - '\certutil.exe'
    - '\regsvr32.exe'
    - '\mshta.exe'
    - '\rundll32.exe'
    - '\cmstp.exe'
    - '\installutil.exe'
  CommandLine|contains_any:
    - 'http'
    - 'ftp'
    - '-urlcache'
    - '/i:'
severity: HIGH
mitre: T1218
```

---

## Event 4663 — Object Access

```
Channel    : Security
Category   : Object Access
Subcategory: Audit File System / Audit Registry / Audit Kernel Object
Trigger    : Khi một thao tác truy cập THỰC SỰ xảy ra trên object được giám sát
Volume     : Rất cao nếu SACL cấu hình rộng
Prerequisite:
  1. Bật "Audit Object Access" trong Advanced Audit Policy
  2. Thiết lập SACL trên từng file/folder/registry key cần giám sát
```

> **Phân biệt 4663 vs 4656:**
> - `4656` = Process **yêu cầu** cấp quyền truy cập (handle request) — chưa chắc thao tác đã xảy ra.
> - `4663` = Thao tác truy cập đã **thực sự diễn ra** trên object.

### Cấu trúc XML mẫu

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4663</EventID>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-111111111-222222222-333333333-1002</Data>
    <Data Name="SubjectUserName">jane.smith</Data>
    <Data Name="SubjectDomainName">CORP.LOCAL</Data>
    <Data Name="SubjectLogonId">0xA2B4C</Data>
    <Data Name="ObjectServer">Security</Data>
    <Data Name="ObjectType">File</Data>
    <Data Name="ObjectName">C:\Confidential\HR\salary.xlsx</Data>
    <Data Name="HandleId">0x1F4</Data>
    <Data Name="AccessList">%%4416
			%%4423</Data>
    <Data Name="AccessMask">0x00000081</Data>
    <Data Name="ProcessId">0x1234</Data>
    <Data Name="ProcessName">C:\Program Files\WinRAR\WinRAR.exe</Data>
    <Data Name="ResourceAttributes">S:AI</Data>
  </EventData>
</Event>
```

### Field Reference

| Field | Type | Mô tả | Ví dụ |
|---|---|---|---|
| `SubjectUserSid` | SID | SID của tài khoản thực hiện thao tác truy cập. | `S-1-5-21-...-1002` |
| `SubjectUserName` | String | Tên tài khoản thực hiện truy cập object. | `jane.smith` |
| `SubjectDomainName` | String | Domain của tài khoản. `WORKGROUP` = local account. | `CORP.LOCAL` |
| `SubjectLogonId` | HEX | Session ID — correlate với Event 4624 để trace toàn bộ session. | `0xA2B4C` |
| `ObjectServer` | String | Server xử lý request. `Security` = NTFS file system. `SC Manager` = Service Control. `SAM` = Security Account Manager. | `Security` |
| `ObjectType` | String | Loại object bị truy cập. | `File` / `Directory` / `Key` / `Process` / `Thread` |
| `ObjectName` | String | **Đường dẫn đầy đủ** của object bị truy cập. Field quan trọng nhất. | `C:\Confidential\HR\salary.xlsx` |
| `HandleId` | HEX | Handle ID được cấp. Correlate với Event 4656 và 4658. | `0x1F4` |
| `AccessList` | HEX List | Danh sách quyền truy cập thực hiện (multi-line, mỗi dòng là 1 quyền). Xem Phụ lục A để decode. | `%%4416\n%%4417` |
| `AccessMask` | HEX | Bitmask tổng hợp của tất cả quyền. | `0x00000003` |
| `ProcessId` | HEX | PID của process thực hiện thao tác. Correlate với Event 4688. | `0x1234` |
| `ProcessName` | String | Đường dẫn đầy đủ của process thực hiện thao tác. | `C:\Program Files\WinRAR\WinRAR.exe` |
| `ResourceAttributes` | String | Thuộc tính Dynamic Access Control (DAC). Chỉ xuất hiện khi DAC được cấu hình. | `S:AI(RA;ID;;;WD;(...))` |

### Điều kiện bật log

```
# Group Policy
Computer Configuration
  -> Windows Settings
    -> Security Settings
      -> Advanced Audit Policy Configuration
        -> Object Access
          -> Audit File System    : SUCCESS, FAILURE
          -> Audit Registry       : SUCCESS, FAILURE
          -> Audit Kernel Object  : SUCCESS (nếu cần)

# SACL — phải thiết lập thủ công trên từng object
# Cách thiết lập qua PowerShell:
$acl = Get-Acl "C:\Confidential"
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "ReadData,WriteData,Delete",
    "ContainerInherit,ObjectInherit",
    "None",
    "Success"
)
$acl.AddAuditRule($auditRule)
Set-Acl "C:\Confidential" $acl
```

### Detection Patterns

```yaml
# Pattern 1: Mass File Write — Ransomware Indicator
event_id: 4663
condition:
  AccessList|contains: '%%4417'   # WriteData
  ObjectType: 'File'
  timeframe: 60s
  aggregation: COUNT(ObjectName) > 100 GROUP BY SubjectUserSid
severity: CRITICAL
mitre: T1486  # Data Encrypted for Impact

# Pattern 2: SAM / NTDS Credential Theft
event_id: 4663
condition:
  ObjectName|contains_any:
    - '\config\SAM'
    - '\config\SYSTEM'
    - '\ntds.dit'
    - '\Windows\System32\config\SECURITY'
  AccessList|contains: '%%4416'   # ReadData
severity: CRITICAL
mitre: T1003  # OS Credential Dumping

# Pattern 3: Shadow Copy / Backup Deletion
event_id: 4663
condition:
  AccessList|contains: '%%1537'   # DELETE
  ObjectName|contains_any:
    - 'System Volume Information'
    - 'WindowsImageBackup'
    - '.vhd'
    - '.vhdx'
severity: HIGH
mitre: T1490  # Inhibit System Recovery

# Pattern 4: Event Log Tampering
event_id: 4663
condition:
  ObjectName|contains: '.evtx'
  AccessList|contains_any:
    - '%%4417'   # WriteData
    - '%%1537'   # DELETE
severity: CRITICAL
mitre: T1070.001  # Clear Windows Event Logs

# Pattern 5: Mass ReadData — Data Exfiltration
event_id: 4663
condition:
  AccessList|contains: '%%4416'   # ReadData
  ObjectType: 'File'
  timeframe: 300s
  aggregation: COUNT(DISTINCT ObjectName) > 500 GROUP BY SubjectUserSid
severity: HIGH
mitre: T1005  # Data from Local System
```

---

## Event 4657 — Registry Value Modified

```
Channel    : Security
Category   : Object Access
Subcategory: Audit Registry
Trigger    : Khi một registry value được tạo, sửa đổi hoặc xóa
Volume     : Trung bình (phụ thuộc vào SACL)
Prerequisite:
  1. Bật "Audit Registry" trong Advanced Audit Policy
  2. Thiết lập SACL trên từng Registry Key cần giám sát
Forensic value: Ghi lại cả OldValue và NewValue — rất quan trọng cho forensics
```

### Cấu trúc XML mẫu

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4657</EventID>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-111111111-222222222-333333333-1003</Data>
    <Data Name="SubjectUserName">attacker</Data>
    <Data Name="SubjectDomainName">WORKGROUP</Data>
    <Data Name="SubjectLogonId">0xF4A2</Data>
    <Data Name="ObjectName">\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</Data>
    <Data Name="ObjectValueName">WindowsUpdater</Data>
    <Data Name="HandleId">0x2A8</Data>
    <Data Name="OperationType">%%1904</Data>
    <Data Name="OldValue"></Data>
    <Data Name="NewValue">C:\Users\Public\malware.exe /auto</Data>
    <Data Name="OldValueType">%%1873</Data>
    <Data Name="NewValueType">%%1873</Data>
    <Data Name="ProcessId">0x9A4</Data>
    <Data Name="ProcessName">C:\Windows\System32\cmd.exe</Data>
  </EventData>
</Event>
```

### Field Reference

| Field | Type | Mô tả | Ví dụ |
|---|---|---|---|
| `SubjectUserSid` | SID | SID của tài khoản thực hiện thay đổi registry. | `S-1-5-21-...-1003` |
| `SubjectUserName` | String | Tên tài khoản. `SYSTEM` = OS hoặc service. | `attacker` |
| `SubjectDomainName` | String | Domain của tài khoản. | `WORKGROUP` |
| `SubjectLogonId` | HEX | Session ID — correlate với Event 4624. | `0xF4A2` |
| `ObjectName` | String | **Đường dẫn đầy đủ của Registry Key** bị thao tác. Dùng hive prefix (`\REGISTRY\MACHINE\` = HKLM, `\REGISTRY\USER\` = HKCU/HKU). | `\REGISTRY\MACHINE\SOFTWARE\...\Run` |
| `ObjectValueName` | String | Tên của registry **value** bị thay đổi. Rỗng nếu thao tác trên key (không phải value). | `WindowsUpdater` |
| `HandleId` | HEX | Handle ID của registry key. Correlate với Event 4656 và 4658. | `0x2A8` |
| `OperationType` | String | Loại thao tác. Xem bảng giải mã bên dưới. | `%%1904` |
| `OldValue` | String | **Giá trị cũ trước khi thay đổi.** Rỗng nếu là value mới. Chỉ có khi `OperationType = %%1904`. | `(rỗng)` hoặc giá trị cũ |
| `NewValue` | String | **Giá trị mới sau khi thay đổi.** Có thể chứa executable path hoặc encoded payload. | `C:\Users\Public\malware.exe /auto` |
| `OldValueType` | String | Kiểu dữ liệu của giá trị cũ. Xem bảng giải mã bên dưới. | `%%1873` |
| `NewValueType` | String | Kiểu dữ liệu của giá trị mới. Thay đổi type bất thường = dấu hiệu obfuscation. | `%%1873` |
| `ProcessId` | HEX | PID của process thực hiện thay đổi. Correlate với Event 4688. | `0x9A4` |
| `ProcessName` | String | Đường dẫn đầy đủ của process thực hiện registry modification. | `C:\Windows\System32\cmd.exe` |

### OperationType Decoder

| Giá trị | Ý nghĩa | Ghi chú |
|---|---|---|
| `%%1904` | **Value Set** — tạo mới hoặc sửa đổi value | Phổ biến nhất. `OldValue` + `NewValue` đều có. |
| `%%1905` | **Value Deleted** — xóa một registry value | `OldValue` có giá trị cũ, `NewValue` rỗng. |
| `%%1906` | **Key Deleted** — xóa toàn bộ registry key | `ObjectValueName` rỗng. |

### ObjectName Hive Path Mapping

| Prefix trong log | Registry Hive tương ứng |
|---|---|
| `\REGISTRY\MACHINE\` | `HKEY_LOCAL_MACHINE (HKLM)` |
| `\REGISTRY\USER\<SID>\` | `HKEY_CURRENT_USER (HKCU)` của user có SID đó |
| `\REGISTRY\USER\.DEFAULT\` | `HKU\.DEFAULT` |
| `\REGISTRY\USER\S-1-5-18\` | `HKU\SYSTEM` |

### Registry Value Type Decoder

| Giá trị | Tên kiểu | Mô tả |
|---|---|---|
| `%%1872` | `REG_NONE` | Không có kiểu dữ liệu |
| `%%1873` | `REG_SZ` | Chuỗi ký tự (null-terminated) |
| `%%1874` | `REG_EXPAND_SZ` | Chuỗi có biến môi trường (`%SystemRoot%`) |
| `%%1875` | `REG_BINARY` | Dữ liệu nhị phân |
| `%%1876` | `REG_DWORD` | 32-bit integer |
| `%%1877` | `REG_DWORD_BIG_ENDIAN` | 32-bit integer (big-endian) |
| `%%1878` | `REG_LINK` | Symbolic link |
| `%%1879` | `REG_MULTI_SZ` | Mảng chuỗi |
| `%%1880` | `REG_RESOURCE_LIST` | Resource list |
| `%%1883` | `REG_QWORD` | 64-bit integer |

### Điều kiện bật log

```
# Group Policy
Computer Configuration
  -> Windows Settings
    -> Security Settings
      -> Advanced Audit Policy Configuration
        -> Object Access
          -> Audit Registry: SUCCESS, FAILURE

# SACL trên Registry Key — PowerShell
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
    "SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
    [System.Security.AccessControl.RegistryRights]::ChangePermissions
)
$acl = $key.GetAccessControl()
$auditRule = New-Object System.Security.AccessControl.RegistryAuditRule(
    "Everyone",
    "SetValue,Delete",
    "ContainerInherit,ObjectInherit",
    "None",
    "Success"
)
$acl.AddAuditRule($auditRule)
$key.SetAccessControl($acl)
```

### Detection Patterns

```yaml
# Pattern 1: Malware Persistence via Run Key
event_id: 4657
condition:
  OperationType: '%%1904'
  ObjectName|contains_any:
    - '\CurrentVersion\Run'
    - '\CurrentVersion\RunOnce'
    - '\CurrentVersion\RunServices'
  NewValue|contains_any:
    - '\Temp\'
    - '\AppData\'
    - '\Users\Public\'
severity: CRITICAL
mitre: T1547.001  # Boot/Logon Autostart Execution

# Pattern 2: Disable Windows Defender
event_id: 4657
condition:
  OperationType: '%%1904'
  ObjectName|contains_any:
    - '\Windows Defender\Real-Time Protection'
    - '\Policies\Microsoft\Windows Defender'
  ObjectValueName|contains_any:
    - 'DisableAntiSpyware'
    - 'DisableRealtimeMonitoring'
    - 'DisableBehaviorMonitoring'
  NewValue: '1'
severity: CRITICAL
mitre: T1562.001  # Impair Defenses

# Pattern 3: UAC Bypass via Registry
event_id: 4657
condition:
  OperationType: '%%1904'
  ObjectName|contains: 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
  ObjectValueName: 'ConsentPromptBehaviorAdmin'
  NewValue|in: ['0', '1']   # 0=No prompt, 1=Elevate without prompt
severity: CRITICAL
mitre: T1548.002

# Pattern 4: Winlogon Hijack
event_id: 4657
condition:
  OperationType: '%%1904'
  ObjectName|contains: '\Windows NT\CurrentVersion\Winlogon'
  ObjectValueName|in: ['Userinit', 'Shell', 'GinaDLL']
severity: CRITICAL
mitre: T1547.004  # Winlogon Helper DLL

# Pattern 5: Image File Execution Options (Debugger Hijack)
event_id: 4657
condition:
  OperationType: '%%1904'
  ObjectName|contains: '\Image File Execution Options\'
  ObjectValueName: 'Debugger'
severity: HIGH
mitre: T1546.012

# Pattern 6: Disable Event Logging
event_id: 4657
condition:
  OperationType: '%%1904'
  ObjectName|contains: '\SYSTEM\CurrentControlSet\Services\EventLog'
  ObjectValueName: 'Start'
  NewValue: '4'   # SERVICE_DISABLED
severity: CRITICAL
mitre: T1070.001

# Pattern 7: LSA Security Package Modification
event_id: 4657
condition:
  OperationType: '%%1904'
  ObjectName|contains: '\CurrentControlSet\Control\Lsa'
  ObjectValueName|in: ['Security Packages', 'Authentication Packages', 'Notification Packages']
severity: HIGH
mitre: T1547.005  # Security Support Provider
```

---

## Phụ lục A — AccessList / AccessMask Decoder

Dùng cho field `AccessList` trong Event 4663. Mỗi dòng trong `AccessList` là một quyền riêng biệt.

### File / Directory Access Rights

| Mã AccessList | AccessMask (bit) | Tên quyền | Mô tả |
|---|---|---|---|
| `%%4416` | `0x0001` | `ReadData` / `ListDirectory` | Đọc nội dung file / liệt kê thư mục |
| `%%4417` | `0x0002` | `WriteData` / `AddFile` | Ghi dữ liệu vào file / tạo file mới trong folder |
| `%%4418` | `0x0004` | `AppendData` / `AddSubdirectory` | Thêm dữ liệu cuối file / tạo thư mục con |
| `%%4419` | `0x0008` | `ReadEA` | Đọc Extended Attributes |
| `%%4420` | `0x0010` | `WriteEA` | Ghi Extended Attributes |
| `%%4421` | `0x0020` | `Execute` / `Traverse` | Thực thi file / traverse qua directory |
| `%%4422` | `0x0040` | `DeleteChild` | Xóa file/thư mục con bên trong directory |
| `%%4423` | `0x0080` | `ReadAttributes` | Đọc thuộc tính cơ bản (timestamps, size) |
| `%%4424` | `0x0100` | `WriteAttributes` | Thay đổi thuộc tính cơ bản của file |

### Generic / Standard Access Rights

| Mã AccessList | AccessMask (bit) | Tên quyền | Mô tả |
|---|---|---|---|
| `%%1537` | `0x00010000` | `DELETE` | Xóa object |
| `%%1538` | `0x00020000` | `READ_CONTROL` | Đọc DACL và Owner |
| `%%1539` | `0x00040000` | `WRITE_DAC` | Thay đổi Discretionary ACL |
| `%%1540` | `0x00080000` | `WRITE_OWNER` | Thay đổi Owner |
| `%%1541` | `0x00100000` | `SYNCHRONIZE` | Đồng bộ thread với object (I/O completion) |
| `%%1542` | `0x01000000` | `ACCESS_SYS_SEC` | Đọc/ghi System ACL (SACL) |

### Ví dụ giải mã AccessMask

```python
# AccessMask decode helper
ACCESS_RIGHTS = {
    0x0001: "ReadData/ListDirectory",
    0x0002: "WriteData/AddFile",
    0x0004: "AppendData/AddSubdirectory",
    0x0008: "ReadEA",
    0x0010: "WriteEA",
    0x0020: "Execute/Traverse",
    0x0040: "DeleteChild",
    0x0080: "ReadAttributes",
    0x0100: "WriteAttributes",
    0x10000: "DELETE",
    0x20000: "READ_CONTROL",
    0x40000: "WRITE_DAC",
    0x80000: "WRITE_OWNER",
}

def decode_access_mask(mask: int) -> list[str]:
    return [name for bit, name in ACCESS_RIGHTS.items() if mask & bit]

# Ví dụ:
# decode_access_mask(0x00000003) -> ["ReadData/ListDirectory", "WriteData/AddFile"]
# decode_access_mask(0x00010002) -> ["WriteData/AddFile", "DELETE"]
```

---

## Phụ lục B — Registry Persistence Keys

Danh sách registry keys cần thiết lập SACL và giám sát Event 4657.

```
# AUTORUN — chạy khi boot/logon
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# WINLOGON HIJACK
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
  -> Values: Userinit, Shell, GinaDLL

# IMAGE FILE EXECUTION OPTIONS (Debugger Hijack)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*
  -> Value: Debugger

# SERVICES (malicious service installation)
HKLM\SYSTEM\CurrentControlSet\Services\*
  -> Values: ImagePath, Start, Type

# SECURITY SUPPORT PROVIDERS
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
  -> Values: Security Packages, Authentication Packages

# APPCERTDLLS / APPINIT_DLLS (DLL injection)
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
  -> Value: AppInit_DLLs

# DISABLE SECURITY TOOLS
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender
HKLM\SOFTWARE\Microsoft\Windows Defender
HKLM\SYSTEM\CurrentControlSet\Services\WinDefend
  -> Value: Start (4 = disabled)
HKLM\SYSTEM\CurrentControlSet\Services\EventLog\*
  -> Value: Start (4 = disabled)

# UAC SETTINGS
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
  -> Values: EnableLUA, ConsentPromptBehaviorAdmin, ConsentPromptBehaviorUser

# FILE ASSOCIATION HIJACK
HKCU\SOFTWARE\Classes\*\shell\open\command
HKLM\SOFTWARE\Classes\*\shell\open\command

# COM OBJECT HIJACK
HKCU\SOFTWARE\Classes\CLSID\*\InProcServer32

# LOGON SCRIPT
HKCU\Environment
  -> Value: UserInitMprLogonScript
```

---

## Phụ lục C — Correlation Map

### Event Relationships

```
Event 4624 (Logon)
  └── SubjectLogonId / TargetLogonId
        ├── Event 4688 (Process Creation)   <- SubjectLogonId
        ├── Event 4663 (Object Access)      <- SubjectLogonId
        └── Event 4657 (Registry Modified)  <- SubjectLogonId

Event 4688 (Process Creation)
  └── NewProcessId
        ├── Event 4663 (Object Access)      <- ProcessId
        └── Event 4657 (Registry Modified)  <- ProcessId

Event 4656 (Handle Requested)
  └── HandleId
        ├── Event 4663 (Object Access)      <- HandleId (access occurred)
        └── Event 4658 (Handle Closed)      <- HandleId (access ended)
```

### Kill Chain Correlation Example

```
T=0  Event 4657  -> Run Key modified     (persistence installed)
                    ObjectName: \...\CurrentVersion\Run
                    NewValue:   C:\Temp\beacon.exe

T=1  Event 4688  -> Process created      (malware executed)
                    NewProcessName: C:\Temp\beacon.exe
                    ParentProcessName: C:\Windows\System32\svchost.exe

T=2  Event 4688  -> Child process        (reconnaissance)
                    NewProcessName: C:\Windows\System32\cmd.exe
                    CommandLine: cmd.exe /c whoami /all & net user
                    ParentProcessName: C:\Temp\beacon.exe   <- correlate với T=1

T=3  Event 4663  -> File access          (data staging)
                    ObjectName: C:\Users\*\Documents\*.docx
                    AccessList: %%4416 (ReadData)
                    ProcessId: <same PID as T=1>            <- correlate với T=1

# Correlation keys:
# T=1 NewProcessId == T=2 ProcessId (via ParentProcessName)
# T=1 NewProcessId == T=3 ProcessId
# T=0 SubjectLogonId == T=1 SubjectLogonId == T=3 SubjectLogonId
```

### Quick Reference — Field Cross-Reference

| Để correlate | Dùng field này | Với event |
|---|---|---|
| Xác định process thực hiện file/registry access | `ProcessId` (4663/4657) = `NewProcessId` (4688) | 4663/4657 → 4688 |
| Trace toàn bộ session | `SubjectLogonId` (bất kỳ event) = `TargetLogonId` (4624) | Any → 4624 |
| Theo dõi vòng đời handle | `HandleId` (4663) = `HandleId` (4656) = `HandleId` (4658) | 4663 → 4656, 4658 |
| Xây dựng process tree | `ProcessId` (4688) = `NewProcessId` của parent | 4688 → 4688 (parent) |
| Xác định user context | `SubjectUserSid` (any event) | Any → AD/SAM |
