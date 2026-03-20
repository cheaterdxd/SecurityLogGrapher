# I. Event ID 4688 — *A new process has been created*

## 1. Mục đích

Event 4688 ghi nhận việc **một process mới được tạo ra**. Đây là log **cốt lõi trong detection** (TTP như execution, privilege escalation, lateral movement).

---

## 2. Các fields và ý nghĩa

### 🔹 Subject (Security Context khởi tạo process)

* **SubjectUserSid**

  * SID của user tạo process
  * 👉 Dùng để map identity (kể cả khi username bị spoof/log mismatch)

* **SubjectUserName**

  * Username thực thi process
  * 👉 Field quan trọng để detect account abuse

* **SubjectDomainName**

  * Domain hoặc hostname
  * 👉 Phân biệt local vs domain account

* **SubjectLogonId**

  * Logon session ID
  * 👉 Pivot cực mạnh để correlate với:

    * 4624 (logon)
    * 4672 (privileged logon)

---

### 🔹 Process Information

* **NewProcessId**

  * PID của process mới
  * 👉 Dùng correlate với:

    * 4689 (process termination)
    * Sysmon Event 1

* **NewProcessName**

  * Full path executable
  * 👉 Detection chính:

    * LOLBins (powershell.exe, cmd.exe, rundll32.exe)
    * Suspicious path (Temp, AppData)

---

### 🔹 Token Elevation

* **TokenElevationType**

  * Mức độ privilege:

    * %%1936 → Default (không elevate)
    * %%1937 → Full (admin)
    * %%1938 → Limited (UAC)
  * 👉 Dùng detect privilege escalation

---

### 🔹 Creator Process

* **ProcessId**

  * PID của parent process

* **ProcessName**

  * Parent process name

👉 Đây là **critical field cho process tree analysis**

Ví dụ detection:

* `winword.exe → powershell.exe`
* `explorer.exe → cmd.exe → suspicious.exe`

---

### 🔹 Command Line (nếu enable Audit Process Creation + CLI logging)

* **CommandLine**

  * Toàn bộ argument

👉 Field quan trọng nhất trong detection:

* Encoded PowerShell
* Download cradles
* Living-off-the-land attacks

---

### 🔹 Mandatory Label

* **MandatoryLabel**

  * Integrity level:

    * Low
    * Medium
    * High
    * System

👉 Dùng detect:

* Process chạy ở mức SYSTEM bất thường
* Sandbox escape / privilege abuse

---

## 3. Giá trị detection thực tế

* Process spawn bất thường
* Parent-child anomaly
* Execution từ thư mục không chuẩn
* Abuse of admin token

---

# II. Event ID 4663 — *An attempt was made to access an object*

## 1. Mục đích

Event 4663 ghi nhận **truy cập vào object (file, folder, registry, kernel object)**.

⚠️ Chỉ xuất hiện khi:

* Object có SACL (audit enabled)

---

## 2. Các fields và ý nghĩa

### 🔹 Subject

* **SubjectUserSid / Name / Domain / LogonId**
  👉 Giống 4688 — xác định actor

---

### 🔹 Object Information

* **ObjectServer**

  * Loại subsystem:

    * Security
    * File System
    * Registry

* **ObjectType**

  * Loại object:

    * File
    * Key
    * Directory

* **ObjectName**

  * Full path object

👉 Field quan trọng nhất:

* File nhạy cảm:

  * `C:\Windows\System32`
  * `SAM`
  * `LSASS dump`

---

### 🔹 Handle Information

* **HandleId**

  * ID handle tới object

👉 Dùng correlate với:

* Event 4656 (handle request)

---

### 🔹 Process Information

* **ProcessId**

  * PID truy cập object

* **ProcessName**

  * Executable path

👉 Dùng xác định:

* Ai truy cập file

---

### 🔹 Access Information

* **AccessMask**

  * Bitmask quyền truy cập

* **AccessList**

  * Decode quyền:

    * ReadData (0x1)
    * WriteData (0x2)
    * AppendData
    * Delete
    * ReadAttributes
    * WriteAttributes

👉 Cực kỳ quan trọng cho detection:

* Write vào system file
* Delete log
* Modify DLL

---

## 3. Giá trị detection thực tế

* File tampering
* Credential access (SAM, NTDS)
* Malware dropper activity
* Defense evasion (xóa log, sửa binary)

---

# III. Event ID 4657 — *A registry value was modified*

## 1. Mục đích

Event 4657 ghi nhận **thay đổi registry value**.

👉 Rất quan trọng cho:

* Persistence
* Configuration tampering

---

## 2. Các fields và ý nghĩa

### 🔹 Subject

* **SubjectUserSid / Name / Domain / LogonId**
  👉 Actor thực hiện thay đổi

---

### 🔹 Object Information

* **ObjectType**

  * Luôn là `Key`

* **ObjectName**

  * Registry path:

    * `HKLM\Software\...`

👉 Detection trọng tâm:

* Run keys
* Services
* Security config

---

### 🔹 Value Information

* **ObjectValueName**

  * Tên value bị sửa

* **OldValueType / NewValueType**

  * Kiểu dữ liệu:

    * REG_SZ
    * REG_DWORD
    * REG_BINARY

* **OldValue / NewValue**

  * Giá trị trước và sau

👉 Đây là field **quan trọng nhất**:

* So sánh delta (before/after)

---

### 🔹 Process Information

* **ProcessId**
* **ProcessName**

👉 Ai thực hiện thay đổi registry

---

### 🔹 Operation Type

* **OperationType**

  * %%1905 → Value modified

---

## 3. Giá trị detection thực tế

* Persistence:

  * Run key injection
* UAC bypass
* Disable security controls:

  * Defender
  * Firewall
* Credential harvesting config

---

# IV. Correlation giữa 3 Event (Cực kỳ quan trọng)

## 1. Chuỗi tấn công điển hình

### Ví dụ:

1. **4688**

   * powershell.exe được spawn

2. **4663**

   * powershell truy cập file payload

3. **4657**

   * persistence qua registry

👉 Đây là attack chain hoàn chỉnh:

* Execution → File access → Persistence

---

## 2. Pivot chính

* **LogonId**

  * Theo session

* **ProcessId**

  * Theo process lifecycle

* **ObjectName**

  * Theo target

---

# V. Các lỗi thường gặp khi phân tích log

* Không bật:

  * Audit Process Creation (4688 thiếu command line)
  * Object Access (4663 không có)

* Không correlate:

  * Chỉ nhìn từng event riêng lẻ

* Không decode AccessMask

---

# VI. Kết luận

| Event | Vai trò chính                             |
| ----- | ----------------------------------------- |
| 4688  | Process execution (entry point detection) |
| 4663  | Object interaction (file/registry access) |
| 4657  | Persistence & config tampering            |


---