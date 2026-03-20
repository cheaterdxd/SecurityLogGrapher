### 1. Event ID 4688(S): A new process has been created
**Mô tả sự kiện:** Sự kiện này được tạo mỗi khi một tiến trình mới khởi tạo trên hệ thống. Nó ghi nhận chi tiết về chủ thể tạo tiến trình, ngữ cảnh bảo mật và thông tin tiến trình mới.

**Công dụng chính trong an toàn thông tin:**  
- Phát hiện tiến trình độc hại (malware injection, LOLBins abuse như powershell.exe với tham số lạ).  
- Giám sát escalation privilege qua Token Elevation Type.  
- Tương quan với command line để phát hiện tấn công supply-chain hoặc persistence.  
- Hỗ trợ forensic: xác định cha-con process tree (parent-child relationship).  
- Kết hợp với Process Command Line (khi kích hoạt policy “Include command line in process creation events”) để xây dựng baseline hành vi bình thường và phát hiện anomaly.  
Sự kiện này là nền tảng cho threat hunting trên Windows, đặc biệt trong môi trường domain.

**Các trường dữ liệu (fields) và ý nghĩa chi tiết:**

**Creator Subject (Subject ở phiên bản 0 và 1):**  
- **Security ID** [Type = SID]: SID của tài khoản yêu cầu tạo tiến trình. Giúp xác định chính xác identity (user, service account hoặc SYSTEM). Công dụng: loại trừ false positive khi SYSTEM tạo tiến trình hợp pháp.  
- **Account Name** [Type = UnicodeString]: Tên tài khoản.  
- **Account Domain** [Type = UnicodeString]: Tên domain hoặc máy (NETBIOS, FQDN hoặc NT AUTHORITY). Công dụng: phân biệt local account vs domain account.  
- **Logon ID** [Type = HexInt64]: ID phiên đăng nhập (hex). Công dụng: tương quan với Event 4624 để truy vết session.

**Target Subject (chỉ phiên bản 2):**  
Thêm thông tin về principal của tiến trình đích khi khác với creator.  
- **Security ID**, **Account Name**, **Account Domain**, **Logon ID** (tương tự trên). Công dụng: phát hiện impersonation hoặc UAC bypass khi creator và target khác nhau.

**Process Information:**  
- **New Process ID** [Type = Pointer]: PID hex của tiến trình mới. Công dụng: chuyển sang decimal để so sánh Task Manager; tương quan với các event khác qua PID.  
- **New Process Name** [Type = UnicodeString]: Đường dẫn đầy đủ file thực thi. Công dụng: xác định chính xác chương trình (ví dụ: C:\Windows\System32\cmd.exe).  
- **Token Elevation Type** [Type = UnicodeString]: Loại token (Type 1: full, Type 2: elevated, Type 3: limited). Công dụng: phát hiện UAC bypass hoặc run-as-admin.  
- **Mandatory Label** [Type = SID] (phiên bản 2): Integrity level (Low/Medium/High/System). Công dụng: phát hiện process chạy với low integrity (sandboxed malware).  
- **Creator Process ID** [Type = Pointer]: PID của tiến trình cha. Công dụng: xây dựng process tree.  
- **Creator Process Name** [Type = UnicodeString] (phiên bản 2): Đường dẫn thực thi của tiến trình cha.  
- **Process Command Line** [Type = UnicodeString] (phiên bản 1/2): Lệnh và tham số (chỉ có khi kích hoạt policy). Công dụng sâu: phát hiện command-line obfuscation, encoded PowerShell, hoặc tham số độc hại.

**Lưu ý phiên bản:** Phiên bản 0 (Windows Server 2008/Vista), phiên bản 2 bổ sung Target Subject, Mandatory Label, Creator Process Name.

### 2. Event ID 4663(S): An attempt was made to access an object
**Mô tả sự kiện:** Sự kiện ghi nhận khi quyền truy cập thực tế được sử dụng trên đối tượng (file, registry, kernel object). Không có Failure events; chỉ Success khi SACL được cấu hình đúng và quyền được thực thi (khác với 4656 chỉ request handle).

**Công dụng chính trong an toàn thông tin:**  
- Giám sát truy cập file nhạy cảm (exfiltration, ransomware encryption).  
- Phát hiện thao tác trên registry hoặc device objects.  
- Phân tích post-exploitation: xác định process nào truy cập file nào.  
- Xây dựng audit trail cho tuân thủ (NIST, ISO 27001) vì ghi rõ “access was used”.  
- Tương quan với 4656/4658 để theo dõi toàn bộ vòng đời handle.

**Các trường dữ liệu (fields) và ý nghĩa chi tiết:**

**Subject:**  
- **Security ID** [Type = SID]: SID của tài khoản thực hiện truy cập.  
- **Account Name**, **Account Domain**, **Logon ID** [Type = HexInt64]: Tương tự 4688. Công dụng: truy vết user/session thực hiện hành động.

**Object:**  
- **Object Server** [Type = UnicodeString]: Luôn là “Security”.  
- **Object Type** [Type = UnicodeString]: Loại đối tượng (File, Key, Process, Device, …). Công dụng: phân biệt file system vs registry vs kernel.  
- **Object Name** [Type = UnicodeString]: Đường dẫn đầy đủ đối tượng (ví dụ: C:\path\file.txt hoặc \REGISTRY\…). Công dụng: xác định chính xác tài nguyên bị truy cập.  
- **Handle ID** [Type = Pointer]: Handle hex. Công dụng: tương quan với 4656/4658.  
- **Resource Attributes** [Type = UnicodeString] (phiên bản 1): Thuộc tính resource (ví dụ: Impact_MS). Công dụng: phân tích metadata bổ sung.

**Process Information:**  
- **Process ID** [Type = Pointer]: PID của tiến trình thực hiện truy cập. Công dụng: liên kết với 4688 để xác định chương trình gây ra.  
- **Process Name** [Type = UnicodeString]: Đường dẫn thực thi.  

**Access Request Information:**  
- **Accesses** [Type = UnicodeString]: Danh sách quyền được sử dụng (dựa trên Object Type). Các quyền phổ biến cho file system (và tương tự registry):  
  - ReadData (0x1): Đọc dữ liệu hoặc liệt kê thư mục.  
  - WriteData (0x2): Ghi dữ liệu hoặc tạo file.  
  - AppendData (0x4): Thêm dữ liệu hoặc tạo thư mục con.  
  - ReadEA (0x8): Đọc thuộc tính mở rộng.  
  - WriteEA (0x10): Ghi thuộc tính mở rộng.  
  - Execute/Traverse (0x20): Thực thi hoặc duyệt thư mục.  
  - DeleteChild (0x40): Xóa thư mục và nội dung.  
  - ReadAttributes (0x80): Đọc thuộc tính.  
  - WriteAttributes (0x100): Ghi thuộc tính.  
  - DELETE (0x10000): Xóa đối tượng.  
  - READ_CONTROL (0x20000): Đọc security descriptor (không SACL).  
  - WRITE_DAC (0x40000): Sửa DACL.  
  - WRITE_OWNER (0x80000): Thay đổi owner.  
  - SYNCHRONIZE (0x100000): Đồng bộ hóa.  
  - ACCESS_SYS_SEC (0x1000000): Truy cập SACL.  
Công dụng: xác định chính xác hành động (read/write/delete) để phân biệt benign vs malicious access.

### 3. Event ID 4657(S): A registry value was modified
**Mô tả sự kiện:** Sự kiện được tạo khi giá trị (value) của registry key bị thay đổi (không phải key). Chỉ ghi nhận nếu “Set Value” auditing được bật trong SACL của key.

**Công dụng chính trong an toàn thông tin:**  
- Phát hiện persistence technique (Run keys, services modification).  
- Giám sát thay đổi cấu hình hệ thống (malware thay đổi firewall rules, autorun).  
- Theo dõi Old Value → New Value để phát hiện tampering.  
- Kết hợp với 4663 (nếu key bị truy cập) và 4688 (process gây ra) để xây dựng chuỗi tấn công đầy đủ.  
- Hỗ trợ compliance auditing cho registry nhạy cảm (HKLM\SOFTWARE, HKCU\Run).

**Các trường dữ liệu (fields) và ý nghĩa chi tiết:**

**Subject:**  
- **Security ID**, **Account Name**, **Account Domain**, **Logon ID**: Tương tự các event trên. Công dụng: xác định ai thực hiện thay đổi.

**Object:**  
- **Object Name** [Type = UnicodeString]: Đường dẫn đầy đủ key (\REGISTRY\MACHINE\… hoặc \REGISTRY\USER\[SID]\…). Công dụng: xác định chính xác hive và key.  
- **Object Value Name** [Type = UnicodeString]: Tên value bị sửa (ví dụ: “ImagePath”).  
- **Handle ID** [Type = Pointer]: Handle để tương quan với 4656.

**Process Information:**  
- **Process ID** [Type = Pointer]: PID của tiến trình gây ra thay đổi.  
- **Process Name** [Type = UnicodeString]: Đường dẫn thực thi. Công dụng: liên kết với 4688.

**Change Information:**  
- **Operation Type** [Type = UnicodeString]: Loại thao tác (New registry value created / Registry value deleted / Existing registry value modified).  
- **Old Value Type** / **New Value Type** [Type = UnicodeString]: Kiểu dữ liệu (REG_SZ, REG_DWORD, REG_BINARY, REG_EXPAND_SZ, …).  
- **Old Value** / **New Value** [Type = UnicodeString]: Giá trị cũ và mới. Công dụng sâu nhất: so sánh trực tiếp để phát hiện thay đổi cụ thể (ví dụ: từ “notepad.exe” sang “malware.exe”).

**Lưu ý:** Event này chỉ ghi value, không ghi key structure change. Minimum OS: Windows Server 2008/Vista (phiên bản 0).
