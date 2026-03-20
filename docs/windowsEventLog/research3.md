Dưới đây là một **tài liệu chuyên nghiệp** về **Windows Security Logs**, đặc biệt tập trung vào ba event ID quan trọng: **4688 (Process Creation)**, **4663 (File Access)**, và **4657 (Registry Value Modification)**. Tài liệu được viết dưới góc độ của một **chuyên gia an toàn thông tin**, giải thích chi tiết về công dụng, ý nghĩa, và mối liên hệ giữa các fields trong log.

---

---

# **TÀI LIỆU: GIẢI THÍCH CÁC FIELDS TRONG WINDOWS SECURITY LOG (Security Logs)**
**Chuyên gia an toàn thông tin: Thanh Tuấn Lê**
**Ngày: 20/03/2026**

---

## **1. Tổng Quan về Windows Security Log**
Windows Security Log là một thành phần quan trọng của **Windows Event Log**, ghi lại các sự kiện liên quan đến **bảo mật hệ thống**, bao gồm:
- Đăng nhập/đăng xuất (Logon/Logoff)
- Thay đổi chính sách bảo mật
- Truy cập tài nguyên (file, thư mục, registry)
- Khởi chạy tiến trình (Process Creation)
- Thay đổi cấu hình hệ thống

Các sự kiện được ghi lại dưới dạng **Event Logs**, mỗi log chứa nhiều **fields** (trường thông tin) mô tả chi tiết diễn biến của sự kiện.

---

## **2. Event ID 4688: Process Creation**
**Mô tả:**
Được ghi lại khi một **tiến trình (process)** mới được khởi chạy trên hệ thống. Sự kiện này cung cấp thông tin chi tiết về người dùng đã khởi tạo tiến trình, lệnh thực thi, và các thuộc tính bảo mật liên quan.

**Công dụng:**
- Phát hiện các tiến trình đáng ngờ (malware, APT)
- Theo dõi hoạt động của người dùng
- Phân tích chuỗi tấn công (kill chain)

---

### **Các Fields quan trọng trong Event ID 4688**

| **Field**               | **Ý nghĩa**                                                                                     | **Ví dụ**                                                                 |
|-------------------------|-------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| **SubjectUserSid**      | SID (Security Identifier) của người dùng khởi tạo tiến trình.                                  | `S-1-5-21-123456789-1234567890-123456789-1001`                           |
| **SubjectUserName**     | Tên người dùng khởi tạo tiến trình.                                                            | `admin`                                                                   |
| **SubjectDomainName**   | Domain của người dùng (nếu có).                                                               | `DOMAIN`                                                                  |
| **SubjectLogonId**      | Logon ID của phiên đăng nhập liên quan.                                                         | `0x3e7`                                                                   |
| **NewProcessId**        | PID (Process ID) của tiến trình mới.                                                           | `4120`                                                                    |
| **NewProcessName**      | Đường dẫn đầy đủ của tệp thực thi.                                                            | `C:\Windows\System32\notepad.exe`                                        |
| **TokenElevationType**  | Loại nâng cấp quyền (Token Elevation).                                                         | `%%1938` (TokenElevationTypeDefault)                                      |
| **CreatorProcessId**    | PID của tiến trình khởi tạo tiến trình mới.                                                   | `512`                                                                     |
| **ProcessCommandLine**  | Lệnh đầy đủ được sử dụng để khởi chạy tiến trình.                                             | `"C:\Windows\System32\cmd.exe" /c echo "Hello World"`                     |
| **TargetUserSid**       | SID của người dùng sở hữu tiến trình (nếu khác với Subject).                                   | `S-1-5-21-123456789-1234567890-123456789-1002`                           |
| **TargetUserName**      | Tên người dùng sở hữu tiến trình.                                                              | `user`                                                                    |
| **TargetDomainName**    | Domain của người dùng sở hữu tiến trình.                                                      | `WORKGROUP`                                                               |
| **TargetLogonId**       | Logon ID của người dùng sở hữu tiến trình.                                                    | `0x42a7`                                                                  |

---

### **Phân Tích Mối Liên Hệ Giữa Các Fields**
- **ProcessCommandLine**: Nếu lệnh chứa các tham số đáng ngờ (ví dụ: tải xuống file từ URL), đây có thể là dấu hiệu của hành vi độc hại.
- **NewProcessName**: So sánh với danh sách tiến trình hợp pháp (whitelist) để phát hiện tiến trình lạ.
- **TokenElevationType**: Nếu tiến trình được khởi chạy với quyền **TokenElevationTypeFull** (quyền admin), đây có thể là dấu hiệu của hành vi leo thang đặc quyền.

---

## **3. Event ID 4663: File Access**
**Mô tả:**
Được ghi lại khi một **tiến trình truy cập file hoặc thư mục**. Sự kiện này cung cấp thông tin về người dùng, tiến trình, quyền truy cập, và đường dẫn file.

**Công dụng:**
- Phát hiện truy cập trái phép vào file nhạy cảm
- Phân tích hành vi của malware (ví dụ: ransomware truy cập file)
- Theo dõi hoạt động của người dùng

---

### **Các Fields quan trọng trong Event ID 4663**

| **Field**               | **Ý nghĩa**                                                                                     | **Ví dụ**                                                                 |
|-------------------------|-------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| **SubjectUserSid**      | SID của người dùng khởi tạo truy cập.                                                          | `S-1-5-21-123456789-1234567890-123456789-1001`                           |
| **SubjectUserName**     | Tên người dùng khởi tạo truy cập.                                                              | `admin`                                                                   |
| **SubjectDomainName**   | Domain của người dùng.                                                                         | `DOMAIN`                                                                  |
| **SubjectLogonId**      | Logon ID của phiên đăng nhập liên quan.                                                         | `0x3e7`                                                                   |
| **ObjectServer**        | Tên của dịch vụ Object (thường là **Security**).                                               | `Security`                                                                |
| **ObjectType**          | Loại đối tượng truy cập (ví dụ: **File**, **Registry Key**).                                    | `File`                                                                    |
| **ObjectName**          | Đường dẫn đầy đủ của file/thư mục truy cập.                                                   | `C:\Users\admin\Documents\secret.docx`                                   |
| **HandleId**            | ID của handle truy cập file/thư mục.                                                          | `0x12345678`                                                             |
| **AccessMask**          | Mã quyền truy cập (xem bảng dưới).                                                             | `0x120089` (FILE_READ_DATA + FILE_WRITE_DATA)                            |
| **AccessList**          | Danh sách quyền truy cập (dưới dạng text).                                                    | `%%4416;%%4419;%%4417` (FILE_READ_DATA; FILE_WRITE_DATA; SYNCHRONIZE)    |
| **PrivilegeList**       | Danh sách quyền đặc biệt (nếu có).                                                             | `SeBackupPrivilege;SeRestorePrivilege`                                   |
| **ProcessId**           | PID của tiến trình truy cập file.                                                              | `4120`                                                                    |
| **ProcessName**         | Đường dẫn đầy đủ của tiến trình truy cập.                                                      | `C:\Windows\System32\notepad.exe`                                        |

---

### **Mã Quyền Truy Cập (AccessMask)**
| **Mã**       | **Quyền**                     | **Ý nghĩa**                                                                 |
|--------------|--------------------------------|-------------------------------------------------------------------------------|
| `0x1`        | FILE_READ_DATA                 | Đọc dữ liệu khỏi file.                                                      |
| `0x2`        | FILE_WRITE_DATA                | Ghi dữ liệu vào file.                                                       |
| `0x4`        | FILE_APPEND_DATA               | Thêm dữ liệu vào cuối file.                                                 |
| `0x8`        | FILE_READ_EA                   | Đọc thuộc tính mở rộng (Extended Attributes).                               |
| `0x10`       | FILE_WRITE_EA                  | Ghi thuộc tính mở rộng.                                                    |
| `0x20`       | FILE_EXECUTE                   | Thực thi file (dành cho file .exe, .bat).                                  |
| `0x10000`    | FILE_TRAVERSE                  | Truy cập thư mục (dành cho thư mục).                                       |
| `0x100000`   | FILE_DELETE_CHILD              | Xóa file/thư mục con.                                                      |

---

### **Phân Tích Mối Liên Hệ Giữa Các Fields**
- **ObjectName**: Nếu file truy cập nằm trong thư mục nhạy cảm (ví dụ: `C:\Windows\System32\`), đây có thể là dấu hiệu của hành vi leo thang đặc quyền.
- **AccessMask**: Kết hợp với **ProcessName** để xác định tiến trình có quyền truy cập bất thường.
- **PrivilegeList**: Nếu tiến trình có quyền **SeBackupPrivilege** hoặc **SeRestorePrivilege**, đây có thể là dấu hiệu của hành vi trộm cắp dữ liệu.

---

## **4. Event ID 4657: Registry Value Modification**
**Mô tả:**
Được ghi lại khi một **giá trị trong Registry** được sửa đổi. Registry là cơ sở dữ liệu quan trọng lưu trữ cấu hình hệ thống, vì vậy bất kỳ thay đổi nào đều có thể ảnh hưởng đến bảo mật.

**Công dụng:**
- Phát hiện chỉnh sửaRegistry trái phép (ví dụ: malware thay đổi giá trị khởi động)
- Phân tích hành vi của các tiến trình độc hại
- Theo dõi thay đổi cấu hình hệ thống

---

### **Các Fields quan trọng trong Event ID 4657**

| **Field**               | **Ý nghĩa**                                                                                     | **Ví dụ**                                                                 |
|-------------------------|-------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| **SubjectUserSid**      | SID của người dùng khởi tạo sửa đổi.                                                          | `S-1-5-21-123456789-1234567890-123456789-1001`                           |
| **SubjectUserName**     | Tên người dùng khởi tạo sửa đổi.                                                              | `admin`                                                                   |
| **SubjectDomainName**   | Domain của người dùng.                                                                         | `DOMAIN`                                                                  |
| **SubjectLogonId**      | Logon ID của phiên đăng nhập liên quan.                                                         | `0x3e7`                                                                   |
| **ObjectServer**        | Tên của dịch vụ Object (thường là **Security**).                                               | `Security`                                                                |
| **ObjectType**          | Loại đối tượng Registry.                                                                        | `Key`                                                                     |
| **ObjectName**          | Đường dẫn đầy đủ của key Registry bị sửa đổi.                                                  | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`                     |
| **HandleId**            | ID của handle truy cập Registry.                                                              | `0x12345678`                                                             |
| **OperationType**       | Loại thao tác (ví dụ: **RegistryValueSet**).                                                   | `RegistryValueSet`                                                        |
| **RegistryValue**       | Tên giá trị Registry bị sửa đổi.                                                              | `MyMalware`                                                              |
| **RegistryDataType**    | Kiểu dữ liệu của giá trị Registry.                                                             | `REG_SZ`                                                                  |
| **RegistryData**        | Giá trị mới được thiết lập.                                                                    | `C:\Malware\malware.exe`                                                  |
| **ProcessId**           | PID của tiến trình sửa đổi Registry.                                                          | `4120`                                                                    |
| **ProcessName**         | Đường dẫn đầy đủ của tiến trình sửa đổi.                                                      | `C:\Windows\System32\regedit.exe`                                        |

---

### **Phân Tích Mối Liên Hệ Giữa Các Fields**
- **RegistryValue**: Nếu giá trị Registry nằm trong danh sách khởi động (ví dụ: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`), đây có thể là dấu hiệu của malware.
- **RegistryData**: Kiểm tra xem giá trị mới có trỏ đến một file lạ hay không.
- **ProcessName**: Nếu tiến trình sửa đổi Registry không phải là `regedit.exe` hoặc `svchost.exe`, đây có thể là dấu hiệu của hành vi độc hại.

---


