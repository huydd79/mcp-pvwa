Bạn là một chuyên gia lập trình Python, DevOps và giải pháp Bảo mật đặc quyền (CyberArk Self-Hosted PAM). Tôi muốn bạn sử dụng `claude-code` để xây dựng một MCP (Model Context Protocol) Server bằng Python nhằm quản lý tài khoản đặc quyền thông qua CyberArk PVWA REST API. Server này yêu cầu phải chạy được trên môi trường Docker.

Dưới đây là các yêu cầu và đặc tả chi tiết:

1. Nguồn đặc tả API:
- Đặc tả lấy từ Bruno collection chuẩn do CyberArk cung cấp, đã tải về thư mục làm việc hiện tại của chúng ta dưới tên thư mục: `CyberArk-REST-API-Bruno`.
- Tập trung vào các bộ API chính cho Self-Hosted PAM tại thư mục: `/Users/huy.do/Documents/Working/Coding/ClaudeCode/mcp-pvwa/CyberArk-REST-API-Bruno/CyberArk Self-Hosted REST API/CyberArk Self-Hosted REST API/Self-Hosted PAM`
  * Authentication (Logon / Logoff)
  * Accounts (Get Accounts, Add Account, Delete Account, Update Account)
  * Safes (Get Safes, Add Safe, Add Safe Member)
  * System Health

2. Kiến trúc MCP Server (Python):
- Ngôn ngữ: Python 3.11+
- MCP hoạt động theo cơ chế streamableHttp như một server độc lập để tích hợp với các mcp gateway khác
- Sử dụng SDK `mcp` chính thức (Khuyến khích sử dụng lớp `FastAPI` nếu phù hợp để đơn giản hóa việc định nghĩa tool).
- Sử dụng thư viện `httpx` (async) để thực hiện các cuộc gọi REST API đến CyberArk PVWA.
- Mỗi REST API endpoint từ Bruno collection phải được ánh xạ thành một MCP Tool bằng decorator (ví dụ: `@mcp.tool()`).
- Đặt tên Tool theo định dạng: `cyberark_[action]_[resource]` (Ví dụ: `cyberark_get_account`).
- Đảm bảo viết đầy đủ Type Hints và Docstring chi tiết cho từng hàm để MCP tự động sinh `inputSchema` chính xác cho LLM khác tiêu thụ.

3. Cơ chế Xác thực & Cấu hình:
- Server nhận cấu hình qua Biến môi trường (Environment Variables): `CYBERARK_PVWA_URL`, `CYBERARK_AUTH_TYPE`, `CYBERARK_USERNAME`, `CYBERARK_PASSWORD`.
- Triển khai cơ chế tự động quản lý Session Token (Tự động Logon khi khởi chạy, lưu token vào bộ nhớ và tự động refresh nếu token hết hạn / trả về lỗi 401).
- Hỗ trợ tùy chọn bỏ qua kiểm tra SSL (bằng cách truyền `verify=False` vào httpx.AsyncClient) cho môi trường Lab.

4. Đóng gói với Docker:
- Viết một `Dockerfile` tối ưu (sử dụng image nền dạng `python:3.11-slim`).
- Quản lý gói phụ thuộc bằng `requirements.txt`.
- Đảm bảo không làm nghẽn luồng stdout bằng cách đặt biến môi trường `PYTHONUNBUFFERED=1` trong Dockerfile để cơ chế giao tiếp `stdio` của MCP hoạt động chính xác.

5. QUY TRÌNH TƯƠNG TÁC VÀ PHẢN HỒI CHỦ ĐỘNG (QUAN TRỌNG):
- Trước khi bắt đầu viết code cho bất kỳ module nào, bạn cần phân tích cấu trúc các file `.bru` liên quan.
- Bạn KHÔNG ĐƯỢC tự ý giả định các tham số phức tạp nếu tài liệu Bruno không nêu rõ.
- Hãy CHỦ ĐỘNG dừng lại và đặt câu hỏi cho tôi nếu:
  * Bạn cần tôi cung cấp nội dung chi tiết của một file `.bru` cụ thể.
  * Bạn phát hiện ra điểm mâu thuẫn trong cách truyền tham số hoặc Header của CyberArk API.
  * Bạn muốn đề xuất giải pháp lưu trữ Session Token tối ưu.
- Tôi muốn chúng ta làm việc theo từng bước (Step-by-step). Sau mỗi bước tạo file cấu hình nền tảng (ví dụ: xong `requirements.txt` và `Dockerfile`), hãy tóm tắt và hỏi ý kiến tôi trước khi tiến hành viết file logic chính (`main.py`).

Hãy bắt đầu bằng việc phân tích cấu trúc dự án và đưa ra câu hỏi hoặc đề xuất đầu tiên của bạn về cách tiếp cận bộ API CyberArk Bruno.