// cgo_callbacks.c
#include <stdint.h>
#include <stddef.h> // Dành cho size_t

// Lấy lại các typedef từ file Go của S
typedef intptr_t (*ReadCallback)(void* ctx, uint8_t* buf, size_t buf_len);
typedef int32_t (*WriteCallback)(void* ctx, const uint8_t* data, size_t data_len);

// ====== ĐÂY LÀ PHẦN QUAN TRỌNG ======
// Khai báo `extern` cho các hàm Go đã được //export
// Báo cho C linker "hãy tin tôi, hàm này tồn tại ở đâu đó"
extern intptr_t goReadCallbackBridge(void* ctx, uint8_t* buf, size_t buf_len);
extern int32_t goWriteCallbackBridge(void* ctx, const uint8_t* data, size_t data_len);

// Đây là các hàm "trampoline" (cầu nối)
// Go sẽ gọi các hàm này. Chúng chỉ đơn giản là
// trả về con trỏ C tới các hàm Go đã export.
ReadCallback get_read_callback() {
    return goReadCallbackBridge;
}

WriteCallback get_write_callback() {
    return goWriteCallbackBridge;
}