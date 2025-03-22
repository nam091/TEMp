import os
import sys
from time import time
from PIL import Image
from Crypt import AESCipher
import struct
from check_file_type import file_type as ftype
import codecs
from bitarray import bitarray


def Image_Steganography(action: int, input_image_path: str, output_path: str, secret_file_path: str, lsb_bits: int, compress_level: int, password: str):
    """
    Main function for steganography operations.
    
    Args:
        input_image_path: Địa chỉ ảnh gốc
        output_path: Địa chỉ ảnh kết quả
        secret_file_path: Địa chỉ file bí mật để ẩn
        lsb_bits: Số bit ít quan trọng để sử dụng
        action: 0: Embed, 1: Decode
        compress_level: Mức Nén ảnh PNG
        password: Mật khẩu để mã hóa dữ liệu
    """
    
    def count_lsb_bits(img):
        (width, height) = img.size # Lấy kích thước ảnh
        conv = img.convert("RGBA")
        lsb_bit_count = 0    
        for h in range(height):
            for w in range(width):
                r, g, b, a = conv.getpixel((w, h))
                lsb_bit_count += sum((r >> bit) & 1 for bit in range(lsb_bits)) # Đếm số bit ít quan trọng trong kênh màu red
                lsb_bit_count += sum((g >> bit) & 1 for bit in range(lsb_bits)) # Đếm số bit ít quan trọng trong kênh màu green
                lsb_bit_count += sum((b >> bit) & 1 for bit in range(lsb_bits)) # Đếm số bit ít quan trọng trong kênh màu blue
        print(f"[+] Kích thước ảnh: {width}x{height} pixels")
        print(f"[+] Tổng số lượng bits lsb của ảnh: {lsb_bit_count} bits")
        print(f"[+] Số lượng bits lsb có thể sử dụng: {lsb_bit_count // lsb_bits} bits")
        return lsb_bit_count // lsb_bits if lsb_bits > 0 else 1
    
    def decompose(data):
        v = bitarray()
        
        fSize = len(data)
        size_bytes = struct.pack("i", fSize)
        
        v.frombytes(size_bytes)
        v.frombytes(data)
        
        return v

    def assemble(v):
        bytes_data = bytearray() # Khởi tạo mảng bytes_data rỗng
        length = len(v)
        for idx in range(0, len(v) // 8): # Duyệt qua từng byte (8 bit) của mảng v
            byte = 0
            for i in range(0, 8): # Duyệt qua từng bit trong byte
                if (idx * 8 + i < length): # Duyệt đến khi hết mảng v
                    byte = (byte << 1) + v[idx * 8 + i] # Thêm bit thứ i vào byte
            bytes_data.append(byte) # Ghi byte vào mảng bytes_data
        payload_size = struct.unpack("i", bytes_data[:4])[0] # Đọc kích thước payload từ 4 byte đầu
        return bytes_data[4: payload_size + 4] # Trả về dữ liệu từ byte thứ 4 đến byte thứ 4 + kích thước payload

    def set_bit(n, i, x):
        mask = 1 << i # Tạo mask với bit thứ i bằng 1, các bit khác bằng 0
        n &= ~mask # Đặt bit thứ i của n bằng 0
        if x:  # Nếu x = 1
            n |= mask # Đặt bit thứ i của n bằng 1
        return n # Trả về giá trị n mới

    def Embed(imgFile, output_path, payload, password):
        # Phương pháp nhúng mới - nhúng dữ liệu trực tiếp vào byte màu
        # thay vì chuyển đổi thành mảng bit
        
        # Process source image
        print("[+] Bắt đầu nhúng Payload vào ảnh...")
        img = Image.open(imgFile)
        (width, height) = img.size
        original_format = img.format
        original_mode = img.mode
        has_alpha = "A" in original_mode or "transparency" in img.info
        print("[*] Kích thước ảnh: %dx%d pixels." % (width, height))
        max_size = width * height * lsb_bits / 8
        print("[*] Dung lượng của ảnh: %.2f B." % (os.path.getsize(imgFile)))
        
        # Đọc và xử lý payload
        if os.path.isfile(payload):
            with open(payload, "rb") as f:
                data = f.read()
        elif isinstance(payload, str):
            data = payload.encode('utf-8')
        elif isinstance(payload, bytes):
            data = payload
        else:
            raise ValueError("[-] Payload không hợp lệ, cần là đường dẫn file, chuỗi text hoặc bytes")
        
        print("[+] Kích thước Payload: %.3f KB " % (len(data) / 1024.0))
        
        if password:
            cipher = AESCipher(password)
            data_enc = cipher.encrypt_data(data)
        else:
            data_enc = data
        
        # Thêm kích thước payload vào đầu dữ liệu
        fSize = len(data_enc)
        data_with_header = struct.pack("i", fSize) + data_enc
        
        # Tính toán kích thước bit cần thiết
        payload_size = len(data_with_header) * 8
        print("[+] Kích thước sau khi mã hóa: %.3f KB " % (len(data_with_header) / 1024.0))
        
        # Kiểm tra kích thước
        if payload_size / 8 > max_size * 1024 - 4:
            print("[-] Không thể nhúng. Tệp quá lớn")
            sys.exit()
        
        # Tạo ảnh mới
        steg_img = Image.new(original_mode, img.size, (0, 0, 0, 0))
        
        # Tối ưu hóa phần nhúng dữ liệu vào ảnh
        idx = 0

        # Xử lý theo từng dòng để tối ưu hiệu suất
        for h in range(height):
            row_pixels = []
            for w in range(width):
                r, g, b, a = steg_img.getpixel((w, h))
                
                # Xử lý mỗi kênh màu hiệu quả hơn
                if idx < len(data_enc):
                    # Nhúng nhiều bit cùng lúc thay vì vòng lặp
                    for bit in range(lsb_bits):
                        bit_pos = idx + bit * 3
                        if bit_pos < len(data_enc):
                            r = set_bit(r, bit, data_enc[bit_pos])
                        bit_pos = idx + bit * 3 + 1
                        if bit_pos < len(data_enc):
                            g = set_bit(g, bit, data_enc[bit_pos])
                        bit_pos = idx + bit * 3 + 2
                        if bit_pos < len(data_enc):
                            b = set_bit(b, bit, data_enc[bit_pos])
                    
                    idx += 3 * lsb_bits
                
                row_pixels.append((r, g, b, a))
            
            # Đặt cả một dòng pixel cùng lúc
            for w, pixel in enumerate(row_pixels):
                steg_img.putpixel((w, h), pixel)
            
        if not output_path:
            # Giữ định dạng gốc
            ext = os.path.splitext(input_image_path)[1]
            output_path = f"{os.path.splitext(input_image_path)[0]}_encoded{ext}"
        
        if output_path.endswith((".jpg", ".jpeg")):
            img_out = steg_img.convert("RGB")
            quality = 100 - min(compress_level*10, 95)
            img_out.save(output_path, quality=quality)
        else:
            # Giữ định dạng và chế độ màu tương tự ảnh gốc
            if has_alpha:
                img_out = steg_img
            else:
                img_out = steg_img.convert("RGB")
            
            img_out.save(
                output_path,
                format='PNG',
                optimize=True,
                compress_level=compress_level
            )
        print(f"[+] Dung lượng ảnh đã lưu: {os.path.getsize(output_path):.2f} B")
        if password:
            print(f"[+] {payload} đã nhúng thành công với mật khẩu {password}!")
        print(f"[+] Đã lưu tại địa chỉ {output_path}")

    def Recover(in_file, out_file, password):
        print("[+] Bắt đầu khôi phục ảnh...")
        img = Image.open(in_file)
        (width, height) = img.size
        conv = img.convert("RGBA")
        print("[+] Kích thước ảnh: %dx%d pixels." % (width, height))

        bits = [] # Mảng chứa bit của ảnh
        for h in range(height):
            for w in range(width):
                (r, g, b, a) = conv.getpixel((w, h))
                for bit in range(lsb_bits):  
                    bits.append((r >> bit) & 1) # Ghi số bit cuối của kênh màu red vào mảng bits
                    bits.append((g >> bit) & 1) # Ghi số bit cuối của kênh màu green vào mảng bits
                    bits.append((b >> bit) & 1) # Ghi số bit cuối của kênh màu blue vào mảng bits
        data_out = bytes(assemble(bits))        # Gom các bit thành dữ liệu và chuyển thành bytes

        if password:
            cipher = AESCipher(password)
            data_dec = cipher.decrypt_data(data_out)
            if isinstance(data_dec, str):
                data_dec = data_dec.encode('utf-8')
        else:
            data_dec = data_out

        if not out_file:
            out_file = os.path.dirname(in_file) + "/" + os.path.basename(in_file).split(".")[0] + "_decoded"
        if not os.path.isfile(out_file):
            os.makedirs(os.path.dirname(out_file), exist_ok=True) # Tạo thư mục nếu chưa tồn tại
        with open(out_file, "wb") as out_f: # Ghi dữ liệu đã giải mã vào file
            out_f.write(data_dec) # Ghi dữ liệu đã giải mã vào file
        ftype(out_file, password) # Kiểm tra loại file và giải nén nếu cần
        
        if password:
            print(f"[+] File đã khôi phục thành công với mật khẩu {password}!")

    print("=" * 50)
    begin = time()
    match action:
        case 0:
            Embed(input_image_path, output_path, secret_file_path, password)
        case 1:
            Recover(input_image_path, output_path, password)
        case _:
            raise ValueError("[-] Lỗi với các đối số.")
    print(f"[+] Thời gian thực thi: {time() - begin:.2f}s")
    print("=" * 50)