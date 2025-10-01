# decode_qr.py
from PIL import Image
from pyzbar.pyzbar import decode

def decode_ctf_qr(output_path):
    # 1) بخوانیم خروجی هگزا را
    hexstr = open(output_path, 'r').read().strip()
    # 2) 14 کاراکتر اول را دور می‌اندازیم
    hex_cipher = hexstr[14:]
    # 3) به بایت تبدیل می‌کنیم
    data = bytes.fromhex(hex_cipher)  # طول باید 116 باشد

    # 4) ماتریس 29x29 را بازسازی می‌کنیم
    size = 29
    matrix = [[0]*size for _ in range(size)]
    # هر سطر 4 بایت
    for row in range(size):
        for k in range(4):
            byte = data[row*4 + k]
            # هر بیت را از MSB به LSB بگیرید
            for b in range(8):
                col = k*8 + b
                if col < size:
                    bit = (byte >> (7 - b)) & 1
                    matrix[row][col] = bit

    # 5) از ماتریس، یک تصویر PIL می‌سازیم
    scale = 10  # هر سل بزرگنمایی
    img = Image.new('RGB', (size*scale, size*scale), 'white')
    pixels = img.load()
    for y in range(size):
        for x in range(size):
            c = 0 if matrix[y][x] == 1 else 255
            for dy in range(scale):
                for dx in range(scale):
                    pixels[x*scale+dx, y*scale+dy] = (c,c,c)
    img.save('reconstructed_qr.png')
    print("QR code written to reconstructed_qr.png")

    # 6) با pyzbar اسکن می‌کنیم
    decoded = decode(img)
    if decoded:
        text = decoded[0].data.decode('utf-8')
        print("Decoded text:", text)
    else:
        print("No QR code found or cannot decode.")

if __name__ == '__main__':
    decode_ctf_qr('output.txt')
