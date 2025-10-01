
<img width="1920" height="958" alt="{6D3A9562-8E6E-472B-8C82-9D2E8DE63AC6}" src="https://github.com/user-attachments/assets/4cd2322d-f450-409b-af05-74b8c1d6f50b" />




# Write-up: Show_Me Reverse Engineering Challenge

نمای کلی چالش




این یک چالش ریورس انجینیرینگ است که در آن یک برنامه C ورودی کاربر را دریافت کرده و آن را به فرمت QR Code تبدیل می‌کند، سپس داده‌های باینری QR Code را به هگزادسیمال تبدیل می‌کند.



# 📋 فهرست مطالب

- [🎯 توضیح کامل تابع FUN_00101525](#توضیح-کامل-تابع-fun_00101525)
- [🎯 توضیح کامل تابع FUN_00101329](#fun_00101329)
- [🎯 توضیح کامل تابع fun_00101454](#step-3-تبدیل-به-hex-تابع-fun_00101454)
- [🔐 مثال](#رمزگذاری-مرحله-به-مرحله-برای-asis-test)
- [💻 پاسخ](#مراحل-حل-چالش-show_me-ctf)


## توضیح کامل تابع FUN_00101525 

---
<img width="1717" height="990" alt="{886DB25D-5534-45D4-B27A-5A752215EEF4}" src="https://github.com/user-attachments/assets/8e327dd5-1fe8-4800-bef8-e3a9bb19d47a" />

## 🧠 نمای کلی

این تابع منطق اصلی برنامه است. ورودی کاربر را می‌گیرد، آن را پدینگ می‌کند، سپس با استفاده از **QR Code** رمزگذاری کرده و در نهایت خروجی را به **هگزادسیمال** تبدیل می‌کند و در ابتدای آن یک **Salt** تصادفی اضافه می‌کند.

در این تحلیل، هر خط کد را با مثال ورودی:

```
ورودی کاربر: flag
طول: ۴ کاراکتر
```

بررسی می‌کنیم تا دقیقاً بفهمیم هر بخش چه کاری انجام می‌دهد.

---

## 🔹 بخش ۱: تعریف متغیرها

```c
undefined8 FUN_00101525(void)
{
  int iVar1;
  time_t tVar2;
  void *__ptr;
  undefined8 uVar3;
  char *pcVar4;
  size_t sVar5;
  long in_FS_OFFSET;
  int local_4b4;
  int local_4b0;
  undefined1 local_498 [849];
  undefined1 local_147 [14];
  undefined1 local_139;
  undefined8 local_138;
  undefined8 local_130;
  undefined1 local_128;
  char local_118 [38];
  undefined1 local_f2;
  long local_10;
```

**توضیح متغیرها:**

| متغیر                                 | توضیح                        |
| ------------------------------------- | ---------------------------- |
| `local_498[849]`                      | ذخیره QR code (ماتریس 29×29) |
| `local_147[14]`                       | رشته تصادفی Salt             |
| `local_138`, `local_130`, `local_128` | جدول کاراکترهای hex          |
| `local_118[38]`                       | بافر ورودی کاربر             |
| `local_4b4`, `local_4b0`              | شمارنده‌های حلقه             |

---

## 🔹 بخش ۲: محافظت از Stack (Stack Canary)

```c
local_10 = *(long *)(in_FS_OFFSET + 0x28);
```

برای جلوگیری از حملات **buffer overflow** استفاده می‌شود. در پایان بررسی می‌شود.

---

## 🔹 بخش ۳: ساخت جدول کاراکترهای Hex

```c
local_138 = 0x3736353433323130;
local_130 = 0x6665646362613938;
local_128 = 0;
```

با در نظر گرفتن Little-Endian:

```
hex_chars = "0123456789abcdef"
```

---

## 🔹 بخش ۴: تولید Salt تصادفی

```c
tVar2 = time((time_t *)0x0);
srand((uint)tVar2);
```

فرض می‌کنیم `time()` مقدار `1727654400` برگرداند. سپس با این مقدار RNG را seed می‌کند.

حلقه تولید Salt:

```c
for (local_4b4 = 0; local_4b4 < 0xe; local_4b4++) {
  iVar1 = rand();
  local_147[local_4b4] = *(undefined1 *)((long)&local_138 + (long)(iVar1 % 0x10));
}
local_139 = 0;
```

### 🔢 نتیجه شبیه‌سازی Salt

| i  | rand()     | %16 | کاراکتر |
| -- | ---------- | --- | ------- |
| 0  | 846930886  | 6   | '6'     |
| 1  | 1681692777 | 9   | '9'     |
| 2  | 1714636915 | 3   | '3'     |
| 3  | 1957747793 | 1   | '1'     |
| 4  | 424238335  | 15  | 'f'     |
| 5  | 719885386  | 10  | 'a'     |
| 6  | 1649760492 | 12  | 'c'     |
| 7  | 596516649  | 9   | '9'     |
| 8  | 1189641421 | 13  | 'd'     |
| 9  | 1025202362 | 10  | 'a'     |
| 10 | 1350490027 | 11  | 'b'     |
| 11 | 783368690  | 2   | '2'     |
| 12 | 1495764371 | 3   | '3'     |
| 13 | 1894536430 | 14  | 'e'     |

📦 **Salt نهایی:** `6931fac9dab23e`

---

## 🔹 بخش ۵: تخصیص حافظه

```c
__ptr = malloc(0xe9);
```

🔸 `0xE9 = 233 بایت`

دلیل: `29 × 8 = 232` کاراکتر هگز + ۱ بایت برای Null Terminator.

---

## 🔹 بخش ۶: دریافت ورودی کاربر

```c
printf("Enter secret text: ");
pcVar4 = fgets(local_118, 0x100, stdin);
```

ورودی کاربر:

```
flag\n
```

پس از ورود:

```
local_118 = { 'f', 'l', 'a', 'g', '\n', '\0' }
```

---

## 🔹 بخش ۷: حذف کاراکتر Newline

```c
sVar5 = strcspn(local_118, "\n");
local_118[sVar5] = '\0';
```

نتیجه:

```
local_118 = "flag"
```

---

## 🔹 بخش ۸: بررسی خالی بودن ورودی

اگر ورودی خالی باشد برنامه متوقف می‌شود — در این مثال ادامه می‌دهد.

---

## 🔹 بخش ۹: Padding تا طول ۳۸ کاراکتر

```c
sVar5 = strlen(local_118);  // sVar5 = 4
local_4b0 = (int)sVar5;

if (local_4b0 < 0x26) {
  for (; local_4b0 < 0x26; local_4b0++) {
    if (local_4b0 % 3 == 0) local_118[local_4b0] = '*';
    else if (local_4b0 % 3 == 1) local_118[local_4b0] = '+';
    else local_118[local_4b0] = '-';
  }
}
```

نتیجه نهایی:

```
flag+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*+
```

طول: ۳۸ کاراکتر ✅

---

## 🔹 بخش ۱۰: تبدیل رشته به QR Code

```c
FUN_00101329(local_118, local_498);
```

رشته را به **ماتریس QR 29×29** تبدیل می‌کند.

---

## 🔹 بخش ۱۱: تبدیل QR به Hexadecimal

```c
FUN_00101454(local_498, __ptr);
```

مثال خروجی:

```
__ptr = "feeb53f882e2f208ba..."
```

---

## 🔹 بخش ۱۲: چاپ خروجی نهایی

```c
printf("Ciphertext: \n%s%s\n", local_147, __ptr);
```

📜 خروجی:

```
Ciphertext:
6931fac9dab23efeeb53f882e2f208ba...
```

```
┌────Salt────┐┌────────────QR────────────┐
6931fac9dab23e feeb53f882e2f208ba...
```

---

## 🔹 بخش ۱۳: آزادسازی حافظه و بررسی Stack Canary

```c
free(__ptr);
return 0;
```

---

## ✅ خلاصه عملکرد تابع (با مثال `flag`)

| مرحله | توضیح               | نتیجه                                 |
| ----- | ------------------- | ------------------------------------- |
| ۱     | تولید Salt          | `6931fac9dab23e`                      |
| ۲     | دریافت ورودی        | `flag`                                |
| ۳     | حذف \n              | `flag`                                |
| ۴     | پدینگ تا ۳۸ کاراکتر | `flag+-*+-*+-*+...`                   |
| ۵     | ساخت QR Code        | ماتریس ۲۹×۲۹                          |
| ۶     | تبدیل به Hex        | `feeb53f882e2f208ba...`               |
| ۷     | ترکیب Salt + QR     | `6931fac9dab23efeeb53f882e2f208ba...` |

📦 **خروجی نهایی:**

```
6931fac9dab23efeeb53f882e2f208ba...
```

---





# FUN_00101329
```c
1   void FUN_00101329(char *param_1, undefined1 *param_2)
2   {
3     int iVar1;
4     uint uVar2;
5     QRcode *pQVar3;
6     long in_FS_OFFSET;
7     int local_34;
8     int local_30;
9     long local_10;
10    
11    local_10 = *(long *)(in_FS_OFFSET + 0x28);
12    pQVar3 = QRcode_encodeString(param_1, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
13    if (pQVar3 == (QRcode *)0x0) {
14      fwrite("QR encoding failed\n", 1, 0x13, stderr);
15      exit(1);
16    }
17    uVar2 = pQVar3->width;
18    memset(param_2, 0, (long)(int)uVar2 * (long)(int)uVar2);
19    for (local_34 = 0; local_34 < (int)pQVar3->width; local_34 = local_34 + 1) {
20      for (local_30 = 0; local_30 < (int)pQVar3->width; local_30 = local_30 + 1) {
21        iVar1 = local_34 * (int)pQVar3->width + local_30;
22        param_2[local_34 * (int)pQVar3->width + local_30] =
23            (undefined1)((uint)pQVar3->data[iVar1] & 1);
24      }
25    }
26    QRcode_free(pQVar3);
27    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
28      __stack_chk_fail();
29    }
30    return;
31  }
```

ورودی مثال ما:

```c
input_string = "flag+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*+"
length = 38 characters
```

خطوط 3-9: تعریف متغیرها

```c
int iVar1;           // متغیر موقت برای محاسبه index
uint uVar2;          // برای ذخیره width ماتریس QR
QRcode *pQVar3;      // pointer به ساختار QRcode
long in_FS_OFFSET;   // offset برای stack canary
int local_34;        // counter سطرها (row)
int local_30;        // counter ستون‌ها (column)
long local_10;       // مقدار canary
```

توضیح هر متغیر:

** QRcode *pQVar3: **

این یک pointer به ساختار زیر است:

```c
typedef struct {
    int version;        // نسخه QR (1 تا 40)
    int width;          // عرض/ارتفاع ماتریس
    unsigned char *data; // آرایه داده‌های QR
} QRcode;
```

مثال:

```c
pQVar3->version = 3      // نسخه 3
pQVar3->width = 29       // ماتریس 29×29
pQVar3->data = [841 bytes]  // 29×29 = 841
```

**in_FS_OFFSET:**

این مقدار مربوط به Stack Canary است که برای امنیت استفاده می‌شود.


خط 11: Stack Canary Initialization

```c
local_10 = *(long *)(in_FS_OFFSET + 0x28);
```

توضیح کامل:

Memory Layout:

```
┌────────────────────┐
│ FS Segment         │
│ …                  │
│ +0x28: canary      │ ← یک مقدار تصادفی
│ …                  │
└────────────────────┘
```

`local_10` = این مقدار را کپی می‌کند.

**هدف:** در پایان تابع، این مقدار چک می‌شود. اگر تغییر کرده باشد یعنی buffer overflow رخ داده!

---

خط 12: تولید QR Code ⭐ **مهمترین خط**

```c
pQVar3 = QRcode_encodeString(param_1, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
```

تحلیل هر پارامتر:

**پارامتر 1:** `param_1` (ورودی)

```c
"flag+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*+"
```

**پارامتر 2:** `0` (Version - Auto)

QR Code نسخه‌های مختلفی دارد:

| Version | Size    | Max Characters (Alphanumeric) |
| ------- | ------- | ----------------------------- |
| 1       | 21×21   | 25                            |
| 2       | 25×25   | 47                            |
| 3       | 29×29   | 77                            |
| 4       | 33×33   | 114                           |
| …       | …       | …                             |
| 40      | 177×177 | 4296                          |

فرمول Size:

```
Size = 17 + 4 × Version
```

مثال:

* Version 1: 17 + 4×1 = 21
* Version 2: 17 + 4×2 = 25
* Version 3: 17 + 4×3 = 29

برای 38 کاراکتر ما، Version 3 (29×29) انتخاب می‌شود.

**پارامتر 3:** `QR_ECLEVEL_L` (Error Correction Level)

چهار سطح تصحیح خطا وجود دارد:

| Level        | Recovery Capacity | Data Capacity | Use Case           |
| ------------ | ----------------- | ------------- | ------------------ |
| L (Low)      | ~7%               | Maximum       | Clean environments |
| M (Medium)   | ~15%              | High          | Normal use         |
| Q (Quartile) | ~25%              | Medium        | Outdoor            |
| H (High)     | ~30%              | Low           | Damaged/dirty      |

مثال عملی:

فرض کنیم QR Code دارای 100 بایت داده است:

* Level L: اگر 7 بایت آسیب ببیند، قابل ترمیم است
* Level H: اگر 30 بایت آسیب ببیند، قابل ترمیم است

اما:

* Level L: می‌تواند 100 بایت داده ذخیره کند
* Level H: فقط می‌تواند ~70 بایت داده ذخیره کند

**پارامتر 4:** `QR_MODE_8` (Encoding Mode)

چند حالت کدگذاری وجود دارد:

| Mode         | Description       | Bits per Character | Example  |
| ------------ | ----------------- | ------------------ | -------- |
| Numeric      | فقط اعداد 0-9     | 3.33 bits          | "123456" |
| Alphanumeric | 0-9, A-Z, symbols | 5.5 bits           | "HELLO"  |
| Byte (8-bit) | هر بایت           | 8 bits             | "flag±*" |
| Kanji        | کاراکترهای ژاپنی  | 13 bits            | "日本"     |

چرا **MODE_8**؟

```c
"flag+-*+-*..."
 ↑    ↑↑
 حروف  کاراکترهای خاص
```

نیاز به Byte mode داریم چون کاراکترهای ASCII معمولی + ویژه داریم.

**پارامتر 5:** `1` (Case Sensitive)

```c
1 = Case Sensitive (حساس به حروف بزرگ/کوچک)
0 = Case Insensitive
```

مثال:

* `"Flag"` ≠ `"flag"`  (با 1)
* `"Flag"` = `"flag"`  (با 0)




جریان درونی QRcode_encodeString:

```
┌────────────────────────────────────────┐

│ 1. تحلیل ورودی و انتخاب Mode │

│ “flag±*…” → Byte Mode │

└────────────────────────────────────────┘

↓

┌────────────────────────────────────────┐

│ 2. محاسبه Version مناسب │

│ 38 chars → Version 3 (29×29) │

└────────────────────────────────────────┘

↓

┌────────────────────────────────────────┐

│ 3. تبدیل به Binary Stream │

│ “flag” → 01100110 01101100… │

└────────────────────────────────────────┘

↓

┌────────────────────────────────────────┐

│ 4. افزودن Error Correction Codes │

│ Reed-Solomon Algorithm │

└────────────────────────────────────────┘

↓

┌────────────────────────────────────────┐

│ 5. قرار دادن در ماتریس │

│ Masking, Patterns, etc. │

└────────────────────────────────────────┘

↓

┌────────────────────────────────────────┐

│ نتیجه: ماتریس 29×29 │

└────────────────────────────────────────┘
```

---

خطوط 13-16: بررسی خطا

```c
if (pQVar3 == (QRcode *)0x0) {
    fwrite("QR encoding failed\n", 1, 0x13, stderr);
    exit(1);
}
```

**چه زمانی NULL برمی‌گردد؟**

* حافظه کافی نیست (malloc failed)
* ورودی خیلی بزرگ است (بیش از Version 40)
* کاراکترهای نامعتبر در ورودی

**مثال:**

```c
// ورودی 3000 کاراکتری
char huge[3000];
QRcode_encodeString(huge, ...) → NULL (خیلی بزرگ!)
```

---

خط 17: ذخیره Width

```c
uVar2 = pQVar3->width;
```

**برای مثال ما:**

```c
uVar2 = 29  // ماتریس 29×29
```

---

خط 18: پاک کردن آرایه خروجی

```c
memset(param_2, 0, (long)(int)uVar2 * (long)(int)uVar2);
```

**محاسبه دقیق:**

```c
width = 29
size = 29 × 29 = 841 bytes

memset(param_2, 0, 841)
```

**عملیات:**

قبل از memset:

param_2 = [garbage, garbage, garbage, …]

بعد از memset:

param_2 = [0, 0, 0, 0, 0, …, 0] (841 zero)



خطوط 19-25: حلقه‌های اصلی ⭐

```c
for (local_34 = 0; local_34 < (int)pQVar3->width; local_34 = local_34 + 1) {
    for (local_30 = 0; local_30 < (int)pQVar3->width; local_30 = local_30 + 1) {
        iVar1 = local_34 * (int)pQVar3->width + local_30;
        param_2[local_34 * (int)pQVar3->width + local_30] =
            (undefined1)((uint)pQVar3->data[iVar1] & 1);
    }
}
```

شبیه‌سازی کامل با ماتریس واقعی:

فرض کنیم QR کوچک 5×5 داریم:

QR Matrix (5×5):

Col 0 1 2 3 4

Row ┌─────────────────┐

0 │ 1 1 1 0 0 │

1 │ 1 0 0 1 1 │

2 │ 1 0 1 0 1 │

3 │ 0 1 1 1 0 │

4 │ 0 1 0 0 1 │

└─────────────────┘

نمایش در pQVar3->data:

Index: 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24

Value: 1 1 1 0 0 1 0 0 1 1 1 0 1 0 1 0 1 1 1 0 0 1 0 0 1

Row: |← Row 0 →| |← Row 1 →| |← Row 2 →| |← Row 3 →| |← Row 4 →|

حلقه iteration by iteration:
Iteration 1: row=0, col=0

```c
local_34 = 0  (row)
local_30 = 0  (col)

iVar1 = 0 * 5 + 0 = 0

param_2[0] = pQVar3->data[0] & 1
           = 1 & 1
           = 1
```

param_2:

┌───┬───┬───┬───┬───┐

│ 1 │ ? │ ? │ ? │ ? │

└───┴───┴───┴───┴───┘

↑

filled

Iteration 2: row=0, col=1

```c
local_34 = 0
local_30 = 1

iVar1 = 0 * 5 + 1 = 1

param_2[1] = pQVar3->data[1] & 1
           = 1 & 1
           = 1
```

Iteration 3-5: row=0, col=2,3,4

```c
param_2[2] = data[2] & 1 = 1
param_2[3] = data[3] & 1 = 0
param_2[4] = data[4] & 1 = 0
```

بعد از تمام شدن سطر 0:

param_2:

┌───┬───┬───┬───┬───┬───┐

│ 1 │ 1 │ 1 │ 0 │ 0 │ ? │ …

└───┴───┴───┴───┴───┴───┘

└─────Row 0─────┘

Iteration 6: row=1, col=0

```c
local_34 = 1
local_30 = 0

iVar1 = 1 * 5 + 0 = 5

param_2[5] = pQVar3->data[5] & 1
           = 1 & 1
           = 1
```

ادامه تا پایان…

```c
Iteration  Row Col  Index  Value
─────────────────────────────────
    1       0   0     0      1
    2       0   1     1      1
    3       0   2     2      1
    4       0   3     3      0
    5       0   4     4      0
    6       1   0     5      1
    7       1   1     6      0
    8       1   2     7      0
    9       1   3     8      1
   10       1   4     9      1
   11       2   0    10      1
    ...
   25       4   4    24      1
```

نتیجه نهایی param_2:

<img width="1202" height="153" alt="{3884F1BC-8247-414E-BB11-69493E54142F}" src="https://github.com/user-attachments/assets/6edff912-139c-401b-be84-068e90ab6030" />


عملیات & 1 چیست؟
pQVar3->data[i] می‌تواند مقادیر مختلفی داشته باشد:

مثال 1:

data[i] = 0x00 (0000 0000)

& 0x01 (0000 0001)

─────────────────

0x00 (0000 0000) → 0 (white)

مثال 2:

data[i] = 0x01 (0000 0001)

& 0x01 (0000 0001)

─────────────────

0x01 (0000 0001) → 1 (black)

مثال 3:

data[i] = 0xFF (1111 1111)

& 0x01 (0000 0001)

─────────────────

0x01 (0000 0001) → 1 (black)

نتیجه: فقط بیت کم‌ارزش (LSB) استخراج می‌شود.
برای ماتریس 29×29 واقعی:

```c
Total iterations = 29 × 29 = 841

Row  0: param_2[0..28]   = 29 bytes
Row  1: param_2[29..57]  = 29 bytes
Row  2: param_2[58..86]  = 29 bytes
...
Row 28: param_2[812..840]= 29 bytes
```

**Formula:**

```python
def get_pixel(row, col):
    index = row * 29 + col
    return param_2[index]

# مثال:
pixel_at_10_15 = param_2[10 * 29 + 15]
                = param_2[305]
```

---

خط 26: آزادسازی حافظه

```c
QRcode_free(pQVar3);
```

**چرا لازم است؟**

```c
QRcode_encodeString() {
    QRcode *qr = malloc(sizeof(QRcode));
    qr->data = malloc(width * width);
    ...
    return qr;  // حافظه allocated شده برگشت داده می‌شود
}
```

اگر `QRcode_free` فراخوانی نشود → **Memory Leak!**

بدون free:

* Iteration 1: 841 bytes leaked
* Iteration 2: 841 bytes leaked
* Iteration 3: 841 bytes leaked
* …
* After 1000 calls: 841 KB leaked!

---

خطوط 27-29: Stack Canary Check

```c
if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
}
```

چک می‌کند:

* ابتدای تابع: local_10 = 0xDEADBEEFCAFEBABE (مقدار تصادفی)
* انتهای تابع: canary = 0xDEADBEEFCAFEBABE ؟

اگر YES → همه چیز OK
اگر NO → Buffer overflow! → CRASH

**مثال Buffer Overflow:**

```c
char buffer[10];
strcpy(buffer, "این رشته خیلی بلند است!");  // Overflow!
```

* canary آسیب می‌بیند
* `__stack_chk_fail()` فراخوانی می‌شود
* برنامه crash می‌کند

---



# Step 3: تبدیل به Hex (تابع FUN_00101454)

این قلب اصلی رمزگذاری است!

## کد کامل

```c
void FUN_00101454(byte *qr_matrix, char *hex_output) {
    uint uVar1;
    byte bVar2;
    int row;
    int bit_index;
    
    for (row = 0; row < 29; row = row + 1) {
        uVar1 = 0;  // جمع‌کننده 8-bit
        
        for (bit_index = 0; bit_index < 8; bit_index = bit_index + 1) {
            if (bit_index < 5) {
                bVar2 = qr_matrix[bit_index * 29 + row];  // توجه: transpose!
            }
            else {
                bVar2 = 0;  // padding با 0
            }
            uVar1 = uVar1 << 1 | (uint)bVar2;
        }
        
        sprintf(hex_output + row * 2, "%02x", (ulong)uVar1);
    }
    
    hex_output[58] = '\0';
}
```

## درک عمیق الگوریتم

### نکته کلیدی: Transpose!

```c
qr_matrix[bit_index * 29 + row]
```

این ستون‌ها را می‌خواند، نه سطرها!

معادل:

```python
value = qr_matrix[column][row]  # transpose of normal indexing
```

## شبیه‌سازی کامل با مثال

فرض کنیم بخش کوچکی از QR:

QR Matrix (29×29):

```
Col0 Col1 Col2 Col3 Col4
Row0: 1 0 1 1 0
Row1: 0 1 0 1 1
Row2: 1 1 1 0 0
Row3: 0 0 1 1 1
Row4: 1 1 0 0 1
...
```

### پردازش Row 0

```python
row = 0
uVar1 = 0b00000000

# bit_index = 0
bVar2 = qr_matrix[0*29 + 0] = qr_matrix[0]   # Row0, Col0 = 1
uVar1 = (0b00000000 << 1) | 1 = 0b00000001

# bit_index = 1
bVar2 = qr_matrix[1*29 + 0] = qr_matrix[29]  # Row0, Col1 = 0
uVar1 = (0b00000001 << 1) | 0 = 0b00000010

# bit_index = 2
bVar2 = qr_matrix[2*29 + 0] = qr_matrix[58]  # Row0, Col2 = 1
uVar1 = (0b00000010 << 1) | 1 = 0b00000101

# bit_index = 3
bVar2 = qr_matrix[3*29 + 0] = qr_matrix[87]  # Row0, Col3 = 1
uVar1 = (0b00000101 << 1) | 1 = 0b00001011

# bit_index = 4
bVar2 = qr_matrix[4*29 + 0] = qr_matrix[116] # Row0, Col4 = 0
uVar1 = (0b00001011 << 1) | 0 = 0b00010110

# bit_index = 5,6,7 (padding)
uVar1 = 0b10110000
```

### خروجی

```c
sprintf(hex_output + 0*2, "%02x", 0xB0);
// hex_output[0..1] = "b0"
```

### نمودار Bit Shifting

```
Initial: 00000000
Shift+OR 1: 00000001 (Col0)
Shift+OR 0: 00000010 (Col1)
Shift+OR 1: 00000101 (Col2)
Shift+OR 1: 00001011 (Col3)
Shift+OR 0: 00010110 (Col4)
Shift+OR 0: 00101100 (padding)
Shift+OR 0: 01011000 (padding)
Shift+OR 0: 10110000 (padding)
Final: 0xB0
```

## مثال کامل با 3 سطر

QR Matrix:

```
Col0 Col1 Col2 Col3 Col4
Row0: 1 0 1 1 0 → 0xB0
Row1: 0 1 0 1 1 → 0x58
Row2: 1 1 1 0 0 → 0xE0
```

خروجی:

```c
hex_output = "b058e0..."
```

## چرا Transpose؟

* Normal row-major: [Row0_Col0, Row0_Col1, …]
* This algorithm: [Row0_Col0, Row1_Col0, …, Row28_Col0]

**دلیل احتمالی:**

* افزایش پیچیدگی reverse engineering
* ایجاد dependency بین سطرهای مختلف
* الگوی غیرمعمول داده

## محاسبه دقیق Indices

```c
index = bit_index * 29 + row
```

جدول indices برای row=0:

| bit_index | محاسبه | Index | موقعیت     |
| --------- | ------ | ----- | ---------- |
| 0         | 0*29+0 | 0     | Row0, Col0 |
| 1         | 1*29+0 | 29    | Row0, Col1 |
| 2         | 2*29+0 | 58    | Row0, Col2 |
| 3         | 3*29+0 | 87    | Row0, Col3 |
| 4         | 4*29+0 | 116   | Row0, Col4 |
| 5         | -      | -     | Padding 0  |
| 6         | -      | -     | Padding 0  |
| 7         | -      | -     | Padding 0  |

```

### تست با داده واقعی
- فقط 5 ستون اول استفاده می‌شود
- Every row produces: 0b10110000 = 0xB0
- Output: 29 repetitions of “b0” → 58 chars

## نکات مهم
1. فقط 5 ستون اول استفاده می‌شود (145 پیکسل از 841)
2. 3 Bit Padding: [Col0..Col4, 0,0,0]
3. Big-Endian Bit Order: اولین bit خوانده شده → MSB

```

🔢 **Step 3: تبدیل به Hex (تابع FUN_00101454)**

این قلب اصلی رمزگذاری است!

```c
void FUN_00101454(byte *qr_matrix, char *hex_output) {
    uint uVar1;
    byte bVar2;
    int row;
    int bit_index;
    
    for (row = 0; row < 29; row = row + 1) {
        uVar1 = 0;  // جمع‌کننده 8-bit
        
        for (bit_index = 0; bit_index < 8; bit_index = bit_index + 1) {
            if (bit_index < 5) {
                bVar2 = qr_matrix[bit_index * 29 + row];  // توجه: transpose!
            }
            else {
                bVar2 = 0;  // padding با 0
            }
            uVar1 = uVar1 << 1 | (uint)bVar2;
        }
        
        sprintf(hex_output + row * 2, "%02x", (ulong)uVar1);
    }
    
    hex_output[58] = '\0';
}
```

---

### 🧠 درک عمیق الگوریتم

**نکته کلیدی: Transpose!**

```c
qr_matrix[bit_index * 29 + row]
```

این ستون‌ها را می‌خواند، نه سطرها!

معادل در پایتون:

```python
value = qr_matrix[column][row]  # transpose of normal indexing
```

### 📐 شبیه‌سازی کامل با مثال

فرض کنیم بخش کوچکی از QR:

**QR Matrix (29×29):**

|      | Col0 | Col1 | Col2 | Col3 | Col4 |
| ---- | ---- | ---- | ---- | ---- | ---- |
| Row0 | 1    | 0    | 1    | 1    | 0    |
| Row1 | 0    | 1    | 0    | 1    | 1    |
| Row2 | 1    | 1    | 1    | 0    | 0    |
| Row3 | 0    | 0    | 1    | 1    | 1    |
| Row4 | 1    | 1    | 0    | 0    | 1    |
| ...  | ...  | ...  | ...  | ...  | ...  |

هر ردیف با 8 بیت گرفته می‌شود: 5 بیت داده + 3 بیت padding.

---


### پردازش Row 0 (FUN_00101454)

```python
row = 0
uVar1 = 0b00000000

# bit_index = 0
bVar2 = qr_matrix[0*29 + 0] = qr_matrix[0]   # Row0, Col0 = 1
uVar1 = (0b00000000 << 1) | 1 = 0b00000001

# bit_index = 1
bVar2 = qr_matrix[1*29 + 0] = qr_matrix[29]  # Row0, Col1 = 0
uVar1 = (0b00000001 << 1) | 0 = 0b00000010

# bit_index = 2
bVar2 = qr_matrix[2*29 + 0] = qr_matrix[58]  # Row0, Col2 = 1
uVar1 = (0b00000010 << 1) | 1 = 0b00000101

# bit_index = 3
bVar2 = qr_matrix[3*29 + 0] = qr_matrix[87]  # Row0, Col3 = 1
uVar1 = (0b00000101 << 1) | 1 = 0b00001011

# bit_index = 4
bVar2 = qr_matrix[4*29 + 0] = qr_matrix[116] # Row0, Col4 = 0
uVar1 = (0b00001011 << 1) | 0 = 0b00010110

# bit_index = 5 (padding)
bVar2 = 0
uVar1 = (0b00010110 << 1) | 0 = 0b00101100

# bit_index = 6 (padding)
bVar2 = 0
uVar1 = (0b00101100 << 1) | 0 = 0b01011000

# bit_index = 7 (padding)
bVar2 = 0
uVar1 = (0b01011000 << 1) | 0 = 0b10110000

# نتیجه نهایی
uVar1 = 0b10110000 = 0xB0
```

### خروجی

```c
sprintf(hex_output + 0*2, "%02x", 0xB0); // hex_output[0..1] = "b0"
```

### 🔄 نمودار Bit Shifting

```
Initial: 00000000
Shift+OR 1: 00000001 (read col0)
Shift+OR 0: 00000010 (read col1)
Shift+OR 1: 00000101 (read col2)
Shift+OR 1: 00001011 (read col3)
Shift+OR 0: 00010110 (read col4)
Shift+OR 0: 00101100 (padding)
Shift+OR 0: 01011000 (padding)
Shift+OR 0: 10110000 (padding)
^^^^^^^^
Final: 0xB0
```

**ترتیب Bits:** MSB ← Col0, Col1, …, Col4, 0, 0, 0 → LSB
 مثال کامل با 3 سطر

QR Matrix:

Col0 Col1 Col2 Col3 Col4
Row0: 1 0 1 1 0 → 0b10110000 → 0xB0
Row1: 0 1 0 1 1 → 0b01011000 → 0x58
Row2: 1 1 1 0 0 → 0b11100000 → 0xE0

خروجی:

<img width="1039" height="543" alt="{55127C43-DDAF-425D-8D2E-29DED7CE1949}" src="https://github.com/user-attachments/assets/ff682dd7-250c-4686-bb8e-24e7795f00f9" />


🔢 محاسبه دقیق Indices

```c
index = bit_index * 29 + row
```

جدول indices برای row=0:

| bit_index | محاسبه | Index | موقعیت در ماتریس |
| --------- | ------ | ----- | ---------------- |
| 0         | 0×29+0 | 0     | Row0, Col0       |
| 1         | 1×29+0 | 29    | Row0, Col1       |
| 2         | 2×29+0 | 58    | Row0, Col2       |
| 3         | 3×29+0 | 87    | Row0, Col3       |
| 4         | 4×29+0 | 116   | Row0, Col4       |
| 5         | -      | -     | Padding (0)      |
| 6         | -      | -     | Padding (0)      |
| 7         | -      | -     | Padding (0)      |

جدول indices برای row=5:

| bit_index | محاسبه | Index | موقعیت     |
| --------- | ------ | ----- | ---------- |
| 0         | 0×29+5 | 5     | Row5, Col0 |
| 1         | 1×29+5 | 34    | Row5, Col1 |
| 2         | 2×29+5 | 63    | Row5, Col2 |
| 3         | 3×29+5 | 92    | Row5, Col3 |
| 4         | 4×29+5 | 121   | Row5, Col4 |

تست با داده واقعی:
فرض کنیم 5 ستون اول تمام سطرها:

All rows have: Col0=1, Col1=0, Col2=1, Col3=1, Col4=0

Every row produces: 0b10110000 = 0xB0

Output:
"b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0" (58 chars)
└─ 29 repetitions of “b0”

⚠️ نکات مهم:

1. فقط 5 ستون اول استفاده می‌شود:

   * 29×29 matrix → فقط 29×5 = 145 پیکسل
   * Remaining 29×24 = 696 پیکسل نادیده گرفته می‌شوند!
   * چرا؟ احتمالاً:

     * کاهش سایز خروجی (58 char vs 212 char)
     * 5 ستون کافی برای encoding منحصر بفرد است
     * بقیه QR برای error correction و metadata

2. 3 Bit Padding:

   * 8 bits total: [Col0, Col1, Col2, Col3, Col4, 0, 0, 0]
     ────┬─────────────────────────┬─────
     Data (5 bits)  Padding (3 bits)
   * این باعث می‌شود: هر byte همیشه bit های پایین صفر باشد
   * Range مقادیر: 0x00-0xF8 (مضرب 8)

3. Big-Endian Bit Order:

```c
uVar1 = uVar1 << 1 | bVar2;
```

* اولین bit خوانده شده → MSB می‌شود.


# رمزگذاری مرحله به مرحله برای ASIS{test}

## 📌 ورودی اولیه

```
ASIS{test}
```

* طول: 10 کاراکتر

---

## مرحله 1: Padding

طول ورودی: 10 کاراکتر

* نیاز به padding: 28 کاراکتر (برای رسیدن به 38)
* موقعیت شروع padding: 10
* الگوی padding بر اساس `index mod 3`:

  * 1 → `+`
  * 2 → `-`
  * 0 → `*`

### مراحل

```
موقعیت 10: 10 mod 3 = 1 → +
موقعیت 11: 11 mod 3 = 2 → -
موقعیت 12: 12 mod 3 = 0 → *
موقعیت 13: 13 mod 3 = 1 → +
```

... ادامه تا موقعیت 37

### خروجی بعد از Padding

```
ASIS{test}+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*-
```

* طول: 38 کاراکتر

---

## مرحله 2: تولید QR Code

* ورودی: `ASIS{test}+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*-`
* تنظیمات: ECLevel=L, Mode=8-bit
* خروجی: ماتریس باینری 29×29

### نمونه ماتریس (5 سطر اول از 29)

```
[1,1,1,1,1,1,1,0,1,0,1,0,0,1,0,1,1,1,1,1,1,1,1,0,1,0,1,1,0]
[1,0,0,0,0,0,1,0,0,1,0,1,1,0,1,0,1,0,0,0,0,0,1,0,0,1,1,0,1]
[1,0,1,1,1,0,1,0,1,0,1,0,1,1,0,1,0,0,1,1,1,0,1,0,1,0,0,1,0]
[1,0,1,1,1,0,1,0,1,1,0,1,0,0,1,0,1,0,1,1,1,0,1,0,1,1,1,0,1]
[1,0,1,1,1,0,1,0,0,1,1,1,0,1,1,1,0,0,1,1,1,0,1,0,0,0,1,1,0]
```

... (24 سطر دیگر)

---

## مرحله 3: تبدیل به Hex (خواندن ستونی)

### نمونه محاسبات

* ستون 0 (5 بیت اول): `[1,1,1,1,1]` → `0b11111000` → 248 → `0xF8`
* ستون 1 (5 بیت اول): `[1,0,0,0,0]` → `0b10000000` → 128 → `0x80`
* ستون 2 (5 بیت اول): `[1,0,1,1,1]` → `0b11011000` → 216 → `0xD8`

### خروجی مرحله 3 (فرضی)

```
f880d8f8f840a8604050d8a8f8f840f840a850f0d8a050d8e8f860
```

* طول: 58 کاراکتر (29 بایت × 2)

---

## مرحله 4: اضافه کردن Prefix

* Prefix تصادفی تولید شده از seed بر اساس زمان:

```
Ky7Xm2Qp9Vs1L
```

* طول: 14 کاراکتر

### خروجی نهایی

```
Ky7Xm2Qp9Vs1Lf880d8f8f840a8604050d8a8f8f840f840a850f0d8a050d8e8f860
```

* طول: 72 کاراکتر

---

## 📝 خلاصه نهایی

| مرحله          | خروجی                                                               | طول |
| -------------- | ------------------------------------------------------------------- | --- |
| ورودی          | ASIS{test}                                                          | 10  |
| بعد از Padding | ASIS{test}+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*-                           | 38  |
| بعد از QR      | ماتریس 29×29 باینری                                                 | -   |
| بعد از Hex     | f880d8f8f840a8604050d8a8f8f840f840a850f0d8a050d8e8f860              | 58  |
| خروجی نهایی    | Ky7Xm2Qp9Vs1Lf880d8f8f840a8604050d8a8f8f840f840a850f0d8a050d8e8f860 | 72  |

⚠️ توجه: مقادیر Hex و Prefix در بالا فرضی هستند. برای داده واقعی باید کد با کتابخانه `libqrencode` اجرا شود.





# 📋 مراحل حل چالش Show_Me CTF

## مرحله 1: تحلیل باینری (Reverse Engineering)

ابتدا باید فایل اجرایی را با ابزارهای مهندسی معکوس تحلیل کنیم:

```bash
# بررسی نوع فایل
file challenge

# دیس‌اسمبل کردن

Ghidra
```

چیزهایی که باید پیدا کنیم:

* ✅ تابع padding (`processEntry`) و الگوی `+-*`
* ✅ استفاده از `libqrencode` برای تولید QR
* ✅ نحوه تبدیل ماتریس QR به hex (خواندن ستونی)
* ✅ اضافه شدن 14 کاراکتر prefix تصادفی

---

## مرحله 2: شناسایی فرمت داده

از تحلیل کد متوجه می‌شویم:

```
خروجی = [14 char random] + [hex از QR code]
```

* Prefix 14 کاراکتری تصادفی باید حذف شود.
* QR Code از نوع Version 3 است (سایز 29×29)
* داده به صورت 4 بایت در هر سطر ذخیره شده (29 سطر × 4 = 116 بایت = 232 کاراکتر hex)
* خواندن داده: سطر به سطر، از MSB به LSB

---

## مرحله 3: نوشتن اسکریپت دیکدر

برعکس فرآیند encode را پیاده‌سازی می‌کنیم:

```python
from PIL import Image
from pyzbar.pyzbar import decode

def decode_ctf_qr(output_path):
    # ── گام 1: خواندن فایل خروجی ──
    hexstr = open(output_path, 'r').read().strip()
    print(f"[+] رشته کامل: {hexstr[:50]}... (طول: {len(hexstr)})")

    # ── گام 2: حذف 14 کاراکتر prefix ──
    prefix = hexstr[:14]
    hex_cipher = hexstr[14:]
    print(f"[+] Prefix: {prefix}")
    print(f"[+] Hex cipher: {hex_cipher[:50]}... (طول: {len(hex_cipher)})")

    # ── گام 3: تبدیل hex به بایت ──
    data = bytes.fromhex(hex_cipher)
    print(f"[+] تعداد بایت‌ها: {len(data)} (انتظار: 116)")

    # ── گام 4: بازسازی ماتریس 29×29 QR ──
    size = 29
    matrix = [[0]*size for _ in range(size)]
    for row in range(size):
        for k in range(4):  # هر سطر 4 بایت
            byte_index = row * 4 + k
            byte = data[byte_index]
            for b in range(8):  # MSB → LSB
                col = k * 8 + b
                if col < size:
                    bit = (byte >> (7 - b)) & 1
                    matrix[row][col] = bit
    print(f"[+] ماتریس {size}×{size} بازسازی شد")

    # ── گام 5: تبدیل ماتریس به تصویر PNG ──
    scale = 10
    img = Image.new('RGB', (size*scale, size*scale), 'white')
    pixels = img.load()
    for y in range(size):
        for x in range(size):
            color = 0 if matrix[y][x] == 1 else 255
            for dy in range(scale):
                for dx in range(scale):
                    pixels[x*scale+dx, y*scale+dy] = (color, color, color)
    img.save('reconstructed_qr.png')
    print("[+] تصویر QR ذخیره شد: reconstructed_qr.png")

    # ── گام 6: اسکن و دیکد QR Code ──
    decoded = decode(img)
    if decoded:
        text = decoded[0].data.decode('utf-8')
        print(f"\n🎉 FLAG: {text}")
        return text
    else:
        print("❌ QR code خوانده نشد!")
        return None

if __name__ == '__main__':
    decode_ctf_qr('output.txt')
```

---

## 🔍 تحلیل دقیق‌تر هر بخش

1. **چرا 14 کاراکتر اول را حذف می‌کنیم؟**

```c
// در کد اصلی:
char prefix[15];
generate_random_prefix(prefix, 14);
strcat(output, prefix);
```

* فقط برای سردرگمی است و اطلاعاتی ندارد.

2. **چرا 116 بایت؟**

* ماتریس QR = 29×29 بیت
* هر سطر = 29 بیت → نیاز به 4 بایت (32 بیت)
* کل داده = 29×4 = 116 بایت

3. **چرا خواندن MSB-first؟**

```python
bit = (byte >> (7 - b)) & 1
```

* مطابق با نحوه encode اصلی.

4. **چرا scale = 10؟**

* برای قابل اسکن شدن QR code توسط pyzbar.

---

## 🚀 اجرای نهایی

```bash
# نصب کتابخانه‌ها
pip install pillow pyzbar

# اجرا
python decode_qr.py
```
