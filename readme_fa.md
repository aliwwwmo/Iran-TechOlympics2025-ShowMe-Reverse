
<img width="1920" height="958" alt="{6D3A9562-8E6E-472B-8C82-9D2E8DE63AC6}" src="https://github.com/user-attachments/assets/4cd2322d-f450-409b-af05-74b8c1d6f50b" />

# ⚠️ Note: This text was translated from Persian to English using AI. While it should be mostly accurate, some technical nuances or context-specific details may not be perfectly preserved.

---
# Write-up: Show_Me Reverse Engineering Challenge


# 📋 فهرست مراحل توابع

# 📋 Table of Contents

- [Step 3: Convert to Hex (function FUN_00101454)](#step-3-convert-to-hex-function-fun_00101454)
- [Complete explanation of function FUN_00101525](#complete-explanation-of-function-fun_00101525)
- [fun_00101329](#fun_00101329)
- [Encoding walkthrough for ASIS{test}](#encoding-walkthrough-for-asis-test)
- [📋 Steps to solve the Show_Me CTF challenge](#-steps-to-solve-the-show_me-ctf-challenge)

---



## Complete Explanation of Function FUN_00101525

---
# Complete explanation of function FUN_00101525
### 🧠 Overview

This function contains the main logic of the program. It takes the user input, applies padding, encodes it into a **QR Code**, converts the QR data into **hexadecimal**, and finally adds a random **Salt** at the beginning.

In this analysis, each line of code is explained step by step using the following example input:

```
User input: flag
Length: 4 characters
```

---

### 🔹 Section 1: Variable Definitions

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

**Variable Explanation:**

| Variable                              | Description                       |
| ------------------------------------- | --------------------------------- |
| `local_498[849]`                      | Stores the QR Code matrix (29×29) |
| `local_147[14]`                       | Random Salt string                |
| `local_138`, `local_130`, `local_128` | Hexadecimal character table       |
| `local_118[38]`                       | User input buffer                 |
| `local_4b4`, `local_4b0`              | Loop counters                     |

---

### 🔹 Section 2: Stack Protection (Stack Canary)

```c
local_10 = *(long *)(in_FS_OFFSET + 0x28);
```

This line sets up a **stack canary** for preventing **buffer overflow attacks**. It will be checked at the end of the function.

---

### 🔹 Section 3: Creating the Hex Character Table

```c
local_138 = 0x3736353433323130;
local_130 = 0x6665646362613938;
local_128 = 0;
```

Considering the **Little-Endian** format, this creates the following table:

```
hex_chars = "0123456789abcdef"
```

---

### 🔹 Section 4: Generating a Random Salt

```c
tVar2 = time((time_t *)0x0);
srand((uint)tVar2);
```

Assume `time()` returns `1727654400`. This value seeds the random number generator (RNG).

Salt generation loop:

```c
for (local_4b4 = 0; local_4b4 < 0xe; local_4b4++) {
  iVar1 = rand();
  local_147[local_4b4] = *(undefined1 *)((long)&local_138 + (long)(iVar1 % 0x10));
}
local_139 = 0;
```

### 🔢 Simulated Salt Output

| i  | rand()     | %16 | Character |
| -- | ---------- | --- | --------- |
| 0  | 846930886  | 6   | '6'       |
| 1  | 1681692777 | 9   | '9'       |
| 2  | 1714636915 | 3   | '3'       |
| 3  | 1957747793 | 1   | '1'       |
| 4  | 424238335  | 15  | 'f'       |
| 5  | 719885386  | 10  | 'a'       |
| 6  | 1649760492 | 12  | 'c'       |
| 7  | 596516649  | 9   | '9'       |
| 8  | 1189641421 | 13  | 'd'       |
| 9  | 1025202362 | 10  | 'a'       |
| 10 | 1350490027 | 11  | 'b'       |
| 11 | 783368690  | 2   | '2'       |
| 12 | 1495764371 | 3   | '3'       |
| 13 | 1894536430 | 14  | 'e'       |

📦 **Final Salt:** `6931fac9dab23e`

<img width="1717" height="990" alt="{886DB25D-5534-45D4-B27A-5A752215EEF4}" src="https://github.com/user-attachments/assets/8e327dd5-1fe8-4800-bef8-e3a9bb19d47a" />

  ## 🔹 Section 5: Memory Allocation

```c
__ptr = malloc(0xe9);
```

🔸 `0xE9 = 233 bytes`

Reason: `29 × 8 = 232` hex characters + 1 byte for the null terminator.

---

## 🔹 Section 6: Getting User Input

```c
printf("Enter secret text: ");
pcVar4 = fgets(local_118, 0x100, stdin);
```

User input:

```
flag\n
```

After reading:

```
local_118 = { 'f', 'l', 'a', 'g', '\n', '\0' }
```

---

## 🔹 Section 7: Removing the Newline Character

```c
sVar5 = strcspn(local_118, "\n");
local_118[sVar5] = '\0';
```

Result:

```
local_118 = "flag"
```

---

## 🔹 Section 8: Checking for Empty Input

If the input is empty, the program terminates — in this case, it continues.

---

## 🔹 Section 9: Padding to 38 Characters

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

Final Result:

```
flag+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*+
```

Length: 38 characters ✅

---

## 🔹 Section 10: Convert String to QR Code

```c
FUN_00101329(local_118, local_498);
```

This function converts the **input string** into a **29×29 QR matrix**.

---

## 🔹 Section 11: Convert QR to Hexadecimal

```c
FUN_00101454(local_498, __ptr);
```

Example output:

```
__ptr = "feeb53f882e2f208ba..."
```

---

## 🔹 Section 12: Print Final Output

```c
printf("Ciphertext: \n%s%s\n", local_147, __ptr);
```

📜 Output:

```
Ciphertext:
6931fac9dab23efeeb53f882e2f208ba...
```

```
┌────Salt────┐┌────────────QR────────────┐
6931fac9dab23e feeb53f882e2f208ba...
```

---

## 🔹 Section 13: Free Memory & Check Stack Canary

```c
free(__ptr);
return 0;
```

---

## ✅ Function Summary (Example with `flag`)

| Step | Description           | Result                                |
| ---- | --------------------- | ------------------------------------- |
| 1    | Generate Salt         | `6931fac9dab23e`                      |
| 2    | Read Input            | `flag`                                |
| 3    | Remove `\n`           | `flag`                                |
| 4    | Pad to 38 chars       | `flag+-*+-*+-*+...`                   |
| 5    | Build QR Code         | 29×29 Matrix                          |
| 6    | Convert to Hex        | `feeb53f882e2f208ba...`               |
| 7    | Combine Salt + QR Hex | `6931fac9dab23efeeb53f882e2f208ba...` |

📦 **Final Output:**

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

Example input:

```c
input_string = "flag+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*+"
length = 38 characters
```

Lines 3–9: Variable definitions

```c
int iVar1;           // Temporary variable for index calculation
uint uVar2;          // Stores QR matrix width
QRcode *pQVar3;      // Pointer to QRcode structure
long in_FS_OFFSET;   // Stack canary offset
int local_34;        // Row counter
int local_30;        // Column counter
long local_10;       // Canary value
```

### Explanation of Variables:

**QRcode *pQVar3:**

Pointer to the following structure:

```c
typedef struct {
    int version;         // QR version (1–40)
    int width;           // Matrix width/height
    unsigned char *data; // QR data array
} QRcode;
```

Example:

```c
pQVar3->version = 3      // Version 3
pQVar3->width = 29       // 29x29 matrix
pQVar3->data = [841 bytes]  // 29×29 = 841
```

**in_FS_OFFSET:**

This value refers to the Stack Canary used for protection.

---

### Line 11: Stack Canary Initialization

```c
local_10 = *(long *)(in_FS_OFFSET + 0x28);
```

#### Explanation:

Memory Layout:

```
┌────────────────────┐
│ FS Segment         │
│ …                  │
│ +0x28: canary      │ ← Random value
│ …                  │
└────────────────────┘
```

`local_10` copies this value.

**Purpose:** At the end of the function, this value is checked. If it has changed, it indicates a buffer overflow!
Line 12: QR Code Generation ⭐ **Most Important Line**

```c
pQVar3 = QRcode_encodeString(param_1, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
```

### Parameter Analysis

**Parameter 1:** `param_1` (Input String)

```c
"flag+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*+"
```

**Parameter 2:** `0` (Version - Auto)

QR Codes have multiple versions:

| Version | Size    | Max Characters (Alphanumeric) |
| ------- | ------- | ----------------------------- |
| 1       | 21×21   | 25                            |
| 2       | 25×25   | 47                            |
| 3       | 29×29   | 77                            |
| 4       | 33×33   | 114                           |
| …       | …       | …                             |
| 40      | 177×177 | 4296                          |

Formula for size:

```
Size = 17 + 4 × Version
```

Examples:

* Version 1: 17 + 4×1 = 21
* Version 2: 17 + 4×2 = 25
* Version 3: 17 + 4×3 = 29

For a 38-character string, Version 3 (29×29) is selected.

---

**Parameter 3:** `QR_ECLEVEL_L` (Error Correction Level)

There are four error correction levels:

| Level        | Recovery Capacity | Data Capacity | Use Case           |
| ------------ | ----------------- | ------------- | ------------------ |
| L (Low)      | ~7%               | Maximum       | Clean environments |
| M (Medium)   | ~15%              | High          | Normal use         |
| Q (Quartile) | ~25%              | Medium        | Outdoor            |
| H (High)     | ~30%              | Low           | Damaged/dirty      |

**Example:**

Suppose the QR Code contains 100 bytes of data:

* Level L: can recover if 7 bytes are damaged
* Level H: can recover if 30 bytes are damaged

However:

* Level L: can store 100 bytes of data
* Level H: can store only ~70 bytes of data

---

**Parameter 4:** `QR_MODE_8` (Encoding Mode)

Different encoding modes exist:

| Mode         | Description       | Bits per Character | Example  |
| ------------ | ----------------- | ------------------ | -------- |
| Numeric      | Only digits 0–9   | 3.33 bits          | "123456" |
| Alphanumeric | 0–9, A–Z, symbols | 5.5 bits           | "HELLO"  |
| Byte (8-bit) | Any 8-bit char    | 8 bits             | "flag±*" |
| Kanji        | Japanese chars    | 13 bits            | "日本"     |

Why **MODE_8**?

```c
"flag+-*+-*..."
 ↑    ↑↑
 letters special chars
```

We need Byte mode because it contains normal ASCII and special characters.

---

**Parameter 5:** `1` (Case Sensitive)

```c
1 = Case Sensitive
0 = Case Insensitive
```

Example:

* `"Flag" ≠ "flag"` (when 1)
* `"Flag" = "flag"` (when 0)

---

### Internal Flow of `QRcode_encodeString`

```
┌────────────────────────────────────────┐
│ 1. Analyze input & select Mode          │
│ “flag±*…” → Byte Mode                  │
└────────────────────────────────────────┘

↓

┌────────────────────────────────────────┐
│ 2. Determine appropriate Version        │
│ 38 chars → Version 3 (29×29)           │
└────────────────────────────────────────┘

↓

┌────────────────────────────────────────┐
│ 3. Convert to Binary Stream             │
│ “flag” → 01100110 01101100…            │
└────────────────────────────────────────┘

↓

┌────────────────────────────────────────┐
│ 4. Add Error Correction Codes           │
│ Reed-Solomon Algorithm                 │
└────────────────────────────────────────┘

↓

┌────────────────────────────────────────┐
│ 5. Place into Matrix                   │
│ Masking, Patterns, etc.                │
└────────────────────────────────────────┘

↓

┌────────────────────────────────────────┐
│ Result: 29×29 Matrix                   │
└────────────────────────────────────────┘
```

---

### Lines 13–16: Error Checking

```c
if (pQVar3 == (QRcode *)0x0) {
    fwrite("QR encoding failed\n", 1, 0x13, stderr);
    exit(1);
}
```

**When does it return NULL?**

* Not enough memory (malloc failed)
* Input too large (exceeds Version 40)
* Invalid characters in input

**Example:**

```c
// 3000-character input
char huge[3000];
QRcode_encodeString(huge, ...) → NULL (too large!)
```
Line 17: Store Width

```c
uVar2 = pQVar3->width;
```

**For our example:**

```c
uVar2 = 29  // 29×29 matrix
```

---

Line 18: Clear output array

```c
memset(param_2, 0, (long)(int)uVar2 * (long)(int)uVar2);
```

**Exact calculation:**

```c
width = 29
size = 29 × 29 = 841 bytes

memset(param_2, 0, 841)
```

**Operation:**

Before memset:

```
param_2 = [garbage, garbage, garbage, …]
```

After memset:

```
param_2 = [0, 0, 0, 0, 0, …, 0] (841 zeros)
```

---

Lines 19–25: Main Loops ⭐

```c
for (local_34 = 0; local_34 < (int)pQVar3->width; local_34 = local_34 + 1) {
    for (local_30 = 0; local_30 < (int)pQVar3->width; local_30 = local_30 + 1) {
        iVar1 = local_34 * (int)pQVar3->width + local_30;
        param_2[local_34 * (int)pQVar3->width + local_30] =
            (undefined1)((uint)pQVar3->data[iVar1] & 1);
    }
}
```

Full simulation with a real matrix example:

Assume we have a small 5×5 QR code:

QR Matrix (5×5):

| Col   | 0 | 1 | 2 | 3 | 4 |
| ----- | - | - | - | - | - |
| **0** | 1 | 1 | 1 | 0 | 0 |
| **1** | 1 | 0 | 0 | 1 | 1 |
| **2** | 1 | 0 | 1 | 0 | 1 |
| **3** | 0 | 1 | 1 | 1 | 0 |
| **4** | 0 | 1 | 0 | 0 | 1 |

Representation in `pQVar3->data`:

```
Index:  0  1  2  3  4   5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
Value:  1  1  1  0  0   1  0  0  1  1   1  0  1  0  1   0  1  1  1  0   0  1  0  0  1

Row:   |← Row 0 →| |← Row 1 →| |← Row 2 →| |← Row 3 →| |← Row 4 →|
```

Iteration breakdown:

```
Iteration 1: row = 0, col = 0
```
Step-by-step Iteration of the Loops

---

### Iteration 1: row=0, col=0

```c
local_34 = 0  (row)
local_30 = 0  (col)

iVar1 = 0 * 5 + 0 = 0

param_2[0] = pQVar3->data[0] & 1
           = 1 & 1
           = 1
```

param_2:

```
┌───┬───┬───┬───┬───┐
│ 1 │ ? │ ? │ ? │ ? │
└───┴───┴───┴───┴───┘
↑
filled
```

---

### Iteration 2: row=0, col=1

```c
local_34 = 0
local_30 = 1

iVar1 = 0 * 5 + 1 = 1

param_2[1] = pQVar3->data[1] & 1
           = 1 & 1
           = 1
```

---

### Iteration 3–5: row=0, col=2..4

```c
param_2[2] = data[2] & 1 = 1
param_2[3] = data[3] & 1 = 0
param_2[4] = data[4] & 1 = 0
```

After completing Row 0:

```
┌───┬───┬───┬───┬───┬───┐
│ 1 │ 1 │ 1 │ 0 │ 0 │ ? │ …
└───┴───┴───┴───┴───┴───┘
└─────Row 0─────┘
```

---

### Iteration 6: row=1, col=0

```c
local_34 = 1
local_30 = 0

iVar1 = 1 * 5 + 0 = 5

param_2[5] = pQVar3->data[5] & 1
           = 1 & 1
           = 1
```

---

### Iteration Table

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
   12       2   1    11      0
   13       2   2    12      1
   14       2   3    13      0
   15       2   4    14      1
   16       3   0    15      0
   17       3   1    16      1
   18       3   2    17      1
   19       3   3    18      1
   20       3   4    19      0
   21       4   0    20      0
   22       4   1    21      1
   23       4   2    22      0
   24       4   3    23      0
   25       4   4    24      1
```

---

### Final Result in `param_2`


<img width="1202" height="153" alt="{3884F1BC-8247-414E-BB11-69493E54142F}" src="https://github.com/user-attachments/assets/6edff912-139c-401b-be84-068e90ab6030" />


  What does the `& 1` operation do?

`pQVar3->data[i]` can hold different byte values. The expression `value & 0x01` extracts the least-significant bit (LSB). Examples:

Example 1:

```
data[i] = 0x00  // 0000 0000
& 0x01 = 0000 0001
-------------------
0x00 -> 0 (white)
```

Example 2:

```
data[i] = 0x01  // 0000 0001
& 0x01 = 0000 0001
-------------------
0x01 -> 1 (black)
```

Example 3:

```
data[i] = 0xFF  // 1111 1111
& 0x01 = 0000 0001
-------------------
0x01 -> 1 (black)
```

Conclusion: only the least-significant bit (LSB) is extracted.

---

For a real 29×29 matrix:

```
Total iterations = 29 × 29 = 841

Row  0: param_2[0..28]   = 29 bytes
Row  1: param_2[29..57]  = 29 bytes
Row  2: param_2[58..86]  = 29 bytes
...
Row 28: param_2[812..840] = 29 bytes
```

**Index formula:**

```python
def get_pixel(row, col):
    index = row * 29 + col
    return param_2[index]

# Example:
pixel_at_10_15 = param_2[10 * 29 + 15]
                = param_2[305]
```

---

Line 26: Freeing memory

```c
QRcode_free(pQVar3);
```

Why is this necessary?

```c
QRcode_encodeString() {
    QRcode *qr = malloc(sizeof(QRcode));
    qr->data = malloc(width * width);
    ...
    return qr;  // allocated memory is returned
}
```

If `QRcode_free` is not called → **Memory leak!**

Example leak accounting:

* Each call leaks 841 bytes (for a 29×29 matrix)
* After 1000 calls: 841 × 1000 = 841,000 bytes ≈ 821 KB leaked

---

Lines 27–29: Stack canary check

```c
if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
}
```

What it checks:

* At function start: `local_10` is set to the stack canary (a guard value)
* At function end: it compares `local_10` to the stored canary value again

If they match → OK
If they differ → possible buffer overflow detected → `__stack_chk_fail()` is called (program aborts)

(This protects the function's stack frame from being corrupted by stack-based buffer overflows.)


Buffer Overflow example

```c
char buffer[10];
strcpy(buffer, "This string is way too long!");  // Overflow!
```

* The canary is corrupted
* `__stack_chk_fail()` is called
* The program crashes

---

# Step 3: Convert to Hex (function FUN_00101454)

This is the heart of the encoding routine!

## Full code

```c
void FUN_00101454(byte *qr_matrix, char *hex_output) {
    uint uVar1;
    byte bVar2;
    int row;
    int bit_index;
    
    for (row = 0; row < 29; row = row + 1) {
        uVar1 = 0;  // 8-bit accumulator
        
        for (bit_index = 0; bit_index < 8; bit_index = bit_index + 1) {
            if (bit_index < 5) {
                bVar2 = qr_matrix[bit_index * 29 + row];  // note: transpose!
            }
            else {
                bVar2 = 0;  // padding with 0
            }
            uVar1 = uVar1 << 1 | (uint)bVar2;
        }
        
        sprintf(hex_output + row * 2, "%02x", (ulong)uVar1);
    }
    
    hex_output[58] = '\0';
}
```

## Deep understanding of the algorithm

### Key point: Transpose!

The access pattern:

```c
qr_matrix[bit_index * 29 + row]
```

reads columns, not rows — it is a transpose of the usual row-major indexing.

Equivalent in Python-style notation:

```python
value = qr_matrix[column][row]  # transposed indexing
```

## Full simulation with an example

Assume a small section of the QR matrix (29×29, shown here as first 5 columns):

```
Col0 Col1 Col2 Col3 Col4
Row0: 1 0 1 1 0
Row1: 0 1 0 1 1
Row2: 1 1 1 0 0
Row3: 0 0 1 1 1
Row4: 1 1 0 0 1
...
```

### Processing row 0

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

### Output

```c
sprintf(hex_output + 0*2, "%02x", 0xB0);
// hex_output[0..1] = "b0"
```

### Bit shifting diagram

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

Notes:

* The function processes each row by reading the first 5 columns (transposed) and packs those bits into the high bits of an 8-bit value, then pads with zeros for the remaining bits.
* The result for each row is written as two hex characters into `hex_output` (so 29 rows -> 58 hex chars + null terminator at index 58).


## Complete Example (3 rows)

**QR Matrix (first 5 columns shown):**

```
Col0 Col1 Col2 Col3 Col4
Row0: 1 0 1 1 0 → 0xB0
Row1: 0 1 0 1 1 → 0x58
Row2: 1 1 1 0 0 → 0xE0
```

**Output:**

```c
hex_output = "b058e0..."
```

---

## Why Transpose?

* Normal row-major: [Row0_Col0, Row0_Col1, …]
* This algorithm reads: [Row0_Col0, Row1_Col0, …, Row28_Col0] (i.e. columns)

**Possible reasons:**

* Increase reverse-engineering difficulty
* Create dependency across different rows
* Produce an unusual data pattern

---

## Exact index calculation

```c
index = bit_index * 29 + row
```

Index table for `row = 0`:

| bit_index | calculation | Index | Position   |
| --------- | ----------- | ----- | ---------- |
| 0         | 0*29 + 0    | 0     | Row0, Col0 |
| 1         | 1*29 + 0    | 29    | Row0, Col1 |
| 2         | 2*29 + 0    | 58    | Row0, Col2 |
| 3         | 3*29 + 0    | 87    | Row0, Col3 |
| 4         | 4*29 + 0    | 116   | Row0, Col4 |
| 5         | -           | -     | Padding 0  |
| 6         | -           | -     | Padding 0  |
| 7         | -           | -     | Padding 0  |

---

### Test with real data

* Only the first 5 columns are used (per row).
* Every row produces: `0b10110000` → `0xB0` (in the toy example).
* Output would be 29 repetitions of `"b0"` → 58 hex chars total.

---

## Key observations

1. Only 5 out of 29 columns are used (145 pixels of 841 total).
2. 3-bit padding: each byte = [Col0, Col1, Col2, Col3, Col4, 0, 0, 0].
3. Big-endian bit order: the first bit read becomes the MSB of the byte.

---

### Step 3: Convert to Hex (function `FUN_00101454`)

This is the encoding core.

```c
void FUN_00101454(byte *qr_matrix, char *hex_output) {
    uint uVar1;
    byte bVar2;
    int row;
    int bit_index;
    
    for (row = 0; row < 29; row = row + 1) {
        uVar1 = 0;  // 8-bit accumulator
        
        for (bit_index = 0; bit_index < 8; bit_index = bit_index + 1) {
            if (bit_index < 5) {
                bVar2 = qr_matrix[bit_index * 29 + row];  // transpose!
            }
            else {
                bVar2 = 0;  // padding with 0
            }
            uVar1 = uVar1 << 1 | (uint)bVar2;
        }
        
        sprintf(hex_output + row * 2, "%02x", (ulong)uVar1);
    }
    
    hex_output[58] = '\0';
}
```

---

### Deep understanding (recap)

* The function processes each of the 29 rows by reading the first 5 columns **as columns** (transposed access), packing them into an 8-bit value, padding with three zero bits, and writing the resulting byte as two hex characters into `hex_output`.
* Final `hex_output` length: 58 characters + null terminator.

---

If you want, I can:

* produce a runnable Python/C example that takes a 29×29 `qr_matrix` and prints the `hex_output`,
* visualize the 29×29 bit grid and the produced hex string, or
* show how to reverse the encoding (recover the first 5 columns from the hex).


### Processing Row 0 (FUN_00101454)

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

# final result
uVar1 = 0b10110000 = 0xB0
```

### Output

```c
sprintf(hex_output + 0*2, "%02x", 0xB0); // hex_output[0..1] = "b0"
```

### 🔄 Bit Shifting Diagram

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

**Bit order:** MSB ← Col0, Col1, …, Col4, 0,0,0 → LSB

---

## Full 3-row example

QR Matrix (first 5 columns shown):

Col0 Col1 Col2 Col3 Col4
Row0: 1 0 1 1 0 → 0b10110000 → 0xB0
Row1: 0 1 0 1 1 → 0b01011000 → 0x58
Row2: 1 1 1 0 0 → 0b11100000 → 0xE0

Output:

```
hex_output = "b058e0..."
```

(Shown image: repository-hosted preview of the QR/visualization.)

---

## Exact index calculation

```c
index = bit_index * 29 + row
```

Index table for `row = 0`:

| bit_index | calculation | Index | Position in matrix |
| --------- | ----------- | ----- | ------------------ |
| 0         | 0×29 + 0    | 0     | Row0, Col0         |
| 1         | 1×29 + 0    | 29    | Row0, Col1         |
| 2         | 2×29 + 0    | 58    | Row0, Col2         |
| 3         | 3×29 + 0    | 87    | Row0, Col3         |
| 4         | 4×29 + 0    | 116   | Row0, Col4         |
| 5         | -           | -     | Padding (0)        |
| 6         | -           | -     | Padding (0)        |
| 7         | -           | -     | Padding (0)        |

Index table for `row = 5`:

| bit_index | calculation | Index | Position   |
| --------- | ----------- | ----- | ---------- |
| 0         | 0×29 + 5    | 5     | Row5, Col0 |
| 1         | 1×29 + 5    | 34    | Row5, Col1 |
| 2         | 2×29 + 5    | 63    | Row5, Col2 |
| 3         | 3×29 + 5    | 92    | Row5, Col3 |
| 4         | 4×29 + 5    | 121   | Row5, Col4 |

---

## Test with real data

Assume every row's first 5 columns are:
Col0=1, Col1=0, Col2=1, Col3=1, Col4=0

Every row produces: `0b10110000` = `0xB0`
Output: 29 repetitions of "b0" (58 hex chars):

```
"b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"
```

(29 × "b0")

---

## Important notes

1. Only the first 5 columns are used:

   * 29×29 matrix → only 29×5 = 145 pixels used
   * Remaining 29×24 = 696 pixels ignored
   * Possible reasons: smaller output, those 5 columns suffice for unique encoding, rest reserved for error correction/metadata

2. 3-bit padding:

   * Each byte = [Col0, Col1, Col2, Col3, Col4, 0, 0, 0]
   * Ensures lower 3 bits are always zero
   * Byte values are multiples of 8 (0x00 to 0xF8)

3. Big-endian bit order:

```c
uVar1 = uVar1 << 1 | bVar2;
```

* The first read bit becomes the MSB.

---

# Encoding walkthrough for `ASIS{test}`

## 📌 Initial input

```
ASIS{test}
```

* Length: 10 characters

---

## Step 1: Padding

Input length: 10

* Need to reach total length 38 → add 28 padding characters
* Padding pattern uses `index mod 3` starting at position 10:

  * 1 → `+`
  * 2 → `-`
  * 0 → `*`

Example sequence:

```
position 10: 10 mod 3 = 1 → +
position 11: 11 mod 3 = 2 → -
position 12: 12 mod 3 = 0 → *
position 13: 13 mod 3 = 1 → +
```

... continue until position 37

Output after padding:

```
ASIS{test}+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*-
```

* Length: 38 characters

---

## Step 2: Generate QR Code

* Input: `ASIS{test}+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*-`
* Settings: EC Level = L, Mode = 8-bit
* Output: 29×29 binary matrix

Sample first 5 rows (of 29):

```
[1,1,1,1,1,1,1,0,1,0,1,0,0,1,0,1,1,1,1,1,1,1,1,0,1,0,1,1,0]
[1,0,0,0,0,0,1,0,0,1,0,1,1,0,1,0,1,0,0,0,0,0,1,0,0,1,1,0,1]
[1,0,1,1,1,0,1,0,1,0,1,0,1,1,0,1,0,0,1,1,1,0,1,0,1,0,0,1,0]
[1,0,1,1,1,0,1,0,1,1,0,1,0,0,1,0,1,0,1,1,1,0,1,0,1,1,1,0,1]
[1,0,1,1,1,0,1,0,0,1,1,1,0,1,1,1,0,0,1,1,1,0,1,0,0,0,1,1,0]
```

... (24 more rows)

---

If you'd like, I can:

* produce a runnable Python script that performs `FUN_00101454` on a 29×29 matrix and prints `hex_output`,
* visualize the 29×29 bit grid and the produced hex string, or
* show how to reverse the hex back into the first 5 columns (decode).



## Stage 3: Convert to Hex (column-wise reading)

### Sample calculations

* Column 0 (first 5 bits): `[1,1,1,1,1]` → `0b11111000` → 248 → `0xF8`
* Column 1 (first 5 bits): `[1,0,0,0,0]` → `0b10000000` → 128 → `0x80`
* Column 2 (first 5 bits): `[1,0,1,1,1]` → `0b11011000` → 216 → `0xD8`

### Stage 3 output (hypothetical)

```
f880d8f8f840a8604050d8a8f8f840f840a850f0d8a050d8e8f860
```

* Length: 58 characters (29 bytes × 2)

---

## Stage 4: Adding the Prefix

* Random prefix generated from a time-based seed:

```
Ky7Xm2Qp9Vs1L
```

* Length: 14 characters

### Final output

```
Ky7Xm2Qp9Vs1Lf880d8f8f840a8604050d8a8f8f840f840a850f0d8a050d8e8f860
```

* Length: 72 characters

---

## 📝 Final summary

| Stage         | Output                                                              | Length |
| ------------- | ------------------------------------------------------------------- | ------ |
| Input         | ASIS{test}                                                          | 10     |
| After padding | ASIS{test}+-*+-*+-*+-*+-*+-*+-*+-*+-*+-*-                           | 38     |
| After QR      | 29×29 binary matrix                                                 | -      |
| After Hex     | f880d8f8f840a8604050d8a8f8f840f840a850f0d8a050d8e8f860              | 58     |
| Final output  | Ky7Xm2Qp9Vs1Lf880d8f8f840a8604050d8a8f8f840f840a850f0d8a050d8e8f860 | 72     |

⚠️ Note: The hex values and the prefix above are hypothetical. For real data you must run the code using the `libqrencode` library.

# 📋 Steps to solve the Show_Me CTF challenge

## Stage 1: Binary analysis (Reverse Engineering)

First, analyze the executable with reverse-engineering tools:

```bash
# Check file type
file challenge

# Disassemble

# Use Ghidra
```

Things to identify:

* ✅ The padding function (`processEntry`) and the `+-*` pattern
* ✅ The use of `libqrencode` to generate the QR
* ✅ How the QR matrix is converted to hex (column-wise reading)
* ✅ The addition of a 14-character random prefix

---

For an actual run, implement the encoding steps using `libqrencode` and reproduce the column-wise hex conversion and prefix generation.
## Stage 2: Identify data format

From code analysis we understand:

```
output = [14 char random] + [hex of QR code]
```

* The 14-character random prefix must be removed.
* The QR Code is Version 3 (size 29×29).
* Data is stored as 4 bytes per row (29 rows × 4 = 116 bytes = 232 hex characters).
* Reading order: row by row, from MSB to LSB.

---

## Stage 3: Writing the decoder script

We implement the reverse of the encoding process:

```python
from PIL import Image
from pyzbar.pyzbar import decode

def decode_ctf_qr(output_path):
    # ── Step 1: read the output file ──
    hexstr = open(output_path, 'r').read().strip()
    print(f"[+] full string: {hexstr[:50]}... (length: {len(hexstr)})")

    # ── Step 2: remove 14-char prefix ──
    prefix = hexstr[:14]
    hex_cipher = hexstr[14:]
    print(f"[+] Prefix: {prefix}")
    print(f"[+] Hex cipher: {hex_cipher[:50]}... (length: {len(hex_cipher)})")

    # ── Step 3: hex -> bytes ──
    data = bytes.fromhex(hex_cipher)
    print(f"[+] number of bytes: {len(data)} (expected: 116)")

    # ── Step 4: reconstruct 29×29 matrix ──
    size = 29
    matrix = [[0]*size for _ in range(size)]
    for row in range(size):
        for k in range(4):  # 4 bytes per row
            byte_index = row * 4 + k
            byte = data[byte_index]
            for b in range(8):  # MSB -> LSB
                col = k * 8 + b
                if col < size:
                    bit = (byte >> (7 - b)) & 1
                    matrix[row][col] = bit
    print(f"[+] reconstructed {size}×{size} matrix")

    # ── Step 5: matrix -> PNG ──
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
    print('[+] saved QR image: reconstructed_qr.png')

    # ── Step 6: scan and decode QR ──
    decoded = decode(img)
    if decoded:
        text = decoded[0].data.decode('utf-8')
        print(f"\n🎉 FLAG: {text}")
        return text
    else:
        print('❌ QR code could not be read!')
        return None

if __name__ == '__main__':
    decode_ctf_qr('output.txt')
```

---

## 🔍 Detailed analysis of each part

1. **Why remove the first 14 characters?**

```c
// in the original code:
char prefix[15];
generate_random_prefix(prefix, 14);
strcat(output, prefix);
```

* It's only for obfuscation and carries no information.

2. **Why 116 bytes?**

* QR matrix = 29×29 bits
* Each row = 29 bits → requires 4 bytes (32 bits)
* Total data = 29×4 = 116 bytes

3. **Why MSB-first reading?**

```python
bit = (byte >> (7 - b)) & 1
```

* Matches the original encoder's ordering.

4. **Why scale = 10?**

* To make the QR image large enough to be scanned by `pyzbar`.

---

## 🚀 Final execution

```bash
# install libs
pip install pillow pyzbar

# run
python decode_qr.py
```
