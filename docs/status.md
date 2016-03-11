### NIST CAVP Test Result Status

| Mode     | Test    | Encrypt: 128-bit | 192-bit | 256-bit | Decrypt: 128-bit | 192-bit | 256-bit |
| -------- | ------- | ---------------: | ------: | ------: | ---------------: | ------: | ------: |
| ECB      | GFSbox  | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | KeySbox | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | VarKey  | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | VarTxt  | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | MMT     | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | MCT     | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
| CBC      | GFSbox  | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | KeySbox | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | VarKey  | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | VarTxt  | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | MMT     | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | MCT     | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] |
| OFB      | GFSbox  | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | KeySbox | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | VarKey  | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | VarTxt  | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | MMT     | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | MCT     | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] |
| CFB-128  | GFSbox  | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | KeySbox | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | VarKey  | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | VarTxt  | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | MMT     | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | MCT     | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] |
| CFB-8    | GFSbox  | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | KeySbox | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | VarKey  | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | VarTxt  | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] | ![PASS][✓] |
|          | MMT     | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] |
|          | MCT     | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] |
| CFB-1*   | ------- | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] | ![FAIL][✗] |

> *Note: Support for CFB-1 mode has been removed.  It provides no significant
> benefit in return for the added complexity to implement it and the 128x
> slowdown compared to CFB-128.

[✓]: check16.png
[✗]: cross16.png

