### PSARDecrypter.cpp
Code:
```cpp
static int is5Dnum(char *str)
{
    int len = strlen(str);

    if (len != 5)
        return 0;

    int i;

    for (i = 0; i < len; i++)
    {
        if (str[i] < '0' || str[i] > '9')
            return 0;
    }

    return 1;
}
```
#### Hypothesis
Seeing this function, I think it tells me something: I suppose is5Dnum means "is 5 digits the length of the string that Im sending as a parameter?"
If I suppose that function means that, then everything makes sense. Since `int len` stores the length of the string that I'm sending as a parameter (well... the array of chars, but technically a string is an array of bytes IN C, In rust we have to be really carefull while doing the translation since it's different).
Then we check if len is not equal to 5 -> if true, then we return 0

Then we do an iteration for each character from the array and we check 2 things:
- if `str[i]` is less than 0 (I think this means is a null byte?)
- if `str[i]` is greater than 9 (I think this means that also is null? I don't know...)

#### Solution
While doing a deep research about this, I stumble upon something interesting about chars in c: **characters in C are really just small integers**.
so for example, in ASCII:
- `'0' -> 48`
- `'9' -> 57`
- `'A' -> 65`

**So when I write:**
`str[i] < '0'` -> The compiler actually compares integer values:
`str[i] < 48`
and `str[i] > '9'` -> becomes -> `str[i] > 57`

**If the value is**
Less than `48` → not a digit
Greater than `57` → not a digit