# PSARDecrypter.cpp
## is_5_d_num()
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



## Lines 519-544 switch statement before is_5_d_num()
Code:
```cpp
if (is5Dnum(name))
{
    if (atoi(name) >= 100 || (atoi(name) >= 10 && intVersion < 660))
    {
        int found = 0;
        for (const auto &table : g_tables) {
            if (table.size() > 0) {
                found = FindTablePath(table.data(), table.size(), name, name);
                if (found) {
                    break;
                }
            }
        }

        if (!found)
        {
            printf("Part 1 Error: cannot find path of %s.\n", name);
            continue;
        }
    }
}
```
### Hypothesis
Ok first, inside we have a switch statmente which'll depend on if it's true or false. Then whe enter into another switch statement which is **larger** than the other one:
`if (atoi(name) >= 100 || (atoi(name) >= 10 && intVersion < 660))`
This tells us lots of things:
- If `atoi(name) >= 100` (I don't know that that means yet)
- if `atoi(name) >= 100` (I don't know)
- AND `intVersion < 660` (This one I know it since I had to parse the slice in order to get the desired int version thing)

Now that we know what we lack, let's investigate about atoi() thing, which I dont know:
Is it inside the file or is it a custom function? -> NO
Is it a dependency? -> Probably YES
By doing a short research, I found the meaning of `atoi()`:

Term:
- `atoi()` in C++ stands for "ASCII to integer" and converts a numeric string into an integer value, stopping at the first non-digit character.
That's nice, so technically what it does is convert a numeric string (which makes sense since a char is technically a number but in ascii) Into an integer value, and it stops at the non-digit character (which might be null byte, since we only have digits inside the name)

### Solution
First -> `cargo add atoi`

### Second Hypothesis
I see something that is really weird here:
```cpp
int found = 0;
for (const auto &table : g_tables) {
    if (table.size() > 0) {
        found = FindTablePath(table.data(), table.size(), name, name);
        if (found) {
            break;
        }
    }
}

if (!found)
{
    printf("Part 1 Error: cannot find path of %s.\n", name);
    continue;
}
```
**Questions:**
1. What the hell is g_tables?
2. What is FindTablePath
3. Where does g_table comes from?

Then, let's research about g_tables inside the original code:
```cpp
// File tables, com = offset 0, then 01g = offset 1, etc.
std::array<std::vector<char>, 13> g_tables;
```
This is the first appearance inside `PsarDecrypter.cpp`!!!
So this is an array of arrays of character which it's size is 13? mmm this is kinda confusing.
Because it is declared as a global variable at the top of the file, it isn't initialized with any secret data whatsoever. So when the program starts, it's literally just 13 empty arrays (size 0)...

And below that, we have this:
```cpp
const std::vector<std::pair<std::string, int>> g_tableFilenames = {
    {"com:00000", 0},
    {"01g:00000", 1},
    {"02g:00000", 2},
    {"00001", 1},
    {"00002", 2},
    {"00003", 3},
    {"00004", 4},
    {"00005", 5},
    {"00006", 6},
    {"00007", 7},
    {"00008", 8},
    {"00009", 9},
    {"00011", 11},
    {"00012", 12}
};
```
What a coincidence, it's size is 13...
The second appearance inside the code is the iterator that we already saw:
```cpp
    for (const auto &table : g_tables) {
        if (table.size() > 0) {
            found = FindTablePath(table.data(), table.size(), name, name);
            if (found) {
                break;
            }
        }
    }
```
So... Where the hell does `g_tables` get filled?
It seems that it gets filled dynamically while the main extraction loop is running...
There's something that I'm missing: a go-between function, so this is the loop process:
1. Extract -> Calls `pspPSARGetNextFile` and gets the decrypted, unzipped data and it's name
3. The "go-between" function: what's the name on the g_tableFilenames's list? THAT'S WHERE I HAVE TO FIND OUT WHERE IT DOES THAT.
#### While reading the entire code, I found the solution:
The entire PSAR extraction process relies on a desing choice by Sony: the physical order of the files inside the archive is important!!!. But why?
Sony stacked the archive sequentially like if it was the pages of a book: The damm "Table of Contents" are places at the very beginning of the archive, and the "Chapters" are placed later. This ensures the program dynamically builds its routing system BEFORE it actually really need to use the Table itself!!!!.

`while(1) timeline`
The main loop extracts chunks one by one from the archive. So depending on what type of file comes down the pipeline, the loop processes like this:
1. Building the Map (Table of Contents)
- When the loop extracts early chunks, it encounters names like com:000 or 0001.
- These are MAP FILES. They bypass the first is_5_d_num() that I translated before because they contain letters or fail the firmware version conditions!!!.
- So the code reaches an else block where it checks the name against g_table_filenames list!!!
- And then it finds a match, it decrypts the map file and directly copies the unzipped bytes into the corresponding g_tables array in RAM
So the go-between function needed was already the one that's inside the `else {}` thing...

So know the translation is so much easy since yesterday
```cpp
int found = 0;
for (const auto &table : g_tables) {
    if (table.size() > 0) {
        found = FindTablePath(table.data(), table.size(), name, name);
        if (found) {
            break;
        }
    }
}
```
So since first it checks if the table.len() is higher than 0, then it first checks wheter is empty or no, so we don't have to be skeptical that it'll send into FindTablePath an empty `Vec<u8>`.

**Translation:**
```rust
for table in &mut *g_tables {
    if table.len() > 0 {
        let found = find_table_path(table.data(), table.len(), name, name);
        if found {
            break;
        }
    }
}
```
But I don't understand the last 2 parameters that I'm sending: Why do we send the same variable? Let's reverse_engineer the function itself:

## FindTablePath function Reverse Engineering
Ok... This function is somewhat big:
```cpp
static int FindTablePath(const char *table, int table_size, char *number, char *szOut)
{
    int i, j, k;

    for (i = 0; i < table_size-5; i++)
    {
        if (strncmp(number, table+i, 5) == 0)
        {
            for (j = 0, k = 0; ; j++, k++)
            {
                if (table[i+j+6] < 0x20)
                {
                    szOut[k] = 0;
                    break;
                }

                if (table[i+5] == '|' && !strncmp(table+i+6, "flash", 5) &&
                    j == 6)
                {
                    szOut[6] = ':';
                    szOut[7] = '/';
                    k++;
                }
                else if (table[i+5] == '|' && !strncmp(table+i+6, "ipl", 3) &&
                    j == 3)
                {
                    szOut[3] = ':';
                    szOut[4] = '/';
                    k++;
                }
                else
                {
                    szOut[k] = table[i+j+6];
                }
            }

            return 1;
        }
    }

    return 0;
}
```
Let's analyze first their parameters:
`static int FindTablePath(const char *table, int table_size, char *number, char *szOut)`
What I see here is that we are sending:
- A const char pointer called "table"
- An integer which might be the table_size of the table above
- A pointer of chars called number

- A pointer of chars called szOut (Which I think it's the abbreviation of sizeOut, but of what? And why it creates 2 references at the same memory address? This is highly dangerous and It'll make me fight with the rust compiler non-stop...)
- NO, GOT THIS ABOVE WRONG: Since this is actually ancient C++ naming convention called Hungarian Notation:
    - sz stands for String-Zero-Terminated I think (which is a standard C-String endingin a null byte `\0`)
    - Out means it's a buffer intended to be written to and returned to the caller.

Then inside the function what it does is iterate between each collum (because it's a matrix); First they do the first iterator (int i = 0) up to the desired lenght that the Vec inside has.But i think it doesn't make any sense, because the first array is a fixed-size, but the other one isn't, so why sending the table size?...
Something is weird, because the iterator goes from 0 up to the table size -5.. What?
I Think what the programmer did was do the in-place overwrite, which is highly efficient for the 32mb ram of the psp but highly risky...

1. The function reads for example "00010" from the number pointer
2. Then it finds the real path (e.g., "bsjh/modulue_urmom.prx).
3. Then immediately writes the new path directly over the "00010" string in the exact same memory array by using the szOut pointer.

### Just to clarify
table is not matrix, is a giant 1D array OF BYTES. It's literally just raw text contents of the map file dumped into the memory. So my bad there...
The problem is that, when I open that map file in NOTEDPAD, the rae text inside "table" is something like this:
```txt
00010|flash0/kd/loadexec.prx[0x0A]00011|vsh/module/vshmain.prx[0x0A]
```

I'm just gonna trust the original code for now, and once I finished with it, I might debugg it and see if their hyptothesis are true. Because now I don't have a hacked PSP at my disposal in order to make the dump into ram thing..


### Analysing FindTablePath
1. Declares i, j, k as int

2. First for-loop | Ranges -> i = 0; i M table_size-5; i++
Why this: While doing the research, found something interesting:
    - It's a safe mechanism in order to prevent buffer overflow
Why is that? Let's look below:

`if (strncmp(number, table+i, 5) == 0)`

The function `strncmp` what it does is that it takes like a "magnifying glass" of 5 bytes wide, then it places at index `i`, and reads 5 characters to see if they match out 5 digit number (like for example `00010`).

Now let's make this hypothesis: imagine the table is 100 bytes long, right?
The loop goes into that 5 bytes magnifying glass through the array one step at a time: `i = 0`, `i = 1`, `i = 2`...

Then what happens when the loop reaches **i = 98**?
- The **magnifying glass** will try to read 5 bytes starting from 98... it'll fall of the edge of the array -> Segmentation fault!!!

By writing `i < table_size - 5` the programmer is making sure the **Segmentation Fault** behavior doesn't happen.
Why writing in Rust `for  i in 0..table.len()` it perfectly mimics the C++ behavior. But we must be carefull, since if `table.len()` happens to be less than 5, it will cause an integer underflow, resulting into panic with Rust's side.







