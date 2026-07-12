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






