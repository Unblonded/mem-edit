// TestTarget - a small "game" to practice with Memory Browser.
// Every value here is something the browser can find, edit, freeze or follow.
#include <windows.h>
#include <conio.h>

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

// Static values: live in the exe image, so they show up green as TestTarget.exe+offset.
static volatile int32_t g_health = 100;
static volatile int32_t g_gold = 250;
static volatile uint8_t g_level = 1;
static volatile int64_t g_score = 0;

// Heap object reached through a static pointer: practice pointer chains.
struct Player
{
    char name[32];       // +0x00  ASCII string
    float speed;         // +0x20  Float
    int32_t ammo;        // +0x24  Int32
    double posX;         // +0x28  Double, changes every tick
    double posY;         // +0x30
    wchar_t title[24];   // +0x38  UTF-16 string
    uint8_t secret[8];   // +0x68  byte pattern marker
};
static_assert(offsetof(Player, speed) == 0x20 && offsetof(Player, ammo) == 0x24 && offsetof(Player, posX) == 0x28 &&
              offsetof(Player, title) == 0x38 && offsetof(Player, secret) == 0x68, "offsets shown in the comments");
static Player* volatile g_player = nullptr;

static bool g_poison = false;
static bool g_showAddresses = false;
static int g_moves = 0;

static Player* NewPlayer(const Player* old)
{
    // Allocate a padding block first so the new object lands somewhere else.
    static void* padding[64];
    static int padIndex = 0;
    padding[padIndex++ % 64] = malloc(4096 + (padIndex * 977) % 8192);

    Player* p = (Player*)calloc(1, sizeof(Player));
    if (old) *p = *old;
    else
    {
        strcpy_s(p->name, "Hero");
        p->speed = 1.5f;
        p->ammo = 30;
        wcscpy_s(p->title, L"Knight of Memory");
        const uint8_t marker[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xC0, 0xDE };
        memcpy(p->secret, marker, 8);
    }
    return p;
}

static void Draw(double t)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD home = { 0, 0 };
    SetConsoleCursorPosition(out, home);

    Player* p = g_player;
    char title[64];
    WideCharToMultiByte(CP_UTF8, 0, p->title, -1, title, sizeof(title), nullptr, nullptr);

    printf("=== TestTarget  (PID %lu) ==========================================\n", GetCurrentProcessId());
    printf("                                                                     \n");
    printf("  Health  : %-6d %s                                   \n", g_health, g_poison ? "(POISONED: -1/sec)" : "                  ");
    printf("  Gold    : %-10d                                                \n", g_gold);
    printf("  Level   : %-4u   (Byte)                                        \n", (unsigned)g_level);
    printf("  Score   : %-14lld (Int64)                                     \n", (long long)g_score);
    printf("                                                                     \n");
    printf("  Player  : %-20s (heap object, moved %d times)       \n", p->name, g_moves);
    printf("  Title   : %-24s (UTF-16)                     \n", title);
    printf("  Speed   : %-10.3f (Float)                                     \n", p->speed);
    printf("  Ammo    : %-6d                                                 \n", p->ammo);
    printf("  Pos     : %10.4f, %10.4f (Double, always moving)            \n", p->posX, p->posY);
    printf("                                                                     \n");
    printf("  Keys:  [D] take 7 damage   [H] heal 10     [G] +25 gold   [S] spend 40 gold\n");
    printf("         [L] level up        [F] fire ammo   [R] reload     [+/-] speed\n");
    printf("         [P] toggle poison   [M] move player object in memory\n");
    printf("         [A] show/hide addresses (answers)   [Q] quit\n");
    printf("                                                                     \n");

    if (g_showAddresses)
    {
        uint64_t base = (uint64_t)GetModuleHandleW(nullptr);
        uint64_t ptrOff = (uint64_t)&g_player - base;
        printf("  Answers:                                                              \n");
        printf("    Health   TestTarget.exe+%llX   (%p)          \n", (unsigned long long)((uint64_t)&g_health - base), (void*)&g_health);
        printf("    Gold     TestTarget.exe+%llX   (%p)          \n", (unsigned long long)((uint64_t)&g_gold - base), (void*)&g_gold);
        printf("    Player   [TestTarget.exe+%llX]  -> %p              \n", (unsigned long long)ptrOff, (void*)p);
        printf("    Ammo     [TestTarget.exe+%llX]+24  (pointer chain)          \n", (unsigned long long)ptrOff);
        printf("    Speed    [TestTarget.exe+%llX]+20                           \n", (unsigned long long)ptrOff);
        printf("    Secret   AOB  DE AD BE EF ?? 37 C0 DE                       \n");
    }
    else
    {
        for (int i = 0; i < 7; i++)
            printf("                                                                              \n");
    }
    (void)t;
}

int main()
{
    SetConsoleTitleW(L"TestTarget - practice target for Memory Browser");
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO ci = { 1, FALSE };
    SetConsoleCursorInfo(out, &ci);
    system("cls");

    g_player = NewPlayer(nullptr);
    ULONGLONG start = GetTickCount64(), lastPoison = start;

    for (;;)
    {
        ULONGLONG now = GetTickCount64();
        double t = (now - start) / 1000.0;
        Player* p = g_player;
        p->posX = std::cos(t * 0.7) * 100.0 * p->speed;
        p->posY = std::sin(t * 0.7) * 100.0 * p->speed;
        g_score = g_score + 1;

        if (g_poison && now - lastPoison >= 1000)
        {
            g_health = g_health - 1;
            lastPoison = now;
        }
        if (!g_poison) lastPoison = now;

        while (_kbhit())
        {
            int c = _getch();
            if (c == 0 || c == 0xE0) { _getch(); continue; }
            switch (toupper(c))
            {
            case 'D': g_health = g_health - 7; break;
            case 'H': g_health = g_health + 10; break;
            case 'G': g_gold = g_gold + 25; break;
            case 'S': g_gold = g_gold - 40; break;
            case 'L': g_level = (uint8_t)(g_level + 1); break;
            case 'F': if (p->ammo > 0) p->ammo--; break;
            case 'R': p->ammo = 30; break;
            case '+': case '=': p->speed += 0.25f; break;
            case '-': case '_': p->speed -= 0.25f; break;
            case 'P': g_poison = !g_poison; break;
            case 'A': g_showAddresses = !g_showAddresses; break;
            case 'M':
            {
                Player* old = g_player;
                Player* moved = NewPlayer(old);
                g_player = moved;
                memset(old, 0, sizeof(Player)); // the old copy goes stale, like a real game
                free(old);
                g_moves++;
                break;
            }
            case 'Q':
                return 0;
            }
        }
        Draw(t);
        Sleep(50);
    }
}
