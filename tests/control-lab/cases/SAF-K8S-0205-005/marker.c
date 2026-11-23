/* Public test program that is loaded, inspected, and never attached. */
__attribute__((section("socket"), used))
int saf_marker(void *unused)
{
    (void)unused;
    return 0;
}

__attribute__((section("license"), used))
char fixture_license[] = "GPL";
