/* New inline assembly syntax available in nightly,
 * We use the C language link method to make asm calls.
 */
int do_hypercall(unsigned int p1)
{
        long ret = 0;

        asm volatile("vmmcall" : "=a"(ret) : "a"(p1) : "memory");

        return (int)ret;
}
