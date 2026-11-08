/* kaaslr.h — determining the runtime kernel base (_text) via perf.
 * Method: perf HW_INSTRUCTIONS + PERF_SAMPLE_CALLCHAIN; the deepest syscall
 * stack frame is el0t_64_sync (offset < 0x12000 from _text), so
 * _text = round_down(root_frame, 2MB). We take the MODE over the samples.
 * Read-only, modifies nothing.
 */
#ifndef KAASLR_H
#define KAASLR_H
#include <stdint.h>

/* Returns the runtime _text (2MB-aligned) or 0 on error. */
uint64_t kaaslr_text_base(void);

/* Nominal _text without slide. */
#define KIMAGE_NOMINAL 0xffffffc008000000UL

#endif /* KAASLR_H */
