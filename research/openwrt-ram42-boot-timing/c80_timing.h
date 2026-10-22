/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef C80_TIMING_H
#define C80_TIMING_H
/* RAM40's !HIGH_RES_TIMERS/HZ100 startup implicitly used tick-sized sleeps.
 * Keep a conservative explicit startup/teardown floor while phase37's active
 * AP loop, command replies and packet completions use the requested delays.
 * These are host scheduling minima, not a documented MT7626 timing contract.
 */
#define C80_INIT_SLEEP_US 10000u
#define C80_OWN_SETTLE_US 10000u
static inline unsigned int c80_delay_min_us(unsigned int phase,unsigned int us)
{ return phase==37 || us>=C80_INIT_SLEEP_US?us:C80_INIT_SLEEP_US; }
#endif
