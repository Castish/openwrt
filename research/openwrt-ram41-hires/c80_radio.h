/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef C80_RADIO_H
#define C80_RADIO_H
/* One boot-time profile, shared by the physical adapter and QEMU peer.
 * Zero is retained solely for legacy channel6 regression fixtures. */
#define C80_EXPERIMENT_CHANNEL 1u
static inline unsigned c80_selected_channel(unsigned channel)
{ return channel?channel:6u; }
static inline unsigned c80_selected_frequency(unsigned channel)
{ return 2407u+5u*c80_selected_channel(channel); }
#endif
