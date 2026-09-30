#!/usr/bin/env python3
"""
ULPF launch video — music + SFX, synthesized from scratch.

One piece, not layered stems: everything shares A minor and the same short
reverb, so the sound effects sit *inside* the track rather than on top of it.

A minor, 100 BPM (beat = 0.60s, bar = 2.40s), 21.0s.
"""
import numpy as np, wave, struct, os, sys

SR = 48000
DUR = 21.0
N = int(SR * DUR)
OUT = sys.argv[1]

t = np.arange(N) / SR
rng = np.random.default_rng(20260930)          # deterministic

# ---------- helpers ----------
def env(n, a, d, s_lvl=0.0, r=0.0):
    """ADSR over n samples; a/d/r in seconds."""
    A = int(a * SR); D = int(d * SR); R = int(r * SR)
    e = np.zeros(n)
    a_i = min(A, n); e[:a_i] = np.linspace(0, 1, a_i)
    d_i = min(D, max(0, n - a_i))
    if d_i: e[a_i:a_i + d_i] = np.linspace(1, s_lvl, d_i)
    rest = n - a_i - d_i
    if rest > 0:
        if R > 0:
            e[a_i + d_i:] = s_lvl
            e[n - R:] *= np.linspace(1, 0, R)
        else:
            e[a_i + d_i:] = s_lvl
    return e

def place(buf, x, at):
    """Mix x into buf at time `at` (seconds), clipping at the edges."""
    i = int(at * SR)
    if i >= len(buf): return
    j = min(len(buf), i + len(x))
    buf[i:j] += x[:j - i]

def sine(f, dur, detune=0.0):
    n = int(dur * SR)
    ph = 2 * np.pi * f * np.arange(n) / SR
    return np.sin(ph + detune)

def saw(f, dur, harmonics=14):
    """Additive saw — band-limited, so it never aliases or buzzes."""
    n = int(dur * SR)
    x = np.zeros(n)
    for k in range(1, harmonics + 1):
        x += np.sin(2 * np.pi * f * k * np.arange(n) / SR) / k
    return x / (harmonics ** 0.5)

def tri(f, dur):
    n = int(dur * SR)
    x = np.zeros(n)
    for k in range(1, 9):
        if k % 2 == 1:
            x += np.sin(2 * np.pi * f * k * np.arange(n) / SR) / (k * k)
    return x * 0.82

def lp(x, cutoff):
    """One-pole lowpass. cutoff may be a float or a per-sample array."""
    a = np.exp(-2 * np.pi * np.asarray(cutoff) / SR)
    y = np.zeros_like(x)
    acc = 0.0
    # vectorised where cutoff is constant, looped where it sweeps
    if a.ndim == 0:
        for i in range(len(x)):
            acc += a * (x[i] - acc); y[i] = acc
    else:
        for i in range(len(x)):
            acc += a[i] * (x[i] - acc); y[i] = acc
    return y

def hp(x, cutoff):
    return x - lp(x, cutoff)

def noise(dur):
    return rng.uniform(-1, 1, int(dur * SR))

# ---------- note helpers ----------
A1, A2 = 55.00, 110.00
C3, E3, G3, B3 = 130.81, 164.81, 196.00, 246.94
A3, C4, E4, G4, A4, C5, E5, A5 = 220.00, 261.63, 329.63, 392.00, 440.00, 523.25, 659.25, 880.00
F2, F3, G2 = 87.31, 174.61, 98.00

BEAT, BAR = 0.60, 2.40
CHORDS = [                                   # (root, triad) per 2 bars
    (A2, [A2, C3, E3]),   # i
    (F2, [F2, A2, C3]),   # VI
    (C3, [C3, E3, G3]),   # III
    (G2, [G2, B3, D3 if False else G3]),  # VII (G B D)
]

music = np.zeros(N)
sfx   = np.zeros(N)

# ---------- sub-bass pulse: every beat, whole way through ----------
for b in range(int(DUR / BEAT) + 1):
    at = b * BEAT
    if at >= DUR: break
    dur = BEAT * 0.92
    f = CHORDS[min(int(at / (BAR * 2)), len(CHORDS) - 1)][0] / 2.0
    x = sine(f, dur) * env(int(dur * SR), 0.006, 0.10, 0.55, 0.22)
    x = np.tanh(x * 1.7) * 0.42                  # soft saturation, adds body
    place(music, x, at)

# ---------- pad: enters at the reveal, carries the rest ----------
pad_in, pad_out = 5.80, 19.30
pad = np.zeros(N)
for ci, (root, triad) in enumerate(CHORDS):
    dur_s = BAR * 2                      # seconds (for the tone generators)
    seg = int(dur_s * SR)                # samples (for env/lp/arange)
    if ci * BAR * 2 >= DUR: break
    for ni, f in enumerate(triad):
        for det in (-0.16, 0.0, 0.16):
            x = saw(f * 2, dur_s, 9) * 0.085
            x = lp(x, 1500 + 500 * np.sin(np.arange(seg) / SR * 0.6))
            x = x * env(seg, 0.55, 0.5, 0.8, 0.7)
            place(pad, x, ci * BAR * 2)
pstart, pend = int(pad_in * SR), int(pad_out * SR)
fade_in = np.clip((np.arange(N) - pstart) / (0.9 * SR), 0, 1)
fade_out = np.clip((pend - np.arange(N)) / (1.4 * SR), 0, 1)
music += pad * fade_in * fade_out

# ---------- arp: 16th-note pluck, from the schema beat onward ----------
arp_from, arp_to = 8.60, 19.20
sixteenth = BEAT / 4
step = 0
at = arp_from
while at < arp_to:
    ci = min(int(at / (BAR * 2)), len(CHORDS) - 1)
    triad = CHORDS[ci][1]
    # gentle arpeggio: root, 5th, 3rd, octave
    f = [triad[0], triad[2], triad[1], triad[0] * 2][step % 4]
    if step % 8 == 6:
        f *= 1.5                              # a lift every other bar
    dur = 0.34
    x = tri(f, dur) * env(int(dur * SR), 0.004, 0.20, 0.16, 0.10)
    x = lp(x, 2600) * 0.30
    place(music, x, at)
    at += sixteenth
    step += 1

# ---------- pad-only sustain under the losslessness beat ----------
for f in (A3, E4):
    dur = 16.4 - 12.2
    x = sine(f, dur) * env(int(dur * SR), 0.9, 0.8, 0.75, 1.2)
    x = lp(x, 2200) * 0.055
    place(music, x, 12.2)

# ---------- riser into the reveal (soft, band-limited, never harsh) ----------
dur = 3.2
n = int(dur * SR)
nz = hp(noise(dur), 400)
cut = np.linspace(500, 5200, n)
nz = lp(nz, cut)
riser_env = (np.arange(n) / n) ** 2.2
riser_env *= np.clip((np.arange(n) / (0.35 * SR)), 0, 1)   # fade the onset in
place(sfx, nz * riser_env * 0.085, 0.0)

# ---------- SFX: vendor line arrivals in the hook ----------
for i, at in enumerate([0.15, 0.33, 0.51, 0.69]):
    f = [A4, C5, E5, G4][i]
    dur = 0.16
    x = sine(f, dur) * env(int(dur * SR), 0.002, 0.07, 0.10, 0.08)
    tick = hp(noise(0.05), 2200) * 0.16 * env(int(0.05 * SR), 0.001, 0.02, 0.05, 0.02)
    x[:len(tick)] += tick
    place(sfx, x * 0.11, at)

# ---------- SFX: compression thud when the clutter collapses (S2) ----------
x = sine(70, 0.55) * env(int(0.55 * SR), 0.004, 0.22, 0.20, 0.30)
x = np.tanh(x * 2.2) * 0.30
place(sfx, x, 3.20)

# ---------- SFX: reveal impact (S3) ----------
for f, g in ((A2, 0.30), (A3, 0.16), (E4, 0.10)):
    x = sine(f, 0.9) * env(int(0.9 * SR), 0.003, 0.30, 0.22, 0.55)
    place(sfx, np.tanh(x * 1.5) * g, 5.80)

# ---------- SFX: one soft tick per OCSF field illumination ----------
for t0, rows in ((9.00, 8), (10.25, 10)):
    for i in range(rows):
        at = t0 + i * 0.10
        f = [E5, A4, C5][i % 3]
        x = sine(f, 0.10) * env(int(0.10 * SR), 0.002, 0.04, 0.06, 0.05)
        place(sfx, x * 0.055, at)

# ---------- SFX: the hash computing, then verifying ----------
# a slow rise while the digest types in
dur = 1.0
n = int(dur * SR)
rise = sine(440, dur) * (np.arange(n) / n) ** 1.6 * 0.045
place(sfx, lp(rise, 3000), 13.45)
# soft major-ish dyad the moment it lands
for f, g in ((A4, 0.075), (E5, 0.055), (A5, 0.030)):
    x = sine(f, 1.1) * env(int(1.1 * SR), 0.004, 0.42, 0.16, 0.60)
    place(sfx, x * g, 14.70)

# ---------- SFX: stats tick-in (S6) ----------
for i in range(4):
    at = 16.75 + i * 0.20
    f = [A4, C5, E5, A4][i]
    x = sine(f, 0.13) * env(int(0.13 * SR), 0.002, 0.05, 0.07, 0.06)
    place(sfx, x * 0.06, at)

# ---------- resolve chord under the outro ----------
for f, g in ((A2, 0.20), (A3, 0.13), (C4, 0.10), (E4, 0.10), (A4, 0.075)):
    x = sine(f, 3.2) * env(int(3.2 * SR), 0.05, 0.7, 0.7, 1.9)
    x += saw(f * 2, 3.2, 7) * 0.020 * env(int(3.2 * SR), 0.10, 0.7, 0.6, 1.9)
    place(music, lp(x, 2600) * g, 19.30)

# ---------- shared reverb: the glue that makes SFX part of the track ----------
def reverb(x, mix=0.26):
    wet = np.zeros_like(x)
    for d_ms, g in ((37, 0.52), (61, 0.40), (89, 0.30), (127, 0.20)):
        d = int(d_ms * SR / 1000)
        wet[d:] += x[:-d] * g
    # roll off the repeats so the tail sits dark, like the visuals
    wet = lp(wet, 2600)
    return x * (1 - mix * 0.5) + wet * mix

music = reverb(music, 0.22)
sfx = reverb(sfx, 0.34)

mix = music + sfx

# ---------- gentle master: soft-knee limiting, then normalize ----------
mix = np.tanh(mix * 1.18) / 1.18
peak = np.max(np.abs(mix))
mix = mix / peak * 0.89                      # ~ -1.0 dBFS
# short fades so the cut never clicks
fi, fo = int(0.05 * SR), int(0.35 * SR)
mix[:fi] *= np.linspace(0, 1, fi)
mix[-fo:] *= np.linspace(1, 0, fo)

stereo = np.stack([mix, mix], axis=1)
pcm = (np.clip(stereo, -1, 1) * 32767).astype('<i2')

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with wave.open(OUT, 'wb') as w:
    w.setnchannels(2); w.setsampwidth(2); w.setframerate(SR)
    w.writeframes(pcm.tobytes())

print(f"wrote {OUT}  {DUR}s  peak={np.max(np.abs(mix)):.3f}  "
      f"music_peak={np.max(np.abs(music)):.3f}  sfx_peak={np.max(np.abs(sfx)):.3f}")
