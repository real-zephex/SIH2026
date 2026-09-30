#!/usr/bin/env python3
"""Procedural music bed for the ULPF walkthrough.

Generated rather than licensed so the render is fully offline and
reproducible. A minor, 100 BPM, 268s.

The arc follows brag-plan.md: tension (0-32s), explanatory (32-180s),
analytical (180-227s), sober (227-258s), resolution (258-268s).
"""
import math
import struct
import wave

SR = 44100
DUR = 268.0
BPM = 100.0
BEAT = 60.0 / BPM          # 0.6s
N = int(SR * DUR)

# A natural minor. A2 root.
ROOT = 110.0
def semi(n):
    return ROOT * (2.0 ** (n / 12.0))

# scale degrees in A minor: A B C D E F G
A2, B2, C3, D3, E3, F3, G3 = (semi(0), semi(2), semi(3), semi(5), semi(7), semi(8), semi(10))
A3, C4, D4, E4, G4, A4, C5, D5, E5 = (
    semi(12), semi(15), semi(17), semi(19), semi(22), semi(24), semi(27), semi(29), semi(31))


def env(t, dur, a=0.01, d=0.12, s=0.7, r=0.3):
    """Simple ADSR in seconds."""
    if t < 0 or t > dur:
        return 0.0
    if t < a:
        return t / a
    if t < a + d:
        return 1.0 - (1.0 - s) * (t - a) / d
    if t > dur - r:
        return max(0.0, s * (dur - t) / r)
    return s


def saw(ph):
    return 2.0 * (ph - math.floor(ph + 0.5))


def tri(ph):
    x = (ph % 1.0)
    return 4.0 * abs(x - 0.5) - 1.0


def lp(x, state, coef):
    return state + coef * (x - state)


# --- arrangement -----------------------------------------------------------
# (start, end) -> (sub level, pad level, arp level, brightness)
def levels(t):
    if t < 6:                       # hook: pulse only, sparse
        return 0.85, 0.00, 0.00, 0.25
    if t < 16:                      # the tax: pulse + a low pad creeps in
        return 0.85, 0.20, 0.00, 0.30
    if t < 23:                      # blind spot: everything thins out
        return 0.55, 0.28, 0.00, 0.22
    if t < 32:                      # title: first full pad statement
        return 0.75, 0.62, 0.10, 0.45
    if t < 46:                      # pipeline: pad, arp enters
        return 0.70, 0.55, 0.30, 0.52
    if t < 94:                      # architecture + schema: steady, code floor
        return 0.62, 0.50, 0.34, 0.50
    if t < 108:                     # losslessness: the one beautiful moment
        return 0.50, 0.72, 0.42, 0.62
    if t < 124:                     # four parsers: brisk
        return 0.68, 0.46, 0.48, 0.58
    if t < 180:                     # deep dive: music drops so code reads
        return 0.42, 0.34, 0.26, 0.40
    if t < 203:                     # the 75x reveal: pulse returns
        return 0.80, 0.40, 0.40, 0.58
    if t < 216:                     # two ceilings: analytical, steady
        return 0.66, 0.44, 0.30, 0.48
    if t < 227:                     # silent loss: near-silence, uncomfortable
        return 0.34, 0.22, 0.00, 0.26
    if t < 244:                     # testing + outcomes: sober, cumulative
        return 0.56, 0.40, 0.22, 0.40
    if t < 258:                     # roadmap: resolved, forward
        return 0.68, 0.52, 0.30, 0.50
    # 258-268 closing: full pad, arp resolves on A, gentle tail
    return 0.52, 0.78, 0.34, 0.55


# arp pattern: A2 C3 E3 G3 (16ths, but we only sound every other 16th)
ARP = [A3, C4, E4, G4]
CHORD = [A2, C3, E3, A3]           # pad voicing

buf = [0.0] * N
lp1 = lp2 = lp3 = 0.0
arp_ph = [0.0] * len(ARP)
sub_ph = 0.0
pad_ph = [0.0] * len(CHORD)

# one 16th-note step = BEAT/4
STEP = BEAT / 4.0
steps = int(DUR / STEP) + 2

for st in range(steps):
    t0 = st * STEP
    if t0 >= DUR:
        break
    sub_l, pad_l, arp_l, bright = levels(t0)
    i0 = int(t0 * SR)
    i1 = min(N, i0 + int(STEP * SR) + 1)

    # ---- sub pulse on every beat
    bpos = t0 % BEAT
    if bpos < 1e-9:
        dur_b = BEAT * 0.92
        amp = 0.30 * sub_l
        ph0 = sub_ph
        for i in range(i0, i1):
            dt = (i - i0) / SR
            e = env(dt, dur_b, a=0.004, d=0.09, s=0.34, r=0.16)
            if e <= 0:
                continue
            ph0 += A2 / SR
            v = math.sin(2 * math.pi * ph0) * 0.85 + saw(ph0 * 0.5) * 0.15
            buf[i] += v * e * amp

    # ---- pad: sustained chord, refreshed every 2 beats
    if bpos < 1e-9 and (int(round(t0 / BEAT)) % 2 == 0):
        for k in range(len(CHORD)):
            pad_ph[k] = 0.0
        pad_dur = BEAT * 2.6
        for i in range(i0, min(N, i0 + int(pad_dur * SR))):
            dt = (i - i0) / SR
            e = env(dt, pad_dur, a=0.35, d=0.5, s=0.72, r=0.9)
            if e <= 0:
                continue
            v = 0.0
            for k, f in enumerate(CHORD):
                pad_ph[k] += f / SR
                v += saw(pad_ph[k]) * 0.25
            lp1 = lp(v, lp1, 0.10 + 0.22 * bright)
            buf[i] += lp1 * e * 0.085 * pad_l

    # ---- arp pluck every other 16th (0.3s apart) -> keeps text readable
    if arp_l > 0.001 and (st % 2 == 0):
        note = ARP[(st // 2) % len(ARP)]
        dur_a = 0.34
        ph0 = 0.0
        for i in range(i0, min(N, i0 + int(dur_a * SR))):
            dt = (i - i0) / SR
            e = env(dt, dur_a, a=0.002, d=0.10, s=0.20, r=0.20)
            if e <= 0:
                continue
            ph0 += note / SR
            v = tri(ph0) * 0.6 + saw(ph0) * 0.4
            lp3 = lp(v, lp3, 0.30 + 0.35 * bright)
            buf[i] += lp3 * e * 0.075 * arp_l

# --- master: soft clip, fade in/out, normalise ---------------------------
peak = max(1e-9, max(abs(x) for x in buf))
g = 0.72 / peak
for i in range(N):
    x = buf[i] * g
    # one-pole high shelf cut above ~7k to take the edge off
    buf[i] = math.tanh(x * 1.15) * 0.88

fade_in = int(0.9 * SR)
fade_out = int(2.6 * SR)
for i in range(fade_in):
    buf[i] *= i / fade_in
for i in range(fade_out):
    buf[N - 1 - i] *= i / fade_out

# final normalise to -1.5 dBFS
peak = max(1e-9, max(abs(x) for x in buf))
g = (10 ** (-1.5 / 20)) / peak
frames = bytearray()
for x in buf:
    v = int(max(-1.0, min(1.0, x * g)) * 32767)
    frames += struct.pack('<h', v)

out = 'audio.wav'
with wave.open(out, 'wb') as w:
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(SR)
    w.writeframes(bytes(frames))
print(f'wrote {out}  {DUR}s  {BPM} BPM  peak-normalised -1.5 dBFS')
