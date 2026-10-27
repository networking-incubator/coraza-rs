# Historical side-by-side SQLi and XSS benchmark report

This report preserves the comparison made before consolidation. In its tables,
“YA original” means the initial libperfusion implementation,
“libinjection-rs original” means the Rust implementation removed during P3,
and “YA after all optimizations” means the selected implementation before it
moved into `libperfusion/`. The repository now contains only libperfusion;
current benchmark targets do not reproduce these pairwise measurements.

**Measured:** 2026-10-13

**Latest measured source:** HEAD `af42a1590af7da5e374fe8e1d12abbfa4787c371` plus
the PR1 working-tree changes to SQLi LIKE folding and Unicode keyword
matching, HTML NUL tokenization, and XSS name classification. The report
preserves original YA and reference measurements and refreshes the final
YA column from the current source.

**Implementations at measurement time:** YA libperfusion and the then-current
in-repository libinjection-rs crate

## Executive summary

The final implementations agreed on all 496 checked-in corpus inputs and
all 130 generated inputs in the scaling sweep. The original corpus
run favored YA by 1.44× to 2.09× per input. The synthetic measurements show
why that average does not describe every input shape.

None of the measured runs showed quadratic XSS behavior in the tested sizes
up to 10 MiB. The latest YA log-log scaling estimates for XSS miss families
ranged from 1.00 to 1.01; its tested early-hit case stayed almost constant
with input length. These results are consistent with near-linear scans plus
fixed context costs, not quadratic growth. They do not prove a bound for every
byte sequence.

In the original run, the largest XSS slowdown was on misses with no useful
HTML marker: at 1 MiB, YA took 1.37 ms on plain text and 6.65 ms on repeating
binary bytes, compared with 0.25 ms for libinjection-rs on both. YA tried all
five contexts on every input; libinjection-rs skipped DataState without a less
than sign and skipped quoted contexts without their delimiter. That source
difference was consistent with the measured gap. Other inputs reversed the
result: YA was 1.36× faster on a benign tag stream and 1.75× faster on repeated
near-miss event attributes at 1 MiB.

The quadratic case recorded in the older performance artifacts is SQLi, not
XSS. It used an escaped-quote suffix. This run recreates that exact byte
pattern and size series; both current implementations scale close to linearly
through 51,202 bytes.

**Optimization history:** The shared-search revision added XSS context
pruning, `memchr`-backed byte searches, and a binary attribute-name guard.
Its SQLi escaped-quote case regressed to 251.0 µs at 51,202 bytes, from
69.4 µs originally. The SQLi-local delimiter fast path and the newer
`memchr` pair, slice, and presence searches brought the latest result to
55.9 µs in this run. HTML fast paths still avoid repeated `<` scans. The
tables compare original YA and libinjection-rs with YA after all
optimizations.

A follow-up regression check found that inlining the Unicode keyword fallback
inflated the SQLi tokenizer's hot path. At 1 MiB, SQLi plain misses measured
481.2 µs versus 256.1 µs in libinjection-rs. Keeping the Unicode fallback
out-of-line restored the result to 250.2 µs versus 246.2 µs while preserving
Unicode keyword matching. The earlier XSS NUL-aware per-byte delimiter check
also slowed plain-text misses; using delimiter tables that leave NUL in the
token span restored the 1 MiB result to 267.8 µs versus 253.8 µs. Both fixes
are included in the latest measurements below.

The latest pinned compare and scaling runs matched all 496 corpus inputs and
all 130 generated inputs. CPU frequency was not locked. At 10 MiB, current YA
slash-miss measured 8.48 ms [8.39–8.93], and libinjection-rs measured
8.74 ms [8.16–9.33]. The earlier original measurements were 25.2 ms for YA
and 11.1 ms for libinjection-rs; an earlier optimized YA run measured
8.33 ms. These timings vary with CPU frequency, so treat small differences
as directional.

## Scope and method

The historical comparison used the shared public legacy APIs: libperfusion
sqli/xss and libinjection-rs detect_sqli/detect_xss. SQLi outputs were checked by exact
fingerprint; XSS outputs by boolean. These return values are passed through
black_box during timing so result construction remains part of the measured
call. Modern analyze APIs and APIs without a behavior-equivalent counterpart
are outside this comparison.

The optimized Cargo bench profile was used. Each synthetic input was generated
before timing, verified against the expected hit or miss, and checked for exact
parity. The two implementations then ran in alternating order for five
samples, targeting 15 ms per sample. The report shows the median and the
observed minimum and maximum sample latencies. A single large-input call can
exceed the 15 ms target, so those samples contain one call. The timer is checked
after batches of calls for small inputs to reduce timer overhead.

The measurements were taken with these commands at the time. The current
`compare` target measures two libperfusion API entry points; it cannot
reproduce this historical cross-implementation comparison:

    taskset -c 3 cargo bench -p libperfusion --bench compare
    taskset -c 3 cargo bench -p libperfusion --bench scaling

The benchmark process was pinned to logical CPU 3. The CPU frequency was not
locked and the host was not otherwise isolated, so the sample ranges matter,
especially for multi-megabyte inputs.

Hardware and toolchain: AMD Ryzen 7 PRO 7840HS, x86_64 Linux 7.2.9,
rustc 1.97.1, release bench profile.

## Inputs

The corpus run parses all 496 files in libperfusion/tests/corpus. The XSS
workload contains 17 hits and 479 misses; the SQLi workload contains 96 hits
and 400 misses. The shared fixture results are checked before timing.

The generated sweep contains 130 inputs:

- XSS: ten shapes at 64, 256, 1,024, 4,096, 16,384, 65,536, 262,144, and
  1,048,576 bytes. Shapes are plain text, benign tags, near-miss event
  attributes, ordinary comments, unclosed comments, repeated less-than signs,
  repeated quotes, NUL/0xff/0x80 bytes, a script at the start, and an
  entity-encoded JavaScript URL at the end.
- XSS large-input controls: repeated slash bytes and a repeated benign tag
  stream at 1, 5, and 10 MiB.
- SQLi: plain text, repeated plus signs, an attack at the start followed by
  spaces, and leading spaces followed by an attack, at the same eight sizes.
- SQLi historical stress case: an apostrophe, a backslash, then repeated
  apostrophes, at exact total lengths 1,602, 3,202, 6,402, 12,802, 25,602,
  and 51,202 bytes.
- Prose, JSON, and base64-like 4 KiB misses for both detectors.

For scaling, the exponent is the ordinary least-squares slope of
log(median latency) against log(input bytes), using points at least 4 KiB.
A slope near 1 is linear; a slope near 2 is quadratic. Early-hit slopes are
expected to be close to zero because the detector returns before scanning the
padding.

## Corpus results

These are medians from five 100 ms samples per detector/workload, pinned to
logical CPU 3. The counts sum to all 496 corpus inputs for each API.

| Workload | Inputs | YA original ns/input | libinjection-rs original ns/input | YA after all optimizations ns/input |
| --- | ---: | ---: | ---: | ---: |
| SQLi hit | 96 | 160.0 | 329.7 | 173.2 |
| SQLi miss | 400 | 158.2 | 330.8 | 167.5 |
| XSS hit | 17 | 35.2 | 52.8 | 31.1 |
| XSS miss | 479 | 131.1 | 188.1 | 79.1 |


These corpus averages mostly reflect small inputs. The synthetic size sweep
shows materially different performance on long inputs and different byte
classes.

## Scaling estimates

### XSS

| Shape | YA original exponent | libinjection-rs original exponent | YA after all optimizations exponent |
| --- | ---: | ---: | ---: |
| plain_miss | 0.99 | 0.94 | 1.01 |
| benign_tags_miss | 0.98 | 0.99 | 1.00 |
| event_near_miss | 0.99 | 1.00 | 1.00 |
| comment_miss | 1.00 | 1.00 | 1.00 |
| unclosed_comment_miss | 0.99 | 0.99 | 1.01 |
| angle_noise_miss | 1.01 | 1.00 | 1.00 |
| quote_noise_miss | 1.00 | 0.99 | 1.00 |
| binary_noise_miss | 1.00 | 0.94 | 1.01 |
| attack_at_start | 0.11 | 0.09 | 0.14 |
| encoded_url_at_end | 1.00 | 1.00 | 0.97 |
| slashes_miss | 1.10 | 1.12 | 1.01 |
| large_tag_stream_miss | 1.03 | 1.04 | 1.01 |


The latest YA XSS miss-family estimates range from 1.00 to 1.01.
The preserved original libinjection-rs estimate for that shape is 1.12. Both
are far below the quadratic slope of 2. The 1/5/10 MiB rows show timing
variation at the largest size, so treat small differences in these estimates
as directional.

### SQLi

| Shape | YA original exponent | libinjection-rs original exponent | YA after all optimizations exponent |
| --- | ---: | ---: | ---: |
| plain_miss | 1.00 | 0.99 | 1.00 |
| operator_noise_miss | 1.00 | 1.00 | 1.01 |
| attack_at_start | 1.00 | 0.76 | 0.86 |
| attack_after_whitespace | 0.98 | 0.99 | 0.99 |
| mixed_escaped_quote_suffix | 1.00 | 1.00 | 0.99 |


## Earlier quadratic report

The repository's archived performance evidence at commit 5b45dc6 identifies
mixed_escaped_quote_suffix as an SQLi quadratic-shape exception. Its recorded
Rust exponent was about 1.97. The accompanying XSS scaling input was repeated
slashes at 1, 5, and 10 MiB.

The present benchmark uses the same SQLi byte pattern and exact size series.

| Bytes | YA original ns/op (median [min–max]) | libinjection-rs original ns/op (median [min–max]) | YA after all optimizations ns/op (median [min–max]) |
| --- | ---: | ---: | ---: |
| 1,602 | 2,317.6 [2,279.9–2,412.5] | 7,433.2 [7,365.4–7,495.8] | 1,889.4 [1,877.4–1,906.0] |
| 3,202 | 4,464.5 [4,406.6–4,630.4] | 14,911.0 [14,820.6–15,084.1] | 3,603.7 [3,588.0–3,623.7] |
| 6,402 | 8,780.7 [8,697.3–8,931.2] | 29,728.0 [29,641.8–29,857.3] | 7,077.3 [7,055.5–7,226.8] |
| 12,802 | 17,420.9 [17,394.0–18,097.8] | 59,695.9 [59,383.3–60,208.3] | 14,062.1 [14,041.6–14,517.8] |
| 25,602 | 35,020.8 [34,626.6–35,301.5] | 120,590.8 [120,138.8–122,745.2] | 27,986.4 [27,923.1–28,367.9] |
| 51,202 | 69,385.6 [68,622.7–70,418.4] | 236,855.2 [234,857.2–238,835.7] | 55,928.4 [55,823.4–56,071.4] |


The optimized YA and original libinjection-rs SQLi slopes are near 1. This is
a fresh current-branch measurement, not a controlled comparison with the old
artifact, which came from a different source revision and environment.

## XSS large-input samples

| Shape | Bytes | Output | YA original median [min–max] | libinjection-rs original median [min–max] | YA after all optimizations median [min–max] |
| --- | ---: | ---: | ---: | ---: | ---: |
| slashes_miss | 1,048,576 | miss | 1,939,023.5 [1,870,911.3–1,984,698.1] | 826,255.7 [790,220.9–891,618.2] | 830,388.9 [826,326.6–835,468.3] |
| large_tag_stream_miss | 1,048,576 | miss | 5,429,876.7 [5,294,064.7–5,478,581.7] | 7,360,782.0 [7,292,707.3–7,515,862.0] | 4,022,920.2 [3,888,252.0–4,177,706.5] |
| slashes_miss | 5,242,880 | miss | 10,094,291.5 [9,794,272.5–11,094,333.0] | 4,776,243.8 [4,492,199.8–5,166,007.0] | 4,159,539.8 [4,134,956.0–4,214,252.8] |
| large_tag_stream_miss | 5,242,880 | miss | 30,997,555.0 [27,955,382.0–41,938,835.0] | 46,792,555.0 [37,648,255.0–52,426,442.0] | 20,516,016.0 [19,538,367.0–20,888,047.0] |
| slashes_miss | 10,485,760 | miss | 25,154,996.0 [23,731,498.0–29,482,656.0] | 11,069,160.5 [10,321,865.0–13,574,107.0] | 8,484,340.5 [8,393,264.5–8,933,591.5] |
| large_tag_stream_miss | 10,485,760 | miss | 56,216,501.0 [54,577,107.0–58,032,246.0] | 75,971,980.0 [75,059,934.0–76,805,087.0] | 41,223,234.0 [40,374,638.0–42,758,002.0] |


In the original run at 10 MiB, the slash miss took about 25.2 ms in YA and
11.1 ms in libinjection-rs. The benign tag stream took about 56.2 ms and
76.0 ms, respectively. The input shape changed the winner; the large tag
stream was about 1.35× faster in YA, while repeated slashes were about 2.27×
slower. The final optimized YA measurements are in the last column.

## Full generated measurements

Values are nanoseconds per public detector call. Each range is the minimum
and maximum of five samples.

### XSS

| Shape | Bytes | Output | YA original median [min–max] | libinjection-rs original median [min–max] | YA after all optimizations median [min–max] |
| --- | ---: | ---: | ---: | ---: | ---: |
| plain_miss | 64 | miss | 138.0 [132.9–144.7] | 120.6 [118.4–130.3] | 74.8 [74.7–82.5] |
| benign_tags_miss | 64 | miss | 509.5 [431.5–673.6] | 712.2 [681.0–833.7] | 275.2 [270.6–290.8] |
| event_near_miss | 64 | miss | 783.5 [691.0–1,109.3] | 1,271.2 [1,158.0–1,594.9] | 392.7 [388.6–404.8] |
| comment_miss | 64 | miss | 237.8 [232.8–251.9] | 355.0 [349.1–369.3] | 147.5 [146.7–149.9] |
| unclosed_comment_miss | 64 | miss | 129.2 [128.1–131.2] | 157.9 [155.4–158.7] | 89.9 [88.1–115.8] |
| angle_noise_miss | 64 | miss | 368.1 [366.4–409.4] | 379.7 [375.3–381.8] | 405.8 [404.4–418.4] |
| quote_noise_miss | 64 | miss | 154.6 [150.9–157.4] | 252.2 [250.9–252.7] | 138.6 [137.3–139.6] |
| binary_noise_miss | 64 | miss | 449.7 [444.2–452.3] | 106.6 [105.3–107.3] | 68.3 [65.5–73.4] |
| attack_at_start | 64 | hit | 19.7 [19.6–20.2] | 31.2 [26.9–34.4] | 16.8 [16.8–17.2] |
| encoded_url_at_end | 64 | hit | 66.4 [66.1–78.2] | 120.1 [114.6–121.2] | 55.4 [55.1–55.6] |
| plain_miss | 256 | miss | 427.2 [401.8–450.4] | 147.1 [138.1–159.3] | 121.5 [120.6–124.6] |
| benign_tags_miss | 256 | miss | 1,692.0 [1,526.8–2,564.5] | 2,404.5 [2,067.5–3,410.6] | 1,040.0 [1,023.4–1,062.1] |
| event_near_miss | 256 | miss | 3,220.8 [2,977.2–3,482.8] | 5,574.0 [5,203.9–5,809.3] | 1,542.2 [1,497.6–1,585.0] |
| comment_miss | 256 | miss | 656.0 [631.3–708.5] | 693.6 [665.0–802.7] | 375.4 [372.3–386.3] |
| unclosed_comment_miss | 256 | miss | 354.5 [347.5–372.4] | 226.7 [225.1–228.0] | 137.9 [134.3–143.3] |
| angle_noise_miss | 256 | miss | 1,300.0 [1,277.9–1,411.1] | 1,310.5 [1,130.8–1,394.7] | 1,501.8 [1,470.1–1,523.9] |
| quote_noise_miss | 256 | miss | 412.5 [405.5–433.2] | 350.4 [346.5–385.1] | 225.9 [224.0–236.9] |
| binary_noise_miss | 256 | miss | 1,679.8 [1,659.8–1,730.4] | 137.3 [136.7–141.1] | 138.4 [132.8–227.1] |
| attack_at_start | 256 | hit | 19.0 [18.7–19.9] | 30.1 [24.5–38.2] | 16.9 [16.7–16.9] |
| encoded_url_at_end | 256 | hit | 147.3 [146.1–148.6] | 196.4 [192.9–198.7] | 59.1 [58.6–60.3] |
| plain_miss | 1,024 | miss | 1,491.7 [1,394.3–1,633.9] | 395.4 [368.0–409.9] | 302.9 [302.0–308.6] |
| benign_tags_miss | 1,024 | miss | 5,453.9 [5,358.5–5,519.1] | 7,784.9 [7,213.3–8,237.8] | 3,995.0 [3,965.5–4,119.9] |
| event_near_miss | 1,024 | miss | 10,379.8 [10,187.7–11,145.9] | 18,129.5 [17,887.7–18,562.6] | 6,050.1 [5,980.7–6,135.3] |
| comment_miss | 1,024 | miss | 2,262.9 [2,214.7–2,566.8] | 2,001.9 [1,994.3–2,027.7] | 1,229.2 [1,221.2–1,372.2] |
| unclosed_comment_miss | 1,024 | miss | 1,339.7 [1,322.4–1,358.7] | 756.0 [710.2–772.2] | 333.9 [332.7–381.0] |
| angle_noise_miss | 1,024 | miss | 5,281.4 [5,174.2–5,570.0] | 4,650.5 [4,591.5–5,476.3] | 5,688.0 [5,673.8–5,708.9] |
| quote_noise_miss | 1,024 | miss | 1,438.0 [1,411.3–1,451.9] | 1,084.0 [1,079.6–1,106.5] | 584.9 [582.3–592.7] |
| binary_noise_miss | 1,024 | miss | 6,648.3 [6,592.2–6,702.5] | 387.2 [381.4–391.3] | 317.0 [313.9–356.4] |
| attack_at_start | 1,024 | hit | 19.7 [18.6–19.8] | 25.5 [24.0–34.1] | 18.2 [17.4–21.1] |
| encoded_url_at_end | 1,024 | hit | 472.6 [459.9–482.8] | 517.3 [502.7–529.5] | 68.8 [64.4–74.7] |
| plain_miss | 4,096 | miss | 5,456.2 [5,346.8–5,552.8] | 1,310.4 [1,300.6–1,345.8] | 1,019.7 [1,014.5–1,040.7] |
| benign_tags_miss | 4,096 | miss | 21,575.1 [21,453.2–21,889.1] | 29,376.5 [29,268.9–31,324.7] | 16,326.0 [16,160.1–16,537.0] |
| event_near_miss | 4,096 | miss | 41,762.1 [41,397.6–46,192.1] | 71,578.7 [71,243.2–72,003.2] | 24,175.3 [23,812.0–24,467.4] |
| comment_miss | 4,096 | miss | 8,812.0 [8,715.5–8,996.2] | 7,207.4 [7,072.0–7,368.9] | 4,778.9 [4,774.5–4,886.4] |
| unclosed_comment_miss | 4,096 | miss | 5,244.2 [5,194.1–5,320.1] | 2,564.8 [2,546.0–2,664.6] | 1,062.7 [1,038.5–1,162.9] |
| angle_noise_miss | 4,096 | miss | 20,727.3 [20,613.9–23,348.9] | 18,307.6 [18,153.4–18,574.1] | 22,394.7 [22,377.1–22,642.6] |
| quote_noise_miss | 4,096 | miss | 5,430.1 [5,374.3–5,508.6] | 3,962.6 [3,936.8–3,996.7] | 1,965.7 [1,911.6–2,011.0] |
| binary_noise_miss | 4,096 | miss | 26,324.7 [26,079.6–26,592.6] | 1,301.8 [1,298.4–1,413.2] | 1,030.7 [1,028.5–1,037.7] |
| attack_at_start | 4,096 | hit | 19.7 [19.0–20.7] | 26.1 [22.0–34.4] | 18.0 [17.8–18.1] |
| encoded_url_at_end | 4,096 | hit | 1,733.2 [1,695.9–1,816.2] | 1,762.6 [1,758.3–2,030.5] | 89.8 [89.6–100.1] |
| plain_miss | 16,384 | miss | 22,139.9 [21,346.6–24,398.6] | 5,134.8 [5,110.9–5,726.3] | 3,870.9 [3,853.0–3,935.7] |
| benign_tags_miss | 16,384 | miss | 107,554.3 [87,613.0–114,114.9] | 141,083.3 [117,766.7–152,654.7] | 62,335.0 [62,024.8–64,101.4] |
| event_near_miss | 16,384 | miss | 177,951.5 [163,639.6–211,025.4] | 300,949.0 [286,941.1–340,138.7] | 95,961.7 [95,404.1–97,557.1] |
| comment_miss | 16,384 | miss | 34,967.2 [34,739.1–36,721.1] | 28,412.8 [27,963.9–29,366.9] | 19,044.5 [18,874.8–19,071.3] |
| unclosed_comment_miss | 16,384 | miss | 20,404.0 [19,998.0–20,508.9] | 9,944.5 [9,739.9–10,951.6] | 3,990.3 [3,963.1–4,036.2] |
| angle_noise_miss | 16,384 | miss | 85,922.0 [82,351.5–91,858.3] | 79,872.9 [74,076.1–92,060.7] | 89,340.9 [88,890.6–90,057.8] |
| quote_noise_miss | 16,384 | miss | 22,716.4 [22,207.6–24,889.6] | 16,563.7 [16,288.2–16,912.3] | 7,378.8 [7,368.6–7,472.8] |
| binary_noise_miss | 16,384 | miss | 111,485.4 [106,682.4–115,954.5] | 5,401.6 [5,161.2–5,579.2] | 3,853.0 [3,843.7–3,902.5] |
| attack_at_start | 16,384 | hit | 22.8 [22.5–23.9] | 26.3 [25.9–27.8] | 21.8 [21.7–21.9] |
| encoded_url_at_end | 16,384 | hit | 7,506.0 [7,315.5–7,844.8] | 7,625.9 [7,284.1–8,006.1] | 188.5 [187.3–189.4] |
| plain_miss | 65,536 | miss | 84,758.2 [84,246.7–85,073.6] | 15,280.7 [15,015.9–15,629.7] | 16,377.3 [16,206.5–16,841.8] |
| benign_tags_miss | 65,536 | miss | 342,756.1 [336,825.6–382,392.0] | 466,206.6 [458,810.9–469,553.5] | 269,189.0 [256,353.2–305,659.1] |
| event_near_miss | 65,536 | miss | 640,615.4 [627,528.7–654,307.2] | 1,099,040.1 [1,078,752.6–1,134,975.5] | 388,545.9 [378,030.0–399,231.4] |
| comment_miss | 65,536 | miss | 136,368.5 [129,164.6–140,776.7] | 113,358.0 [111,533.6–124,621.3] | 76,743.0 [76,428.6–77,904.2] |
| unclosed_comment_miss | 65,536 | miss | 81,097.4 [79,863.5–82,310.6] | 38,834.2 [38,417.4–39,401.9] | 16,703.2 [16,693.3–17,359.2] |
| angle_noise_miss | 65,536 | miss | 315,862.9 [315,154.9–400,101.5] | 280,083.3 [277,778.9–296,335.2] | 358,169.8 [356,808.7–360,055.0] |
| quote_noise_miss | 65,536 | miss | 87,296.1 [85,184.5–90,132.6] | 63,268.2 [61,833.7–66,507.9] | 30,328.7 [30,193.8–30,460.7] |
| binary_noise_miss | 65,536 | miss | 419,302.6 [414,709.5–431,284.1] | 15,830.4 [15,628.8–16,547.5] | 16,304.9 [16,247.1–16,477.0] |
| attack_at_start | 65,536 | hit | 34.5 [34.2–37.4] | 39.8 [39.0–44.1] | 37.0 [36.7–37.2] |
| encoded_url_at_end | 65,536 | hit | 33,558.0 [32,455.1–35,999.9] | 34,937.7 [32,162.1–36,263.7] | 957.6 [954.2–964.3] |
| plain_miss | 262,144 | miss | 345,088.9 [339,532.2–354,985.4] | 68,167.1 [66,492.9–70,333.6] | 66,145.6 [65,442.1–67,253.9] |
| benign_tags_miss | 262,144 | miss | 1,416,602.7 [1,399,342.1–1,426,955.8] | 1,881,752.0 [1,865,930.8–1,891,740.9] | 1,017,504.1 [1,003,792.9–1,025,081.7] |
| event_near_miss | 262,144 | miss | 2,646,815.3 [2,621,729.7–2,745,582.5] | 4,605,785.5 [4,538,546.8–4,701,353.2] | 1,516,917.6 [1,476,095.8–1,542,474.6] |
| comment_miss | 262,144 | miss | 596,072.3 [586,193.4–665,521.8] | 529,321.5 [513,408.7–575,365.2] | 303,491.1 [301,634.0–312,419.3] |
| unclosed_comment_miss | 262,144 | miss | 359,050.6 [339,080.2–448,691.6] | 180,752.9 [165,209.1–215,998.3] | 66,700.4 [66,257.2–67,628.1] |
| angle_noise_miss | 262,144 | miss | 1,434,706.8 [1,407,621.4–1,452,545.8] | 1,257,910.2 [1,171,899.7–1,431,632.8] | 1,428,153.8 [1,425,860.5–1,459,909.1] |
| quote_noise_miss | 262,144 | miss | 359,079.0 [351,855.3–361,769.3] | 257,049.3 [249,855.2–264,402.4] | 122,300.4 [120,056.0–146,657.5] |
| binary_noise_miss | 262,144 | miss | 1,776,507.1 [1,729,182.4–1,795,351.3] | 66,489.3 [65,826.7–70,103.3] | 65,909.0 [65,208.2–66,745.2] |
| attack_at_start | 262,144 | hit | 36.6 [34.5–38.7] | 40.5 [39.3–41.6] | 37.0 [36.8–37.4] |
| encoded_url_at_end | 262,144 | hit | 120,708.4 [117,486.5–124,184.0] | 123,701.0 [119,993.5–127,324.7] | 3,621.0 [3,605.8–3,637.3] |
| plain_miss | 1,048,576 | miss | 1,366,312.6 [1,287,804.8–1,430,239.3] | 251,345.9 [235,948.2–254,316.3] | 267,772.3 [264,845.8–273,917.1] |
| benign_tags_miss | 1,048,576 | miss | 5,453,848.7 [5,409,141.0–5,987,215.0] | 7,431,605.3 [7,260,343.0–7,539,942.5] | 4,060,175.5 [4,000,385.5–4,084,579.0] |
| event_near_miss | 1,048,576 | miss | 10,594,898.5 [10,581,678.5–10,959,589.5] | 18,577,052.0 [18,133,549.0–20,179,707.0] | 6,077,386.3 [5,966,094.0–6,179,565.3] |
| comment_miss | 1,048,576 | miss | 2,184,633.4 [2,166,406.4–2,222,892.6] | 1,767,097.1 [1,764,091.6–1,805,739.8] | 1,260,437.7 [1,242,839.5–1,298,239.7] |
| unclosed_comment_miss | 1,048,576 | miss | 1,236,305.5 [1,223,163.8–1,276,226.3] | 556,495.3 [552,493.9–667,487.3] | 276,222.7 [275,432.1–277,448.3] |
| angle_noise_miss | 1,048,576 | miss | 5,609,992.3 [5,309,540.3–5,860,891.0] | 4,643,960.0 [4,575,686.8–5,270,119.3] | 5,742,115.3 [5,708,879.7–5,752,388.0] |
| quote_noise_miss | 1,048,576 | miss | 1,381,155.1 [1,369,876.6–1,431,633.7] | 994,146.2 [988,560.7–1,018,760.9] | 488,508.3 [485,510.7–492,196.2] |
| binary_noise_miss | 1,048,576 | miss | 6,650,566.0 [6,575,381.3–6,702,874.3] | 248,997.7 [246,564.9–252,914.4] | 267,011.8 [265,264.3–271,367.8] |
| attack_at_start | 1,048,576 | hit | 33.8 [33.7–33.9] | 38.9 [38.7–43.1] | 37.0 [36.6–37.0] |
| encoded_url_at_end | 1,048,576 | hit | 454,042.0 [447,767.2–456,272.8] | 458,961.8 [457,598.9–466,842.4] | 17,576.7 [17,241.4–17,823.2] |
| slashes_miss | 1,048,576 | miss | 1,939,023.5 [1,870,911.3–1,984,698.1] | 826,255.7 [790,220.9–891,618.2] | 830,388.9 [826,326.6–835,468.3] |
| large_tag_stream_miss | 1,048,576 | miss | 5,429,876.7 [5,294,064.7–5,478,581.7] | 7,360,782.0 [7,292,707.3–7,515,862.0] | 4,022,920.2 [3,888,252.0–4,177,706.5] |
| slashes_miss | 5,242,880 | miss | 10,094,291.5 [9,794,272.5–11,094,333.0] | 4,776,243.8 [4,492,199.8–5,166,007.0] | 4,159,539.8 [4,134,956.0–4,214,252.8] |
| large_tag_stream_miss | 5,242,880 | miss | 30,997,555.0 [27,955,382.0–41,938,835.0] | 46,792,555.0 [37,648,255.0–52,426,442.0] | 20,516,016.0 [19,538,367.0–20,888,047.0] |
| slashes_miss | 10,485,760 | miss | 25,154,996.0 [23,731,498.0–29,482,656.0] | 11,069,160.5 [10,321,865.0–13,574,107.0] | 8,484,340.5 [8,393,264.5–8,933,591.5] |
| large_tag_stream_miss | 10,485,760 | miss | 56,216,501.0 [54,577,107.0–58,032,246.0] | 75,971,980.0 [75,059,934.0–76,805,087.0] | 41,223,234.0 [40,374,638.0–42,758,002.0] |


### SQLi

| Shape | Bytes | Fingerprint | YA original median [min–max] | libinjection-rs original median [min–max] | YA after all optimizations median [min–max] |
| --- | ---: | ---: | ---: | ---: | ---: |
| plain_miss | 64 | miss | 85.4 [82.2–97.9] | 129.4 [122.5–146.4] | 85.6 [84.0–86.3] |
| operator_noise_miss | 64 | miss | 392.0 [323.7–407.8] | 416.4 [353.7–472.6] | 347.2 [337.1–358.1] |
| attack_at_start | 64 | 1&1c | 176.4 [160.1–195.7] | 310.8 [295.3–362.9] | 163.0 [161.7–167.1] |
| attack_after_whitespace | 64 | 1&1c | 200.2 [193.8–242.7] | 479.6 [444.6–627.2] | 206.0 [202.1–208.9] |
| plain_miss | 256 | miss | 141.1 [136.5–151.2] | 165.0 [157.9–173.7] | 141.0 [139.8–144.1] |
| operator_noise_miss | 256 | miss | 1,135.7 [1,125.6–1,249.8] | 1,278.8 [1,275.0–1,486.2] | 1,236.9 [1,233.3–1,242.5] |
| attack_at_start | 256 | 1&1c | 317.2 [315.7–322.2] | 282.5 [276.7–289.8] | 167.2 [165.1–170.3] |
| attack_after_whitespace | 256 | 1&1c | 314.6 [309.0–319.0] | 771.4 [736.8–845.7] | 374.9 [370.9–444.0] |
| plain_miss | 1,024 | miss | 384.2 [355.5–432.5] | 341.3 [321.0–360.6] | 320.6 [312.8–325.1] |
| operator_noise_miss | 1,024 | miss | 4,397.5 [4,358.3–4,596.4] | 5,008.3 [4,973.6–5,096.6] | 4,793.8 [4,773.6–4,895.9] |
| attack_at_start | 1,024 | 1&1c | 993.4 [979.9–1,022.5] | 301.7 [294.1–363.0] | 177.3 [176.7–182.5] |
| attack_after_whitespace | 1,024 | 1&1c | 1,120.8 [1,012.3–1,148.0] | 2,463.3 [2,322.8–2,618.3] | 1,036.9 [1,008.6–1,220.2] |
| plain_miss | 4,096 | miss | 1,321.7 [1,318.0–1,333.5] | 1,034.4 [1,028.0–1,049.6] | 1,003.2 [1,002.5–1,017.4] |
| operator_noise_miss | 4,096 | miss | 17,461.8 [17,317.8–19,082.1] | 19,661.4 [19,595.9–20,088.5] | 18,938.3 [18,894.8–19,307.0] |
| attack_at_start | 4,096 | 1&1c | 3,673.7 [3,633.4–4,007.4] | 427.3 [419.0–428.5] | 240.6 [238.3–242.6] |
| attack_after_whitespace | 4,096 | 1&1c | 3,882.1 [3,640.2–4,718.8] | 8,286.1 [8,260.3–8,410.7] | 3,770.6 [3,745.5–3,810.5] |
| plain_miss | 16,384 | miss | 5,221.6 [5,144.7–5,572.2] | 3,878.6 [3,824.1–4,025.4] | 3,739.7 [3,717.2–3,747.3] |
| operator_noise_miss | 16,384 | miss | 70,120.1 [69,880.0–71,408.4] | 79,560.1 [79,027.8–82,760.7] | 81,573.4 [75,075.6–86,237.3] |
| attack_at_start | 16,384 | 1&1c | 14,308.7 [14,304.7–14,363.0] | 608.6 [601.9–624.8] | 488.3 [486.5–496.8] |
| attack_after_whitespace | 16,384 | 1&1c | 14,396.9 [14,335.1–14,676.6] | 32,897.4 [32,660.5–33,048.1] | 14,565.9 [14,476.2–14,607.2] |
| plain_miss | 65,536 | miss | 22,738.7 [22,047.0–23,682.1] | 16,340.7 [16,219.0–17,163.0] | 15,381.2 [15,347.5–15,451.6] |
| operator_noise_miss | 65,536 | miss | 334,802.6 [310,468.5–412,925.4] | 448,925.9 [339,075.6–507,471.2] | 326,540.4 [300,400.9–328,622.7] |
| attack_at_start | 65,536 | 1&1c | 69,731.8 [63,528.7–75,993.9] | 2,189.3 [2,082.8–2,355.4] | 1,695.7 [1,693.3–1,704.2] |
| attack_after_whitespace | 65,536 | 1&1c | 76,948.0 [68,559.2–93,821.3] | 158,110.9 [137,733.7–190,031.5] | 58,003.3 [57,462.4–59,247.5] |
| plain_miss | 262,144 | miss | 83,664.0 [82,666.1–90,327.2] | 62,245.7 [61,002.3–64,880.8] | 61,261.8 [61,130.4–61,466.7] |
| operator_noise_miss | 262,144 | miss | 1,130,740.5 [1,071,876.9–1,210,792.1] | 1,279,961.7 [1,276,242.2–1,469,581.5] | 1,209,085.9 [1,203,319.0–1,307,816.9] |
| attack_at_start | 262,144 | 1&1c | 230,180.1 [229,010.2–233,419.0] | 6,373.0 [6,346.1–6,427.5] | 6,238.8 [6,174.0–6,318.4] |
| attack_after_whitespace | 262,144 | 1&1c | 225,884.0 [220,528.7–230,286.5] | 513,384.0 [503,479.7–521,701.3] | 231,030.6 [230,087.7–232,058.7] |
| plain_miss | 1,048,576 | miss | 327,403.2 [326,492.4–331,534.7] | 245,945.9 [244,357.9–266,872.5] | 250,163.1 [249,106.8–254,521.7] |
| operator_noise_miss | 1,048,576 | miss | 4,457,684.8 [4,427,347.5–4,506,509.0] | 5,056,073.7 [5,039,115.0–5,147,789.3] | 5,464,780.3 [5,098,466.8–5,494,315.7] |
| attack_at_start | 1,048,576 | 1&1c | 907,066.1 [891,776.8–912,093.2] | 26,313.4 [25,974.3–26,696.3] | 26,661.6 [26,517.2–31,654.1] |
| attack_after_whitespace | 1,048,576 | 1&1c | 883,434.6 [875,653.8–901,350.7] | 1,999,542.2 [1,990,843.4–2,011,481.0] | 931,898.9 [926,884.8–935,235.8] |
| mixed_escaped_quote_suffix | 1,602 | miss | 2,317.6 [2,279.9–2,412.5] | 7,433.2 [7,365.4–7,495.8] | 1,889.4 [1,877.4–1,906.0] |
| mixed_escaped_quote_suffix | 3,202 | miss | 4,464.5 [4,406.6–4,630.4] | 14,911.0 [14,820.6–15,084.1] | 3,603.7 [3,588.0–3,623.7] |
| mixed_escaped_quote_suffix | 6,402 | miss | 8,780.7 [8,697.3–8,931.2] | 29,728.0 [29,641.8–29,857.3] | 7,077.3 [7,055.5–7,226.8] |
| mixed_escaped_quote_suffix | 12,802 | miss | 17,420.9 [17,394.0–18,097.8] | 59,695.9 [59,383.3–60,208.3] | 14,062.1 [14,041.6–14,517.8] |
| mixed_escaped_quote_suffix | 25,602 | miss | 35,020.8 [34,626.6–35,301.5] | 120,590.8 [120,138.8–122,745.2] | 27,986.4 [27,923.1–28,367.9] |
| mixed_escaped_quote_suffix | 51,202 | miss | 69,385.6 [68,622.7–70,418.4] | 236,855.2 [234,857.2–238,835.7] | 55,928.4 [55,823.4–56,071.4] |


The six added 4 KiB misses also matched both verdicts. Current YA versus the
current in-repository libinjection-rs median was, for XSS: prose 13.2 vs
63.3 µs, JSON 6.47 vs 6.93 µs, base64-like 3.08 vs 4.29 µs; for SQLi:
prose 344 vs 721 ns, JSON 281 vs 527 ns, base64-like 3.23 vs 5.23 µs. These new shapes
have no historical original-YA measurements, so they are summarized here
without adding columns or changing the existing tables.

## Interpretation and limits

The initial measurements used the five-context YA XSS path. The original
source-level explanation was that repeated context scans contributed to
large misses; no profiler was run to apportion that cost. The changed YA
[entry point](../libperfusion/src/xss.rs) preserves context priority, skips Data when no
less than sign occurs, always checks unquoted values, and skips quoted
contexts without their delimiter. The comparison implementation applied
similar context gates in its own detector.

The repeated-`<` miss measured 5.93 ms at 1 MiB versus 5.61 ms in original
YA. The early hit measured 37.8 ns versus 33.8 ns. The escaped-quote SQLi
case measured 56.8 µs at 51,202 bytes. The 10 MiB slash miss
measured 8.85 ms in this run and 8.33 ms in a previous pinned run;
CPU frequency was not locked, so that difference is inconclusive. Binary
misses remain the clearest XSS path to investigate next.

The benchmark is single-threaded and replays one in-memory byte buffer per
case. It does not model request parsing, concurrent WAF load, allocator
pressure, cache-cold traffic, or deployment-specific input distributions.
The legacy methods are unbounded; the 10 MiB cases are deliberate stress
inputs. These are latency measurements, not a security accuracy study or a
CI performance gate.

The final optimized YA result includes context pruning, `memchr`-backed byte,
pair, slice, and presence searches, the binary attribute-name guard, HTML
short-match fast paths, and the SQLi-local delimiter fast path. It matched
libinjection-rs on all 496 corpus inputs and 130 generated inputs. Further
work could target binary tokenization while preserving NUL and high-byte
behavior.

The retained benchmark targets are
[compare.rs](../libperfusion/benches/compare.rs) and
[scaling.rs](../libperfusion/benches/scaling.rs). `compare` times the capped
and caller-bounded APIs; `scaling` verifies expected verdicts and times the
caller-bounded API over generated inputs.

## Current implementation after P3 optimizations

**Measured:** 2026-10-14. This section records the consolidated `libperfusion`
crate after the performance changes; the historical tables above are unchanged.

The consolidation removed an incidental `memchr/std` feature unification from
the old crate graph. That left the new package using compile-time SSE2 instead
of runtime AVX2 dispatch on this x86_64 host. `libperfusion` now requires `std`
and enables `memchr/std` directly. Detection still does not allocate.

The code changes skip the `sp_password` search when a longer SQL fingerprint
cannot be rejected by the whitelist, start Data-context XSS tokenization at the
first `<` found in the input, and consume consecutive slash bytes in one HTML
tokenizer step. The slash tokenizer keeps the same public token boundaries.

Before and after were measured in one process, alternating measurement order,
with seven 20 ms samples per case and two runs. The baseline was the current
P3 working tree before these changes. The CPU frequency was not locked.

| Workload | Before | After | Change |
| --- | ---: | ---: | ---: |
| XSS encoded URL at end, 1 MiB | 26.6–26.9 µs | 9.4–9.5 µs | 65% faster |
| SQLi attack at start, 1 MiB | 48.0–48.1 µs | 9.1–9.5 µs | 80–81% faster |
| XSS slash miss, 10 MiB | 8.44–8.72 ms | 3.89–3.95 ms | 54–55% faster |
| XSS repeated-angle miss, 1 MiB | 5.71–5.72 ms | 5.68 ms | within 1% |
| SQLi attack after whitespace, 1 MiB | 0.71–0.73 ms | 0.67–0.69 ms | about 5% faster |
| SQLi plain miss, 1 MiB | 0.47–0.48 ms | 0.47 ms | within 1% |
| SQLi escaped-quote miss, 51,202 bytes | 55.5–56.8 µs | 55.2–56.5 µs | within 1% |

The same paired check compared all 496 corpus inputs. Each hit/miss group was
within 3% of the baseline. A standalone corpus run measured 159.6 / 155.4 ns
per SQLi hit / miss and 30.8 / 85.3 ns per XSS hit / miss. The 130-case full
scaling sweep verified every expected hit and miss before timing.

Against the previous report's unpaired scaling run, SQLi attack-at-start at
1 MiB changed from 26.7 µs to 9.09 µs, XSS encoded-URL-at-end from 17.6 µs to
9.55 µs, and the 10 MiB slash miss from 8.48 ms to 3.89 ms. The escaped-quote
miss stayed level at 55.58 µs versus 55.9 µs. The standalone angle-noise result
was 6.45 ms versus 5.74 ms; the paired before/after runs differed by less than
1%, so the standalone increase is not repeatable as a code regression.

The `speed` benchmark compared the port against libinjection C at
`533a165ebc1f7c36ecbe3e5583990ea0db81f554`, built with `cc -O3`. Port/C ratios
were 0.54–0.57× for SQLi workloads and 0.28–0.41× for XSS workloads, so the
Rust port was 1.8–3.6× faster in every measured group. The benchmark used a
temporary copy of C's sample data with nine already-reviewed C-only XSS cases
removed so its aggregate hit-count assertion passed. The full C differential
still checked all 862 cases and retained the same 24 reviewed differences.

The final source also passed exact before/after comparisons on 100,000
deterministic SQLi, XSS, and context inputs; 486 repeated-slash boundary inputs
kept identical HTML token streams in all five contexts. At measurement time,
pinned C and Go v0.3.5 differentials passed with their reviewed exceptions.
These checks do not replace broader fuzzing or make the unlocked-frequency
timings portable to other CPUs.

## Caller-bounded scan benchmark

**Measured:** 2026-10-15, on the `feature/envoy-libperfusion-wasm` working tree
at HEAD `90ac00e898e6b6528141a8fd7221926a97fe087a`, including the uncommitted
Envoy adapter change to call `sqli_with_limit` and `xss_with_limit` over the
complete admitted slice.

The default libperfusion `sqli` and `xss` APIs reject inputs longer than
65,536 bytes without scanning. The adapter now passes the bounded body slice's
full length to the caller-bounded APIs, so content after that boundary is
inspected. The larger scan cost below is the intended coverage for oversized
inputs; the capped API does not provide a valid performance baseline for those
inputs because it skips them.

### Corpus API comparison

Command: `taskset -c 3 cargo bench -p libperfusion --bench compare`. It verified
and timed all 498 repository corpus inputs. Each group reports the median of
five 100 ms samples; capped is measured before caller-bounded in this run.

| Workload | Inputs | Capped ns/input | Caller-bounded ns/input | Change |
| --- | ---: | ---: | ---: | ---: |
| SQLi hit | 98 | 160.6 | 163.2 | +1.6% |
| SQLi miss | 400 | 159.0 | 160.6 | +1.0% |
| XSS hit | 17 | 31.3 | 31.4 | +0.3% |
| XSS miss | 481 | 84.4 | 84.8 | +0.5% |

This same-build API comparison shows no material corpus-size regression. The
differences are below 2% and should be treated as measurement noise, not a
stable throughput change.

### Full-input scaling

Command: `taskset -c 3 cargo bench -p libperfusion --bench scaling`. The full
sweep verified the expected hit or miss for all 130 generated inputs before
timing. The table shows representative 1 MiB detector cases and the larger
XSS cases; values are median nanoseconds per call with the observed range.

| Detector and shape | Bytes | Median [min–max] |
| --- | ---: | ---: |
| SQLi plain miss | 1,048,576 | 248,603 [246,830–250,023] ns |
| SQLi operator-noise miss | 1,048,576 | 4,605,121 [4,572,595–4,650,371] ns |
| SQLi attack after leading whitespace | 1,048,576 | 452,805 [450,426–456,331] ns |
| XSS encoded URL at end | 1,048,576 | 8,907 [8,821–8,937] ns |
| XSS slash miss | 1,048,576 | 484,481 [481,929–487,232] ns |
| XSS slash miss | 5,242,880 | 2,454,625 [2,404,365–2,507,982] ns |
| XSS slash miss | 10,485,760 | 5,076,110 [5,010,463–5,307,288] ns |
| XSS benign tag stream miss | 1,048,576 | 4,075,107 [4,046,884–4,098,804] ns |
| XSS benign tag stream miss | 5,242,880 | 20,134,946 [20,012,275–20,537,493] ns |
| XSS benign tag stream miss | 10,485,760 | 42,607,847 [40,553,244–42,717,203] ns |

From 1 to 10 MiB, the slash and benign-tag XSS misses took about 10.5 times
longer for 10 times as many bytes. These tested shapes therefore scaled close
to linearly. Latency depends strongly on the input shape: the 10 MiB benign
tag stream took 42.6 ms, while the slash miss took 5.08 ms.

### C speed comparison

The optional `speed` target completed against libinjection C revision
`d88a8f86d617ac8dcb9169c9f34637aaac71ac76`, built with GCC 16.2.1 and `-O3`.
The source was from a temporary copy of the upstream checkout with the nine
reviewed C-only XSS samples listed by `C_XSS_SAMPLE_DIFFERENCES` in
`libperfusion/tests/oracle_differential.rs` removed. With the full sample set,
the target stops on the known nine-hit difference (C detects 81,397 XSS
samples; Rust detects 81,388). This filtering changes only the benchmark input
set; it does not modify the checkout or the differential tests.

> Superseded. The `speed` target runs on the unmodified sample set and
> checks correctness **input by input**: `benches/speed.c` prints a verdict
> per input next to its timing, and `REVIEWED_DIFFERENCES` in
> `benches/speed.rs` pins the nine inputs the two sides are known to read
> differently, by their exact bytes. An unreviewed disagreement fails before
> any time is reported. An earlier version of this compared per-workload hit
> *counts*, which one new false positive cancelling one lost detection would
> have satisfied. The constant naming the C-only XSS samples was also renamed
> to `C_XSS_SAMPLE_VERDICTS`, and the current counts are in
> `libperfusion/tests/parity/mismatch-ledger.md`.

Across the seven measured workload groups, libperfusion's port/C timing ratio
was 0.54–0.59× for SQLi and 0.29–0.39× for XSS. Ratios below 1 mean the port
was faster on these workloads. This C comparison calls the capped public APIs
on sample inputs; it does not measure the Envoy adapter or multi-megabyte body
scanning.

### Environment and limits

The runs used an AMD Ryzen 7 PRO 7840HS, Linux 7.2.9, rustc/cargo 1.97.1, and
GCC 16.2.1. Processes were pinned to logical CPU 3, but CPU frequency was not
locked (observed range 419–5,138 MHz). The full-input numbers are single-thread
detector timings over in-memory data; they do not include Envoy/WASM execution,
request parsing, concurrency, or end-to-end proxy latency.

### Recheck against the prior generated-measurement column

The full scaling sweep was rerun and compared row by row with the
`YA after all optimizations` medians above. Of 124 matching rows, 74 current
medians were lower, 47 were higher, and 3 were within 0.05% of the prior
median. The geometric mean of current/prior latency was 0.911 overall (0.781
for SQLi and 0.974 for XSS). Six newer 4 KiB prose/JSON/base64 cases have no
row in that table and are not included.

| Detector | Matched rows | Current median lower | Higher | Within 0.05% | Current range above prior range | Below | Overlapping |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SQLi | 38 | 34 | 4 | 0 | 1 | 24 | 13 |
| XSS | 86 | 40 | 43 | 3 | 27 | 18 | 41 |
| All | 124 | 74 | 47 | 3 | 28 | 42 | 54 |

The XSS `comment_miss` family was slower at every tested size, with the
current median 10–26% above the prior median. All five current samples for
each size were above the prior row's observed range.

| Bytes | Prior median ns | Current median ns | Change |
| ---: | ---: | ---: | ---: |
| 64 | 147.5 | 163.5 | +10.8% |
| 256 | 375.4 | 413.9 | +10.3% |
| 1,024 | 1,229.2 | 1,454.8 | +18.4% |
| 4,096 | 4,778.9 | 5,630.5 | +17.8% |
| 16,384 | 19,044.5 | 23,936.8 | +25.7% |
| 65,536 | 76,743.0 | 91,990.7 | +19.9% |
| 262,144 | 303,491.1 | 375,443.9 | +23.7% |
| 1,048,576 | 1,260,437.7 | 1,416,794.7 | +12.4% |

Several XSS `angle_noise_miss` sizes were also higher: 256 bytes (+14.9%),
4 KiB (+17.7%), 16 KiB (+17.6%), and 256 KiB (+22.1%). These standalone results
include slower synthetic rows, despite the faster overall geometric mean and
the near-flat corpus API comparison. They do not isolate the implementation
change responsible for a timing difference. The reported
min/max values come from separate runs with unlocked CPU frequency; they show
observed spread, not statistical confidence intervals.

Subsequent paired comparisons across five executable layouts confirmed native
code-layout sensitivity but did not confirm a persistent tag-stream slowdown. See the
[investigation and fix plan](performance-regression-plan.md) before attributing
these historical timing differences to a particular implementation change.

## Native HTML scanner follow-up (2026-10-15)

The long attribute-name scan now keeps the scalar path for spans up to 128
bytes and uses memchr on the tail of longer spans. This targets the confirmed
native scalar-loop cliff without changing SQL's shared delimiter search. In
three paired runs across five code layouts, 4 KiB plain XSS misses measured
0.270× the same-source control median (about 3.7× faster); 16 KiB measured
0.210×. The 64-byte plain XSS miss median was 1.026×, with each run median
below 1.05×. Across all 130 cases, the median of each case's three run-level
medians stayed at or below 1.05. Run 1 alone had nine run-level medians above
1.05 (seven SQL plain misses and two 64-byte XSS misses); runs 2 and 3 had none.

The historical YA after all optimizations tables above are unchanged. These
new ratios compare the candidate with a same-source control and expose the
remaining layout spread; they are not absolute latency values or measurements
inside Envoy/WASM. The [per-case results](performance-investigation/cspan-comparison.tsv)
and [raw samples](performance-investigation/cspan-samples.tsv.gz) preserve the
full native comparison.

## Coraza debug logging, disabled path (2026-10-27)

The debug logger is compiled in and enabled per configuration. Each emission
point calls a single predicate that compares the effective numeric level first
and only calls the logger's `enabled()` when the number passes. With the
default configuration (`SecDebugLog` unset, `SecDebugLogLevel` 0) the compare
fails, so neither the sink nor the logger is touched. A nonzero
`SecDebugLogLevel` with no configured sink still calls the no-op logger's
`enabled()` for each event. The cost carried unconditionally is the compare,
the transaction-level override lookup, and the logger reference held by each
transaction (two pointers).

**Performance gate: incomplete for this change.** Three campaigns against the
six `make coraza-bench` workloads with logging off did not resolve the effect.
The first recorded a dirty candidate identity and is void. The second, pinned
to one CPU, reported four workloads overlapping baseline and two (GET attack,
form benign) about 1.3-1.4% above it. The third, five alternating pairs on the
same host, produced per-pair ratios from 0.47 to 2.41 as background load rose
from 2.7 to 5.7 on a 16-core developer machine, so it carries no information
about a 1% effect.

The prerequisite for closing this gate is an isolated machine: rerun the paired
comparison there with exact revision identities and record per-workload medians
and ranges. Until then no regression and no absence of regression is claimed.
If such a run shows the effect matters, remove the per-transaction logger
reference (resolve it through the shared configuration instead) so the disabled
path keeps only the numeric compare.

## Coraza transformation dispatch (2026-10-27)

The custom-transformation seam stores each chain entry as a built-in function
pointer or a host-supplied implementation behind a shared pointer. Built-in-only
chains therefore pay one enum-tag branch per entry, while the call itself still
goes through the built-in function pointer.

A paired release measurement of a five-entry built-in chain
(`urlDecode`, `lowercase`, `removeNulls`, `compressWhitespace`, `trim`, single
match, 1,000,000 applies per side, seven samples per run, three alternating
runs pinned to one CPU) reported baseline medians of 415.3, 415.9 and 417.3
ns/op against candidate medians of 416.5, 420.5 and 420.7 ns/op. The candidate
median is 1.11% higher with overlapping ranges, and the pinned CPU carried
background activity, so the workload measures whole-chain cost and cannot
isolate dispatch overhead.

That roughly 1% median difference is accepted for this seam rather than adding
a second built-in-only code path. Upgrade only if a real workload shows it
matters: split the chain into a built-in slice and a custom slice, so the
built-in path drops the tag entirely.

## Coraza custom-action dispatch (2026-10-27)

The custom-action implementation adds an implementation-enum check to built-in
action evaluation and grows each compiled action. A focused release test
precompiled a rule matching `ARGS:q` against `hit`, then called `Rule::evaluate`
one million times per sample with `setvar`, `skip`, and `setenv` runtime actions
and `log,capture` metadata actions. The rule ID was cleared in the harness to
avoid accumulating match records. It compares whole matched-rule evaluation,
not the dispatch branch in isolation.

Seven alternating pairs ran pinned to logical CPU 3 against clean worktrees at
`2b4ef751` (base) and `c0888bc1` (candidate plus this lane's code changes),
five samples per side per pair, Rust 1.99.1, AMD Ryzen 7 PRO 7840HS, CPU
frequency not locked. The measured process CPU was 99% in every sample.

| Base median (ns/evaluation) | Candidate median (ns/evaluation) | Candidate/base |
| ---: | ---: | ---: |
| 904.2 | 916.8 | +1.4% |
| 929.3 | 892.4 | -4.0% |
| 920.3 | 898.5 | -2.4% |
| 920.3 | 915.0 | -0.6% |
| 904.0 | 897.4 | -0.7% |
| 932.7 | 910.7 | -2.4% |
| 950.3 | 1,045.0 | +10.0% |

The median of the per-pair ratios is 0.9927, i.e. the candidate was 0.7% faster
at the median, and the same-tree spread within a pair had a median range of
about 8% (81.3 ns/evaluation base, 71.2 candidate). A single noisy pairing
(+10.0%) shows how easily this host produces spurious differences; an earlier
three-sample run reported +40%, which did not reproduce here.

This workload carries matching and transaction work, so it cannot isolate
dispatch cost, and this host cannot resolve effects around 1% (the same
limitation recorded in the
[debug-logging measurement](#coraza-debug-logging-disabled-path-2026-10-27)).
No regression is claimed and none is established; the change is accepted
without a built-in-only fast path. If an isolated or production profile later
shows material dispatch cost, split built-in actions from custom actions so
built-in evaluation avoids both the enum branch and the larger custom-action
representation. Raw samples:
`/tmp/opencode/parity/l3b-bench2/`.
