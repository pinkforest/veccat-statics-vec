# quick bench

$ cargo bench

Just how much concat byte slice costs ? and does with_capacity help ?

hash_pasword_veccat     time:   [15.869 ns 15.953 ns 16.091 ns]

hash_pasword_static     time:   [0.0000 ps 0.0000 ps 0.0000 ps]

hash_pasword_vec        time:   [32.999 ns 33.036 ns 33.071 ns]

hash_pasword_vec_with_capacity
                        time:   [12.779 ns 12.790 ns 12.803 ns]

hash_pasword_vec_with_capacity_inline
                        time:   [8.4060 ns 8.4132 ns 8.4214 ns]

For three things below happens+ vs static:
 - veccat: **2x** heap allocations (works best with many elements)
 - vec: **3x** heap allocations
 - vec with_capacity: **1x** heap allocation
 - inline is cheetos

`veccat!` macro pilfered from: https://crates.io/crates/concat_in_place

```rust
macro_rules! veccat {
    ($input:expr, $($element:expr)*) => {{
        let out = $input;
        let mut required = 0;

        $(
            required += $element.len();
        )*

        let free = out.capacity() - out.len();
        if (free < required) {
            out.reserve(required - free);
        }

        $(
            out.extend_from_slice($element);
        )*

        &*out
    }};

    ($($element:expr)+) => {{
        let mut required = 0;
        $(required += $element.len();)+
        let mut out = Vec::with_capacity(required);
        $(out.extend_from_slice($element);)+
        out
    }}
}
```