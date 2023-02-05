# quick bench

$ cargo bench

Just how much concat byte slice costs ?

hash_pasword_veccat     time:   [15.869 ns 15.953 ns 16.091 ns]
hash_pasword_copy       time:   [0.0000 ps 0.0000 ps 0.0000 ps]
hash_pasword_vec        time:   [32.999 ns 33.036 ns 33.071 ns]

`veccat!` macro pilfered from: https://crates.io/crates/concat_in_place
