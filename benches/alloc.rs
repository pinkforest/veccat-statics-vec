use criterion::{criterion_group, criterion_main, Criterion};
use no_hash::*;

#[allow(unused_imports)]
use pbkdf2::{
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString, Salt,
    },
    Pbkdf2,
    Params,
};

fn criterion_benchmark(c: &mut Criterion) {

    let valid_user = b"test-user";
    let valid_password = b"hunter42";
    let salt = Salt::new("salt").unwrap();

    let params = Params::default();

    c.bench_function("hash_pasword_veccat_2x", |b| {
        b.iter(|| hash_password_veccat_2x(valid_user.as_ref(), valid_password.as_ref(), salt, params, Pbkdf2))
    });

    c.bench_function("hash_pasword_veccat_1x", |b| {
        b.iter(|| hash_password_veccat_1x(valid_user.as_ref(), valid_password.as_ref(), salt, params, Pbkdf2))
    });
    
    c.bench_function("hash_pasword_static", |b| {
        b.iter(|| hash_password_static(valid_user.as_ref(), valid_password.as_ref(), salt, params, Pbkdf2))
    });

    c.bench_function("hash_pasword_vec", |b| {
        b.iter(|| hash_password_vec(valid_user.as_ref(), valid_password.as_ref(), salt, params, Pbkdf2))
    });

    c.bench_function("hash_pasword_vec_inline", |b| {
        b.iter(|| hash_password_vec_inline(valid_user.as_ref(), valid_password.as_ref(), salt, params, Pbkdf2))
    });
    
    c.bench_function("hash_pasword_vec_with_capacity", |b| {
        b.iter(|| hash_password_vec_with_capacity(valid_user.as_ref(), valid_password.as_ref(), salt, params, Pbkdf2))
    });

    c.bench_function("hash_pasword_vec_with_capacity_inline", |b| {
        b.iter(|| hash_password_vec_with_capacity_inline(valid_user.as_ref(), valid_password.as_ref(), salt, params, Pbkdf2))
    });
    
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
