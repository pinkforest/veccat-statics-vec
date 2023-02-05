//stub: use password_hash::{ParamsString, PasswordHash, PasswordHasher, Salt, SaltString};
#![allow(unused_imports)]
#![allow(unused_variables)]

use pbkdf2::{
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString, Salt, 
    },
    Pbkdf2,
    Params,
};

use core::fmt;

/// Errors that can occur during the protocol
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Wrapper around `password_hash`'s error type, for propagating errors should they occur
    PasswordHashing(pbkdf2::password_hash::Error),
    /// PasswordHasher produced an empty hash.
    HashEmpty,
    /// PasswordHasher produced a hash of an invalid size (size was not 32 or 64 bytes)
    HashSizeInvalid,
    /// Failure during Explicit Mutual Authentication
    MutualAuthFail,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PasswordHashing(error) => write!(f, "Error while hashing password: {}", error),
            Error::HashEmpty => write!(f, "password hash empty"),
            Error::HashSizeInvalid => write!(f, "password hash invalid, should be 32 or 64 bytes"),
            Error::MutualAuthFail => write!(
                f,
                "explicit mutual authentication failed, authenticators didn't match"
            ),
        }
    }
}

/// Result type
pub type Result<T> = core::result::Result<T, Error>;

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

/// Hash a username and password with the given password hasher
pub fn hash_password_vec_with_capacity<'a, U, P, H>(
    username: U,
    password: P,
    salt: impl Into<Salt<'a>>,
    params: H::Params,
    hasher: H,
    //) -> Result<PasswordHash<'a>>
) -> ()
where
    H: PasswordHasher,
    U: AsRef<[u8]>,
    P: AsRef<[u8]>,
{

    let user = username.as_ref();
    let pass = password.as_ref();

    let mut v = Vec::with_capacity(user.len() + pass.len() + 1);
    v.extend_from_slice(user);
    v.push(b':');
    v.extend_from_slice(pass);

    
    ()
/*    hasher
        .hash_password_customized(&v, None, None, params, salt)
        .map_err(Error::PasswordHashing) */
}

/// Hash a username and password with the given password hasher
#[inline]
pub fn hash_password_vec_with_capacity_inline<'a, U, P, H>(
    username: U,
    password: P,
    salt: impl Into<Salt<'a>>,
    params: H::Params,
    hasher: H,
    //) -> Result<PasswordHash<'a>>
) -> Vec<u8>
where
    H: PasswordHasher,
    U: AsRef<[u8]>,
    P: AsRef<[u8]>,
{

    let user = username.as_ref();
    let pass = password.as_ref();

    let mut v = Vec::with_capacity(user.len() + pass.len() + 1);
    v.extend_from_slice(user);
    v.push(b':');
    v.extend_from_slice(pass);

    
    v
/*    hasher
        .hash_password_customized(&v, None, None, params, salt)
        .map_err(Error::PasswordHashing) */
}

/// Hash a username and password with the given password hasher
pub fn hash_password_vec<'a, U, P, H>(
    username: U,
    password: P,
    salt: impl Into<Salt<'a>>,
    params: H::Params,
    hasher: H,
    //) -> Result<PasswordHash<'a>>
) -> ()
where
    H: PasswordHasher,
    U: AsRef<[u8]>,
    P: AsRef<[u8]>,
{

    let mut v = username.as_ref().to_vec();
    v.push(b':');
    v.extend_from_slice(password.as_ref());

    ()
/*    hasher
        .hash_password_customized(&v, None, None, params, salt)
        .map_err(Error::PasswordHashing) */
}

/// Hash a username and password with the given password hasher
#[inline]
pub fn hash_password_vec_inline<'a, U, P, H>(
    username: U,
    password: P,
    salt: impl Into<Salt<'a>>,
    params: H::Params,
    hasher: H,
    //) -> Result<PasswordHash<'a>>
) -> ()
where
    H: PasswordHasher,
    U: AsRef<[u8]>,
    P: AsRef<[u8]>,
{

    let mut v = username.as_ref().to_vec();
    v.push(b':');
    v.extend_from_slice(password.as_ref());

    ()
/*    hasher
        .hash_password_customized(&v, None, None, params, salt)
        .map_err(Error::PasswordHashing) */
}

/// Hash a username and password with the given password hasher
pub fn hash_password_static<'a, U, P, H>(
    username: U,
    password: P,
    salt: impl Into<Salt<'a>>,
    params: H::Params,
    hasher: H,
//) -> Result<PasswordHash<'a>>
) -> ()
where
    H: PasswordHasher,
    U: AsRef<[u8]>,
    P: AsRef<[u8]>,
{
    const BUFSIZ: usize = 100;
    
    let user = username.as_ref();
    let pass = password.as_ref();
    let u = user.len();
    let p = pass.len();

    let mut buf = [0u8; BUFSIZ];
    buf[0..u].copy_from_slice(user);
    buf[u] = b':';
    buf[u + 1..u + p + 1].copy_from_slice(pass);

    ()
    /*
    hasher
        .hash_password_customized(&buf[0..u+p+1], None, None, params, salt)
        .map_err(Error::PasswordHashing)
     */
}

/// Hash a username and password with the given password hasher
pub fn hash_password_veccat_2x<'a, U, P, H>(
    username: U,
    password: P,
    salt: impl Into<Salt<'a>>,
    params: H::Params,
    hasher: H,
//) -> Result<PasswordHash<'a>>
) -> ()
where
    H: PasswordHasher,
    U: AsRef<[u8]>,
    P: AsRef<[u8]>,
{
    let mut out = Vec::new();
    
    let buf = veccat!(&mut out, username.as_ref() b":" password.as_ref());
    
    ()
/*    hasher
        .hash_password_customized(&buf, None, None, params, salt)
        .map_err(Error::PasswordHashing) */
}


/// Hash a username and password with the given password hasher
pub fn hash_password_veccat_1x<'a, U, P, H>(
    username: U,
    password: P,
    salt: impl Into<Salt<'a>>,
    params: H::Params,
    hasher: H,
//) -> Result<PasswordHash<'a>>
) -> ()
where
    H: PasswordHasher,
    U: AsRef<[u8]>,
    P: AsRef<[u8]>,
{
    let mut out = Vec::new();
    
    let buf = veccat!(&mut out, username.as_ref() b":" password.as_ref());
    
    ()
/*    hasher
        .hash_password_customized(&buf, None, None, params, salt)
        .map_err(Error::PasswordHashing) */
}
