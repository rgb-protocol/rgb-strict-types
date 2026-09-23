// Strict encoding schema library, implementing validation and parsing of strict encoded data
// against a schema.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@ubideco.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@ubideco.org>
//
// Copyright (C) 2022-2025 Laboratories for Ubiquitous Deterministic Computing (UBIDECO),
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2022-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

//! Reification module: reads & writes strict values from binary strict encodings.

use std::cmp::Ordering;

use amplify::ascii::AsciiString;
use amplify::confinement::{
    Confined, LargeAscii, LargeBlob, LargeString, MediumAscii, MediumBlob, MediumString,
    SmallAscii, SmallBlob, SmallString, TinyAscii, TinyBlob, TinyString, U16 as MAX16,
    U32 as MAX32,
};
use amplify::num::{u24, u40, u48, u56};
use encoding::{DecodeError, Primitive, ReadRaw, StreamReader, StrictDecode, StrictReader};
use indexmap::IndexMap;

use crate::typesys::{SymbolicSys, TypeSymbol, UnknownType};
use crate::typify::{TypeSpec, TypedVal};
use crate::value::{Blob, StrictNum};
use crate::{SemId, StrictVal, Ty, TypeRef, TypeSystem};

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Error {
    /// unknown type `{0}`.
    TypeAbsent(TypeSpec),

    #[display(inner)]
    #[from]
    UnknownType(UnknownType),

    /// {0} is not yet implemented. Please update `strict_types` to the latest version.
    NotImplemented(String),

    #[display(inner)]
    #[from]
    Decode(DecodeError),

    /// data provided to reify operation are not entirely consumed during deserialization.
    NotEntirelyConsumed,
}

impl SymbolicSys {
    pub fn strict_deserialize_type(
        &self,
        spec: impl Into<TypeSpec>,
        data: &[u8],
    ) -> Result<TypedVal, Error> {
        let spec = spec.into();
        let sem_id = self.to_sem_id(spec.clone()).ok_or(Error::TypeAbsent(spec))?;
        self.as_types().strict_deserialize_type(sem_id, data)
    }

    pub fn strict_read_type(
        &self,
        spec: impl Into<TypeSpec>,
        d: &mut impl ReadRaw,
    ) -> Result<TypedVal, Error> {
        let spec = spec.into();
        let sem_id = self.to_sem_id(spec.clone()).ok_or(Error::TypeAbsent(spec))?;
        self.as_types().strict_read_type(sem_id, d)
    }
}

impl TypeSystem {
    fn strict_read_list(
        &self,
        len: usize,
        ty: SemId,
        d: &mut impl ReadRaw,
    ) -> Result<Vec<StrictVal>, Error> {
        let mut list = Vec::with_capacity(len);
        for _ in 0..len {
            let item = self.strict_read_type(ty, d)?;
            list.push(item.val);
        }
        Ok(list)
    }

    fn strict_read_map(
        &self,
        len: usize,
        key_ty: SemId,
        ty: SemId,
        d: &mut impl ReadRaw,
    ) -> Result<Vec<(StrictVal, StrictVal)>, Error> {
        let mut list = Vec::with_capacity(len);
        for _ in 0..len {
            let key = self.strict_read_type(key_ty, d)?;
            let item = self.strict_read_type(ty, d)?;
            list.push((key.val, item.val));
        }
        Ok(list)
    }

    pub fn strict_deserialize_type(&self, sem_id: SemId, data: &[u8]) -> Result<TypedVal, Error> {
        let mut cursor = StreamReader::cursor::<MAX32>(data);
        let ty = self.strict_read_type(sem_id, &mut cursor)?;
        if cursor.unconfine().position() as usize != data.len() {
            return Err(Error::NotEntirelyConsumed);
        }
        Ok(ty)
    }

    pub fn strict_read_type(
        &self,
        sem_id: SemId,
        mut d: &mut impl ReadRaw,
    ) -> Result<TypedVal, Error> {
        let spec = TypeSpec::from(sem_id);
        let ty = self.find(sem_id).ok_or_else(|| Error::TypeAbsent(spec.clone()))?;

        let mut reader = StrictReader::with(d);

        let val = match ty {
            Ty::Primitive(prim) => {
                match *prim {
                    Primitive::UNIT => StrictVal::Unit,
                    Primitive::BYTE => StrictVal::num(u8::strict_decode(&mut reader)?),
                    Primitive::U8 => StrictVal::num(u8::strict_decode(&mut reader)?),
                    Primitive::U16 => StrictVal::num(u16::strict_decode(&mut reader)?),
                    Primitive::U24 => StrictVal::num(u24::strict_decode(&mut reader)?.into_u32()),
                    Primitive::U32 => StrictVal::num(u32::strict_decode(&mut reader)?),
                    Primitive::U40 => StrictVal::num(u40::strict_decode(&mut reader)?),
                    Primitive::U48 => StrictVal::num(u48::strict_decode(&mut reader)?),
                    Primitive::U56 => StrictVal::num(u56::strict_decode(&mut reader)?),
                    Primitive::U64 => StrictVal::num(u64::strict_decode(&mut reader)?),
                    // Primitive::U128 => StrictVal::num(u128::strict_decode(&mut reader)?),
                    Primitive::I8 => StrictVal::num(i8::strict_decode(&mut reader)?),
                    Primitive::I16 => StrictVal::num(i16::strict_decode(&mut reader)?),
                    // I24 => StrictVal::num(i24::strict_decode(&mut reader)?),
                    Primitive::I32 => StrictVal::num(i32::strict_decode(&mut reader)?),
                    Primitive::I64 => StrictVal::num(i64::strict_decode(&mut reader)?),
                    // Primitive::I128 => StrictVal::num(i128::strict_decode(&mut reader)?),
                    other => {
                        return Err(Error::NotImplemented(format!(
                            "loading {other} into a typed value is not yet implemented"
                        )));
                    }
                }
            }
            Ty::UnicodeChar => {
                todo!()
            }

            // ASCII strings:
            Ty::List(sem_id, sizing)
                if self
                    .find(*sem_id)
                    .ok_or_else(|| Error::TypeAbsent(spec.clone()))?
                    .is_char_enum() =>
            {
                if sizing.max <= u8::MAX as u64 {
                    StrictVal::String(TinyAscii::strict_decode(&mut reader)?.to_string())
                } else if sizing.max <= u16::MAX as u64 {
                    StrictVal::String(SmallAscii::strict_decode(&mut reader)?.to_string())
                } else if sizing.max <= u24::MAX.into_u64() {
                    StrictVal::String(MediumAscii::strict_decode(&mut reader)?.to_string())
                } else if sizing.max <= u32::MAX as u64 {
                    StrictVal::String(LargeAscii::strict_decode(&mut reader)?.to_string())
                } else {
                    StrictVal::String(
                        Confined::<AsciiString, 0, { u64::MAX as usize }>::strict_decode(
                            &mut reader,
                        )?
                        .to_string(),
                    )
                }
            }
            // Restricted strings:
            Ty::Tuple(fields) if self.is_rstring(fields)? => {
                let (_, sizing) = self.rstring_sizing(fields)?.expect("checked in match");
                if sizing.max <= u8::MAX as u64 {
                    StrictVal::String(TinyAscii::strict_decode(&mut reader)?.to_string())
                } else if sizing.max <= u16::MAX as u64 {
                    StrictVal::String(SmallAscii::strict_decode(&mut reader)?.to_string())
                } else if sizing.max <= u24::MAX.into_u64() {
                    StrictVal::String(MediumAscii::strict_decode(&mut reader)?.to_string())
                } else if sizing.max <= u32::MAX as u64 {
                    StrictVal::String(LargeAscii::strict_decode(&mut reader)?.to_string())
                } else {
                    StrictVal::String(
                        Confined::<AsciiString, 0, { u64::MAX as usize }>::strict_decode(
                            &mut reader,
                        )?
                        .to_string(),
                    )
                }
            }

            Ty::Enum(variants) => {
                let tag = u8::strict_decode(&mut reader)?;
                let Some(name) = variants.name_by_tag(tag) else {
                    return Err(DecodeError::EnumTagNotKnown(spec.to_string(), tag).into());
                };
                StrictVal::enumer(name.clone())
            }
            Ty::Union(variants) => {
                let tag = u8::strict_decode(&mut reader)?;
                let Some((variant, ty)) = variants.by_tag(tag) else {
                    return Err(DecodeError::EnumTagNotKnown(spec.to_string(), tag).into());
                };
                let fields = self.strict_read_type(*ty, reader.unbox())?;
                StrictVal::union(variant.name.clone(), fields.val)
            }
            Ty::Tuple(reqs) => {
                let mut fields = Vec::with_capacity(reqs.len());
                let d = reader.unbox();
                for ty in reqs {
                    let checked = self.strict_read_type(*ty, d)?;
                    fields.push(checked.val);
                }
                StrictVal::tuple(fields)
            }
            Ty::Struct(reqs) => {
                let mut fields = IndexMap::with_capacity(reqs.len());
                let d = reader.unbox();
                for field in reqs {
                    let checked = self.strict_read_type(field.ty, d)?;
                    fields.insert(field.name.clone(), checked.val);
                }
                StrictVal::Struct(fields)
            }

            // Fixed-size arrays:
            Ty::Array(ty, len) if ty.is_byte() => {
                let d = reader.unbox();
                let buf = d.read_raw::<MAX16>(*len as usize).map_err(DecodeError::from)?;
                StrictVal::Bytes(Blob(buf))
            }
            Ty::Array(ty, len) => {
                let mut list = Vec::<StrictVal>::with_capacity(*len as usize);
                let d = reader.unbox();
                for _ in 0..*len {
                    let checked = self.strict_read_type(*ty, d)?;
                    list.push(checked.val);
                }
                StrictVal::List(list)
            }

            // Byte strings:
            Ty::List(ty, sizing) if ty.is_byte() && sizing.max <= u8::MAX as u64 => {
                let string = TinyBlob::strict_decode(&mut reader)?;
                StrictVal::Bytes(Blob(string.release()))
            }
            Ty::List(ty, sizing) if ty.is_byte() && sizing.max <= u16::MAX as u64 => {
                let string = SmallBlob::strict_decode(&mut reader)?;
                StrictVal::Bytes(Blob(string.release()))
            }
            Ty::List(ty, sizing) if ty.is_byte() && sizing.max <= u24::MAX.into_u64() => {
                let string = MediumBlob::strict_decode(&mut reader)?;
                StrictVal::Bytes(Blob(string.release()))
            }
            Ty::List(ty, sizing) if ty.is_byte() && sizing.max <= u32::MAX as u64 => {
                let string = LargeBlob::strict_decode(&mut reader)?;
                StrictVal::Bytes(Blob(string.release()))
            }

            // Unicode strings:
            Ty::List(ty, sizing) if ty.is_unicode_char() && sizing.max <= u8::MAX as u64 => {
                let string = TinyString::strict_decode(&mut reader)?;
                StrictVal::String(string.release())
            }
            Ty::List(ty, sizing) if ty.is_unicode_char() && sizing.max <= u16::MAX as u64 => {
                let string = SmallString::strict_decode(&mut reader)?;
                StrictVal::String(string.release())
            }
            Ty::List(ty, sizing) if ty.is_unicode_char() && sizing.max <= u24::MAX.into_u64() => {
                let string = MediumString::strict_decode(&mut reader)?;
                StrictVal::String(string.release())
            }
            Ty::List(ty, sizing) if ty.is_unicode_char() && sizing.max <= u32::MAX as u64 => {
                let string = LargeString::strict_decode(&mut reader)?;
                StrictVal::String(string.release())
            }

            // Other lists:
            Ty::List(ty, sizing) if sizing.max <= u8::MAX as u64 => {
                let len = u8::strict_decode(&mut reader)?;
                d = reader.unbox();
                let list = self.strict_read_list(len as usize, *ty, d)?;
                StrictVal::List(list)
            }
            Ty::List(ty, sizing) if sizing.max <= u16::MAX as u64 => {
                let len = u16::strict_decode(&mut reader)?;
                d = reader.unbox();
                let list = self.strict_read_list(len as usize, *ty, d)?;
                StrictVal::List(list)
            }
            Ty::List(ty, sizing) if sizing.max <= u24::MAX.into_u64() => {
                let len = u24::strict_decode(&mut reader)?;
                d = reader.unbox();
                let list = self.strict_read_list(len.into_usize(), *ty, d)?;
                StrictVal::List(list)
            }
            Ty::List(ty, sizing) if sizing.max <= u32::MAX as u64 => {
                let len = u32::strict_decode(&mut reader)?;
                d = reader.unbox();
                let list = self.strict_read_list(len as usize, *ty, d)?;
                StrictVal::List(list)
            }
            Ty::List(ty, _) => {
                let len = u64::strict_decode(&mut reader)?;
                d = reader.unbox();
                let list = self.strict_read_list(len as usize, *ty, d)?;
                StrictVal::List(list)
            }
            // TODO: Find a way to check for the uniqueness of the set values
            Ty::Set(ty, sizing) if sizing.max <= u8::MAX as u64 => {
                let len = u8::strict_decode(&mut reader)?;
                d = reader.unbox();
                let list = self.strict_read_list(len as usize, *ty, d)?;
                StrictVal::Set(list)
            }
            Ty::Set(ty, sizing) if sizing.max <= u16::MAX as u64 => {
                let len = u16::strict_decode(&mut reader)?;
                d = reader.unbox();
                let list = self.strict_read_list(len as usize, *ty, d)?;
                StrictVal::Set(list)
            }
            Ty::Set(ty, sizing) if sizing.max <= u24::MAX.into_u64() => {
                let len = u24::strict_decode(&mut reader)?;
                d = reader.unbox();
                let list = self.strict_read_list(len.into_usize(), *ty, d)?;
                StrictVal::Set(list)
            }
            Ty::Set(ty, sizing) if sizing.max <= u32::MAX as u64 => {
                let len = u32::strict_decode(&mut reader)?;
                d = reader.unbox();
                let list = self.strict_read_list(len as usize, *ty, d)?;
                StrictVal::Set(list)
            }
            Ty::Set(ty, _) => {
                let len = u64::strict_decode(&mut reader)?;
                d = reader.unbox();
                let list = self.strict_read_list(len as usize, *ty, d)?;
                StrictVal::Set(list)
            }
            Ty::Map(key_id, id, sizing) if sizing.max <= u8::MAX as u64 => {
                let len = u8::strict_decode(&mut reader)?;
                d = reader.unbox();
                let list = self.strict_read_map(len as usize, *key_id, *id, d)?;
                StrictVal::Map(list)
            }
            Ty::Map(key_id, id, sizing) if sizing.max <= u16::MAX as u64 => {
                let len = u16::strict_decode(&mut reader)?;
                d = reader.unbox();
                let list = self.strict_read_map(len as usize, *key_id, *id, d)?;
                StrictVal::Map(list)
            }
            Ty::Map(key_id, id, sizing) if sizing.max <= u24::MAX.into_u64() => {
                let len = u24::strict_decode(&mut reader)?;
                d = reader.unbox();
                let list = self.strict_read_map(len.into_usize(), *key_id, *id, d)?;
                StrictVal::Map(list)
            }
            Ty::Map(key_id, id, sizing) if sizing.max <= u32::MAX as u64 => {
                let len = u32::strict_decode(&mut reader)?;
                d = reader.unbox();
                let list = self.strict_read_map(len as usize, *key_id, *id, d)?;
                StrictVal::Map(list)
            }
            Ty::Map(key_id, id, _sizing) => {
                let len = u64::strict_decode(&mut reader)?;
                d = reader.unbox();
                let list = self.strict_read_map(len as usize, *key_id, *id, d)?;
                StrictVal::Map(list)
            }
        };

        self.check_declared(ty, &val, &spec)?;

        Ok(TypedVal {
            val,
            orig: TypeSymbol::unnamed(sem_id),
        })
    }

    /// Enforces the declared sizing and character sets of a decoded value, which the decoding
    /// itself uses only to select the length prefix width.
    fn check_declared(
        &self,
        ty: &Ty<SemId>,
        val: &StrictVal,
        spec: &TypeSpec,
    ) -> Result<(), Error> {
        let (sizing, charset) = match ty {
            Ty::Tuple(fields) if self.is_rstring(fields)? => {
                let (rest, sizing) = self.rstring_sizing(fields)?.expect("checked by is_rstring");
                (sizing, Some((fields[0], rest)))
            }
            Ty::List(el, sizing)
                if self
                    .get(*el)
                    .ok_or_else(|| Error::TypeAbsent(TypeSpec::from(*el)))?
                    .is_char_enum() =>
            {
                (*sizing, Some((*el, *el)))
            }
            Ty::List(_, sizing) | Ty::Set(_, sizing) | Ty::Map(_, _, sizing) => (*sizing, None),
            Ty::Primitive(_)
            | Ty::Enum(_)
            | Ty::Union(_)
            | Ty::Array(_, _)
            | Ty::Struct(_)
            | Ty::UnicodeChar
            | Ty::Tuple(_) => return Ok(()),
        };

        let len = match val {
            StrictVal::String(s) => s.len(),
            StrictVal::Bytes(b) => b.len(),
            StrictVal::List(items) | StrictVal::Set(items) => items.len(),
            StrictVal::Map(items) => items.len(),
            // sized types always decode into collections: fail closed should this ever change
            _ => {
                return Err(DecodeError::DataIntegrityError(format!(
                    "value of type {spec} did not decode into a collection"
                ))
                .into())
            }
        };
        if !sizing.check(len) {
            return Err(DecodeError::DataIntegrityError(format!(
                "value of type {spec} has length {len}, while the type requires {}..={}",
                sizing.min, sizing.max
            ))
            .into());
        }

        match (ty, val) {
            (Ty::Map(key_id, _, _), StrictVal::Map(items)) => {
                self.check_ordered(*key_id, items.iter().map(|(key, _)| key), spec)?
            }
            (Ty::Set(el, _), StrictVal::Set(items)) => {
                self.check_ordered(*el, items.iter(), spec)?
            }
            _ => {}
        }

        if let (Some((first, rest)), StrictVal::String(s)) = (charset, val) {
            let (first_set, rest_set) = (self.char_set(first)?, self.char_set(rest)?);
            for (pos, ch) in s.bytes().enumerate() {
                let set = if pos == 0 { first_set } else { rest_set };
                if !set.contains(ch) {
                    return Err(DecodeError::DataIntegrityError(format!(
                        "value of type {spec} has disallowed character {:?} at position {pos}",
                        ch as char
                    ))
                    .into());
                }
            }
        }
        Ok(())
    }

    /// Checks that set elements or map keys are strictly ascending, the way the canonical
    /// `BTreeSet`/`BTreeMap` decoders require.
    fn check_ordered<'a>(
        &self,
        sem_id: SemId,
        items: impl IntoIterator<Item = &'a StrictVal>,
        spec: &TypeSpec,
    ) -> Result<(), Error> {
        if !self.is_valid_collection_key(sem_id) {
            return Err(DecodeError::DataIntegrityError(format!(
                "type {} cannot be used as a collection key or set element",
                TypeSpec::from(sem_id)
            ))
            .into());
        }
        let mut prev: Option<&StrictVal> = None;
        for (pos, item) in items.into_iter().enumerate() {
            if let Some(prev) = prev {
                if prev == item {
                    return Err(DecodeError::DataIntegrityError(format!(
                        "value of type {spec} repeats the item at position {pos}"
                    ))
                    .into());
                }
                if Self::cmp_vals(prev, item)? == Ordering::Greater {
                    return Err(DecodeError::DataIntegrityError(format!(
                        "value of type {spec} is not ordered at position {pos}"
                    ))
                    .into());
                }
            }
            prev = Some(item);
        }
        Ok(())
    }

    /// Orders two values of a valid key type according to their native ordering.
    fn cmp_vals(a: &StrictVal, b: &StrictVal) -> Result<Ordering, Error> {
        let mismatch = || -> Error {
            DecodeError::DataIntegrityError(
                "unexpected value shape while ordering a collection key".to_string(),
            )
            .into()
        };
        Ok(match (a, b) {
            (StrictVal::Unit, StrictVal::Unit) => Ordering::Equal,
            (StrictVal::Number(a), StrictVal::Number(b)) => match (a, b) {
                (StrictNum::Uint(a), StrictNum::Uint(b)) => a.cmp(b),
                (StrictNum::Int(a), StrictNum::Int(b)) => a.cmp(b),
                _ => return Err(mismatch()),
            },
            (StrictVal::Bytes(a), StrictVal::Bytes(b)) => a.as_slice().cmp(b.as_slice()),
            (StrictVal::List(a), StrictVal::List(b)) => {
                for (x, y) in a.iter().zip(b) {
                    match Self::cmp_vals(x, y)? {
                        Ordering::Equal => {}
                        ord => return Ok(ord),
                    }
                }
                a.len().cmp(&b.len())
            }
            _ => return Err(mismatch()),
        })
    }

    /// Returns the characters allowed by a character enum type.
    fn char_set(&self, sem_id: SemId) -> Result<AsciiSet, Error> {
        let spec = TypeSpec::from(sem_id);
        match self.get(sem_id).ok_or_else(|| Error::TypeAbsent(spec.clone()))? {
            Ty::Enum(variants) if variants.iter().all(|v| v.tag < 128) => {
                let mut set = AsciiSet::default();
                variants.iter().for_each(|v| set.insert(v.tag));
                Ok(set)
            }
            _ => {
                Err(DecodeError::DataIntegrityError(format!("type {spec} is not a character enum"))
                    .into())
            }
        }
    }
}

/// Set of ASCII characters, stored as a bit mask with one bit per character code.
#[derive(Copy, Clone, Default)]
struct AsciiSet(u128);

impl AsciiSet {
    fn insert(&mut self, ch: u8) {
        debug_assert!(ch < 128, "non-ASCII character {ch}");
        self.0 |= 1u128 << ch;
    }

    /// Non-ASCII bytes are never contained; the check also keeps the shift within `u128`.
    fn contains(self, ch: u8) -> bool { ch < 128 && self.0 & (1u128 << ch) != 0 }
}

#[cfg(test)]
mod test {
    use amplify::confinement::Confined;

    use super::super::test_helpers::*;
    use super::{DecodeError, Error};

    /// Asserts that deserialization was rejected and the error contains the given fragment.
    #[track_caller]
    fn assert_rejected<T: core::fmt::Debug>(res: Result<T, Error>, fragment: &str) {
        match res {
            Err(Error::Decode(DecodeError::DataIntegrityError(msg))) => assert!(
                msg.contains(fragment),
                "wrong data-integrity message\n  expected to contain: {fragment:?}\n  got: {msg:?}"
            ),
            other => {
                panic!("expected a data-integrity error containing {fragment:?}, got {other:?}")
            }
        }
    }

    #[test]
    fn typify() {
        let sys = test_system();
        //let nominal = Nominal::with("TICK", "Some name", 2);
        let value = ston!(name "Some name", ticker "TICK", precision svenum!(2));
        let checked = sys.typify(value, "TestLib.Nominal").unwrap();
        assert_eq!(
            format!("{}", checked.val),
            r#"name "Some name", ticker "TICK", precision twoDecimals"#
        );
    }

    /// Strict encoding of `Nominal`: ticker and name are each prefixed with a u8 length.
    fn nominal(ticker: &[u8], name: &[u8]) -> Vec<u8> {
        let mut data = vec![ticker.len() as u8];
        data.extend_from_slice(ticker);
        data.push(name.len() as u8);
        data.extend_from_slice(name);
        data.push(2);
        data
    }

    #[test]
    fn deserialize_canonical() {
        use encoding::StrictSerialize;

        let data = Nominal::with("TICK", "Some name", 2).to_strict_serialized::<0xFF>().unwrap();
        assert_eq!(data.as_slice(), nominal(b"TICK", b"Some name").as_slice());
        test_system().strict_deserialize_type("TestLib.Nominal", &data).unwrap();
    }

    #[test]
    fn deserialize_rejects_out_of_sizing() {
        let sys = test_system();
        // name is a NonEmptyString<32>
        assert_rejected(
            sys.strict_deserialize_type("TestLib.Nominal", &nominal(b"TICK", b"")),
            "has length 0, while the type requires 1..=32",
        );
        assert_rejected(
            sys.strict_deserialize_type("TestLib.Nominal", &nominal(b"TICK", &[b'a'; 33])),
            "has length 33, while the type requires 1..=32",
        );
        sys.strict_deserialize_type("TestLib.Nominal", &nominal(b"TICK", &[b'a'; 32])).unwrap();
        // ticker is an RString of 1..=100 characters
        assert_rejected(
            sys.strict_deserialize_type("TestLib.Nominal", &nominal(b"", b"name")),
            "has length 0, while the type requires 1..=100",
        );
        assert_rejected(
            sys.strict_deserialize_type("TestLib.Nominal", &nominal(&[b'A'; 101], b"name")),
            "has length 101, while the type requires 1..=100",
        );
        sys.strict_deserialize_type("TestLib.Nominal", &nominal(&[b'A'; 100], b"name")).unwrap();
    }

    /// Strict encoding of `Attachments`: a u8 length followed by that many key/value byte pairs.
    fn attachments(pairs: &[(u8, u8)]) -> Vec<u8> {
        let mut data = vec![pairs.len() as u8];
        for (key, val) in pairs {
            data.push(*key);
            data.push(*val);
        }
        data
    }

    #[test]
    fn deserialize_map_requires_ascending_keys() {
        let sys = test_system();
        sys.strict_deserialize_type("TestLib.Attachments", &attachments(&[(1, 10), (2, 20)]))
            .unwrap();
        // a duplicate key: the canonical BTreeMap decoder returns RepeatedMapValue
        assert!(sys
            .strict_deserialize_type("TestLib.Attachments", &attachments(&[(1, 10), (1, 20)]))
            .is_err());
        // descending keys: the canonical decoder returns BrokenMapOrder
        assert!(sys
            .strict_deserialize_type("TestLib.Attachments", &attachments(&[(2, 20), (1, 10)]))
            .is_err());
        // ordering is numeric, not over the little-endian encoding
        sys.strict_deserialize_type("TestLib.Attachments", &attachments(&[(1, 0), (255, 0)]))
            .unwrap();
    }

    /// Strict encoding of a `BTreeMap<u16, u8>`: a u8 length, then little-endian key / value pairs.
    fn u16_map(pairs: &[(u16, u8)]) -> Vec<u8> {
        let mut data = vec![pairs.len() as u8];
        for (k, v) in pairs {
            data.extend_from_slice(&k.to_le_bytes());
            data.push(*v);
        }
        data
    }

    #[test]
    fn deserialize_map_multibyte_key_numeric_order() {
        let sys = test_system();
        // keys are ordered numerically, according to big-endian encoding
        sys.strict_deserialize_type("TestLib.U16Map", &u16_map(&[(1, 0), (256, 0)])).unwrap();
        assert!(sys
            .strict_deserialize_type("TestLib.U16Map", &u16_map(&[(256, 0), (1, 0)]))
            .is_err());
    }

    /// Strict encoding of a `BTreeMap<i8, u8>`.
    fn i8_map(pairs: &[(i8, u8)]) -> Vec<u8> {
        let mut data = vec![pairs.len() as u8];
        for (k, v) in pairs {
            data.push(*k as u8);
            data.push(*v);
        }
        data
    }

    #[test]
    fn deserialize_map_signed_key_numeric_order() {
        let sys = test_system();
        // -1 (encoded `ff`) is numerically below 1 (`01`), though `ff` > `01` as a byte
        sys.strict_deserialize_type("TestLib.I8Map", &i8_map(&[(-1, 0), (1, 0)])).unwrap();
        assert!(sys.strict_deserialize_type("TestLib.I8Map", &i8_map(&[(1, 0), (-1, 0)])).is_err());
    }

    /// Strict encoding of a `BTreeMap<[u8; 2], u8>`: fixed-size keys carry no length prefix.
    fn bytes_map(pairs: &[([u8; 2], u8)]) -> Vec<u8> {
        let mut data = vec![pairs.len() as u8];
        for (k, v) in pairs {
            data.extend_from_slice(k);
            data.push(*v);
        }
        data
    }

    #[test]
    fn deserialize_bytes_keyed_map() {
        let sys = test_system();
        // ascending lexicographic byte order
        sys.strict_deserialize_type("TestLib.BytesMap", &bytes_map(&[([0, 1], 0), ([1, 0], 0)]))
            .unwrap();
        // descending
        assert!(sys
            .strict_deserialize_type("TestLib.BytesMap", &bytes_map(&[([1, 0], 0), ([0, 1], 0)]))
            .is_err());
        // duplicate
        assert!(sys
            .strict_deserialize_type("TestLib.BytesMap", &bytes_map(&[([0, 1], 0), ([0, 1], 0)]))
            .is_err());
    }

    /// Strict encoding of a `BTreeSet<u8>`: a u8 length, then the elements.
    fn u8_set(elems: &[u8]) -> Vec<u8> {
        let mut data = vec![elems.len() as u8];
        data.extend_from_slice(elems);
        data
    }

    #[test]
    fn deserialize_set_requires_ascending() {
        let sys = test_system();
        sys.strict_deserialize_type("TestLib.U8Set", &u8_set(&[1, 2])).unwrap();
        // descending
        assert!(sys.strict_deserialize_type("TestLib.U8Set", &u8_set(&[2, 1])).is_err());
        // duplicate
        assert!(sys.strict_deserialize_type("TestLib.U8Set", &u8_set(&[1, 1])).is_err());
    }

    /// Strict encoding of a `BTreeMap<Confined<Vec<u16>>, u8>`: a u8 map length, then per entry a
    /// u8 sequence length, that many little-endian `u16`s, and the `u8` value.
    fn u16_seq_map(pairs: &[(&[u16], u8)]) -> Vec<u8> {
        let mut data = vec![pairs.len() as u8];
        for (seq, v) in pairs {
            data.push(seq.len() as u8);
            for e in *seq {
                data.extend_from_slice(&e.to_le_bytes());
            }
            data.push(*v);
        }
        data
    }

    #[test]
    fn deserialize_seq_keyed_map() {
        let sys = test_system();
        // lists are ordered lexicographically over their (numeric) elements
        sys.strict_deserialize_type("TestLib.U16SeqMap", &u16_seq_map(&[(&[1], 0), (&[2], 0)]))
            .unwrap();
        // a shorter list orders before a longer one it prefixes
        sys.strict_deserialize_type("TestLib.U16SeqMap", &u16_seq_map(&[(&[1], 0), (&[1, 2], 0)]))
            .unwrap();
        // descending
        assert!(sys
            .strict_deserialize_type("TestLib.U16SeqMap", &u16_seq_map(&[(&[2], 0), (&[1], 0)]))
            .is_err());
        // duplicate
        assert!(sys
            .strict_deserialize_type("TestLib.U16SeqMap", &u16_seq_map(&[(&[1], 0), (&[1], 0)]))
            .is_err());
    }

    #[test]
    fn deserialize_rejects_disallowed_key_type() {
        let sys = test_system();
        // `EnumMap` keys a map by `Precision`, which is not a valid collection key.
        assert!(sys.strict_deserialize_type("TestLib.EnumMap", &attachments(&[])).is_err());
        assert!(sys.strict_deserialize_type("TestLib.EnumMap", &attachments(&[(0, 0)])).is_err());
        assert!(sys
            .strict_deserialize_type("TestLib.EnumMap", &attachments(&[(0, 0), (1, 0)]))
            .is_err());
    }

    #[test]
    fn deserialize_rejects_out_of_charset() {
        let sys = test_system();
        // ticker is an RString<AlphaLodash, AlphaNumLodash, ..>
        assert_rejected(
            sys.strict_deserialize_type("TestLib.Nominal", &nominal(b"1ICK", b"name")),
            "has disallowed character '1' at position 0",
        );
        assert_rejected(
            sys.strict_deserialize_type("TestLib.Nominal", &nominal(b"T@CK", b"name")),
            "has disallowed character '@' at position 1",
        );
        sys.strict_deserialize_type("TestLib.Nominal", &nominal(b"T1CK", b"name")).unwrap();
    }

    /// Strict encoding of `Bounded`: every field is prefixed with a u8 length.
    fn bounded(list: &[u16], set: &[u8], map: &[(u8, u8)], blob: &[u8], text: &[u8]) -> Vec<u8> {
        let mut data = vec![list.len() as u8];
        list.iter().for_each(|item| data.extend_from_slice(&item.to_le_bytes()));
        data.push(set.len() as u8);
        data.extend_from_slice(set);
        data.push(map.len() as u8);
        map.iter().for_each(|(key, val)| data.extend_from_slice(&[*key, *val]));
        data.push(blob.len() as u8);
        data.extend_from_slice(blob);
        data.push(text.len() as u8);
        data.extend_from_slice(text);
        data
    }

    #[test]
    fn deserialize_bounded_canonical() {
        use encoding::StrictSerialize;

        let map = [(1, 1), (2, 2), (3, 3)];
        let value = Bounded::with(&[1, 2, 3], &[1, 2, 3], &map, &[1, 2, 3], "ab");
        let data = value.to_strict_serialized::<0xFF>().unwrap();
        let expected = bounded(&[1, 2, 3], &[1, 2, 3], &map, &[1, 2, 3], b"ab");
        assert_eq!(data.as_slice(), expected.as_slice());
        test_system().strict_deserialize_type("TestLib.Bounded", &data).unwrap();
    }

    #[test]
    fn deserialize_rejects_out_of_sizing_collections() {
        let sys = test_system();
        let check = |data: Vec<u8>| sys.strict_deserialize_type("TestLib.Bounded", &data);
        let (list, set, map, blob) = (&[1u16][..], &[1u8][..], &[(1u8, 1u8)][..], &[1u8][..]);

        let too_short = "has length 0, while the type requires 1..=3";
        let too_long = "has length 4, while the type requires 1..=3";
        // list
        assert_rejected(check(bounded(&[], set, map, blob, b"a")), too_short);
        assert_rejected(check(bounded(&[1, 2, 3, 4], set, map, blob, b"a")), too_long);
        // set
        assert_rejected(check(bounded(list, &[], map, blob, b"a")), too_short);
        assert_rejected(check(bounded(list, &[1, 2, 3, 4], map, blob, b"a")), too_long);
        // map
        assert_rejected(check(bounded(list, set, &[], blob, b"a")), too_short);
        assert_rejected(
            check(bounded(list, set, &[(1, 1), (2, 2), (3, 3), (4, 4)], blob, b"a")),
            too_long,
        );
        // byte string
        assert_rejected(check(bounded(list, set, map, &[], b"a")), too_short);
        assert_rejected(check(bounded(list, set, map, &[1, 2, 3, 4], b"a")), too_long);
        // unicode string
        assert_rejected(
            check(bounded(list, set, map, blob, b"")),
            "has length 0, while the type requires 1..=4",
        );
        assert_rejected(
            check(bounded(list, set, map, blob, b"abcde")),
            "has length 5, while the type requires 1..=4",
        );

        check(bounded(list, set, map, blob, b"a")).unwrap();
        let map3 = [(1, 1), (2, 2), (3, 3)];
        check(bounded(&[1, 2, 3], &[1, 2, 3], &map3, &[1, 2, 3], b"abcd")).unwrap();
    }

    #[test]
    fn deserialize_unicode_sizing_counts_bytes() {
        let sys = test_system();
        let check = |text: &str| {
            let data = bounded(&[1], &[1], &[(1, 1)], &[1], text.as_bytes());
            sys.strict_deserialize_type("TestLib.Bounded", &data)
        };
        // the Rust type bounds the encoded length in bytes, not in characters
        assert!(Confined::<String, 1, 4>::try_from("\u{e9}\u{e9}a".to_owned()).is_err());
        // 2 characters, 4 bytes
        check("\u{e9}\u{e9}").unwrap();
        // 3 characters, 5 bytes
        assert_rejected(check("\u{e9}\u{e9}a"), "has length 5, while the type requires 1..=4");
    }
}
