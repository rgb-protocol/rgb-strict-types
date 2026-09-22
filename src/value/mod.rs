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

//! Strict values: schema-less representation of strict types. The module includes:
//! - [`path`]: path accessors/introspects into strict values;
//! - [STON][ston]: strict type object notation, a JSON-like representation of strict types;
//! - [`decode`]: conversion between strict encoding and strict values;
//! - [`typify`]: checks of strict values against strict type schema;
//! - [`convert`]: conversion between strict values and other text representations (JSON, YAML,
//!   TOML, etc).

#[macro_use]
mod val;
pub mod path;
pub mod ston;
pub mod typify;
pub mod decode;
#[cfg(feature = "serde")]
pub mod convert;
mod encode;

pub use path::{KeyStep, Path, PathError, Step};
pub use val::{Blob, EnumTag, StrictNum, StrictVal};

#[cfg(test)]
mod test_helpers {
    use std::collections::{BTreeMap, BTreeSet};

    use amplify::confinement::{Confined, NonEmptyString};
    use encoding::{Ident, StrictDeserialize, StrictSerialize};

    use crate::stl::{std_stl, strict_types_stl};
    use crate::typesys::{SymbolicSys, SystemBuilder};
    use crate::LibBuilder;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = "TestLib", tags = repr, into_u8, try_from_u8)]
    #[repr(u8)]
    pub enum Precision {
        #[strict_type(dumb)]
        NoDecimals = 0,
        OneDecimal = 1,
        TwoDecimals = 2,
    }

    #[derive(Clone, Eq, PartialEq, Hash, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = "TestLib", dumb = { Nominal::with("DUMB", "Dumb", strict_dumb!()) })]
    pub struct Nominal {
        pub ticker: Ident,
        pub name: NonEmptyString<32>,
        pub precision: Precision,
    }

    impl StrictSerialize for Nominal {}
    impl StrictDeserialize for Nominal {}

    impl Nominal {
        pub fn with(ticker: &'static str, name: &'static str, precision: u8) -> Self {
            Nominal {
                ticker: Ident::try_from(ticker.to_owned()).unwrap(),
                name: Confined::try_from(name.to_owned()).unwrap(),
                precision: Precision::try_from(precision).unwrap(),
            }
        }
    }

    /// Sized collections of every kind, each declared with 1..=3 items (`text` with 1..=4 bytes).
    #[derive(Clone, Eq, PartialEq, Hash, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = "TestLib", dumb = { Bounded::with(&[1], &[1], &[(1, 1)], &[1], "a") })]
    pub struct Bounded {
        pub list: Confined<Vec<u16>, 1, 3>,
        pub set: Confined<BTreeSet<u8>, 1, 3>,
        pub map: Confined<BTreeMap<u8, u8>, 1, 3>,
        pub blob: Confined<Vec<u8>, 1, 3>,
        pub text: Confined<String, 1, 4>,
    }

    impl StrictSerialize for Bounded {}
    impl StrictDeserialize for Bounded {}

    impl Bounded {
        pub fn with(list: &[u16], set: &[u8], map: &[(u8, u8)], blob: &[u8], text: &str) -> Self {
            Bounded {
                list: Confined::try_from(list.to_vec()).unwrap(),
                set: Confined::try_from(set.iter().copied().collect::<BTreeSet<_>>()).unwrap(),
                map: Confined::try_from(map.iter().copied().collect::<BTreeMap<_, _>>()).unwrap(),
                blob: Confined::try_from(blob.to_vec()).unwrap(),
                text: Confined::try_from(text.to_owned()).unwrap(),
            }
        }
    }

    pub fn test_system() -> SymbolicSys {
        let std = std_stl();
        let st = strict_types_stl();
        let lib =
            LibBuilder::with("TestLib", [std.to_dependency_types(), st.to_dependency_types()])
                .transpile::<Nominal>()
                .transpile::<Bounded>()
                .compile()
                .unwrap();
        SystemBuilder::new()
            .import(lib)
            .unwrap()
            .import(std)
            .unwrap()
            .import(st)
            .unwrap()
            .finalize()
            .unwrap()
    }
}
