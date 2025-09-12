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

use amplify::confinement::LargeVec;
use strict_encoding::STRICT_TYPES_LIB;

use crate::typesys::{TypeInfo, TypeTree};

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = STRICT_TYPES_LIB)]
pub struct MemoryLayout {
    items: LargeVec<TypeInfo>,
}

impl From<TypeTree<'_>> for MemoryLayout {
    fn from(tree: TypeTree) -> Self {
        let mut layout = MemoryLayout::new();
        layout.items.extend(&tree).expect("type layout exceeds billions of fields");
        layout
    }
}

impl<'a> From<&'a TypeTree<'_>> for MemoryLayout {
    fn from(tree: &'a TypeTree) -> Self {
        let mut layout = MemoryLayout::new();
        layout.items.extend(tree).expect("type layout exceeds billions of fields");
        layout
    }
}

impl MemoryLayout {
    fn new() -> Self { Self { items: empty!() } }
}
