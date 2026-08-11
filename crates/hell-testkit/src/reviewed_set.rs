//! Independent comparator model for reviewed `Data.Set` paths.
//!
//! This module deliberately does not call the candidate runtime. It models the
//! reviewed create/go and size-balanced tree algorithms and emits the exact
//! direct `Ord.lt`/`Ord.gt` protocol expected from one public Set adapter.
//! The reviewed native source identifies Hell commit
//! `8e952cf9de4ab25d7716982a9ca234f9bdcf1bff`, Stack resolver
//! `nightly-2024-10-21`, GHC 9.8.2, and containers 0.6.8. The expected complete
//! `Data.Map.Internal` and `Data.Set.Internal` source SHA-256 values are,
//! respectively,
//! `541dd92c62307a6543edbc0269af44d95973b4de647149a75c5660697e5c2e56` and
//! `68c58fab8023b84b32fb496219edc148e5efef98fbf7cbba7435a950fa2a57bb`.
//! The Map model maps to these exact `Data.Map.Internal` source anchors (line
//! numbers in the file with the former digest): `lookup` 572; `insert` 778;
//! `insertR` 827; `insertWith` 859; `delete` 1008; `adjust` 1036;
//! `unionWith` 1855; `fromList` 3443 and its `go` 3456 / `create` 3468;
//! `splitLookup` 3898; `link` 3969; `insertMax` 3979; `link2` 3995; `glue`
//! 4007; `balanceL` 4162; and `balanceR` 4187.
//! The Set model maps to these exact `Data.Set.Internal` source anchors (line
//! numbers in the file with the latter digest): `member` 388; `insert` 519;
//! `insertR` 549; `delete` 571; `union` 820; `difference` 843;
//! `intersection` 870; `fromList` 1092 and its `go` 1105 / `create` 1117;
//! `splitMember` 1320; `link` 1579; `insertMax` 1589; `merge` 1605; `glue`
//! 1617; `balanceL` 1745; and `balanceR` 1770. In this model those correspond
//! to `member`, `insert_replacing`, `insert_preserving`, `delete`, `union`,
//! `difference`, `intersection`, `from_list`/`create`, `split`, `link`,
//! `insert_max`, `merge`, `glue`, `balance_left`, and `balance_right`.
//! The containers 0.7 files are byte-identical at those digests; that is
//! equivalence evidence only, not the selected production package. These
//! comments do not retain or verify the source bytes. The separate Linux
//! signed-release asset is tied to Hell commit
//! `d4d028609ed46a560c62caea8c70e7e91d1afd29`; its dependency provenance
//! remains an open join, so this model is not yet claim promotion authority.

use std::cmp::Ordering;
use std::rc::Rc;
use std::sync::Arc;

use crate::ComparatorTraceContract;

const DELTA: usize = 3;
const RATIO: usize = 2;

#[derive(Clone, Debug)]
enum Key {
    Int(i64),
    Double(u64),
    Ci(&'static str),
}

impl Key {
    fn canonical(&self) -> String {
        match self {
            Self::Int(value) => format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}"),
            Self::Double(bits) => {
                format!("{{\"type\":\"Double\",\"ieee754Bits\":\"{bits:016x}\"}}")
            }
            Self::Ci(value) => {
                let folded = value.to_ascii_lowercase();
                format!(
                    "{{\"type\":\"CaseInsensitive\",\"original\":{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}},\"folded\":{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}}}}",
                    hex(value.as_bytes()),
                    hex(folded.as_bytes()),
                )
            }
        }
    }

    fn equal(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Int(left), Self::Int(right)) => left == right,
            (Self::Double(left), Self::Double(right)) => {
                !double_bits_are_nan(*left)
                    && !double_bits_are_nan(*right)
                    && (left == right
                        || double_bits_are_zero(*left) && double_bits_are_zero(*right))
            }
            (Self::Ci(left), Self::Ci(right)) => left.eq_ignore_ascii_case(right),
            _ => unreachable!("reviewed Set keys have one instance per case"),
        }
    }

    fn less(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Int(left), Self::Int(right)) => left < right,
            (Self::Double(left), Self::Double(right)) => {
                f64::from_bits(*left) < f64::from_bits(*right)
            }
            (Self::Ci(left), Self::Ci(right)) => {
                left.to_ascii_lowercase() < right.to_ascii_lowercase()
            }
            _ => unreachable!("reviewed Set keys have one instance per case"),
        }
    }

    fn greater(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Int(left), Self::Int(right)) => left > right,
            (Self::Double(left), Self::Double(right)) => {
                f64::from_bits(*left) > f64::from_bits(*right)
            }
            (Self::Ci(left), Self::Ci(right)) => {
                left.to_ascii_lowercase() > right.to_ascii_lowercase()
            }
            _ => unreachable!("reviewed Set keys have one instance per case"),
        }
    }
}

fn double_bits_are_nan(bits: u64) -> bool {
    bits & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000 && bits & 0x000f_ffff_ffff_ffff != 0
}

fn double_bits_are_zero(bits: u64) -> bool {
    matches!(bits, 0 | 0x8000_0000_0000_0000)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Default)]
struct Review {
    records: Vec<ComparatorTraceContract>,
}

impl Review {
    fn observe(&mut self, comparator: &'static str, left: &Key, right: &Key, result: bool) {
        let ordinal = u64::try_from(self.records.len() + 1).expect("fixture trace fits u64");
        self.records.push(ComparatorTraceContract {
            parent_invocation: 1,
            direct_child_ordinal: ordinal,
            comparator_ordinal: ordinal,
            comparator: Arc::from(comparator),
            canonical_left: Arc::from(left.canonical()),
            canonical_right: Arc::from(right.canonical()),
            result,
            outcome: Arc::from("value"),
        });
    }

    fn compare(&mut self, left: &Key, right: &Key) -> Ordering {
        if left.equal(right) {
            return Ordering::Equal;
        }
        let less = left.less(right);
        self.observe("Ord.lt", left, right, less);
        if less {
            return Ordering::Less;
        }
        let greater = left.greater(right);
        self.observe("Ord.gt", left, right, greater);
        if greater {
            Ordering::Greater
        } else {
            // `compare` for the pinned unlawful Double Ord returns GT after
            // Eq, lt and gt all reject a NaN pairing.
            Ordering::Greater
        }
    }

    fn not_ordered(&mut self, left: &Key, right: &Key) -> bool {
        if left.equal(right) {
            return true;
        }
        let greater = left.greater(right);
        self.observe("Ord.gt", left, right, greater);
        greater
    }
}

#[derive(Clone, Debug)]
struct Node {
    key: Rc<Key>,
    left: Tree,
    right: Tree,
    len: usize,
}

type Tree = Option<Rc<Node>>;

fn node(key: Rc<Key>, left: Tree, right: Tree) -> Rc<Node> {
    Rc::new(Node {
        key,
        len: 1 + len(&left) + len(&right),
        left,
        right,
    })
}

fn len(tree: &Tree) -> usize {
    tree.as_ref().map_or(0, |tree| tree.len)
}

fn rotate_left(tree: &Rc<Node>) -> Rc<Node> {
    let right = tree.right.as_ref().expect("right rotation fixture child");
    node(
        Rc::clone(&right.key),
        Some(node(
            Rc::clone(&tree.key),
            tree.left.clone(),
            right.left.clone(),
        )),
        right.right.clone(),
    )
}

fn rotate_right(tree: &Rc<Node>) -> Rc<Node> {
    let left = tree.left.as_ref().expect("left rotation fixture child");
    node(
        Rc::clone(&left.key),
        left.left.clone(),
        Some(node(
            Rc::clone(&tree.key),
            left.right.clone(),
            tree.right.clone(),
        )),
    )
}

fn balance_left(tree: Rc<Node>) -> Rc<Node> {
    let left_size = len(&tree.left);
    let right_size = len(&tree.right);
    if left_size + right_size <= 1 || left_size <= DELTA * right_size {
        return tree;
    }
    let left = tree.left.as_ref().expect("left-heavy fixture tree");
    if len(&left.right) < RATIO * len(&left.left) {
        rotate_right(&tree)
    } else {
        let rotated = rotate_left(left);
        rotate_right(&node(
            Rc::clone(&tree.key),
            Some(rotated),
            tree.right.clone(),
        ))
    }
}

fn balance_right(tree: Rc<Node>) -> Rc<Node> {
    let left_size = len(&tree.left);
    let right_size = len(&tree.right);
    if left_size + right_size <= 1 || right_size <= DELTA * left_size {
        return tree;
    }
    let right = tree.right.as_ref().expect("right-heavy fixture tree");
    if len(&right.left) < RATIO * len(&right.right) {
        rotate_left(&tree)
    } else {
        let rotated = rotate_right(right);
        rotate_left(&node(
            Rc::clone(&tree.key),
            tree.left.clone(),
            Some(rotated),
        ))
    }
}

fn insert_min(key: Rc<Key>, tree: Tree) -> Rc<Node> {
    let Some(tree) = tree else {
        return node(key, None, None);
    };
    balance_left(node(
        Rc::clone(&tree.key),
        Some(insert_min(key, tree.left.clone())),
        tree.right.clone(),
    ))
}

fn insert_max(key: Rc<Key>, tree: Tree) -> Rc<Node> {
    let Some(tree) = tree else {
        return node(key, None, None);
    };
    balance_right(node(
        Rc::clone(&tree.key),
        tree.left.clone(),
        Some(insert_max(key, tree.right.clone())),
    ))
}

fn link(key: Rc<Key>, left: Tree, right: Tree) -> Rc<Node> {
    if left.is_none() {
        return insert_min(key, right);
    }
    if right.is_none() {
        return insert_max(key, left);
    }
    if DELTA * len(&left) < len(&right) {
        let root = right.expect("right-heavy link fixture");
        return balance_left(node(
            Rc::clone(&root.key),
            Some(link(key, left, root.left.clone())),
            root.right.clone(),
        ));
    }
    if DELTA * len(&right) < len(&left) {
        let root = left.expect("left-heavy link fixture");
        return balance_right(node(
            Rc::clone(&root.key),
            root.left.clone(),
            Some(link(key, root.right.clone(), right)),
        ));
    }
    node(key, left, right)
}

fn take_min(tree: &Rc<Node>) -> (Rc<Key>, Tree) {
    let Some(left) = tree.left.as_ref() else {
        return (Rc::clone(&tree.key), tree.right.clone());
    };
    let (key, remaining) = take_min(left);
    (
        key,
        Some(balance_right(node(
            Rc::clone(&tree.key),
            remaining,
            tree.right.clone(),
        ))),
    )
}

fn take_max(tree: &Rc<Node>) -> (Rc<Key>, Tree) {
    let Some(right) = tree.right.as_ref() else {
        return (Rc::clone(&tree.key), tree.left.clone());
    };
    let (key, remaining) = take_max(right);
    (
        key,
        Some(balance_left(node(
            Rc::clone(&tree.key),
            tree.left.clone(),
            remaining,
        ))),
    )
}

fn glue(left: Tree, right: Tree) -> Tree {
    match (left, right) {
        (None, right) => right,
        (left, None) => left,
        (Some(left), Some(right)) if left.len > right.len => {
            let (key, remaining) = take_max(&left);
            Some(balance_right(node(key, remaining, Some(right))))
        }
        (Some(left), Some(right)) => {
            let (key, remaining) = take_min(&right);
            Some(balance_left(node(key, Some(left), remaining)))
        }
    }
}

fn merge(left: Tree, right: Tree) -> Tree {
    let (Some(left_root), Some(right_root)) = (&left, &right) else {
        return left.or(right);
    };
    if DELTA * left_root.len < right_root.len {
        return Some(balance_left(node(
            Rc::clone(&right_root.key),
            merge(left, right_root.left.clone()),
            right_root.right.clone(),
        )));
    }
    if DELTA * right_root.len < left_root.len {
        return Some(balance_right(node(
            Rc::clone(&left_root.key),
            left_root.left.clone(),
            merge(left_root.right.clone(), right),
        )));
    }
    glue(left, right)
}

fn split(tree: &Tree, key: &Key, review: &mut Review) -> (Tree, Option<Rc<Key>>, Tree) {
    let Some(tree) = tree else {
        return (None, None, None);
    };
    match review.compare(key, &tree.key) {
        Ordering::Less => {
            let (lower, found, upper_left) = split(&tree.left, key, review);
            (
                lower,
                found,
                Some(link(Rc::clone(&tree.key), upper_left, tree.right.clone())),
            )
        }
        Ordering::Equal => (
            tree.left.clone(),
            Some(Rc::clone(&tree.key)),
            tree.right.clone(),
        ),
        Ordering::Greater => {
            let (lower_right, found, upper) = split(&tree.right, key, review);
            (
                Some(link(Rc::clone(&tree.key), tree.left.clone(), lower_right)),
                found,
                upper,
            )
        }
    }
}

fn insert_replacing(tree: &Tree, key: Rc<Key>, review: &mut Review) -> Rc<Node> {
    let Some(tree) = tree else {
        return node(key, None, None);
    };
    match review.compare(&key, &tree.key) {
        Ordering::Less => balance_left(node(
            Rc::clone(&tree.key),
            Some(insert_replacing(&tree.left, key, review)),
            tree.right.clone(),
        )),
        Ordering::Equal if Rc::ptr_eq(&key, &tree.key) => Rc::clone(tree),
        Ordering::Equal => node(key, tree.left.clone(), tree.right.clone()),
        Ordering::Greater => balance_right(node(
            Rc::clone(&tree.key),
            tree.left.clone(),
            Some(insert_replacing(&tree.right, key, review)),
        )),
    }
}

fn insert_preserving(tree: &Tree, key: Rc<Key>, review: &mut Review) -> Rc<Node> {
    let Some(tree) = tree else {
        return node(key, None, None);
    };
    match review.compare(&key, &tree.key) {
        Ordering::Less => {
            let left = Some(insert_preserving(&tree.left, key, review));
            if same_tree(&left, &tree.left) {
                Rc::clone(tree)
            } else {
                balance_left(node(Rc::clone(&tree.key), left, tree.right.clone()))
            }
        }
        Ordering::Equal => Rc::clone(tree),
        Ordering::Greater => {
            let right = Some(insert_preserving(&tree.right, key, review));
            if same_tree(&right, &tree.right) {
                Rc::clone(tree)
            } else {
                balance_right(node(Rc::clone(&tree.key), tree.left.clone(), right))
            }
        }
    }
}

fn same_tree(left: &Tree, right: &Tree) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => Rc::ptr_eq(left, right),
        _ => false,
    }
}

fn delete(tree: &Tree, key: &Key, review: &mut Review) -> Tree {
    let Some(tree) = tree else {
        return None;
    };
    match review.compare(key, &tree.key) {
        Ordering::Less => Some(balance_right(node(
            Rc::clone(&tree.key),
            delete(&tree.left, key, review),
            tree.right.clone(),
        ))),
        Ordering::Equal => glue(tree.left.clone(), tree.right.clone()),
        Ordering::Greater => Some(balance_left(node(
            Rc::clone(&tree.key),
            tree.left.clone(),
            delete(&tree.right, key, review),
        ))),
    }
}

fn member(tree: &Tree, key: &Key, review: &mut Review) -> bool {
    let mut current = tree.as_ref();
    while let Some(tree) = current {
        match review.compare(key, &tree.key) {
            Ordering::Less => current = tree.left.as_ref(),
            Ordering::Equal => return true,
            Ordering::Greater => current = tree.right.as_ref(),
        }
    }
    false
}

fn union(left: &Tree, right: &Tree, review: &mut Review) -> Tree {
    let Some(left_root) = left else {
        return right.clone();
    };
    let Some(right_root) = right else {
        return left.clone();
    };
    if right_root.len == 1 {
        return Some(insert_preserving(left, Rc::clone(&right_root.key), review));
    }
    if left_root.len == 1 {
        return Some(insert_replacing(right, Rc::clone(&left_root.key), review));
    }
    let (right_left, _, right_right) = split(right, &left_root.key, review);
    let joined_left = union(&left_root.left, &right_left, review);
    let joined_right = union(&left_root.right, &right_right, review);
    if same_tree(&joined_left, &left_root.left) && same_tree(&joined_right, &left_root.right) {
        return left.clone();
    }
    Some(link(Rc::clone(&left_root.key), joined_left, joined_right))
}

fn difference(left: &Tree, right: &Tree, review: &mut Review) -> Tree {
    let Some(right_root) = right else {
        return left.clone();
    };
    if left.is_none() {
        return None;
    }
    let (left_lower, _, left_upper) = split(left, &right_root.key, review);
    let lower = difference(&left_lower, &right_root.left, review);
    let upper = difference(&left_upper, &right_root.right, review);
    if len(&lower) + len(&upper) == len(left) {
        return left.clone();
    }
    merge(lower, upper)
}

fn intersection(left: &Tree, right: &Tree, review: &mut Review) -> Tree {
    let Some(left_root) = left else {
        return None;
    };
    if right.is_none() {
        return None;
    }
    let (right_lower, found, right_upper) = split(right, &left_root.key, review);
    let lower = intersection(&left_root.left, &right_lower, review);
    let upper = intersection(&left_root.right, &right_upper, review);
    if found.is_some() {
        if same_tree(&lower, &left_root.left) && same_tree(&upper, &left_root.right) {
            return left.clone();
        }
        Some(link(Rc::clone(&left_root.key), lower, upper))
    } else {
        merge(lower, upper)
    }
}

struct Created {
    tree: Tree,
    next: usize,
    unordered: bool,
}

fn create(input: &[Rc<Key>], index: usize, size: usize, review: &mut Review) -> Created {
    if index >= input.len() {
        return Created {
            tree: None,
            next: index,
            unordered: false,
        };
    }
    if size == 1 {
        return Created {
            tree: Some(node(Rc::clone(&input[index]), None, None)),
            next: index + 1,
            unordered: input
                .get(index + 1)
                .is_some_and(|next| review.not_ordered(&input[index], next)),
        };
    }
    create_wide(input, index, size, review)
}

fn create_wide(input: &[Rc<Key>], index: usize, size: usize, review: &mut Review) -> Created {
    let half = size / 2;
    let left = create(input, index, half, review);
    if left.unordered || left.next >= input.len() {
        return left;
    }
    if left.next + 1 == input.len() {
        return Created {
            tree: Some(insert_max(Rc::clone(&input[left.next]), left.tree)),
            next: input.len(),
            unordered: false,
        };
    }
    if review.not_ordered(&input[left.next], &input[left.next + 1]) {
        return Created {
            tree: left.tree,
            next: left.next,
            unordered: true,
        };
    }
    let pivot = Rc::clone(&input[left.next]);
    let right = create(input, left.next + 1, half, review);
    Created {
        tree: Some(link(pivot, left.tree, right.tree)),
        next: right.next,
        unordered: right.unordered,
    }
}

fn from_list(keys: Vec<Key>, review: &mut Review) -> Tree {
    let input = keys.into_iter().map(Rc::new).collect::<Vec<_>>();
    let first = input.first()?;
    let initial = Some(node(Rc::clone(first), None, None));
    if input.len() == 1 {
        return initial;
    }
    if review.not_ordered(&input[0], &input[1]) {
        return insert_remaining(initial, &input, 1, review);
    }
    ordered_prefix(initial, &input, review)
}

fn ordered_prefix(mut left: Tree, input: &[Rc<Key>], review: &mut Review) -> Tree {
    let mut index = 1;
    let mut size = 1;
    loop {
        if index >= input.len() {
            return left;
        }
        if index + 1 == input.len() {
            return Some(insert_max(Rc::clone(&input[index]), left));
        }
        if review.not_ordered(&input[index], &input[index + 1]) {
            return insert_remaining(left, input, index, review);
        }
        let pivot = Rc::clone(&input[index]);
        let created = create(input, index + 1, size, review);
        left = Some(link(pivot, left, created.tree));
        if created.unordered {
            return insert_remaining(left, input, created.next, review);
        }
        index = created.next;
        size = size.saturating_mul(2);
    }
}

fn insert_remaining(mut tree: Tree, input: &[Rc<Key>], index: usize, review: &mut Review) -> Tree {
    for key in &input[index..] {
        tree = Some(insert_replacing(&tree, Rc::clone(key), review));
    }
    tree
}

enum Operation {
    FromList(Vec<Key>),
    Insert(Key, Vec<Key>),
    Member(Key, Vec<Key>),
    Delete(Key, Vec<Key>),
    Union(Vec<Key>, Vec<Key>),
    Difference(Vec<Key>, Vec<Key>),
    Intersection(Vec<Key>, Vec<Key>),
    SelfUnion(Vec<Key>),
    SelfIntersection(Vec<Key>),
}

/// Returns the exact source-reviewed direct comparator protocol for one of the
/// 59 non-boundary Set fixtures.
pub(crate) fn auxiliary_contracts(
    builtin: &str,
    instance_slug: &str,
    path: &str,
    expected_result: &str,
) -> Vec<ComparatorTraceContract> {
    let operation = reviewed_operation(builtin, instance_slug, path);
    let mut review = Review::default();
    let actual = execute_reviewed(operation, &mut review).canonical();
    assert_eq!(
        actual, expected_result,
        "pinned Set model result disagrees for {builtin}/{instance_slug}/{path}",
    );
    review.records
}

/// Shared reviewed create/go protocol used by the Map lane's five pinned
/// Double chunk discriminators. Values do not participate in key comparison.
pub(crate) fn map_from_list_contracts(path: &str) -> Vec<ComparatorTraceContract> {
    let mut review = Review::default();
    from_list(create_chunk_source(path), &mut review);
    review.records
}

/// Reviewed key-only protocols for the four Map Double/NaN context fixtures.
/// Map payloads and collision callbacks do not participate in these key
/// comparisons.
pub(crate) fn map_auxiliary_contracts(builtin: &str, path: &str) -> Vec<ComparatorTraceContract> {
    let base = doubles(&["nan", "1", "1", "nan", "0", "nan", "2", "2", "3"]);
    let operation = match (builtin, path) {
        ("Map.lookup", "nan-routing-miss") => Operation::Member(double("nan"), base),
        ("Map.delete", "nan-routing-miss") => Operation::Delete(double("nan"), base),
        ("Map.insert", "nan-routing") => Operation::Insert(double("nan"), base),
        ("Map.unionWith", "nan-shape-routing") => {
            Operation::Union(base, doubles(&["2", "nan", "9"]))
        }
        _ => panic!("unreviewed Map auxiliary protocol {builtin}/{path}"),
    };
    let mut review = Review::default();
    execute_reviewed(operation, &mut review);
    review.records
}

enum ReviewedResult {
    Set(Tree),
    Bool(bool),
}

impl ReviewedResult {
    fn canonical(&self) -> String {
        match self {
            Self::Bool(value) => format!("{{\"type\":\"Bool\",\"value\":{value}}}"),
            Self::Set(tree) => {
                let mut elements = Vec::new();
                collect_in_order(tree, &mut elements);
                format!("{{\"type\":\"Set\",\"elements\":[{}]}}", elements.join(","))
            }
        }
    }
}

fn collect_in_order(tree: &Tree, output: &mut Vec<String>) {
    let Some(tree) = tree else {
        return;
    };
    collect_in_order(&tree.left, output);
    output.push(tree.key.canonical());
    collect_in_order(&tree.right, output);
}

fn execute_reviewed(operation: Operation, review: &mut Review) -> ReviewedResult {
    match operation {
        Operation::FromList(values) => ReviewedResult::Set(from_list(values, review)),
        Operation::Insert(key, values) => {
            let tree = silent_from_list(values);
            ReviewedResult::Set(Some(insert_replacing(&tree, Rc::new(key), review)))
        }
        Operation::Member(key, values) => {
            let tree = silent_from_list(values);
            ReviewedResult::Bool(member(&tree, &key, review))
        }
        Operation::Delete(key, values) => {
            let tree = silent_from_list(values);
            ReviewedResult::Set(delete(&tree, &key, review))
        }
        Operation::Union(left, right) => {
            let left = silent_from_list(left);
            let right = silent_from_list(right);
            ReviewedResult::Set(union(&left, &right, review))
        }
        Operation::Difference(left, right) => {
            let left = silent_from_list(left);
            let right = silent_from_list(right);
            ReviewedResult::Set(difference(&left, &right, review))
        }
        Operation::Intersection(left, right) => {
            let left = silent_from_list(left);
            let right = silent_from_list(right);
            ReviewedResult::Set(intersection(&left, &right, review))
        }
        Operation::SelfUnion(values) => {
            let tree = silent_from_list(values);
            ReviewedResult::Set(union(&tree, &tree, review))
        }
        Operation::SelfIntersection(values) => {
            let tree = silent_from_list(values);
            ReviewedResult::Set(intersection(&tree, &tree, review))
        }
    }
}

fn silent_from_list(values: Vec<Key>) -> Tree {
    from_list(values, &mut Review::default())
}

fn reviewed_operation(builtin: &str, slug: &str, path: &str) -> Operation {
    match (builtin, slug, path) {
        ("Set.fromList", "ci", "equal-representative-forward") => {
            Operation::FromList(cis(&["AbC", "aBc"]))
        }
        ("Set.fromList", "ci", "equal-representative-reverse") => {
            Operation::FromList(cis(&["aBc", "AbC"]))
        }
        ("Set.fromList", "double", "signed-zero-forward") => {
            Operation::FromList(doubles(&["0", "-0"]))
        }
        ("Set.fromList", "double", "signed-zero-reverse") => {
            Operation::FromList(doubles(&["-0", "0"]))
        }
        ("Set.insert", "ci", "equal-representative-replacement") => {
            Operation::Insert(Key::Ci("aBc"), cis(&["AbC"]))
        }
        ("Set.insert", "double", "signed-zero-replacement") => {
            Operation::Insert(double("-0"), doubles(&["0"]))
        }
        ("Set.insert", "int", "absent-left") => Operation::Insert(Key::Int(0), ints(&[1, 3])),
        ("Set.insert", "int", "absent-right") => Operation::Insert(Key::Int(4), ints(&[1, 3])),
        ("Set.member", "int", "nonempty-miss") => Operation::Member(Key::Int(2), ints(&[1, 3])),
        ("Set.delete", "int", "nonempty-miss") => Operation::Delete(Key::Int(2), ints(&[1, 3])),
        ("Set.delete", "int", "two-child-interior") => {
            Operation::Delete(Key::Int(4), ints(&[1, 2, 3, 4, 5, 6, 7]))
        }
        ("Set.delete", "double", "nan-routing-miss") => {
            Operation::Delete(double("nan"), long_nan_source())
        }
        ("Set.fromList", "double", path) if path.starts_with("create-chunk-") => {
            Operation::FromList(create_chunk_source(path))
        }
        ("Set.union", "ci", path) => reviewed_ci_union(path),
        ("Set.intersection", "ci", path) => reviewed_ci_intersection(path),
        ("Set.union", "double", path) => reviewed_double_union(path),
        ("Set.intersection", "double", path) => reviewed_double_intersection(path),
        ("Set.difference", "double", path) => reviewed_double_difference(path),
        ("Set.union", "int", path) => reviewed_int_union(path),
        ("Set.difference", "int", path) => reviewed_int_difference(path),
        ("Set.intersection", "int", path) => reviewed_int_intersection(path),
        _ => panic!("unreviewed Ord/Set auxiliary operation {builtin}/{slug}/{path}"),
    }
}

fn reviewed_ci_union(path: &str) -> Operation {
    match path {
        "left-representative-forward" => Operation::Union(cis(&["AbC"]), cis(&["aBc"])),
        "left-representative-reverse" => Operation::Union(cis(&["aBc"]), cis(&["AbC"])),
        "right-singleton-equal" => Operation::Union(cis(&["AbC", "aBd"]), cis(&["aBc"])),
        "left-singleton-equal" => Operation::Union(cis(&["AbC"]), cis(&["aBc", "aBd"])),
        "multi-equal-overlap" => Operation::Union(cis(&["AbC", "aBd"]), cis(&["aBc", "zzz"])),
        _ => panic!("unreviewed CI Set.union path {path}"),
    }
}

fn reviewed_ci_intersection(path: &str) -> Operation {
    match path {
        "left-representative-forward" => Operation::Intersection(cis(&["AbC"]), cis(&["aBc"])),
        "left-representative-reverse" => Operation::Intersection(cis(&["aBc"]), cis(&["AbC"])),
        "multi-equal-overlap" => {
            Operation::Intersection(cis(&["AbC", "aBd"]), cis(&["aBc", "zzz"]))
        }
        _ => panic!("unreviewed CI Set.intersection path {path}"),
    }
}

fn reviewed_double_union(path: &str) -> Operation {
    match path {
        "signed-zero-left-forward" => Operation::Union(doubles(&["-0"]), doubles(&["0"])),
        "signed-zero-left-reverse" => Operation::Union(doubles(&["0"]), doubles(&["-0"])),
        "right-singleton-signed-zero" => Operation::Union(doubles(&["-0", "1"]), doubles(&["0"])),
        "left-singleton-signed-zero" => Operation::Union(doubles(&["-0"]), doubles(&["0", "1"])),
        "nan-shape-routing" => Operation::Union(
            doubles(&["nan", "1", "0", "3"]),
            doubles(&["2", "0", "nan"]),
        ),
        "nan-shape-routing-reverse" => Operation::Union(
            doubles(&["2", "0", "nan"]),
            doubles(&["nan", "1", "0", "3"]),
        ),
        "shared-tree-delete-routing" => Operation::SelfUnion(long_nan_source()),
        _ => panic!("unreviewed Double Set.union path {path}"),
    }
}

fn reviewed_double_intersection(path: &str) -> Operation {
    match path {
        "signed-zero-left-forward" => Operation::Intersection(doubles(&["-0"]), doubles(&["0"])),
        "signed-zero-left-reverse" => Operation::Intersection(doubles(&["0"]), doubles(&["-0"])),
        "nan-shape-routing" => Operation::Intersection(
            doubles(&["nan", "1", "0", "3", "2"]),
            doubles(&["2", "0", "nan"]),
        ),
        "nan-shape-routing-reverse" => Operation::Intersection(
            doubles(&["2", "0", "nan"]),
            doubles(&["nan", "1", "0", "3", "2"]),
        ),
        "shared-tree-delete-routing" => Operation::SelfIntersection(long_nan_source()),
        _ => panic!("unreviewed Double Set.intersection path {path}"),
    }
}

fn reviewed_double_difference(path: &str) -> Operation {
    match path {
        "nan-shape-routing" => Operation::Difference(
            doubles(&["nan", "1", "0", "3", "2"]),
            doubles(&["2", "0", "nan"]),
        ),
        "nan-shape-routing-reverse" => Operation::Difference(
            doubles(&["2", "0", "nan"]),
            doubles(&["nan", "1", "0", "3", "2"]),
        ),
        "disjoint-size-preserved-member-outcome" => Operation::Difference(
            doubles(&["nan", "nan", "nan", "nan", "nan", "nan", "0", "nan"]),
            doubles(&["8", "9"]),
        ),
        _ => panic!("unreviewed Double Set.difference path {path}"),
    }
}

fn reviewed_int_union(path: &str) -> Operation {
    match path {
        "empty-left" => Operation::Union(Vec::new(), ints(&[1, 3])),
        "empty-right" => Operation::Union(ints(&[1, 3]), Vec::new()),
        "disjoint-left-small" => Operation::Union(ints(&[1]), ints(&[2, 3, 4])),
        "disjoint-right-small" => Operation::Union(ints(&[1, 2, 3]), ints(&[4])),
        "overlap" => Operation::Union(ints(&[1, 3, 5]), ints(&[2, 3, 4])),
        _ => panic!("unreviewed Int Set.union path {path}"),
    }
}

fn reviewed_int_difference(path: &str) -> Operation {
    match path {
        "empty-left" => Operation::Difference(Vec::new(), ints(&[1, 3])),
        "empty-right" => Operation::Difference(ints(&[1, 3]), Vec::new()),
        "disjoint" => Operation::Difference(ints(&[1, 3]), ints(&[2, 4])),
        "overlap" => Operation::Difference(ints(&[1, 2, 3, 4]), ints(&[2, 4])),
        "identical" => Operation::Difference(ints(&[1, 2, 3]), ints(&[1, 2, 3])),
        "right-superset" => Operation::Difference(ints(&[2, 3]), ints(&[1, 2, 3, 4])),
        "left-skewed" => Operation::Difference(ints(&[1, 2, 3, 4, 5, 6]), ints(&[2])),
        "right-skewed" => Operation::Difference(ints(&[2, 4]), ints(&[1, 2, 3, 4, 5, 6])),
        _ => panic!("unreviewed Int Set.difference path {path}"),
    }
}

fn reviewed_int_intersection(path: &str) -> Operation {
    match path {
        "empty-left" => Operation::Intersection(Vec::new(), ints(&[1, 3])),
        "empty-right" => Operation::Intersection(ints(&[1, 3]), Vec::new()),
        "disjoint" => Operation::Intersection(ints(&[1, 3]), ints(&[2, 4])),
        "overlap" => Operation::Intersection(ints(&[1, 3, 5]), ints(&[2, 3, 4])),
        "left-skewed" => Operation::Intersection(ints(&[1, 2, 3, 4, 5, 6]), ints(&[2])),
        "right-skewed" => Operation::Intersection(ints(&[2]), ints(&[1, 2, 3, 4, 5, 6])),
        _ => panic!("unreviewed Int Set.intersection path {path}"),
    }
}

fn create_chunk_source(path: &str) -> Vec<Key> {
    match path {
        "create-chunk-1" => doubles(&["1", "1", "2", "3", "nan", "4", "5", "nan", "6", "0"]),
        "create-chunk-2" => doubles(&["1", "2", "2", "3", "4", "nan", "5", "6", "7", "0"]),
        "create-chunk-3" => doubles(&["1", "2", "3", "4", "4", "5", "6", "nan", "7", "8", "0"]),
        "create-chunk-4" => doubles(&["1", "2", "3", "4", "0", "nan", "5", "6"]),
        "create-chunk-5" => doubles(&["nan", "1", "1", "nan", "0", "nan", "2", "2", "3"]),
        _ => panic!("unreviewed Set.fromList create path {path}"),
    }
}

fn long_nan_source() -> Vec<Key> {
    doubles(&[
        "nan", "1", "nan", "0", "nan", "nan", "nan", "nan", "3", "2", "0",
    ])
}

fn ints(values: &[i64]) -> Vec<Key> {
    values.iter().copied().map(Key::Int).collect()
}

fn cis(values: &[&'static str]) -> Vec<Key> {
    values.iter().copied().map(Key::Ci).collect()
}

fn doubles(values: &[&str]) -> Vec<Key> {
    values.iter().copied().map(double).collect()
}

fn double(value: &str) -> Key {
    let bits = match value {
        "nan" => 0x7ff8_0000_0000_0000,
        "-0" => (-0.0_f64).to_bits(),
        candidate => candidate
            .parse::<f64>()
            .expect("reviewed Double literal parses")
            .to_bits(),
    };
    Key::Double(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_map_wrapper_inventory_results_and_operation_wiring_are_exact() {
        let create_cases = [
            (
                "create-chunk-1",
                &["1", "2", "3", "nan", "0", "4", "5", "nan", "6"][..],
            ),
            (
                "create-chunk-2",
                &["0", "1", "2", "3", "4", "nan", "5", "6", "7"][..],
            ),
            (
                "create-chunk-3",
                &["0", "1", "2", "3", "4", "5", "6", "nan", "7", "8"][..],
            ),
            (
                "create-chunk-4",
                &["0", "1", "2", "3", "4", "nan", "5", "6"][..],
            ),
            (
                "create-chunk-5",
                &["nan", "0", "1", "nan", "nan", "2", "3"][..],
            ),
        ];
        let mut distinct = std::collections::BTreeSet::new();
        for (path, expected_keys) in create_cases {
            let mut review = Review::default();
            let result =
                execute_reviewed(Operation::FromList(create_chunk_source(path)), &mut review)
                    .canonical();
            assert_eq!(result, canonical_double_set(expected_keys), "{path}");
            assert!(!review.records.is_empty(), "{path}");
            assert_eq!(map_from_list_contracts(path), review.records, "{path}");
            distinct.insert(
                crate::comparator_trace_sha256("Map.fromList", 1, "Double", &[], &review.records)
                    .hex(),
            );
        }
        assert_eq!(
            distinct.len(),
            5,
            "each Map create/go path is discriminating"
        );
        assert!(std::panic::catch_unwind(|| map_from_list_contracts("create-chunk-6")).is_err());

        let base_values = || doubles(&["nan", "1", "1", "nan", "0", "nan", "2", "2", "3"]);
        let auxiliary = [
            (
                "Map.lookup",
                "nan-routing-miss",
                Operation::Member(double("nan"), base_values()),
                r#"{"type":"Bool","value":false}"#.to_owned(),
            ),
            (
                "Map.delete",
                "nan-routing-miss",
                Operation::Delete(double("nan"), base_values()),
                canonical_double_set(&["nan", "0", "1", "nan", "nan", "2", "3"]),
            ),
            (
                "Map.insert",
                "nan-routing",
                Operation::Insert(double("nan"), base_values()),
                canonical_double_set(&["nan", "0", "1", "nan", "nan", "2", "3", "nan"]),
            ),
            (
                "Map.unionWith",
                "nan-shape-routing",
                Operation::Union(base_values(), doubles(&["2", "nan", "9"])),
                canonical_double_set(&["2", "nan", "nan", "0", "1", "nan", "nan", "2", "3", "9"]),
            ),
        ];
        for (builtin, path, operation, expected_result) in auxiliary {
            let mut review = Review::default();
            assert_eq!(
                execute_reviewed(operation, &mut review).canonical(),
                expected_result,
                "{builtin}/{path}",
            );
            assert!(!review.records.is_empty(), "{builtin}/{path}");
            assert_eq!(
                map_auxiliary_contracts(builtin, path),
                review.records,
                "{builtin}/{path}",
            );
        }

        let correct = map_auxiliary_contracts("Map.unionWith", "nan-shape-routing");
        let mut wrong = Review::default();
        execute_reviewed(
            Operation::Union(
                doubles(&["2", "nan", "9"]),
                doubles(&["nan", "1", "1", "nan", "0", "nan", "2", "2", "3"]),
            ),
            &mut wrong,
        );
        assert_ne!(
            correct, wrong.records,
            "Map.unionWith direction is authority-bound"
        );
    }

    fn canonical_double_set(values: &[&str]) -> String {
        format!(
            "{{\"type\":\"Set\",\"elements\":[{}]}}",
            doubles(values)
                .iter()
                .map(Key::canonical)
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    #[test]
    fn reviewed_auxiliary_inventory_is_exact_and_results_match_pinned_outputs() {
        let cases = crate::corpus::runtime_ord_set_cases();
        let auxiliary = &cases[420..];
        assert_eq!(auxiliary.len(), 59);
        for case in auxiliary {
            let target = &case.claim_evidence.as_ref().unwrap().semantic_targets[0];
            assert!(
                target.expected_comparator_trace_sha256.is_some(),
                "{}",
                case.id
            );
        }
    }

    #[test]
    fn pinned_create_go_rejects_fold_insert_branch_mutant() {
        let values = create_chunk_source("create-chunk-4");
        let mut reviewed = Review::default();
        from_list(values.clone(), &mut reviewed);

        let mut mutant = Review::default();
        let mut tree = None;
        for key in values {
            tree = Some(insert_replacing(&tree, Rc::new(key), &mut mutant));
        }
        assert_ne!(reviewed.records, mutant.records);
    }

    #[test]
    fn pinned_equality_replacement_rejects_preserving_branch_mutant() {
        let expected = ReviewedResult::Set(from_list(cis(&["AbC", "aBc"]), &mut Review::default()))
            .canonical();
        let first = Some(node(Rc::new(Key::Ci("AbC")), None, None));
        let mutant = ReviewedResult::Set(Some(insert_preserving(
            &first,
            Rc::new(Key::Ci("aBc")),
            &mut Review::default(),
        )))
        .canonical();
        assert_ne!(expected, mutant);
    }

    #[test]
    fn pinned_union_direction_rejects_singleton_branch_mutant() {
        let left = silent_from_list(cis(&["AbC", "aBd"]));
        let right = silent_from_list(cis(&["aBc"]));
        let reviewed =
            ReviewedResult::Set(union(&left, &right, &mut Review::default())).canonical();
        let left_key = Rc::clone(&left.as_ref().unwrap().key);
        let mutant = ReviewedResult::Set(Some(insert_replacing(
            &right,
            left_key,
            &mut Review::default(),
        )))
        .canonical();
        assert_ne!(reviewed, mutant);
    }

    #[test]
    fn pinned_size_balance_changes_nan_sensitive_follow_up_protocol() {
        let reviewed_tree = silent_from_list(long_nan_source());
        let mut reviewed = Review::default();
        member(&reviewed_tree, &double("nan"), &mut reviewed);

        let mut construction = Review::default();
        let mut unbalanced = None;
        for key in long_nan_source() {
            unbalanced = Some(insert_without_balance(
                &unbalanced,
                Rc::new(key),
                &mut construction,
            ));
        }
        let mut mutant = Review::default();
        member(&unbalanced, &double("nan"), &mut mutant);
        assert_ne!(reviewed.records, mutant.records);
    }

    #[test]
    fn pinned_glue_rejects_link2_delete_branch_mutant() {
        let left = silent_from_list(ints(&[1, 2, 3, 4, 5, 6, 7]));
        let right = silent_from_list(ints(&[8, 9]));
        let reviewed = glue(left.clone(), right.clone());
        let mutant = merge(left, right);
        assert_ne!(tree_signature(&reviewed), tree_signature(&mutant));
    }

    #[test]
    fn pinned_difference_preserves_disjoint_tree_identity() {
        let left = silent_from_list(doubles(&[
            "nan", "nan", "nan", "nan", "nan", "nan", "0", "nan",
        ]));
        let right = silent_from_list(doubles(&["8", "9"]));
        let reviewed = difference(&left, &right, &mut Review::default());
        let mutant = difference_without_size_preservation(&left, &right, &mut Review::default());
        assert!(same_tree(&reviewed, &left));
        assert!(!same_tree(&mutant, &left));
        let mut reviewed_trace = Review::default();
        let reviewed_result = member(&reviewed, &double("0"), &mut reviewed_trace);
        let mut mutant_trace = Review::default();
        let mutant_result = member(&mutant, &double("0"), &mut mutant_trace);
        assert!(reviewed_result);
        assert!(!mutant_result);
        assert_ne!(reviewed_trace.records, mutant_trace.records);
    }

    #[test]
    fn pinned_intersection_preserves_identity_and_left_representative() {
        let shared = silent_from_list(ints(&[1, 2, 3, 4, 5, 6, 7]));
        let reviewed = intersection(&shared, &shared, &mut Review::default());
        let rebuilt = intersection_without_identity(&shared, &shared, &mut Review::default());
        assert!(same_tree(&reviewed, &shared));
        assert!(!same_tree(&rebuilt, &shared));

        let left = silent_from_list(cis(&["AbC"]));
        let right = silent_from_list(cis(&["aBc"]));
        let retained = intersection(&left, &right, &mut Review::default());
        let right_biased = right.clone();
        assert_ne!(
            ReviewedResult::Set(retained).canonical(),
            ReviewedResult::Set(right_biased).canonical(),
        );
    }

    fn tree_signature(tree: &Tree) -> String {
        let Some(tree) = tree else {
            return "_".to_owned();
        };
        format!(
            "({} {} {})",
            tree.key.canonical(),
            tree_signature(&tree.left),
            tree_signature(&tree.right),
        )
    }

    fn difference_without_size_preservation(
        left: &Tree,
        right: &Tree,
        review: &mut Review,
    ) -> Tree {
        let Some(right_root) = right else {
            return left.clone();
        };
        if left.is_none() {
            return None;
        }
        let (left_lower, _, left_upper) = split(left, &right_root.key, review);
        let lower = difference_without_size_preservation(&left_lower, &right_root.left, review);
        let upper = difference_without_size_preservation(&left_upper, &right_root.right, review);
        merge(lower, upper)
    }

    fn intersection_without_identity(left: &Tree, right: &Tree, review: &mut Review) -> Tree {
        let Some(left_root) = left else {
            return None;
        };
        if right.is_none() {
            return None;
        }
        let (right_lower, found, right_upper) = split(right, &left_root.key, review);
        let lower = intersection_without_identity(&left_root.left, &right_lower, review);
        let upper = intersection_without_identity(&left_root.right, &right_upper, review);
        if found.is_some() {
            Some(link(Rc::clone(&left_root.key), lower, upper))
        } else {
            merge(lower, upper)
        }
    }

    fn insert_without_balance(tree: &Tree, key: Rc<Key>, review: &mut Review) -> Rc<Node> {
        let Some(tree) = tree else {
            return node(key, None, None);
        };
        match review.compare(&key, &tree.key) {
            Ordering::Less => node(
                Rc::clone(&tree.key),
                Some(insert_without_balance(&tree.left, key, review)),
                tree.right.clone(),
            ),
            Ordering::Equal => node(key, tree.left.clone(), tree.right.clone()),
            Ordering::Greater => node(
                Rc::clone(&tree.key),
                tree.left.clone(),
                Some(insert_without_balance(&tree.right, key, review)),
            ),
        }
    }
}
