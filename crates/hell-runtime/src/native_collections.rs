//! Ordered `Map` and `Set` adapters over lazy runtime values.

use std::{cmp::Ordering, sync::Arc};

use hell_builtins::TypeClass;
use hell_core::ClassEvidence;

#[cfg(not(feature = "compat-tracing"))]
use crate::Suspension;
use crate::{
    Evaluator, ForceOutcome, RuntimeError, RuntimeResult, Thunk, ThunkRef, Value, list_from_values,
};

type MapEntry = (ThunkRef, ThunkRef);

const SIZE_BALANCE_DELTA: usize = 3;
const SIZE_BALANCE_RATIO: usize = 2;

#[derive(Clone, Debug)]
struct TreeNode<T> {
    item: T,
    left: Option<Arc<Self>>,
    right: Option<Arc<Self>>,
    len: usize,
}

type TreeSplit<T> = (
    Option<Arc<TreeNode<T>>>,
    Option<T>,
    Option<Arc<TreeNode<T>>>,
);

impl<T: Clone> TreeNode<T> {
    fn new(item: T, left: Option<Arc<Self>>, right: Option<Arc<Self>>) -> Arc<Self> {
        Arc::new(Self {
            item,
            len: 1 + node_len(left.as_ref()) + node_len(right.as_ref()),
            left,
            right,
        })
    }
}

fn node_len<T>(node: Option<&Arc<TreeNode<T>>>) -> usize {
    node.map_or(0, |node| node.len)
}

#[derive(Clone, Debug)]
struct PersistentTree<T> {
    root: Option<Arc<TreeNode<T>>>,
}

impl<T> Default for PersistentTree<T> {
    fn default() -> Self {
        Self { root: None }
    }
}

impl<T: Clone> PersistentTree<T> {
    fn singleton(item: T) -> Self {
        Self {
            root: Some(TreeNode::new(item, None, None)),
        }
    }

    fn from_sorted(items: &[T]) -> Self {
        fn build<T: Clone>(items: &[T]) -> Option<Arc<TreeNode<T>>> {
            let (middle, rest) = items.split_at(items.len() / 2);
            let (item, right) = rest.split_first()?;
            Some(TreeNode::new(item.clone(), build(middle), build(right)))
        }
        Self { root: build(items) }
    }

    #[cfg(feature = "compat-tracing")]
    fn map_preserving_shape<U: Clone, F>(
        &self,
        transform: &mut F,
    ) -> RuntimeResult<PersistentTree<U>>
    where
        F: FnMut(&T) -> RuntimeResult<U>,
    {
        fn map_node<T, U: Clone, F>(
            node: Option<&Arc<TreeNode<T>>>,
            transform: &mut F,
        ) -> RuntimeResult<Option<Arc<TreeNode<U>>>>
        where
            F: FnMut(&T) -> RuntimeResult<U>,
        {
            let Some(node) = node else {
                return Ok(None);
            };
            let item = transform(&node.item)?;
            let left = map_node(node.left.as_ref(), transform)?;
            let right = map_node(node.right.as_ref(), transform)?;
            let mapped = TreeNode::new(item, left, right);
            if mapped.len != node.len {
                return Err(RuntimeError::internal(
                    "shape-preserving collection map changed the retained node length",
                ));
            }
            Ok(Some(mapped))
        }

        Ok(PersistentTree {
            root: map_node(self.root.as_ref(), transform)?,
        })
    }

    fn len(&self) -> usize {
        node_len(self.root.as_ref())
    }

    fn iter(&self) -> TreeIter<'_, T> {
        TreeIter::new(self.root.as_deref())
    }

    fn find<C>(&self, mut compare: C) -> RuntimeResult<Option<&T>>
    where
        C: FnMut(&T) -> RuntimeResult<Ordering>,
    {
        let mut current = self.root.as_deref();
        while let Some(node) = current {
            current = match compare(&node.item)? {
                Ordering::Less => node.left.as_deref(),
                Ordering::Equal => return Ok(Some(&node.item)),
                Ordering::Greater => node.right.as_deref(),
            };
        }
        Ok(None)
    }

    fn insert<C>(&self, item: T, compare: &mut C) -> RuntimeResult<Self>
    where
        C: FnMut(&T, &T) -> RuntimeResult<Ordering>,
    {
        fn insert_node<T: Clone, C>(
            node: Option<&Arc<TreeNode<T>>>,
            item: T,
            compare: &mut C,
        ) -> RuntimeResult<Arc<TreeNode<T>>>
        where
            C: FnMut(&T, &T) -> RuntimeResult<Ordering>,
        {
            let Some(node) = node else {
                return Ok(TreeNode::new(item, None, None));
            };
            match compare(&item, &node.item)? {
                Ordering::Less => Ok(balance_left(TreeNode::new(
                    node.item.clone(),
                    Some(insert_node(node.left.as_ref(), item, compare)?),
                    node.right.clone(),
                ))),
                Ordering::Equal => Ok(TreeNode::new(item, node.left.clone(), node.right.clone())),
                Ordering::Greater => Ok(balance_right(TreeNode::new(
                    node.item.clone(),
                    node.left.clone(),
                    Some(insert_node(node.right.as_ref(), item, compare)?),
                ))),
            }
        }
        Ok(Self {
            root: Some(insert_node(self.root.as_ref(), item, compare)?),
        })
    }

    fn remove<C>(&self, compare: &mut C) -> RuntimeResult<Self>
    where
        C: FnMut(&T) -> RuntimeResult<Ordering>,
    {
        fn remove_node<T: Clone, C>(
            node: Option<&Arc<TreeNode<T>>>,
            compare: &mut C,
        ) -> RuntimeResult<Option<Arc<TreeNode<T>>>>
        where
            C: FnMut(&T) -> RuntimeResult<Ordering>,
        {
            let Some(node) = node else {
                return Ok(None);
            };
            match compare(&node.item)? {
                Ordering::Less => Ok(Some(balance_right(TreeNode::new(
                    node.item.clone(),
                    remove_node(node.left.as_ref(), compare)?,
                    node.right.clone(),
                )))),
                Ordering::Greater => Ok(Some(balance_left(TreeNode::new(
                    node.item.clone(),
                    node.left.clone(),
                    remove_node(node.right.as_ref(), compare)?,
                )))),
                Ordering::Equal => Ok(glue(node.left.clone(), node.right.clone())),
            }
        }
        Ok(Self {
            root: remove_node(self.root.as_ref(), compare)?,
        })
    }

    fn split_lookup<C>(&self, compare: &mut C) -> RuntimeResult<(Self, Option<T>, Self)>
    where
        C: FnMut(&T) -> RuntimeResult<Ordering>,
    {
        fn split_node<T: Clone, C>(
            node: Option<&Arc<TreeNode<T>>>,
            compare: &mut C,
        ) -> RuntimeResult<TreeSplit<T>>
        where
            C: FnMut(&T) -> RuntimeResult<Ordering>,
        {
            let Some(node) = node else {
                return Ok((None, None, None));
            };
            match compare(&node.item)? {
                Ordering::Less => {
                    let (lower, found, upper_left) = split_node(node.left.as_ref(), compare)?;
                    Ok((
                        lower,
                        found,
                        Some(link(node.item.clone(), upper_left, node.right.clone())),
                    ))
                }
                Ordering::Equal => Ok((
                    node.left.clone(),
                    Some(node.item.clone()),
                    node.right.clone(),
                )),
                Ordering::Greater => {
                    let (lower_right, found, upper) = split_node(node.right.as_ref(), compare)?;
                    Ok((
                        Some(link(node.item.clone(), node.left.clone(), lower_right)),
                        found,
                        upper,
                    ))
                }
            }
        }

        let (left, found, right) = split_node(self.root.as_ref(), compare)?;
        Ok((Self { root: left }, found, Self { root: right }))
    }
}

fn balance_left<T: Clone>(node: Arc<TreeNode<T>>) -> Arc<TreeNode<T>> {
    let left_size = node_len(node.left.as_ref());
    let right_size = node_len(node.right.as_ref());
    if left_size.saturating_add(right_size) <= 1
        || left_size <= SIZE_BALANCE_DELTA.saturating_mul(right_size)
    {
        return node;
    }
    let left = node
        .left
        .as_ref()
        .expect("left-heavy size-balanced node has a left child");
    if node_len(left.right.as_ref())
        < SIZE_BALANCE_RATIO.saturating_mul(node_len(left.left.as_ref()))
    {
        rotate_right(&node)
    } else {
        let left = rotate_left(left);
        rotate_right(&TreeNode::new(
            node.item.clone(),
            Some(left),
            node.right.clone(),
        ))
    }
}

fn balance_right<T: Clone>(node: Arc<TreeNode<T>>) -> Arc<TreeNode<T>> {
    let left_size = node_len(node.left.as_ref());
    let right_size = node_len(node.right.as_ref());
    if left_size.saturating_add(right_size) <= 1
        || right_size <= SIZE_BALANCE_DELTA.saturating_mul(left_size)
    {
        return node;
    }
    let right = node
        .right
        .as_ref()
        .expect("right-heavy size-balanced node has a right child");
    if node_len(right.left.as_ref())
        < SIZE_BALANCE_RATIO.saturating_mul(node_len(right.right.as_ref()))
    {
        rotate_left(&node)
    } else {
        let right = rotate_right(right);
        rotate_left(&TreeNode::new(
            node.item.clone(),
            node.left.clone(),
            Some(right),
        ))
    }
}

fn link<T: Clone>(
    item: T,
    left: Option<Arc<TreeNode<T>>>,
    right: Option<Arc<TreeNode<T>>>,
) -> Arc<TreeNode<T>> {
    if left.is_none() {
        return insert_min(item, right);
    }
    if right.is_none() {
        return insert_max(item, left);
    }
    let left_size = node_len(left.as_ref());
    let right_size = node_len(right.as_ref());
    if SIZE_BALANCE_DELTA.saturating_mul(left_size) < right_size {
        let right = right.expect("right-heavy link has a right tree");
        return balance_left(TreeNode::new(
            right.item.clone(),
            Some(link(item, left, right.left.clone())),
            right.right.clone(),
        ));
    }
    if SIZE_BALANCE_DELTA.saturating_mul(right_size) < left_size {
        let left = left.expect("left-heavy link has a left tree");
        return balance_right(TreeNode::new(
            left.item.clone(),
            left.left.clone(),
            Some(link(item, left.right.clone(), right)),
        ));
    }
    TreeNode::new(item, left, right)
}

fn insert_min<T: Clone>(item: T, tree: Option<Arc<TreeNode<T>>>) -> Arc<TreeNode<T>> {
    let Some(tree) = tree else {
        return TreeNode::new(item, None, None);
    };
    balance_left(TreeNode::new(
        tree.item.clone(),
        Some(insert_min(item, tree.left.clone())),
        tree.right.clone(),
    ))
}

fn take_min<T: Clone>(node: &Arc<TreeNode<T>>) -> (T, Option<Arc<TreeNode<T>>>) {
    let Some(left) = node.left.as_ref() else {
        return (node.item.clone(), node.right.clone());
    };
    let (item, new_left) = take_min(left);
    (
        item,
        Some(balance_right(TreeNode::new(
            node.item.clone(),
            new_left,
            node.right.clone(),
        ))),
    )
}

fn take_max<T: Clone>(node: &Arc<TreeNode<T>>) -> (T, Option<Arc<TreeNode<T>>>) {
    let Some(right) = node.right.as_ref() else {
        return (node.item.clone(), node.left.clone());
    };
    let (item, new_right) = take_max(right);
    (
        item,
        Some(balance_left(TreeNode::new(
            node.item.clone(),
            node.left.clone(),
            new_right,
        ))),
    )
}

fn glue<T: Clone>(
    left: Option<Arc<TreeNode<T>>>,
    right: Option<Arc<TreeNode<T>>>,
) -> Option<Arc<TreeNode<T>>> {
    match (left, right) {
        (None, right) => right,
        (left, None) => left,
        (Some(left), Some(right)) if left.len > right.len => {
            let (item, remaining_left) = take_max(&left);
            Some(balance_right(TreeNode::new(
                item,
                remaining_left,
                Some(right),
            )))
        }
        (Some(left), Some(right)) => {
            let (item, remaining_right) = take_min(&right);
            Some(balance_left(TreeNode::new(
                item,
                Some(left),
                remaining_right,
            )))
        }
    }
}

fn rotate_left<T: Clone>(node: &Arc<TreeNode<T>>) -> Arc<TreeNode<T>> {
    let right = node
        .right
        .as_ref()
        .expect("left rotation requires a right child");
    TreeNode::new(
        right.item.clone(),
        Some(TreeNode::new(
            node.item.clone(),
            node.left.clone(),
            right.left.clone(),
        )),
        right.right.clone(),
    )
}

fn rotate_right<T: Clone>(node: &Arc<TreeNode<T>>) -> Arc<TreeNode<T>> {
    let left = node
        .left
        .as_ref()
        .expect("right rotation requires a left child");
    TreeNode::new(
        left.item.clone(),
        left.left.clone(),
        Some(TreeNode::new(
            node.item.clone(),
            left.right.clone(),
            node.right.clone(),
        )),
    )
}

struct TreeIter<'a, T> {
    stack: Vec<&'a TreeNode<T>>,
}

impl<'a, T> TreeIter<'a, T> {
    fn new(root: Option<&'a TreeNode<T>>) -> Self {
        let mut iter = Self { stack: Vec::new() };
        iter.push_left(root);
        iter
    }

    fn push_left(&mut self, mut node: Option<&'a TreeNode<T>>) {
        while let Some(current) = node {
            self.stack.push(current);
            node = current.left.as_deref();
        }
    }
}

impl<'a, T> Iterator for TreeIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.stack.pop()?;
        self.push_left(node.right.as_deref());
        Some(&node.item)
    }
}

/// An immutable, structurally shared, guest-ordered map.
#[derive(Clone, Debug, Default)]
pub struct OrderedMap(PersistentTree<MapEntry>);

/// An immutable, structurally shared, guest-ordered set.
#[derive(Clone, Debug, Default)]
pub struct OrderedSet(PersistentTree<ThunkRef>);

impl OrderedMap {
    pub(crate) fn from_sorted(entries: &[MapEntry]) -> Self {
        Self(PersistentTree::from_sorted(entries))
    }

    #[cfg(feature = "compat-tracing")]
    pub(crate) fn map_preserving_shape<F>(&self, mut transform: F) -> RuntimeResult<Self>
    where
        F: FnMut(&MapEntry) -> RuntimeResult<MapEntry>,
    {
        Ok(Self(self.0.map_preserving_shape(&mut transform)?))
    }

    fn singleton(key: ThunkRef, item: ThunkRef) -> Self {
        Self(PersistentTree::singleton((key, item)))
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn iter(&self) -> std::vec::IntoIter<&MapEntry> {
        self.0.iter().collect::<Vec<_>>().into_iter()
    }
}

impl OrderedSet {
    #[cfg(test)]
    pub(crate) fn from_sorted(elements: &[ThunkRef]) -> Self {
        Self(PersistentTree::from_sorted(elements))
    }

    #[cfg(feature = "compat-tracing")]
    pub(crate) fn map_preserving_shape<F>(&self, mut transform: F) -> RuntimeResult<Self>
    where
        F: FnMut(&ThunkRef) -> RuntimeResult<ThunkRef>,
    {
        Ok(Self(self.0.map_preserving_shape(&mut transform)?))
    }

    fn singleton(element: ThunkRef) -> Self {
        Self(PersistentTree::singleton(element))
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn iter(&self) -> std::vec::IntoIter<&ThunkRef> {
        self.0.iter().collect::<Vec<_>>().into_iter()
    }
}

impl<'a> IntoIterator for &'a OrderedMap {
    type Item = &'a MapEntry;
    type IntoIter = std::vec::IntoIter<&'a MapEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a OrderedSet {
    type Item = &'a ThunkRef;
    type IntoIter = std::vec::IntoIter<&'a ThunkRef>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub(super) fn apply_native(
    implementation: &str,
    arguments: &[ThunkRef],
    evidence: Option<ClassEvidence>,
    evaluator: &mut Evaluator,
) -> Option<RuntimeResult<ForceOutcome>> {
    Some(match implementation {
        "map_from_list" => ord_evidence(evaluator, evidence, "Map.fromList")
            .and_then(|evidence| map_from_list(evaluator, evidence, &arguments[0])),
        "map_to_list" => map_to_list(evaluator, &arguments[0]),
        "map_lookup" => ord_evidence(evaluator, evidence, "Map.lookup")
            .and_then(|evidence| map_lookup(evaluator, evidence, &arguments[0], &arguments[1])),
        "map_insert" => ord_evidence(evaluator, evidence, "Map.insert").and_then(|evidence| {
            map_insert(
                evaluator,
                evidence,
                &arguments[0],
                &arguments[1],
                &arguments[2],
            )
        }),
        "map_delete" => ord_evidence(evaluator, evidence, "Map.delete")
            .and_then(|evidence| map_delete(evaluator, evidence, &arguments[0], &arguments[1])),
        "map_singleton" => ord_evidence(evaluator, evidence, "Map.singleton").and_then(|_| {
            evaluator.force(&arguments[0])?;
            Ok(collection(Value::Map(Arc::new(OrderedMap::singleton(
                Arc::clone(&arguments[0]),
                Arc::clone(&arguments[1]),
            )))))
        }),
        "map_size" => map_size(evaluator, &arguments[0]),
        "map_filter" => map_filter(evaluator, &arguments[0], &arguments[1], false),
        "map_filter_with_key" => map_filter(evaluator, &arguments[0], &arguments[1], true),
        "map_any" => map_quantifier(evaluator, &arguments[0], &arguments[1], false),
        "map_all" => map_quantifier(evaluator, &arguments[0], &arguments[1], true),
        "map_insert_with" => ord_evidence(evaluator, evidence, "Map.insertWith")
            .and_then(|evidence| map_insert_with(evaluator, evidence, arguments)),
        "map_adjust" => ord_evidence(evaluator, evidence, "Map.adjust")
            .and_then(|evidence| map_adjust(evaluator, evidence, arguments)),
        "map_union_with" => ord_evidence(evaluator, evidence, "Map.unionWith")
            .and_then(|evidence| map_union_with(evaluator, evidence, arguments)),
        "map_map" => map_values(evaluator, &arguments[0], &arguments[1]),
        "map_keys" => map_keys(evaluator, &arguments[0]),
        "map_elems" => map_elems(evaluator, &arguments[0]),
        "set_from_list" => ord_evidence(evaluator, evidence, "Set.fromList")
            .and_then(|evidence| set_from_list(evaluator, evidence, &arguments[0])),
        "set_to_list" => set_to_list(evaluator, &arguments[0]),
        "set_insert" => ord_evidence(evaluator, evidence, "Set.insert")
            .and_then(|evidence| set_insert(evaluator, evidence, &arguments[0], &arguments[1])),
        "set_member" => ord_evidence(evaluator, evidence, "Set.member")
            .and_then(|evidence| set_member(evaluator, evidence, &arguments[0], &arguments[1])),
        "set_delete" => ord_evidence(evaluator, evidence, "Set.delete")
            .and_then(|evidence| set_delete(evaluator, evidence, &arguments[0], &arguments[1])),
        "set_union" => ord_evidence(evaluator, evidence, "Set.union").and_then(|evidence| {
            set_merge(
                evaluator,
                evidence,
                &arguments[0],
                &arguments[1],
                SetMerge::Union,
            )
        }),
        "set_difference" => {
            ord_evidence(evaluator, evidence, "Set.difference").and_then(|evidence| {
                set_merge(
                    evaluator,
                    evidence,
                    &arguments[0],
                    &arguments[1],
                    SetMerge::Difference,
                )
            })
        }
        "set_intersection" => {
            ord_evidence(evaluator, evidence, "Set.intersection").and_then(|evidence| {
                set_merge(
                    evaluator,
                    evidence,
                    &arguments[0],
                    &arguments[1],
                    SetMerge::Intersection,
                )
            })
        }
        "set_size" => set_size(evaluator, &arguments[0]),
        "set_singleton" => ord_evidence(evaluator, evidence, "Set.singleton").and_then(|_| {
            evaluator.force(&arguments[0])?;
            Ok(collection(Value::Set(Arc::new(OrderedSet::singleton(
                Arc::clone(&arguments[0]),
            )))))
        }),
        _ => return None,
    })
}

fn ord_evidence(
    evaluator: &Evaluator,
    evidence: Option<ClassEvidence>,
    operation: &str,
) -> RuntimeResult<ClassEvidence> {
    let evidence = evidence.ok_or_else(|| {
        RuntimeError::internal(format!(
            "{operation} reached runtime without retained Ord evidence"
        ))
    })?;
    if evidence.class != TypeClass::Ord {
        return Err(RuntimeError::internal(format!(
            "{operation} received non-Ord class evidence"
        )));
    }
    crate::typeclasses::instance_target(evaluator, evidence)?;
    Ok(evidence)
}

fn collection(value: Value) -> ForceOutcome {
    ForceOutcome::Value(Arc::new(value))
}

fn force_map(evaluator: &mut Evaluator, map: &ThunkRef) -> RuntimeResult<Arc<OrderedMap>> {
    match evaluator.force(map)?.as_ref() {
        Value::Map(entries) => Ok(Arc::clone(entries)),
        _ => Err(RuntimeError::internal(
            "Map operation received a non-Map value",
        )),
    }
}

fn force_set(evaluator: &mut Evaluator, set: &ThunkRef) -> RuntimeResult<Arc<OrderedSet>> {
    match evaluator.force(set)?.as_ref() {
        Value::Set(elements) => Ok(Arc::clone(elements)),
        _ => Err(RuntimeError::internal(
            "Set operation received a non-Set value",
        )),
    }
}

fn compare_keys_with_ord_adapters(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    left: &ThunkRef,
    right: &ThunkRef,
) -> RuntimeResult<Ordering> {
    if evaluator.equal_values(left, right)? {
        return Ok(Ordering::Equal);
    }
    let less = hell_builtins::lookup("Ord.lt")
        .expect("Ord.lt is registry-backed")
        .id;
    let greater = hell_builtins::lookup("Ord.gt")
        .expect("Ord.gt is registry-backed")
        .id;
    let less_outcome =
        evaluator.apply_native(less, &[Arc::clone(left), Arc::clone(right)], Some(evidence))?;
    let less_result = force_outcome_bool(evaluator, less_outcome)?;
    #[cfg(feature = "compat-tracing")]
    evaluator.record_ord_comparator_invocation(less, evidence, left, right, less_result)?;
    if less_result {
        return Ok(Ordering::Less);
    }
    let greater_outcome = evaluator.apply_native(
        greater,
        &[Arc::clone(left), Arc::clone(right)],
        Some(evidence),
    )?;
    let greater_result = force_outcome_bool(evaluator, greater_outcome)?;
    #[cfg(feature = "compat-tracing")]
    evaluator.record_ord_comparator_invocation(greater, evidence, left, right, greater_result)?;
    if greater_result {
        return Ok(Ordering::Greater);
    }
    // Preserve the existing total fallback for values such as NaN that
    // compare neither less, greater, nor equal. The reviewed interaction
    // separately binds the delegated `Ord.gt` result for ordered Int keys.
    Ok(Ordering::Greater)
}

fn force_outcome_bool(evaluator: &mut Evaluator, outcome: ForceOutcome) -> RuntimeResult<bool> {
    match outcome {
        ForceOutcome::Value(value) => match value.as_ref() {
            Value::Bool(value) => Ok(*value),
            _ => Err(RuntimeError::internal(
                "Ord comparator returned a non-Bool value",
            )),
        },
        ForceOutcome::Alias(value) => evaluator.force_bool(&value),
    }
}

fn map_from_list(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    list: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let pairs = evaluator.force_list_elements(list)?;
    let mut entries = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let pair = evaluator.force(&pair)?;
        let Value::Tuple(elements) = pair.as_ref() else {
            return Err(RuntimeError::internal(
                "Map.fromList received a non-pair element",
            ));
        };
        let [key, item] = elements.as_ref() else {
            return Err(RuntimeError::internal(
                "Map.fromList received a tuple with the wrong arity",
            ));
        };
        entries.push((Arc::clone(key), Arc::clone(item)));
    }
    let entries = map_from_entries(evaluator, evidence, &entries)?;
    Ok(collection(Value::Map(Arc::new(OrderedMap(entries)))))
}

fn map_from_entries(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    items: &[MapEntry],
) -> RuntimeResult<PersistentTree<MapEntry>> {
    let Some(first) = items.first() else {
        return Ok(PersistentTree::default());
    };
    let first = PersistentTree::singleton(first.clone());
    if map_entries_not_ordered(evaluator, evidence, &items[0], items.get(1))? {
        return map_insert_entries(evaluator, evidence, first, &items[1..]);
    }
    map_from_ordered_entries(evaluator, evidence, 1, first, items, 1)
}

fn map_insert_entries(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    mut tree: PersistentTree<MapEntry>,
    items: &[MapEntry],
) -> RuntimeResult<PersistentTree<MapEntry>> {
    for item in items {
        tree = tree.insert(item.clone(), &mut |left, right| {
            compare_keys_with_ord_adapters(evaluator, evidence, &left.0, &right.0)
        })?;
    }
    Ok(tree)
}

fn map_entries_not_ordered(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    current: &MapEntry,
    next: Option<&MapEntry>,
) -> RuntimeResult<bool> {
    let Some(next) = next else {
        return Ok(false);
    };
    if evaluator.equal_values(&current.0, &next.0)? {
        return Ok(true);
    }
    let greater = hell_builtins::lookup("Ord.gt")
        .expect("Ord.gt is registry-backed")
        .id;
    let outcome = evaluator.apply_native(
        greater,
        &[Arc::clone(&current.0), Arc::clone(&next.0)],
        Some(evidence),
    )?;
    let result = force_outcome_bool(evaluator, outcome)?;
    #[cfg(feature = "compat-tracing")]
    evaluator.record_ord_comparator_invocation(greater, evidence, &current.0, &next.0, result)?;
    Ok(result)
}

fn map_from_ordered_entries(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    size: usize,
    left: PersistentTree<MapEntry>,
    items: &[MapEntry],
    index: usize,
) -> RuntimeResult<PersistentTree<MapEntry>> {
    if index >= items.len() {
        return Ok(left);
    }
    if index + 1 == items.len() {
        return Ok(PersistentTree {
            root: Some(insert_max(items[index].clone(), left.root)),
        });
    }
    if map_entries_not_ordered(evaluator, evidence, &items[index], items.get(index + 1))? {
        return map_insert_entries(evaluator, evidence, left, &items[index..]);
    }

    let created = map_create_entries(evaluator, evidence, size, items, index + 1)?;
    let linked = PersistentTree {
        root: Some(link(items[index].clone(), left.root, created.root)),
    };
    if created.unordered {
        map_insert_entries(evaluator, evidence, linked, &items[created.next..])
    } else {
        map_from_ordered_entries(
            evaluator,
            evidence,
            size.saturating_mul(2),
            linked,
            items,
            created.next,
        )
    }
}

struct MapCreateResult {
    root: Option<Arc<TreeNode<MapEntry>>>,
    next: usize,
    unordered: bool,
}

fn map_create_entries(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    size: usize,
    items: &[MapEntry],
    index: usize,
) -> RuntimeResult<MapCreateResult> {
    if index >= items.len() {
        return Ok(MapCreateResult {
            root: None,
            next: index,
            unordered: false,
        });
    }
    if size == 1 {
        return Ok(MapCreateResult {
            root: Some(TreeNode::new(items[index].clone(), None, None)),
            next: index + 1,
            unordered: map_entries_not_ordered(
                evaluator,
                evidence,
                &items[index],
                items.get(index + 1),
            )?,
        });
    }

    let left = map_create_entries(evaluator, evidence, size >> 1, items, index)?;
    if left.unordered || left.next >= items.len() {
        return Ok(left);
    }
    let pivot = left.next;
    if pivot + 1 == items.len() {
        return Ok(MapCreateResult {
            root: Some(insert_max(items[pivot].clone(), left.root)),
            next: pivot + 1,
            unordered: false,
        });
    }
    if map_entries_not_ordered(evaluator, evidence, &items[pivot], items.get(pivot + 1))? {
        return Ok(MapCreateResult {
            root: left.root,
            next: pivot,
            unordered: true,
        });
    }

    let right = map_create_entries(evaluator, evidence, size >> 1, items, pivot + 1)?;
    Ok(MapCreateResult {
        root: Some(link(items[pivot].clone(), left.root, right.root)),
        next: right.next,
        unordered: right.unordered,
    })
}

fn insert_max<T: Clone>(item: T, tree: Option<Arc<TreeNode<T>>>) -> Arc<TreeNode<T>> {
    let Some(tree) = tree else {
        return TreeNode::new(item, None, None);
    };
    balance_right(TreeNode::new(
        tree.item.clone(),
        tree.left.clone(),
        Some(insert_max(item, tree.right.clone())),
    ))
}

fn map_to_list(evaluator: &mut Evaluator, map: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    let mut pairs = entries
        .iter()
        .map(|(key, item)| {
            Thunk::evaluated(Value::Tuple([Arc::clone(key), Arc::clone(item)].into()))
        })
        .collect::<Vec<_>>();
    if crate::semantic_mutant_active("collection-stable-order-reversal") {
        pairs.reverse();
    }
    Ok(ForceOutcome::Alias(list_from_values(pairs)))
}

fn map_lookup(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    key: &ThunkRef,
    map: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    let found = entries
        .0
        .find(|entry| compare_keys_with_ord_adapters(evaluator, evidence, key, &entry.0))?
        .map(|entry| Arc::clone(&entry.1));
    Ok(collection(Value::Maybe(found)))
}

fn map_insert(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    key: &ThunkRef,
    item: &ThunkRef,
    map: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    let entries = entries
        .0
        .insert((Arc::clone(key), Arc::clone(item)), &mut |left, right| {
            compare_keys_with_ord_adapters(evaluator, evidence, &left.0, &right.0)
        })?;
    Ok(collection(Value::Map(Arc::new(OrderedMap(entries)))))
}

fn map_delete(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    key: &ThunkRef,
    map: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    let entries = entries
        .0
        .remove(&mut |entry| compare_keys_with_ord_adapters(evaluator, evidence, key, &entry.0))?;
    Ok(collection(Value::Map(Arc::new(OrderedMap(entries)))))
}

fn map_size(evaluator: &mut Evaluator, map: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let size = force_map(evaluator, map)?.len();
    Ok(collection(Value::Int(
        i64::try_from(size).unwrap_or(i64::MAX),
    )))
}

fn map_filter(
    evaluator: &mut Evaluator,
    predicate: &ThunkRef,
    map: &ThunkRef,
    with_key: bool,
) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    let mut filtered = Vec::new();
    for (key, item) in entries.iter() {
        let application = map_filter_callback(evaluator, predicate, key, item, with_key);
        if evaluator.force_bool(&application)? {
            filtered.push((Arc::clone(key), Arc::clone(item)));
        }
    }
    Ok(collection(Value::Map(Arc::new(OrderedMap::from_sorted(
        &filtered,
    )))))
}

#[cfg(feature = "compat-tracing")]
fn map_filter_callback(
    evaluator: &Evaluator,
    predicate: &ThunkRef,
    key: &ThunkRef,
    item: &ThunkRef,
    with_key: bool,
) -> ThunkRef {
    let arguments = if with_key {
        vec![Arc::clone(key), Arc::clone(item)]
    } else {
        vec![Arc::clone(item)]
    };
    evaluator
        .callback_application(Arc::clone(predicate), &arguments, 0, "predicate")
        .unwrap_or_else(Thunk::failed_without_admission)
}

#[cfg(not(feature = "compat-tracing"))]
fn map_filter_callback(
    _evaluator: &Evaluator,
    predicate: &ThunkRef,
    key: &ThunkRef,
    item: &ThunkRef,
    with_key: bool,
) -> ThunkRef {
    if with_key {
        apply(&apply(predicate, key), item)
    } else {
        apply(predicate, item)
    }
}

fn map_quantifier(
    evaluator: &mut Evaluator,
    predicate: &ThunkRef,
    map: &ThunkRef,
    all: bool,
) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    for (_, item) in entries.iter() {
        let application = map_quantifier_callback(evaluator, predicate, item);
        if evaluator.force_bool(&application)? != all {
            return Ok(collection(Value::Bool(!all)));
        }
    }
    Ok(collection(Value::Bool(all)))
}

#[cfg(feature = "compat-tracing")]
fn map_quantifier_callback(
    evaluator: &Evaluator,
    predicate: &ThunkRef,
    item: &ThunkRef,
) -> ThunkRef {
    evaluator
        .callback_application(Arc::clone(predicate), &[Arc::clone(item)], 0, "predicate")
        .unwrap_or_else(Thunk::failed_without_admission)
}

#[cfg(not(feature = "compat-tracing"))]
fn map_quantifier_callback(
    _evaluator: &Evaluator,
    predicate: &ThunkRef,
    item: &ThunkRef,
) -> ThunkRef {
    apply(predicate, item)
}

fn map_insert_with(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    arguments: &[ThunkRef],
) -> RuntimeResult<ForceOutcome> {
    fn insert_node(
        evaluator: &mut Evaluator,
        evidence: ClassEvidence,
        function: &ThunkRef,
        key: &ThunkRef,
        item: &ThunkRef,
        node: Option<&Arc<TreeNode<MapEntry>>>,
    ) -> RuntimeResult<Arc<TreeNode<MapEntry>>> {
        let Some(node) = node else {
            return Ok(TreeNode::new(
                (Arc::clone(key), Arc::clone(item)),
                None,
                None,
            ));
        };
        match compare_keys_with_ord_adapters(evaluator, evidence, key, &node.item.0)? {
            Ordering::Less => Ok(balance_left(TreeNode::new(
                node.item.clone(),
                Some(insert_node(
                    evaluator,
                    evidence,
                    function,
                    key,
                    item,
                    node.left.as_ref(),
                )?),
                node.right.clone(),
            ))),
            Ordering::Equal => Ok(TreeNode::new(
                (
                    Arc::clone(key),
                    map_collision_callback(evaluator, function, item, &node.item.1),
                ),
                node.left.clone(),
                node.right.clone(),
            )),
            Ordering::Greater => Ok(balance_right(TreeNode::new(
                node.item.clone(),
                node.left.clone(),
                Some(insert_node(
                    evaluator,
                    evidence,
                    function,
                    key,
                    item,
                    node.right.as_ref(),
                )?),
            ))),
        }
    }

    let function = &arguments[0];
    let key = &arguments[1];
    let item = &arguments[2];
    let entries = force_map(evaluator, &arguments[3])?;
    let entries = PersistentTree {
        root: Some(insert_node(
            evaluator,
            evidence,
            function,
            key,
            item,
            entries.0.root.as_ref(),
        )?),
    };
    Ok(collection(Value::Map(Arc::new(OrderedMap(entries)))))
}

fn map_adjust(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    arguments: &[ThunkRef],
) -> RuntimeResult<ForceOutcome> {
    fn adjust_node(
        evaluator: &mut Evaluator,
        evidence: ClassEvidence,
        function: &ThunkRef,
        key: &ThunkRef,
        node: Option<&Arc<TreeNode<MapEntry>>>,
    ) -> RuntimeResult<Option<Arc<TreeNode<MapEntry>>>> {
        let Some(node) = node else {
            return Ok(None);
        };
        match compare_keys_with_ord_adapters(evaluator, evidence, key, &node.item.0)? {
            Ordering::Less => Ok(Some(TreeNode::new(
                node.item.clone(),
                adjust_node(evaluator, evidence, function, key, node.left.as_ref())?,
                node.right.clone(),
            ))),
            Ordering::Equal => Ok(Some(TreeNode::new(
                (
                    Arc::clone(&node.item.0),
                    map_value_callback(evaluator, function, &node.item.1),
                ),
                node.left.clone(),
                node.right.clone(),
            ))),
            Ordering::Greater => Ok(Some(TreeNode::new(
                node.item.clone(),
                node.left.clone(),
                adjust_node(evaluator, evidence, function, key, node.right.as_ref())?,
            ))),
        }
    }

    let function = &arguments[0];
    let key = &arguments[1];
    let entries = force_map(evaluator, &arguments[2])?;
    let entries = PersistentTree {
        root: adjust_node(evaluator, evidence, function, key, entries.0.root.as_ref())?,
    };
    Ok(collection(Value::Map(Arc::new(OrderedMap(entries)))))
}

fn map_union_with(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    arguments: &[ThunkRef],
) -> RuntimeResult<ForceOutcome> {
    let function = &arguments[0];
    let left = force_map(evaluator, &arguments[1])?;
    let right = force_map(evaluator, &arguments[2])?;
    let entries = map_union_entries(evaluator, evidence, function, &left.0, &right.0)?;
    Ok(collection(Value::Map(Arc::new(OrderedMap(entries)))))
}

fn map_union_entries(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    function: &ThunkRef,
    left: &PersistentTree<MapEntry>,
    right: &PersistentTree<MapEntry>,
) -> RuntimeResult<PersistentTree<MapEntry>> {
    let Some(right_root) = right.root.as_ref() else {
        return Ok(left.clone());
    };
    if right_root.len == 1 {
        return map_insert_right_entry(evaluator, evidence, function, &right_root.item, left);
    }
    let Some(left_root) = left.root.as_ref() else {
        return Ok(right.clone());
    };
    if left_root.len == 1 {
        return map_insert_left_entry(evaluator, evidence, function, &left_root.item, right);
    }

    let (right_left, matching, right_right) = right.split_lookup(&mut |item| {
        compare_keys_with_ord_adapters(evaluator, evidence, &left_root.item.0, &item.0)
    })?;
    let item = matching.map_or_else(
        || left_root.item.clone(),
        |right_item| {
            (
                Arc::clone(&left_root.item.0),
                map_collision_callback(evaluator, function, &left_root.item.1, &right_item.1),
            )
        },
    );
    let left_branch = PersistentTree {
        root: left_root.left.clone(),
    };
    let right_branch = PersistentTree {
        root: left_root.right.clone(),
    };
    let merged_left = map_union_entries(evaluator, evidence, function, &left_branch, &right_left)?;
    let merged_right =
        map_union_entries(evaluator, evidence, function, &right_branch, &right_right)?;
    Ok(PersistentTree {
        root: Some(link(item, merged_left.root, merged_right.root)),
    })
}

fn map_insert_left_entry(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    function: &ThunkRef,
    item: &MapEntry,
    tree: &PersistentTree<MapEntry>,
) -> RuntimeResult<PersistentTree<MapEntry>> {
    map_insert_union_entry(evaluator, evidence, function, item, tree, true)
}

fn map_insert_right_entry(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    function: &ThunkRef,
    item: &MapEntry,
    tree: &PersistentTree<MapEntry>,
) -> RuntimeResult<PersistentTree<MapEntry>> {
    map_insert_union_entry(evaluator, evidence, function, item, tree, false)
}

fn map_insert_union_entry(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    function: &ThunkRef,
    item: &MapEntry,
    tree: &PersistentTree<MapEntry>,
    item_is_left: bool,
) -> RuntimeResult<PersistentTree<MapEntry>> {
    fn insert_node(
        evaluator: &mut Evaluator,
        evidence: ClassEvidence,
        function: &ThunkRef,
        item: &MapEntry,
        node: Option<&Arc<TreeNode<MapEntry>>>,
        item_is_left: bool,
    ) -> RuntimeResult<Arc<TreeNode<MapEntry>>> {
        let Some(node) = node else {
            return Ok(TreeNode::new(item.clone(), None, None));
        };
        match compare_keys_with_ord_adapters(evaluator, evidence, &item.0, &node.item.0)? {
            Ordering::Less => Ok(balance_left(TreeNode::new(
                node.item.clone(),
                Some(insert_node(
                    evaluator,
                    evidence,
                    function,
                    item,
                    node.left.as_ref(),
                    item_is_left,
                )?),
                node.right.clone(),
            ))),
            Ordering::Greater => Ok(balance_right(TreeNode::new(
                node.item.clone(),
                node.left.clone(),
                Some(insert_node(
                    evaluator,
                    evidence,
                    function,
                    item,
                    node.right.as_ref(),
                    item_is_left,
                )?),
            ))),
            Ordering::Equal => {
                let (key, left_value, right_value) = if item_is_left {
                    (&item.0, &item.1, &node.item.1)
                } else {
                    (&node.item.0, &node.item.1, &item.1)
                };
                Ok(TreeNode::new(
                    (
                        Arc::clone(key),
                        map_collision_callback(evaluator, function, left_value, right_value),
                    ),
                    node.left.clone(),
                    node.right.clone(),
                ))
            }
        }
    }

    Ok(PersistentTree {
        root: Some(insert_node(
            evaluator,
            evidence,
            function,
            item,
            tree.root.as_ref(),
            item_is_left,
        )?),
    })
}

#[cfg(feature = "compat-tracing")]
fn map_collision_callback(
    evaluator: &Evaluator,
    function: &ThunkRef,
    left: &ThunkRef,
    right: &ThunkRef,
) -> ThunkRef {
    evaluator
        .callback_application(
            Arc::clone(function),
            &[Arc::clone(left), Arc::clone(right)],
            0,
            "collision",
        )
        .unwrap_or_else(Thunk::failed_without_admission)
}

#[cfg(not(feature = "compat-tracing"))]
fn map_collision_callback(
    _evaluator: &Evaluator,
    function: &ThunkRef,
    left: &ThunkRef,
    right: &ThunkRef,
) -> ThunkRef {
    apply(&apply(function, left), right)
}

fn map_values(
    evaluator: &mut Evaluator,
    function: &ThunkRef,
    map: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    let mapped = entries
        .iter()
        .map(|(key, item)| {
            (
                Arc::clone(key),
                map_value_callback(evaluator, function, item),
            )
        })
        .collect::<Vec<_>>();
    Ok(collection(Value::Map(Arc::new(OrderedMap::from_sorted(
        &mapped,
    )))))
}

#[cfg(feature = "compat-tracing")]
fn map_value_callback(evaluator: &Evaluator, function: &ThunkRef, item: &ThunkRef) -> ThunkRef {
    evaluator
        .callback_application(Arc::clone(function), &[Arc::clone(item)], 0, "value")
        .unwrap_or_else(Thunk::failed_without_admission)
}

#[cfg(not(feature = "compat-tracing"))]
fn map_value_callback(_evaluator: &Evaluator, function: &ThunkRef, item: &ThunkRef) -> ThunkRef {
    apply(function, item)
}

fn map_keys(evaluator: &mut Evaluator, map: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    Ok(ForceOutcome::Alias(list_from_values(
        entries.iter().map(|(key, _)| Arc::clone(key)).collect(),
    )))
}

fn map_elems(evaluator: &mut Evaluator, map: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    Ok(ForceOutcome::Alias(list_from_values(
        entries.iter().map(|(_, item)| Arc::clone(item)).collect(),
    )))
}

#[cfg(not(feature = "compat-tracing"))]
fn apply(function: &ThunkRef, argument: &ThunkRef) -> ThunkRef {
    Thunk::suspended(Suspension::Apply {
        function: Arc::clone(function),
        argument: Arc::clone(argument),
    })
}

fn set_from_list(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    list: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let input = evaluator.force_list_elements(list)?;
    let elements = set_tree_from_list(evaluator, evidence, &input)?;
    Ok(collection(Value::Set(Arc::new(OrderedSet(elements)))))
}

fn set_tree_from_list(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    input: &[ThunkRef],
) -> RuntimeResult<PersistentTree<ThunkRef>> {
    let Some(first) = input.first() else {
        return Ok(PersistentTree::default());
    };
    let initial = PersistentTree::singleton(Arc::clone(first));
    if input.len() == 1 {
        return Ok(initial);
    }
    if set_list_not_ordered(evaluator, evidence, input, 0)? {
        return set_tree_insert_remaining(evaluator, evidence, initial, input, 1);
    }
    set_tree_from_ordered_prefix(evaluator, evidence, input, 1, initial, 1)
}

fn set_tree_from_ordered_prefix(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    input: &[ThunkRef],
    mut index: usize,
    mut left: PersistentTree<ThunkRef>,
    mut size: usize,
) -> RuntimeResult<PersistentTree<ThunkRef>> {
    loop {
        if index >= input.len() {
            return Ok(left);
        }
        if index + 1 == input.len() {
            return Ok(PersistentTree {
                root: Some(set_insert_max(left.root, Arc::clone(&input[index]))),
            });
        }
        if set_list_not_ordered(evaluator, evidence, input, index)? {
            return set_tree_insert_remaining(evaluator, evidence, left, input, index);
        }
        let pivot = Arc::clone(&input[index]);
        let created = set_tree_create(evaluator, evidence, input, index + 1, size)?;
        left = PersistentTree {
            root: Some(link(pivot, left.root, created.tree)),
        };
        if created.unordered {
            return set_tree_insert_remaining(evaluator, evidence, left, input, created.next);
        }
        index = created.next;
        size = size.saturating_mul(2);
    }
}

struct SetCreateResult {
    tree: Option<Arc<TreeNode<ThunkRef>>>,
    next: usize,
    unordered: bool,
}

fn set_tree_create(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    input: &[ThunkRef],
    index: usize,
    size: usize,
) -> RuntimeResult<SetCreateResult> {
    if index >= input.len() {
        return Ok(SetCreateResult {
            tree: None,
            next: index,
            unordered: false,
        });
    }
    if size == 1 {
        return Ok(SetCreateResult {
            tree: Some(TreeNode::new(Arc::clone(&input[index]), None, None)),
            next: index + 1,
            unordered: set_list_not_ordered(evaluator, evidence, input, index)?,
        });
    }
    let half = size / 2;
    let left = set_tree_create(evaluator, evidence, input, index, half)?;
    if left.unordered || left.next >= input.len() {
        return Ok(left);
    }
    if left.next + 1 == input.len() {
        return Ok(SetCreateResult {
            tree: Some(set_insert_max(left.tree, Arc::clone(&input[left.next]))),
            next: input.len(),
            unordered: false,
        });
    }
    if set_list_not_ordered(evaluator, evidence, input, left.next)? {
        return Ok(SetCreateResult {
            tree: left.tree,
            next: left.next,
            unordered: true,
        });
    }
    let pivot = Arc::clone(&input[left.next]);
    let right = set_tree_create(evaluator, evidence, input, left.next + 1, half)?;
    Ok(SetCreateResult {
        tree: Some(link(pivot, left.tree, right.tree)),
        next: right.next,
        unordered: right.unordered,
    })
}

fn set_list_not_ordered(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    input: &[ThunkRef],
    index: usize,
) -> RuntimeResult<bool> {
    let Some(next) = input.get(index + 1) else {
        return Ok(false);
    };
    let current = &input[index];
    if evaluator.equal_values(current, next)? {
        return Ok(true);
    }
    let greater = hell_builtins::lookup("Ord.gt")
        .expect("Ord.gt is registry-backed")
        .id;
    let result = evaluator.apply_native(
        greater,
        &[Arc::clone(current), Arc::clone(next)],
        Some(evidence),
    )?;
    let result = force_outcome_bool(evaluator, result)?;
    #[cfg(feature = "compat-tracing")]
    evaluator.record_ord_comparator_invocation(greater, evidence, current, next, result)?;
    Ok(result)
}

fn set_tree_insert_remaining(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    mut tree: PersistentTree<ThunkRef>,
    input: &[ThunkRef],
    index: usize,
) -> RuntimeResult<PersistentTree<ThunkRef>> {
    for element in &input[index..] {
        tree = set_insert_replacing(evaluator, evidence, &tree, element)?;
    }
    Ok(tree)
}

fn set_insert_max<T: Clone>(tree: Option<Arc<TreeNode<T>>>, item: T) -> Arc<TreeNode<T>> {
    match tree {
        None => TreeNode::new(item, None, None),
        Some(node) => balance_right(TreeNode::new(
            node.item.clone(),
            node.left.clone(),
            Some(set_insert_max(node.right.clone(), item)),
        )),
    }
}

fn set_to_list(evaluator: &mut Evaluator, set: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    Ok(ForceOutcome::Alias(list_from_values(
        force_set(evaluator, set)?.iter().cloned().collect(),
    )))
}

fn set_insert(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    element: &ThunkRef,
    set: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let elements = force_set(evaluator, set)?;
    let elements = set_insert_replacing(evaluator, evidence, &elements.0, element)?;
    Ok(collection(Value::Set(Arc::new(OrderedSet(elements)))))
}

fn set_insert_replacing(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    tree: &PersistentTree<ThunkRef>,
    element: &ThunkRef,
) -> RuntimeResult<PersistentTree<ThunkRef>> {
    fn insert_node(
        evaluator: &mut Evaluator,
        evidence: ClassEvidence,
        node: Option<&Arc<TreeNode<ThunkRef>>>,
        element: &ThunkRef,
    ) -> RuntimeResult<Arc<TreeNode<ThunkRef>>> {
        let Some(node) = node else {
            return Ok(TreeNode::new(Arc::clone(element), None, None));
        };
        match compare_keys_with_ord_adapters(evaluator, evidence, element, &node.item)? {
            Ordering::Less => {
                let left = insert_node(evaluator, evidence, node.left.as_ref(), element)?;
                if same_tree_root(Some(&left), node.left.as_ref()) {
                    Ok(Arc::clone(node))
                } else {
                    Ok(balance_left(TreeNode::new(
                        Arc::clone(&node.item),
                        Some(left),
                        node.right.clone(),
                    )))
                }
            }
            Ordering::Equal if Arc::ptr_eq(element, &node.item) => Ok(Arc::clone(node)),
            Ordering::Equal => Ok(TreeNode::new(
                Arc::clone(element),
                node.left.clone(),
                node.right.clone(),
            )),
            Ordering::Greater => {
                let right = insert_node(evaluator, evidence, node.right.as_ref(), element)?;
                if same_tree_root(Some(&right), node.right.as_ref()) {
                    Ok(Arc::clone(node))
                } else {
                    Ok(balance_right(TreeNode::new(
                        Arc::clone(&node.item),
                        node.left.clone(),
                        Some(right),
                    )))
                }
            }
        }
    }

    Ok(PersistentTree {
        root: Some(insert_node(
            evaluator,
            evidence,
            tree.root.as_ref(),
            element,
        )?),
    })
}

fn set_member(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    element: &ThunkRef,
    set: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let elements = force_set(evaluator, set)?;
    Ok(collection(Value::Bool(
        elements
            .0
            .find(|existing| {
                compare_keys_with_ord_adapters(evaluator, evidence, element, existing)
            })?
            .is_some(),
    )))
}

fn set_delete(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    element: &ThunkRef,
    set: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let elements = force_set(evaluator, set)?;
    let elements = elements.0.remove(&mut |existing| {
        compare_keys_with_ord_adapters(evaluator, evidence, element, existing)
    })?;
    Ok(collection(Value::Set(Arc::new(OrderedSet(elements)))))
}

#[derive(Clone, Copy)]
enum SetMerge {
    Union,
    Difference,
    Intersection,
}

fn set_merge(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    left: &ThunkRef,
    right: &ThunkRef,
    operation: SetMerge,
) -> RuntimeResult<ForceOutcome> {
    let left = force_set(evaluator, left)?;
    let right = force_set(evaluator, right)?;
    let output = match operation {
        SetMerge::Union => set_union_tree(evaluator, evidence, &left.0, &right.0)?,
        SetMerge::Difference => set_difference_tree(evaluator, evidence, &left.0, &right.0)?,
        SetMerge::Intersection => set_intersection_tree(evaluator, evidence, &left.0, &right.0)?,
    };
    Ok(collection(Value::Set(Arc::new(OrderedSet(output)))))
}

fn set_union_tree(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    left: &PersistentTree<ThunkRef>,
    right: &PersistentTree<ThunkRef>,
) -> RuntimeResult<PersistentTree<ThunkRef>> {
    let Some(left_root) = left.root.as_ref() else {
        return Ok(right.clone());
    };
    let Some(right_root) = right.root.as_ref() else {
        return Ok(left.clone());
    };
    if right_root.len == 1 {
        return set_insert_preserving_existing(evaluator, evidence, left, &right_root.item);
    }
    if left_root.len == 1 {
        return set_insert_replacing(evaluator, evidence, right, &left_root.item);
    }
    let (right_left, _, right_right) = right.split_lookup(&mut |existing| {
        compare_keys_with_ord_adapters(evaluator, evidence, &left_root.item, existing)
    })?;
    let left_left = PersistentTree {
        root: left_root.left.clone(),
    };
    let left_right = PersistentTree {
        root: left_root.right.clone(),
    };
    let joined_left = set_union_tree(evaluator, evidence, &left_left, &right_left)?;
    let joined_right = set_union_tree(evaluator, evidence, &left_right, &right_right)?;
    if same_tree_root(joined_left.root.as_ref(), left_root.left.as_ref())
        && same_tree_root(joined_right.root.as_ref(), left_root.right.as_ref())
    {
        return Ok(left.clone());
    }
    Ok(PersistentTree {
        root: Some(link(
            Arc::clone(&left_root.item),
            joined_left.root,
            joined_right.root,
        )),
    })
}

fn set_insert_preserving_existing(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    tree: &PersistentTree<ThunkRef>,
    element: &ThunkRef,
) -> RuntimeResult<PersistentTree<ThunkRef>> {
    fn insert_node(
        evaluator: &mut Evaluator,
        evidence: ClassEvidence,
        node: Option<&Arc<TreeNode<ThunkRef>>>,
        element: &ThunkRef,
    ) -> RuntimeResult<Arc<TreeNode<ThunkRef>>> {
        let Some(node) = node else {
            return Ok(TreeNode::new(Arc::clone(element), None, None));
        };
        match compare_keys_with_ord_adapters(evaluator, evidence, element, &node.item)? {
            Ordering::Less => {
                let left = insert_node(evaluator, evidence, node.left.as_ref(), element)?;
                if same_tree_root(Some(&left), node.left.as_ref()) {
                    Ok(Arc::clone(node))
                } else {
                    Ok(balance_left(TreeNode::new(
                        Arc::clone(&node.item),
                        Some(left),
                        node.right.clone(),
                    )))
                }
            }
            Ordering::Equal => Ok(Arc::clone(node)),
            Ordering::Greater => {
                let right = insert_node(evaluator, evidence, node.right.as_ref(), element)?;
                if same_tree_root(Some(&right), node.right.as_ref()) {
                    Ok(Arc::clone(node))
                } else {
                    Ok(balance_right(TreeNode::new(
                        Arc::clone(&node.item),
                        node.left.clone(),
                        Some(right),
                    )))
                }
            }
        }
    }
    Ok(PersistentTree {
        root: Some(insert_node(
            evaluator,
            evidence,
            tree.root.as_ref(),
            element,
        )?),
    })
}

fn set_difference_tree(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    left: &PersistentTree<ThunkRef>,
    right: &PersistentTree<ThunkRef>,
) -> RuntimeResult<PersistentTree<ThunkRef>> {
    let Some(right_root) = right.root.as_ref() else {
        return Ok(left.clone());
    };
    if left.root.is_none() {
        return Ok(PersistentTree::default());
    }
    let (left_lower, _, left_upper) = left.split_lookup(&mut |existing| {
        compare_keys_with_ord_adapters(evaluator, evidence, &right_root.item, existing)
    })?;
    let right_lower = PersistentTree {
        root: right_root.left.clone(),
    };
    let right_upper = PersistentTree {
        root: right_root.right.clone(),
    };
    let difference_lower = set_difference_tree(evaluator, evidence, &left_lower, &right_lower)?;
    let difference_upper = set_difference_tree(evaluator, evidence, &left_upper, &right_upper)?;
    if difference_lower.len() + difference_upper.len() == left.len() {
        return Ok(left.clone());
    }
    Ok(PersistentTree {
        root: merge_nodes(difference_lower.root, difference_upper.root),
    })
}

fn set_intersection_tree(
    evaluator: &mut Evaluator,
    evidence: ClassEvidence,
    left: &PersistentTree<ThunkRef>,
    right: &PersistentTree<ThunkRef>,
) -> RuntimeResult<PersistentTree<ThunkRef>> {
    let Some(left_root) = left.root.as_ref() else {
        return Ok(PersistentTree::default());
    };
    if right.root.is_none() {
        return Ok(PersistentTree::default());
    }
    let (right_lower, found, right_upper) = right.split_lookup(&mut |existing| {
        compare_keys_with_ord_adapters(evaluator, evidence, &left_root.item, existing)
    })?;
    let left_lower = PersistentTree {
        root: left_root.left.clone(),
    };
    let left_upper = PersistentTree {
        root: left_root.right.clone(),
    };
    let intersection_lower = set_intersection_tree(evaluator, evidence, &left_lower, &right_lower)?;
    let intersection_upper = set_intersection_tree(evaluator, evidence, &left_upper, &right_upper)?;
    let root = if found.is_some() {
        if same_tree_root(intersection_lower.root.as_ref(), left_root.left.as_ref())
            && same_tree_root(intersection_upper.root.as_ref(), left_root.right.as_ref())
        {
            return Ok(left.clone());
        }
        Some(link(
            Arc::clone(&left_root.item),
            intersection_lower.root,
            intersection_upper.root,
        ))
    } else {
        merge_nodes(intersection_lower.root, intersection_upper.root)
    };
    Ok(PersistentTree { root })
}

fn same_tree_root<T>(left: Option<&Arc<TreeNode<T>>>, right: Option<&Arc<TreeNode<T>>>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        _ => false,
    }
}

fn merge_nodes<T: Clone>(
    left: Option<Arc<TreeNode<T>>>,
    right: Option<Arc<TreeNode<T>>>,
) -> Option<Arc<TreeNode<T>>> {
    let (Some(left_root), Some(right_root)) = (&left, &right) else {
        return left.or(right);
    };
    if SIZE_BALANCE_DELTA.saturating_mul(left_root.len) < right_root.len {
        return Some(balance_left(TreeNode::new(
            right_root.item.clone(),
            merge_nodes(left, right_root.left.clone()),
            right_root.right.clone(),
        )));
    }
    if SIZE_BALANCE_DELTA.saturating_mul(right_root.len) < left_root.len {
        return Some(balance_right(TreeNode::new(
            left_root.item.clone(),
            left_root.left.clone(),
            merge_nodes(left_root.right.clone(), right),
        )));
    }
    glue(left, right)
}

fn set_size(evaluator: &mut Evaluator, set: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let size = force_set(evaluator, set)?.len();
    Ok(collection(Value::Int(
        i64::try_from(size).unwrap_or(i64::MAX),
    )))
}

#[cfg(test)]
mod tests {
    use super::{PersistentTree, TreeNode, apply_native};
    use crate::{Evaluator, Thunk, Value};
    use hell_builtins::{TypeClass, lookup};
    use hell_compiler::{CompilerSession, compile_source};
    use hell_core::{ClassEvidence, CoreKind, ExecutableProgram, InstanceEvidencePlanId};
    use std::sync::Arc;

    fn singleton_evidence(program: &ExecutableProgram, builtin: &str) -> ClassEvidence {
        let builtin = lookup(builtin).expect("singleton builtin exists").id;
        program
            .nodes()
            .iter()
            .find_map(|node| match node.kind {
                CoreKind::Builtin {
                    builtin: candidate,
                    evidence,
                } if candidate == builtin => evidence,
                _ => None,
            })
            .expect("compiled singleton retains Ord evidence")
    }

    fn assert_size_balanced<T>(node: Option<&Arc<TreeNode<T>>>) -> usize {
        let Some(node) = node else {
            return 0;
        };
        let left = assert_size_balanced(node.left.as_ref());
        let right = assert_size_balanced(node.right.as_ref());
        assert_eq!(node.len, left + right + 1);
        if left + right > 1 {
            assert!(left <= 3 * right, "left-heavy node violates delta=3");
            assert!(right <= 3 * left, "right-heavy node violates delta=3");
        }
        node.len
    }

    #[test]
    fn persistent_tree_is_balanced_and_shares_untouched_branches() {
        let mut tree = PersistentTree::default();
        for value in 0_i32..1_024 {
            tree = tree
                .insert(value, &mut |left, right| Ok(left.cmp(right)))
                .expect("ordered insertion succeeds");
        }
        assert_eq!(tree.len(), 1_024);
        assert_eq!(assert_size_balanced(tree.root.as_ref()), 1_024);

        let original_root = tree.root.as_ref().expect("tree is populated");
        let original_left = original_root.left.as_ref().expect("tree has a left branch");
        let extended = tree
            .insert(2_048, &mut |left, right| Ok(left.cmp(right)))
            .expect("persistent insertion succeeds");
        let extended_root = extended.root.as_ref().expect("tree remains populated");
        assert_eq!(assert_size_balanced(extended.root.as_ref()), 1_025);
        assert!(Arc::ptr_eq(
            original_left,
            extended_root
                .left
                .as_ref()
                .expect("left branch remains present")
        ));
        assert_eq!(tree.len(), 1_024);
        assert_eq!(extended.len(), 1_025);

        let removed = extended
            .remove(&mut |existing| Ok(2_048_i32.cmp(existing)))
            .expect("persistent removal succeeds");
        assert_eq!(assert_size_balanced(removed.root.as_ref()), 1_024);
        assert_eq!(
            removed.iter().copied().collect::<Vec<_>>(),
            (0..1_024).collect::<Vec<_>>()
        );
        assert_eq!(
            removed
                .find(|existing| Ok(512_i32.cmp(existing)))
                .expect("lookup succeeds"),
            Some(&512)
        );
        assert!(
            removed
                .find(|existing| Ok(4_096_i32.cmp(existing)))
                .expect("missing lookup succeeds")
                .is_none()
        );
    }

    #[test]
    fn constrained_singletons_reject_missing_wrong_class_and_corrupt_ord_evidence() {
        let program = compile_source(
            &mut CompilerSession::upstream(),
            "collection-evidence.hell",
            concat!(
                "main = do\n",
                "  IO.print $ Map.size $ Map.singleton (1 :: Int) \"one\"\n",
                "  IO.print $ Set.size $ Set.singleton (1 :: Int)\n",
            ),
        )
        .expect("collection evidence fixture compiles");
        let executable = Arc::new(program.executable().clone());
        let map_evidence = singleton_evidence(&executable, "Map.singleton");
        let set_evidence = singleton_evidence(&executable, "Set.singleton");
        let key = Thunk::evaluated(Value::Int(1));
        let value = Thunk::evaluated(Value::Text(Arc::from("one")));

        let mut evaluator = Evaluator::new(Arc::clone(&executable));
        assert!(
            apply_native(
                "map_singleton",
                &[Arc::clone(&key), Arc::clone(&value)],
                Some(map_evidence),
                &mut evaluator,
            )
            .expect("Map.singleton is native")
            .is_ok()
        );
        assert!(
            apply_native(
                "set_singleton",
                &[Arc::clone(&key)],
                Some(set_evidence),
                &mut evaluator,
            )
            .expect("Set.singleton is native")
            .is_ok()
        );

        for (implementation, arguments, evidence) in [
            (
                "map_singleton",
                vec![Arc::clone(&key), Arc::clone(&value)],
                map_evidence,
            ),
            ("set_singleton", vec![Arc::clone(&key)], set_evidence),
        ] {
            let missing = apply_native(implementation, &arguments, None, &mut evaluator)
                .expect("singleton is native")
                .err()
                .expect("missing evidence must fail");
            assert!(missing.message.contains("without retained Ord evidence"));

            let wrong_class = ClassEvidence {
                class: TypeClass::Eq,
                ..evidence
            };
            let wrong_class = apply_native(
                implementation,
                &arguments,
                Some(wrong_class),
                &mut evaluator,
            )
            .expect("singleton is native")
            .err()
            .expect("wrong-class evidence must fail");
            assert!(wrong_class.message.contains("non-Ord class evidence"));

            let corrupt = ClassEvidence {
                plan: InstanceEvidencePlanId(u32::MAX),
                ..evidence
            };
            let corrupt = apply_native(implementation, &arguments, Some(corrupt), &mut evaluator)
                .expect("singleton is native")
                .err()
                .expect("corrupt evidence plan must fail");
            assert!(corrupt.message.contains("evidence plan disappeared"));
        }
    }
}
