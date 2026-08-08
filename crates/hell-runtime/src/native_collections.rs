//! Ordered `Map` and `Set` adapters over lazy runtime values.

use std::{cmp::Ordering, sync::Arc};

use crate::{
    Evaluator, ForceOutcome, RuntimeError, RuntimeResult, Suspension, Thunk, ThunkRef, Value,
    list_from_values,
};

type MapEntry = (ThunkRef, ThunkRef);

#[derive(Clone, Debug)]
struct TreeNode<T> {
    item: T,
    left: Option<Arc<Self>>,
    right: Option<Arc<Self>>,
    height: usize,
    len: usize,
}

impl<T: Clone> TreeNode<T> {
    fn new(item: T, left: Option<Arc<Self>>, right: Option<Arc<Self>>) -> Arc<Self> {
        Arc::new(Self {
            item,
            height: 1 + height(left.as_ref()).max(height(right.as_ref())),
            len: 1 + node_len(left.as_ref()) + node_len(right.as_ref()),
            left,
            right,
        })
    }
}

fn height<T>(node: Option<&Arc<TreeNode<T>>>) -> usize {
    node.map_or(0, |node| node.height)
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
                Ordering::Less => Ok(balance(TreeNode::new(
                    node.item.clone(),
                    Some(insert_node(node.left.as_ref(), item, compare)?),
                    node.right.clone(),
                ))),
                Ordering::Equal => Ok(TreeNode::new(item, node.left.clone(), node.right.clone())),
                Ordering::Greater => Ok(balance(TreeNode::new(
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
        fn take_min<T: Clone>(node: &Arc<TreeNode<T>>) -> (T, Option<Arc<TreeNode<T>>>) {
            let Some(left) = node.left.as_ref() else {
                return (node.item.clone(), node.right.clone());
            };
            let (item, new_left) = take_min(left);
            (
                item,
                Some(balance(TreeNode::new(
                    node.item.clone(),
                    new_left,
                    node.right.clone(),
                ))),
            )
        }

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
                Ordering::Less => Ok(Some(balance(TreeNode::new(
                    node.item.clone(),
                    remove_node(node.left.as_ref(), compare)?,
                    node.right.clone(),
                )))),
                Ordering::Greater => Ok(Some(balance(TreeNode::new(
                    node.item.clone(),
                    node.left.clone(),
                    remove_node(node.right.as_ref(), compare)?,
                )))),
                Ordering::Equal => match (&node.left, &node.right) {
                    (None, right) => Ok(right.clone()),
                    (left, None) => Ok(left.clone()),
                    (Some(_), Some(right)) => {
                        let (successor, new_right) = take_min(right);
                        Ok(Some(balance(TreeNode::new(
                            successor,
                            node.left.clone(),
                            new_right,
                        ))))
                    }
                },
            }
        }
        Ok(Self {
            root: remove_node(self.root.as_ref(), compare)?,
        })
    }
}

fn balance<T: Clone>(node: Arc<TreeNode<T>>) -> Arc<TreeNode<T>> {
    let balance =
        height(node.left.as_ref()).cast_signed() - height(node.right.as_ref()).cast_signed();
    if balance > 1 {
        let left = node
            .left
            .as_ref()
            .expect("left-heavy AVL node has a left child");
        let left = if height(left.left.as_ref()) < height(left.right.as_ref()) {
            rotate_left(left)
        } else {
            Arc::clone(left)
        };
        return rotate_right(&TreeNode::new(
            node.item.clone(),
            Some(left),
            node.right.clone(),
        ));
    }
    if balance < -1 {
        let right = node
            .right
            .as_ref()
            .expect("right-heavy AVL node has a right child");
        let right = if height(right.right.as_ref()) < height(right.left.as_ref()) {
            rotate_right(right)
        } else {
            Arc::clone(right)
        };
        return rotate_left(&TreeNode::new(
            node.item.clone(),
            node.left.clone(),
            Some(right),
        ));
    }
    node
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
    evaluator: &mut Evaluator,
) -> Option<RuntimeResult<ForceOutcome>> {
    Some(match implementation {
        "map_from_list" => map_from_list(evaluator, &arguments[0]),
        "map_to_list" => map_to_list(evaluator, &arguments[0]),
        "map_lookup" => map_lookup(evaluator, &arguments[0], &arguments[1]),
        "map_insert" => map_insert(evaluator, &arguments[0], &arguments[1], &arguments[2]),
        "map_delete" => map_delete(evaluator, &arguments[0], &arguments[1]),
        "map_singleton" => Ok(collection(Value::Map(Arc::new(OrderedMap::singleton(
            Arc::clone(&arguments[0]),
            Arc::clone(&arguments[1]),
        ))))),
        "map_size" => map_size(evaluator, &arguments[0]),
        "map_filter" => map_filter(evaluator, &arguments[0], &arguments[1], false),
        "map_filter_with_key" => map_filter(evaluator, &arguments[0], &arguments[1], true),
        "map_any" => map_quantifier(evaluator, &arguments[0], &arguments[1], false),
        "map_all" => map_quantifier(evaluator, &arguments[0], &arguments[1], true),
        "map_insert_with" => map_insert_with(evaluator, arguments),
        "map_adjust" => map_adjust(evaluator, arguments),
        "map_union_with" => map_union_with(evaluator, arguments),
        "map_map" => map_values(evaluator, &arguments[0], &arguments[1]),
        "map_keys" => map_keys(evaluator, &arguments[0]),
        "map_elems" => map_elems(evaluator, &arguments[0]),
        "set_from_list" => set_from_list(evaluator, &arguments[0]),
        "set_to_list" => set_to_list(evaluator, &arguments[0]),
        "set_insert" => set_insert(evaluator, &arguments[0], &arguments[1]),
        "set_member" => set_member(evaluator, &arguments[0], &arguments[1]),
        "set_delete" => set_delete(evaluator, &arguments[0], &arguments[1]),
        "set_union" => set_merge(evaluator, &arguments[0], &arguments[1], SetMerge::Union),
        "set_difference" => set_merge(
            evaluator,
            &arguments[0],
            &arguments[1],
            SetMerge::Difference,
        ),
        "set_intersection" => set_merge(
            evaluator,
            &arguments[0],
            &arguments[1],
            SetMerge::Intersection,
        ),
        "set_size" => set_size(evaluator, &arguments[0]),
        "set_singleton" => Ok(collection(Value::Set(Arc::new(OrderedSet::singleton(
            Arc::clone(&arguments[0]),
        ))))),
        _ => return None,
    })
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

fn compare_keys(
    evaluator: &mut Evaluator,
    left: &ThunkRef,
    right: &ThunkRef,
) -> RuntimeResult<Ordering> {
    if evaluator.equal_values(left, right)? {
        Ok(Ordering::Equal)
    } else if evaluator.less_values(left, right)? {
        Ok(Ordering::Less)
    } else {
        Ok(Ordering::Greater)
    }
}

fn map_from_list(evaluator: &mut Evaluator, list: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let pairs = evaluator.force_list_elements(list)?;
    let mut entries = PersistentTree::<MapEntry>::default();
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
        entries = entries.insert((Arc::clone(key), Arc::clone(item)), &mut |left, right| {
            compare_keys(evaluator, &left.0, &right.0)
        })?;
    }
    Ok(collection(Value::Map(Arc::new(OrderedMap(entries)))))
}

fn map_to_list(evaluator: &mut Evaluator, map: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    let pairs = entries
        .iter()
        .map(|(key, item)| {
            Thunk::evaluated(Value::Tuple([Arc::clone(key), Arc::clone(item)].into()))
        })
        .collect();
    Ok(ForceOutcome::Alias(list_from_values(pairs)))
}

fn map_lookup(
    evaluator: &mut Evaluator,
    key: &ThunkRef,
    map: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    let found = entries
        .0
        .find(|entry| compare_keys(evaluator, key, &entry.0))?
        .map(|entry| Arc::clone(&entry.1));
    Ok(collection(Value::Maybe(found)))
}

fn map_insert(
    evaluator: &mut Evaluator,
    key: &ThunkRef,
    item: &ThunkRef,
    map: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    let entries = entries
        .0
        .insert((Arc::clone(key), Arc::clone(item)), &mut |left, right| {
            compare_keys(evaluator, &left.0, &right.0)
        })?;
    Ok(collection(Value::Map(Arc::new(OrderedMap(entries)))))
}

fn map_delete(
    evaluator: &mut Evaluator,
    key: &ThunkRef,
    map: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    let entries = entries
        .0
        .remove(&mut |entry| compare_keys(evaluator, key, &entry.0))?;
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
        let application = if with_key {
            let with_key = apply(predicate, key);
            apply(&with_key, item)
        } else {
            apply(predicate, item)
        };
        if evaluator.force_bool(&application)? {
            filtered.push((Arc::clone(key), Arc::clone(item)));
        }
    }
    Ok(collection(Value::Map(Arc::new(OrderedMap::from_sorted(
        &filtered,
    )))))
}

fn map_quantifier(
    evaluator: &mut Evaluator,
    predicate: &ThunkRef,
    map: &ThunkRef,
    all: bool,
) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    for (_, item) in entries.iter() {
        if evaluator.force_bool(&apply(predicate, item))? != all {
            return Ok(collection(Value::Bool(!all)));
        }
    }
    Ok(collection(Value::Bool(all)))
}

fn map_insert_with(
    evaluator: &mut Evaluator,
    arguments: &[ThunkRef],
) -> RuntimeResult<ForceOutcome> {
    let function = &arguments[0];
    let key = &arguments[1];
    let item = &arguments[2];
    let entries = force_map(evaluator, &arguments[3])?;
    let value = entries
        .0
        .find(|entry| compare_keys(evaluator, key, &entry.0))?
        .map_or_else(
            || Arc::clone(item),
            |entry| apply(&apply(function, item), &entry.1),
        );
    let entries = entries
        .0
        .insert((Arc::clone(key), value), &mut |left, right| {
            compare_keys(evaluator, &left.0, &right.0)
        })?;
    Ok(collection(Value::Map(Arc::new(OrderedMap(entries)))))
}

fn map_adjust(evaluator: &mut Evaluator, arguments: &[ThunkRef]) -> RuntimeResult<ForceOutcome> {
    let function = &arguments[0];
    let key = &arguments[1];
    let entries = force_map(evaluator, &arguments[2])?;
    let Some(entry) = entries
        .0
        .find(|entry| compare_keys(evaluator, key, &entry.0))?
    else {
        return Ok(collection(Value::Map(entries)));
    };
    let replacement = (Arc::clone(&entry.0), apply(function, &entry.1));
    let entries = entries.0.insert(replacement, &mut |left, right| {
        compare_keys(evaluator, &left.0, &right.0)
    })?;
    Ok(collection(Value::Map(Arc::new(OrderedMap(entries)))))
}

fn map_union_with(
    evaluator: &mut Evaluator,
    arguments: &[ThunkRef],
) -> RuntimeResult<ForceOutcome> {
    let function = &arguments[0];
    let mut entries = force_map(evaluator, &arguments[1])?.0.clone();
    let right = force_map(evaluator, &arguments[2])?;
    for (right_key, right_item) in right.iter() {
        let item = entries
            .find(|entry| compare_keys(evaluator, right_key, &entry.0))?
            .map_or_else(
                || Arc::clone(right_item),
                |entry| apply(&apply(function, &entry.1), right_item),
            );
        entries = entries.insert((Arc::clone(right_key), item), &mut |left, right| {
            compare_keys(evaluator, &left.0, &right.0)
        })?;
    }
    Ok(collection(Value::Map(Arc::new(OrderedMap(entries)))))
}

fn map_values(
    evaluator: &mut Evaluator,
    function: &ThunkRef,
    map: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    let mapped = entries
        .iter()
        .map(|(key, item)| (Arc::clone(key), apply(function, item)))
        .collect::<Vec<_>>();
    Ok(collection(Value::Map(Arc::new(OrderedMap::from_sorted(
        &mapped,
    )))))
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

fn apply(function: &ThunkRef, argument: &ThunkRef) -> ThunkRef {
    Thunk::suspended(Suspension::Apply {
        function: Arc::clone(function),
        argument: Arc::clone(argument),
    })
}

fn set_from_list(evaluator: &mut Evaluator, list: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let input = evaluator.force_list_elements(list)?;
    let mut elements = PersistentTree::default();
    for element in input {
        elements = elements.insert(element, &mut |left, right| {
            compare_keys(evaluator, left, right)
        })?;
    }
    Ok(collection(Value::Set(Arc::new(OrderedSet(elements)))))
}

fn set_to_list(evaluator: &mut Evaluator, set: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    Ok(ForceOutcome::Alias(list_from_values(
        force_set(evaluator, set)?.iter().cloned().collect(),
    )))
}

fn set_insert(
    evaluator: &mut Evaluator,
    element: &ThunkRef,
    set: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let elements = force_set(evaluator, set)?;
    let elements = elements.0.insert(Arc::clone(element), &mut |left, right| {
        compare_keys(evaluator, left, right)
    })?;
    Ok(collection(Value::Set(Arc::new(OrderedSet(elements)))))
}

fn set_member(
    evaluator: &mut Evaluator,
    element: &ThunkRef,
    set: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let elements = force_set(evaluator, set)?;
    Ok(collection(Value::Bool(
        elements
            .0
            .find(|existing| compare_keys(evaluator, element, existing))?
            .is_some(),
    )))
}

fn set_delete(
    evaluator: &mut Evaluator,
    element: &ThunkRef,
    set: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let elements = force_set(evaluator, set)?;
    let elements = elements
        .0
        .remove(&mut |existing| compare_keys(evaluator, element, existing))?;
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
    left: &ThunkRef,
    right: &ThunkRef,
    operation: SetMerge,
) -> RuntimeResult<ForceOutcome> {
    let left = force_set(evaluator, left)?;
    let right = force_set(evaluator, right)?;
    let mut output = match operation {
        SetMerge::Union | SetMerge::Difference => left.0.clone(),
        SetMerge::Intersection => PersistentTree::default(),
    };
    match operation {
        SetMerge::Union => {
            for element in right.iter() {
                output = output.insert(Arc::clone(element), &mut |left, right| {
                    compare_keys(evaluator, left, right)
                })?;
            }
        }
        SetMerge::Difference => {
            for element in right.iter() {
                output =
                    output.remove(&mut |existing| compare_keys(evaluator, element, existing))?;
            }
        }
        SetMerge::Intersection => {
            for element in left.iter() {
                if right
                    .0
                    .find(|existing| compare_keys(evaluator, element, existing))?
                    .is_some()
                {
                    output = output.insert(Arc::clone(element), &mut |left, right| {
                        compare_keys(evaluator, left, right)
                    })?;
                }
            }
        }
    }
    Ok(collection(Value::Set(Arc::new(OrderedSet(output)))))
}

fn set_size(evaluator: &mut Evaluator, set: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let size = force_set(evaluator, set)?.len();
    Ok(collection(Value::Int(
        i64::try_from(size).unwrap_or(i64::MAX),
    )))
}

#[cfg(test)]
mod tests {
    use super::{PersistentTree, height};
    use std::sync::Arc;

    #[test]
    fn persistent_tree_is_balanced_and_shares_untouched_branches() {
        let mut tree = PersistentTree::default();
        for value in 0_i32..1_024 {
            tree = tree
                .insert(value, &mut |left, right| Ok(left.cmp(right)))
                .expect("ordered insertion succeeds");
        }
        assert_eq!(tree.len(), 1_024);
        assert!(height(tree.root.as_ref()) <= 11);

        let original_root = tree.root.as_ref().expect("tree is populated");
        let original_left = original_root.left.as_ref().expect("tree has a left branch");
        let extended = tree
            .insert(2_048, &mut |left, right| Ok(left.cmp(right)))
            .expect("persistent insertion succeeds");
        let extended_root = extended.root.as_ref().expect("tree remains populated");
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
}
