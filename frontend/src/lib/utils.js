/** Move element from oldIndex to newIndex, returning a new array. */
export function arrayMove(arr, oldIndex, newIndex) {
  const result = [...arr];
  const [removed] = result.splice(oldIndex, 1);
  result.splice(newIndex, 0, removed);
  return result;
}
