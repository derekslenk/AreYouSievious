import Sortable from 'sortablejs';

/**
 * Svelte action that wraps SortableJS for drag-and-drop reordering.
 *
 * Usage: <div use:sortable={{ handle: '.drag-handle', onReorder }}>
 *
 * @param {HTMLElement} node - The container element
 * @param {Object} params
 * @param {string} [params.handle] - CSS selector for drag handle
 * @param {function(number, number)} params.onReorder - Called with (oldIndex, newIndex)
 */
export function sortable(node, params) {
  let instance;

  function init(params) {
    instance = Sortable.create(node, {
      animation: 150,
      handle: params.handle || null,
      filter: params.filter || '.btn-xs, .btn-sm, button',
      preventOnFilter: false,
      ghostClass: 'sortable-ghost',
      chosenClass: 'sortable-chosen',
      dragClass: 'sortable-drag',
      onEnd(evt) {
        const { oldIndex, newIndex } = evt;
        if (oldIndex === newIndex) return;

        // Revert the DOM move that SortableJS performed,
        // so Svelte's {#each} can reconcile from updated data.
        const parent = evt.from;
        const child = evt.item;
        parent.removeChild(child);
        if (oldIndex < parent.children.length) {
          parent.insertBefore(child, parent.children[oldIndex]);
        } else {
          parent.appendChild(child);
        }

        if (params.onReorder) params.onReorder(oldIndex, newIndex);
      },
    });
  }

  init(params);

  return {
    update(newParams) {
      if (instance) instance.destroy();
      init(newParams);
    },
    destroy() {
      if (instance) instance.destroy();
    },
  };
}
