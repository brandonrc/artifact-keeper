import React, { useCallback, useEffect, useState, RefObject } from 'react'

/**
 * Key codes for keyboard navigation
 */
export const Keys = {
  ARROW_UP: 'ArrowUp',
  ARROW_DOWN: 'ArrowDown',
  ARROW_LEFT: 'ArrowLeft',
  ARROW_RIGHT: 'ArrowRight',
  ENTER: 'Enter',
  ESCAPE: 'Escape',
  TAB: 'Tab',
  SPACE: ' ',
  HOME: 'Home',
  END: 'End',
} as const

export type KeyCode = typeof Keys[keyof typeof Keys]

/**
 * Options for the useKeyboardNav hook
 */
export interface UseKeyboardNavOptions {
  /** Callback for arrow up key */
  onArrowUp?: (event: KeyboardEvent) => void
  /** Callback for arrow down key */
  onArrowDown?: (event: KeyboardEvent) => void
  /** Callback for arrow left key */
  onArrowLeft?: (event: KeyboardEvent) => void
  /** Callback for arrow right key */
  onArrowRight?: (event: KeyboardEvent) => void
  /** Callback for enter key */
  onEnter?: (event: KeyboardEvent) => void
  /** Callback for escape key */
  onEscape?: (event: KeyboardEvent) => void
  /** Callback for tab key */
  onTab?: (event: KeyboardEvent) => void
  /** Callback for space key */
  onSpace?: (event: KeyboardEvent) => void
  /** Callback for home key */
  onHome?: (event: KeyboardEvent) => void
  /** Callback for end key */
  onEnd?: (event: KeyboardEvent) => void
  /** Custom key handlers */
  customHandlers?: Record<string, (event: KeyboardEvent) => void>
  /** Whether to prevent default behavior for handled keys */
  preventDefault?: boolean
  /** Whether to stop propagation for handled keys */
  stopPropagation?: boolean
  /** Whether the keyboard navigation is enabled */
  enabled?: boolean
  /** Container ref to scope keyboard events (defaults to document) */
  containerRef?: RefObject<HTMLElement | null>
}

/**
 * Return type for the useKeyboardNav hook
 */
export interface UseKeyboardNavReturn {
  /** Handler to attach to onKeyDown events */
  handleKeyDown: (event: React.KeyboardEvent) => void
}

/**
 * Hook for keyboard navigation in trees, lists, and dialogs
 *
 * Features:
 * - Arrow key navigation for trees and lists
 * - Escape to close modals/dropdowns
 * - Enter to confirm dialogs
 * - Tab navigation support
 * - Home/End key support
 * - Custom key handlers
 *
 * @example
 * ```tsx
 * const { handleKeyDown } = useKeyboardNav({
 *   onArrowDown: () => setFocusedIndex(prev => Math.min(prev + 1, items.length - 1)),
 *   onArrowUp: () => setFocusedIndex(prev => Math.max(prev - 1, 0)),
 *   onEnter: () => handleSelect(focusedIndex),
 *   onEscape: () => setIsOpen(false),
 * })
 *
 * return <ul onKeyDown={handleKeyDown}>...</ul>
 * ```
 */
export const useKeyboardNav = (options: UseKeyboardNavOptions = {}): UseKeyboardNavReturn => {
  const {
    onArrowUp,
    onArrowDown,
    onArrowLeft,
    onArrowRight,
    onEnter,
    onEscape,
    onTab,
    onSpace,
    onHome,
    onEnd,
    customHandlers = {},
    preventDefault = true,
    stopPropagation = false,
    enabled = true,
    containerRef,
  } = options

  const handleKeyboardEvent = useCallback(
    (event: KeyboardEvent) => {
      if (!enabled) return

      const { key } = event
      let handled = false

      // Check for custom handlers first
      if (customHandlers[key]) {
        customHandlers[key](event)
        handled = true
      } else {
        // Check standard handlers
        switch (key) {
          case Keys.ARROW_UP:
            if (onArrowUp) {
              onArrowUp(event)
              handled = true
            }
            break
          case Keys.ARROW_DOWN:
            if (onArrowDown) {
              onArrowDown(event)
              handled = true
            }
            break
          case Keys.ARROW_LEFT:
            if (onArrowLeft) {
              onArrowLeft(event)
              handled = true
            }
            break
          case Keys.ARROW_RIGHT:
            if (onArrowRight) {
              onArrowRight(event)
              handled = true
            }
            break
          case Keys.ENTER:
            if (onEnter) {
              onEnter(event)
              handled = true
            }
            break
          case Keys.ESCAPE:
            if (onEscape) {
              onEscape(event)
              handled = true
            }
            break
          case Keys.TAB:
            if (onTab) {
              onTab(event)
              handled = true
            }
            break
          case Keys.SPACE:
            if (onSpace) {
              onSpace(event)
              handled = true
            }
            break
          case Keys.HOME:
            if (onHome) {
              onHome(event)
              handled = true
            }
            break
          case Keys.END:
            if (onEnd) {
              onEnd(event)
              handled = true
            }
            break
        }
      }

      if (handled) {
        if (preventDefault && key !== Keys.TAB) {
          event.preventDefault()
        }
        if (stopPropagation) {
          event.stopPropagation()
        }
      }
    },
    [
      enabled,
      onArrowUp,
      onArrowDown,
      onArrowLeft,
      onArrowRight,
      onEnter,
      onEscape,
      onTab,
      onSpace,
      onHome,
      onEnd,
      customHandlers,
      preventDefault,
      stopPropagation,
    ]
  )

  // Attach listener to container or document
  useEffect(() => {
    if (!enabled) return

    const target = containerRef?.current || document

    target.addEventListener('keydown', handleKeyboardEvent as EventListener)
    return () => {
      target.removeEventListener('keydown', handleKeyboardEvent as EventListener)
    }
  }, [enabled, containerRef, handleKeyboardEvent])

  // Handler for React's synthetic events
  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent) => {
      handleKeyboardEvent(event.nativeEvent)
    },
    [handleKeyboardEvent]
  )

  return { handleKeyDown }
}

/**
 * Hook for modal/dialog keyboard navigation
 * Provides escape to close and enter to confirm functionality
 *
 * @example
 * ```tsx
 * useModalKeyboardNav({
 *   isOpen: modalOpen,
 *   onClose: () => setModalOpen(false),
 *   onConfirm: handleSubmit,
 * })
 * ```
 */
export interface UseModalKeyboardNavOptions {
  /** Whether the modal is open */
  isOpen: boolean
  /** Callback when escape is pressed */
  onClose?: () => void
  /** Callback when enter is pressed */
  onConfirm?: () => void
  /** Whether to enable confirm on enter (default: true) */
  enableEnterConfirm?: boolean
}

export const useModalKeyboardNav = (options: UseModalKeyboardNavOptions): void => {
  const { isOpen, onClose, onConfirm, enableEnterConfirm = true } = options

  useKeyboardNav({
    enabled: isOpen,
    onEscape: onClose,
    onEnter: enableEnterConfirm ? onConfirm : undefined,
  })
}

/**
 * Hook for list keyboard navigation
 * Provides arrow key navigation with index management
 *
 * @example
 * ```tsx
 * const { focusedIndex, handleKeyDown } = useListKeyboardNav({
 *   itemCount: items.length,
 *   onSelect: (index) => handleItemSelect(items[index]),
 * })
 * ```
 */
export interface UseListKeyboardNavOptions {
  /** Total number of items in the list */
  itemCount: number
  /** Callback when an item is selected (Enter pressed) */
  onSelect?: (index: number) => void
  /** Callback when escape is pressed */
  onEscape?: () => void
  /** Initial focused index */
  initialIndex?: number
  /** Whether navigation wraps around */
  wrap?: boolean
  /** Whether the navigation is enabled */
  enabled?: boolean
}

export interface UseListKeyboardNavReturn {
  /** Currently focused index */
  focusedIndex: number
  /** Set the focused index */
  setFocusedIndex: (index: number) => void
  /** Handler to attach to onKeyDown events */
  handleKeyDown: (event: React.KeyboardEvent) => void
}

export const useListKeyboardNav = (
  options: UseListKeyboardNavOptions
): UseListKeyboardNavReturn => {
  const {
    itemCount,
    onSelect,
    onEscape,
    initialIndex = 0,
    wrap = false,
    enabled = true,
  } = options

  const [focusedIndex, setFocusedIndex] = useState(initialIndex)

  const { handleKeyDown } = useKeyboardNav({
    enabled,
    onArrowDown: () => {
      setFocusedIndex((prev) => {
        if (prev >= itemCount - 1) {
          return wrap ? 0 : prev
        }
        return prev + 1
      })
    },
    onArrowUp: () => {
      setFocusedIndex((prev) => {
        if (prev <= 0) {
          return wrap ? itemCount - 1 : prev
        }
        return prev - 1
      })
    },
    onHome: () => setFocusedIndex(0),
    onEnd: () => setFocusedIndex(itemCount - 1),
    onEnter: () => {
      if (onSelect && focusedIndex >= 0 && focusedIndex < itemCount) {
        onSelect(focusedIndex)
      }
    },
    onEscape,
  })

  return { focusedIndex, setFocusedIndex, handleKeyDown }
}

export default useKeyboardNav
