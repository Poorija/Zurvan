## 2026-04-25 - Password Toggle Accessibility
**Learning:** Icon-only password visibility toggles in PyQt6 lack default accessibility, making them unreadable to screen readers and confusing without tooltips.
**Action:** Use `setAccessibleName` and `setToolTip` on all such buttons, and update the tooltip dynamically on toggle.
