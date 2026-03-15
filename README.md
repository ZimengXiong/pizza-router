# picoCTF 2026: Pizza Router
This binary implements a routing service with map loading, order management, and route calculation. Exploitation relies on a signed out-of-bounds (OOB) write in the `reroute` command and two pointer leaks.

The `replay` and `receipt` commands leak internal pointers:
- **PIE Leak**: `replay <id>` prints a pointer to `fx_draw_basic` (offset `0x2260`).
- **Heap Leak**: `receipt <id>` prints a `hint` pointer, which is the address of the `renderer` object on the heap.

The exploitation target is the `win()` function (offset `0x2460`), which reads `flag.txt`.

##  `reroute` Vulnerability

The `reroute` command writes an 8-byte entry into the renderer's route array without bounds checking on the index.

```c
// Simplified logic
entry = renderer_heap_base + heap_idx * 8;
entry->pos  = order->y * width + order->x;
entry->cost = new_cost;
```

`heap_idx` is a signed integer, allowing writes both forward and backward from the heap base. The write is constrained:
- The upper 32 bits are controlled via `new_cost`.
- The lower 32 bits are derived from the order's current position (`y * width + x`).

## Abandoned Approaches

- Attempting to set coordinates like `(1,0)` (a wall) failed validation, preventing later commands from using the order ID.
- Overwriting the renderer's finish callback directly was impossible because the required low 32 bits (`win & 0xffffffff`) did not match the initial order position.
- Corrupting adjacent heap metadata was discarded in favor of a deterministic overwrite using the leaked addresses.

## Exploit

### 1. Order Header Corruption
We create a valid order at `(1, 1)`. We then calculate the index from the renderer's route array back to the global `ORD` array where order headers are stored.

```python
# Calculate Stage 1 index
idx_stage1 = (order_base - routes_base) // 8
staged_x = (low32(win) - (INIT_Y * MAP_W)) & 0xffffffff
# Command: reroute 0 {idx_stage1} {staged_x}
```

This write overwrites the `x` coordinate of order 0. Because the program calculates `pos = y * width + x`, modifying `x` allows us to control the lower 32 bits of any future `reroute` write using this order.

### 2. Callback Hijack
With the order header corrupted, the program now calculates `pos` as exactly the low 32 bits of `win()`. We then use another OOB write to target the `finish` callback (renderer offset `+0x430`).

```python
# Calculate Stage 2 index
idx_stage2 = (renderer_base + FINISH_OFF - routes_base) // 8
# Command: reroute {bootstrap_id} {idx_stage2} {high32(win)}
```

By providing the upper 32 bits of `win()` via `new_cost`, the full 64-bit address of `win()` is written over the callback.

### 3. Execution
The `dispatch` command is called for the modified order. The renderer executes the hijacked `finish` callback, triggering `win()`.

**Flag:** `flag{thirty_minutes_or_flag_free_xxxxxxxx}`
