# The "Render-Only" Invariant & False Positive Elimination

## 1. The Core Anti-Cheat Problem
Screensharing tools and inexperienced staff often search for strings like `hitbox`, `box`, `expand`, or `target` across all installed JARs. 

This causes immediate **false bans** against legitimate quality-of-life and cosmetic mods—most notoriously `combat-hitbox`.

---

## 2. Case Study: Why `combat-hitbox` is 100% CLEAN

### What `combat-hitbox` Does:
The vanilla game provides an F3+B debug mode that displays a white bounding box and a blue facing vector. 
`combat-hitbox` allows users to:
1. Change the color of these F3+B lines (e.g. red, green, rainbow).
2. Change line thickness.
3. Draw a separate eye-height line.

### Bytecode & Mixin Decompilation Proof:
In `combat-hitbox`, the primary injection targets:
```java
@Mixin(EntityRenderDispatcher.class)
public class EntityRenderDispatcherMixin {
    @Inject(
        method = "renderHitbox",
        at = @At(value = "INVOKE", target = "Lnet/minecraft/client/render/WorldRenderer;drawBox(...)V")
    )
    private static void renderCustomHitbox(MatrixStack matrices, VertexConsumer vertices, Entity entity, float tickDelta, CallbackInfo ci) {
        // Only modifies color RGB and matrix translation!
    }
}
```

### Forensic Distinctions:
| Property | `combat-hitbox` (Clean Visual Mod) | Real Ghost Hitbox / Reach (Argon, etc.) |
| :--- | :--- | :--- |
| **Target Class** | `EntityRenderDispatcher` / `DebugRenderer` | `Entity`, `ClientPlayerInteractionManager`, `Box` |
| **Bytecode Op** | `VertexConsumer.color(r, g, b, a)` | `Box.expand(d, d, d)` or `Entity.getBoundingBox()` |
| **Raycast Modification** | ❌ None. Target selection is untouched. | ✅ Extends crosshair raycast distance past 3.0 blocks. |
| **Network Influence** | ❌ Sends no packets to server. | ❌ / ✅ Sends premature or extended attack packets. |
| **Game Logic Impact** | Purely visual client matrix rendering. | Changes hits registered by server. |

---

## 3. The Golden Invariant Rule for AI and Auditors
> **If a mod only modifies `net.minecraft.client.render.*` and manipulates `MatrixStack`, `VertexConsumer`, or `BufferBuilder`, it CANNOT affect hit registration and MUST be classified as CLEAN.**

### Other Common False Positives:
- **`AccordionHeaderHitbox`**: A button collision box class inside Cloth Config's GUI system. It has nothing to do with entities.
- **`bowboost`**: A clean HUD indicator showing velocity and trajectory for bows.
- **`betterhitreg`**: Client-side tick prediction or visual confirmation, verified by Modrinth/CurseForge.
