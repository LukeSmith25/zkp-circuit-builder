# Computational Graph Library

A Rust library for building and evaluating computational graphs that represent mathematical functions. Designed with zero-knowledge proof circuits in mind.

## Features

- Build graph structures with addition and multiplication operations
- Support for constant values and input nodes
- "Hint" system for operations like division and square root
- Topological evaluation with cycle detection
- Equality constraints between nodes

## Example

```rust
// Compute f(x) = x^2 + x + 5
let mut builder = Builder::new();
let x = builder.init();
let x_squared = builder.mul(x, x);
let five = builder.constant(5);
let x_squared_plus_5 = builder.add(x_squared, five);
let result = builder.add(x_squared_plus_5, x);

builder.fill_nodes(&[(x, 3)])?;
assert_eq!(builder.get_value(result), Some(17));
```

## Using Hints for Extended Operations

Hints enable operations not directly supported by the graph's primitive operations:

```rust
// Division via hint: f(a) = (a+1) / 8
let a = builder.init();
let b = builder.add(a, builder.constant(1));

// Create a hint node for division
let c = builder.hint(move |builder| {
    let b_val = builder.get_value(b).unwrap();
    b_val / 8
});

// Constrain c * 8 = b
builder.assert_equal(b, builder.mul(c, builder.constant(8)));
```

## License

MIT