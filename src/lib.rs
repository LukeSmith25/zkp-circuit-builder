/// A computational graph library for zero-knowledge proofs.
///
/// This library provides a way to build and evaluate computational graphs where:
/// - Nodes represent integer values
/// - Relationships are defined by addition, multiplication, and equality
/// - External values can be computed via "hints" for operations like division
/// - Constraints enforce relationships between nodes

/// A node in the computational graph (lightweight handle).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Node {
    /// Unique identifier for the node
    id: usize,
}

/// A builder that creates and manages a computational graph.
pub struct Builder {
    /// Data for all nodes in the graph
    nodes: Vec<NodeData>,
    /// Equality constraints between pairs of nodes (a_id, b_id)
    constraints: Vec<(usize, usize)>,
    /// Set of nodes currently being evaluated (for cycle detection)
    in_progress: std::collections::HashSet<usize>,
    /// Storage for hint functions and their dependencies
    hint_functions: Vec<(Box<dyn Fn(&Builder) -> u32>, Vec<usize>)>,
}

/// Internal representation of a node's data
#[derive(Debug, Clone)]
struct NodeData {
    /// Current value of the node (if computed)
    value: Option<u32>,
    /// The operation this node performs
    operation: Operation,
}

/// Defines the possible operations a node can perform
#[derive(Clone)]
pub enum Operation {
    /// An input node that gets its value from user input
    Input,
    /// A constant value node
    Constant(u32),
    /// Addition of two other nodes (by node ID)
    Add(usize, usize),
    /// Multiplication of two other nodes (by node ID)
    Multiply(usize, usize),
    /// A hint node with reference to a function in the hint_functions storage
    Hint(usize),
}

// Manual implementation of Debug for Operation
impl std::fmt::Debug for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Input => write!(f, "Input"),
            Operation::Constant(val) => write!(f, "Constant({})", val),
            Operation::Add(a, b) => write!(f, "Add({}, {})", a, b),
            Operation::Multiply(a, b) => write!(f, "Multiply({}, {})", a, b),
            Operation::Hint(idx) => write!(f, "Hint(function_idx: {})", idx),
        }
    }
}

/// Errors that can occur during graph operations
#[derive(Debug)]
pub enum GraphError {
    /// A cycle was detected in the graph
    CycleDetected,
    /// An input node was not provided a value
    MissingInput(usize),
    /// A node was referenced that doesn't exist
    InvalidNodeReference(usize),
    /// Two nodes that should be equal have different values
    ConstraintViolation(usize, usize),
    /// A node's value couldn't be computed
    ComputationError(String),
}

impl Builder {
    /// Creates a new empty builder.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            constraints: Vec::new(),
            in_progress: std::collections::HashSet::new(),
            hint_functions: Vec::new(),
        }
    }

    /// Creates an input node that will receive its value from external input.
    pub fn init(&mut self) -> Node {
        let id = self.nodes.len();
        self.nodes.push(NodeData {
            value: None,
            operation: Operation::Input,
        });
        Node { id }
    }

    /// Creates a constant node with a fixed value.
    pub fn constant(&mut self, value: u32) -> Node {
        let id = self.nodes.len();
        self.nodes.push(NodeData {
            value: Some(value),
            operation: Operation::Constant(value),
        });
        Node { id }
    }

    /// Creates a node that represents the sum of two other nodes.
    pub fn add(&mut self, a: Node, b: Node) -> Node {
        let id = self.nodes.len();
        self.nodes.push(NodeData {
            value: None,
            operation: Operation::Add(a.id, b.id),
        });
        Node { id }
    }

    /// Creates a node that represents the product of two other nodes.
    pub fn mul(&mut self, a: Node, b: Node) -> Node {
        let id = self.nodes.len();
        self.nodes.push(NodeData {
            value: None,
            operation: Operation::Multiply(a.id, b.id),
        });
        Node { id }
    }

    /// Adds a constraint that two nodes must have the same value.
    pub fn assert_equal(&mut self, a: Node, b: Node) {
        self.constraints.push((a.id, b.id));
    }

    /// Sets values for input nodes and computes values for all derived nodes.
    ///
    /// Evaluates the graph in topological order to ensure dependencies are computed first.
    /// Returns an error if the graph has cycles, references invalid nodes, or is missing inputs.
    pub fn fill_nodes(&mut self, inputs: &[(Node, u32)]) -> Result<(), GraphError> {
        // Reset all non-constant node values
        for node in &mut self.nodes {
            if let Operation::Constant(_) = node.operation {
                // Keep constant values
            } else {
                node.value = None;
            }
        }

        // Clear the in-progress set
        self.in_progress.clear();

        // Set input values
        for (node, value) in inputs {
            if node.id >= self.nodes.len() {
                return Err(GraphError::InvalidNodeReference(node.id));
            }

            if let Operation::Input = self.nodes[node.id].operation {
                self.nodes[node.id].value = Some(*value);
            } else {
                return Err(GraphError::ComputationError(
                    format!("Node {} is not an input", node.id)
                ));
            }
        }

        // Perform topological sort and evaluate nodes in that order
        let evaluation_order = self.topological_sort()?;

        // Compute node values in topological order
        for &node_id in &evaluation_order {
            // Skip if already computed
            if self.nodes[node_id].value.is_some() {
                continue;
            }

            // Compute the node value
            self.compute_node_value(node_id)?;
        }

        Ok(())
    }

    /// Computes the value of a single node based on its operation.
    fn compute_node_value(&mut self, node_id: usize) -> Result<(), GraphError> {
        // Check for cycles
        if self.in_progress.contains(&node_id) {
            return Err(GraphError::CycleDetected);
        }

        // Skip if already computed
        if self.nodes[node_id].value.is_some() {
            return Ok(());
        }

        // Mark as in-progress for cycle detection
        self.in_progress.insert(node_id);

        // Clone the operation to avoid borrowing issues
        let operation = self.nodes[node_id].operation.clone();

        // Compute value based on operation type
        match operation {
            Operation::Input => {
                self.in_progress.remove(&node_id);
                return Err(GraphError::MissingInput(node_id));
            }

            Operation::Constant(val) => {
                self.nodes[node_id].value = Some(val);
            }

            Operation::Add(a_id, b_id) => {
                // Ensure nodes exist
                if a_id >= self.nodes.len() || b_id >= self.nodes.len() {
                    self.in_progress.remove(&node_id);
                    return Err(GraphError::InvalidNodeReference(
                        if a_id >= self.nodes.len() { a_id } else { b_id }
                    ));
                }

                // Check if dependencies need to be computed
                let a_needs_compute = self.nodes[a_id].value.is_none();
                let b_needs_compute = self.nodes[b_id].value.is_none();

                // Recursively compute dependencies if needed
                if a_needs_compute {
                    self.compute_node_value(a_id)?;
                }

                if b_needs_compute {
                    self.compute_node_value(b_id)?;
                }

                // Get values
                let a_val = self.nodes[a_id].value.ok_or_else(|| {
                    GraphError::ComputationError(format!("Node {} value not computed", a_id))
                })?;

                let b_val = self.nodes[b_id].value.ok_or_else(|| {
                    GraphError::ComputationError(format!("Node {} value not computed", b_id))
                })?;

                // Compute and store result
                self.nodes[node_id].value = Some(a_val + b_val);
            }

            Operation::Multiply(a_id, b_id) => {
                // Ensure nodes exist
                if a_id >= self.nodes.len() || b_id >= self.nodes.len() {
                    self.in_progress.remove(&node_id);
                    return Err(GraphError::InvalidNodeReference(
                        if a_id >= self.nodes.len() { a_id } else { b_id }
                    ));
                }

                // Check if dependencies need to be computed
                let a_needs_compute = self.nodes[a_id].value.is_none();
                let b_needs_compute = self.nodes[b_id].value.is_none();

                // Recursively compute dependencies if needed
                if a_needs_compute {
                    self.compute_node_value(a_id)?;
                }

                if b_needs_compute {
                    self.compute_node_value(b_id)?;
                }

                // Get values
                let a_val = self.nodes[a_id].value.ok_or_else(|| {
                    GraphError::ComputationError(format!("Node {} value not computed", a_id))
                })?;

                let b_val = self.nodes[b_id].value.ok_or_else(|| {
                    GraphError::ComputationError(format!("Node {} value not computed", b_id))
                })?;

                // Compute and store result
                self.nodes[node_id].value = Some(a_val * b_val);
            }

            Operation::Hint(hint_idx) => {
                // Temporarily remove from in-progress to avoid false cycle detection
                self.in_progress.remove(&node_id);

                // Get the hint function and dependencies
                if hint_idx >= self.hint_functions.len() {
                    return Err(GraphError::InvalidNodeReference(hint_idx));
                }

                // Clone the dependencies to avoid borrowing issues
                let dependencies = self.hint_functions[hint_idx].1.clone();
                
                // Compute all dependencies first
                for dep_id in dependencies {
                    if dep_id < self.nodes.len() && self.nodes[dep_id].value.is_none() {
                        self.compute_node_value(dep_id)?;
                    }
                }

                // Call the hint function, catching any panics
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    (self.hint_functions[hint_idx].0)(self)
                }));

                match result {
                    Ok(value) => {
                        self.nodes[node_id].value = Some(value);
                    }
                    Err(_) => {
                        return Err(GraphError::ComputationError(
                            format!("Hint function for node {} panicked", node_id)
                        ));
                    }
                }
            }
        }

        // Make sure node is not in the in-progress set
        self.in_progress.remove(&node_id);

        Ok(())
    }

    /// Sorts nodes so that dependencies come before dependents.
    ///
    /// Uses Kahn's algorithm for topological sorting, which detects cycles.
    fn topological_sort(&self) -> Result<Vec<usize>, GraphError> {
        use std::collections::{HashMap, HashSet, VecDeque};

        // Build an adjacency list and count incoming edges for each node
        let mut graph: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut in_degree: HashMap<usize, usize> = HashMap::new();

        // Initialize in-degree counters to zero
        for i in 0..self.nodes.len() {
            graph.insert(i, Vec::new());
            in_degree.insert(i, 0);
        }

        // Build the graph and count incoming edges
        for (node_id, node_data) in self.nodes.iter().enumerate() {
            match &node_data.operation {
                Operation::Add(a, b) | Operation::Multiply(a, b) => {
                    // Ensure the node references are valid
                    if *a >= self.nodes.len() || *b >= self.nodes.len() {
                        return Err(GraphError::InvalidNodeReference(
                            if *a >= self.nodes.len() { *a } else { *b }
                        ));
                    }

                    // Add edges from dependencies to the current node
                    graph.get_mut(a).unwrap().push(node_id);
                    graph.get_mut(b).unwrap().push(node_id);

                    // Increment in-degree for current node
                    *in_degree.get_mut(&node_id).unwrap() += 2;
                }
                Operation::Hint(hint_idx) => {
                    // Use stored dependencies for hints
                    if *hint_idx < self.hint_functions.len() {
                        let dependencies = &self.hint_functions[*hint_idx].1;
                        for &dep_id in dependencies {
                            if dep_id < self.nodes.len() {
                                graph.get_mut(&dep_id).unwrap().push(node_id);
                                *in_degree.get_mut(&node_id).unwrap() += 1;
                            }
                        }
                    }
                }
                _ => {} // Input and Constant nodes have no dependencies
            }
        }

        // Start with nodes that have no dependencies (in-degree = 0)
        let mut queue: VecDeque<usize> = in_degree.iter()
            .filter(|&(_, &degree)| degree == 0)
            .map(|(&node, _)| node)
            .collect();

        let mut result = Vec::new();
        let mut visited = HashSet::new();

        // Process nodes in order
        while let Some(node) = queue.pop_front() {
            if visited.contains(&node) {
                continue;
            }

            result.push(node);
            visited.insert(node);

            // Process all neighbors
            if let Some(neighbors) = graph.get(&node) {
                for &next in neighbors {
                    // Decrease in-degree when visiting a dependency
                    let degree = in_degree.get_mut(&next).unwrap();
                    *degree -= 1;

                    // If all dependencies processed, add to queue
                    if *degree == 0 {
                        queue.push_back(next);
                    }
                }
            }
        }

        // Check for cycles - if not all nodes were visited, there's a cycle
        if result.len() != self.nodes.len() {
            return Err(GraphError::CycleDetected);
        }

        Ok(result)
    }

    /// Checks if all equality constraints are satisfied.
    ///
    /// Returns true if all constraints are met, or an error if constraints
    /// can't be checked or are violated.
    pub fn check_constraints(&self) -> Result<bool, GraphError> {
        for (a_id, b_id) in &self.constraints {
            // Ensure nodes exist
            if *a_id >= self.nodes.len() || *b_id >= self.nodes.len() {
                return Err(GraphError::InvalidNodeReference(
                    if *a_id >= self.nodes.len() { *a_id } else { *b_id }
                ));
            }

            // Get node values
            let a_val = match self.nodes[*a_id].value {
                Some(val) => val,
                None => return Err(GraphError::ComputationError(
                    format!("Node {} value not computed", a_id)
                )),
            };

            let b_val = match self.nodes[*b_id].value {
                Some(val) => val,
                None => return Err(GraphError::ComputationError(
                    format!("Node {} value not computed", b_id)
                )),
            };

            // Check if values match
            if a_val != b_val {
                return Err(GraphError::ConstraintViolation(*a_id, *b_id));
            }
        }

        Ok(true) // All constraints satisfied
    }

    /// Creates a node whose value is computed by the provided function.
    ///
    /// Enables operations not directly supported in the graph (like division).
    pub fn hint<F>(&mut self, compute_fn: F) -> Node
    where
        F: Fn(&Builder) -> u32 + 'static
    {
        // Store the function and track which nodes it might depend on
        // For simplicity, we'll track all existing nodes as potential dependencies
        let dependencies = (0..self.nodes.len()).collect::<Vec<_>>();
        let hint_idx = self.hint_functions.len();
        self.hint_functions.push((Box::new(compute_fn), dependencies));

        // Create the node with a reference to the stored function
        let id = self.nodes.len();
        self.nodes.push(NodeData {
            value: None,
            operation: Operation::Hint(hint_idx),
        });
        Node { id }
    }

    /// Gets the current value of a node, if computed.
    pub fn get_value(&self, node: Node) -> Option<u32> {
        if node.id < self.nodes.len() {
            self.nodes[node.id].value
        } else {
            None
        }
    }

    /// Gets a list of all nodes in the graph.
    pub fn get_all_nodes(&self) -> Vec<Node> {
        (0..self.nodes.len()).map(|id| Node { id }).collect()
    }

    /// Gets information about a node's operation and current value.
    pub fn get_node_info(&self, node: Node) -> Option<(&Operation, Option<u32>)> {
        if node.id < self.nodes.len() {
            Some((&self.nodes[node.id].operation, self.nodes[node.id].value))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example1() {
        // Example 1: f(x) = x^2 + x + 5
        let mut builder = Builder::new();
        let x = builder.init();
        let x_squared = builder.mul(x, x);
        let five = builder.constant(5);
        let x_squared_plus_5 = builder.add(x_squared, five);
        let _y = builder.add(x_squared_plus_5, x);
    
        // Test with x = 3
        // Expected: 3^2 + 3 + 5 = 9 + 3 + 5 = 17
        builder.fill_nodes(&[(x, 3)]).unwrap();
        assert_eq!(builder.get_value(_y), Some(17));
    }

    #[test]
    fn test_example2() {
        // Example 2: f(a) = (a+1) / 8
        let mut builder = Builder::new();
        let a = builder.init();
        let one = builder.constant(1);
        let b = builder.add(a, one);

        // Hint for division
        let c = builder.hint(move |builder| {
            let b_val = builder.get_value(b).unwrap();
            b_val / 8
        });

        let eight = builder.constant(8);
        let c_times_8 = builder.mul(c, eight);
        builder.assert_equal(b, c_times_8);

        // Test with a = 7
        // Expected: (7+1) / 8 = 8 / 8 = 1
        builder.fill_nodes(&[(a, 7)]).unwrap();
        assert!(builder.check_constraints().unwrap());
        assert_eq!(builder.get_value(c), Some(1));
    }

    #[test]
    fn test_example3() {
        // Example 3: f(x) = sqrt(x+7)
        let mut builder = Builder::new();
        let x = builder.init();
        let seven = builder.constant(7);
        let x_plus_seven = builder.add(x, seven);

        // Hint for square root 
        let sqrt_x_plus_7 = builder.hint(move |builder| {
            let val = builder.get_value(x_plus_seven).unwrap();
            (val as f64).sqrt() as u32
        });

        let computed_sq = builder.mul(sqrt_x_plus_7, sqrt_x_plus_7);
        builder.assert_equal(computed_sq, x_plus_seven);

        // Test with x = 2 (so x+7 = 9, sqrt(9) = 3)
        builder.fill_nodes(&[(x, 2)]).unwrap();
        assert!(builder.check_constraints().unwrap());
        assert_eq!(builder.get_value(sqrt_x_plus_7), Some(3));
    }

    #[test]
    fn test_cycle_detection() {
        let mut builder = Builder::new();

        // Create nodes for a cyclic relationship
        let a = builder.init();
        let b = builder.add(a, a); // b = a + a

        // Create a cycle: c depends on b, but we'll make b depend on c
        let c = builder.add(b, a); // c = b + a

        // This is a hack to create a cycle - in practice this would be done with hints
        // We manually modify the operation of b to depend on c
        unsafe {
            let nodes_ptr = &mut builder.nodes as *mut Vec<NodeData>;
            (*nodes_ptr)[b.id].operation = Operation::Add(c.id, a.id); // b = c + a
        }

        // Now we have: a → b → c → b (cycle!)

        // Try to fill in values - should fail with cycle detection
        let result = builder.fill_nodes(&[(a, 5)]);
        assert!(matches!(result, Err(GraphError::CycleDetected)));
    }

    #[test]
    fn test_out_of_order_nodes() {
        // This test demonstrates that nodes can be evaluated correctly
        // even when created in an order different from their dependency order
        let mut builder = Builder::new();

        // Create some nodes with IDs 0, 1, 2
        let a = builder.init();
        let b = builder.init();
        let c = builder.init();

        // Create intermediate node to avoid multiple mutable borrows
        let b_plus_a = builder.add(b, a);
        // Now create a node that depends on c and the intermediate node
        let expr = builder.add(c, b_plus_a);

        // Fill in values
        builder.fill_nodes(&[(a, 1), (b, 2), (c, 3)]).unwrap();

        // Should compute: c + (b + a) = 3 + (2 + 1) = 6
        assert_eq!(builder.get_value(expr), Some(6));
    }

    #[test]
    fn test_missing_input() {
        let mut builder = Builder::new();
        let x = builder.init();
        let _y = builder.add(x, x);
    
        // Test missing input
        let result = builder.fill_nodes(&[]);
        assert!(matches!(result, Err(GraphError::MissingInput(_))));
    }
    
    #[test]
    fn test_invalid_node_reference() {
        let mut builder = Builder::new();
        
        // Test invalid node reference
        let invalid_node = Node { id: 999 }; // Doesn't exist
        let result = builder.fill_nodes(&[(invalid_node, 5)]);
        assert!(matches!(result, Err(GraphError::InvalidNodeReference(_))));
    }
    
    #[test]
    fn test_hint_panic_handling() {
        let mut builder = Builder::new();
        let x = builder.init();
        
        // Create a hint function that will panic
        let div_by_zero = builder.hint(|_| {
            panic!("Division by zero");
        });
        
        // Fill only the input node to avoid automatic computation of the hint node
        builder.nodes[x.id].value = Some(5);
        
        // Now directly test the hint computation
        let result = builder.compute_node_value(div_by_zero.id);
        assert!(matches!(result, Err(GraphError::ComputationError(_))));
    }
}