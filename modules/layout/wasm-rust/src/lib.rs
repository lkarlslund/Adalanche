use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use wasm_bindgen::prelude::*;

#[derive(Deserialize, Default)]
struct RunRequest {
    layout: String,
    #[serde(default)]
    graph: Graph,
    #[serde(default)]
    options: Map<String, Value>,
}

#[derive(Deserialize, Default, Clone)]
struct Graph {
    #[serde(default)]
    nodes: Vec<Node>,
    #[serde(default)]
    edges: Vec<Edge>,
}

#[derive(Deserialize, Default, Clone)]
struct Node {
    id: String,
    #[serde(default)]
    x: f64,
    #[serde(default)]
    y: f64,
    #[serde(default = "default_node_render_size")]
    render_size: f64,
    #[serde(default)]
    label: String,
    #[serde(default)]
    is_start: bool,
    #[serde(default)]
    is_end: bool,
}

#[derive(Deserialize, Default, Clone)]
struct Edge {
    source: String,
    target: String,
}

#[derive(Serialize)]
struct RunResponse {
    ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    positions: HashMap<String, Position>,
}

#[derive(Serialize)]
struct StartAnimationResponse {
    ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    session_id: String,
}

#[derive(Deserialize, Default)]
struct StepAnimationRequest {
    session_id: String,
    #[serde(default)]
    steps: i32,
}

#[derive(Serialize)]
struct StepAnimationResponse {
    ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    positions: HashMap<String, Position>,
    done: bool,
}

#[derive(Deserialize, Default)]
struct StopAnimationRequest {
    session_id: String,
}

#[derive(Serialize, Clone, Copy)]
struct Position {
    x: f64,
    y: f64,
}

#[derive(Serialize)]
struct Definition {
    key: String,
    label: String,
    description: String,
    supports_animation: bool,
    options: Vec<OptionDefinition>,
}

#[derive(Serialize)]
struct OptionDefinition {
    key: String,
    label: String,
    r#type: String,
    default: Value,
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    unit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    step: Option<f64>,
}

struct ForceStepper {
    ids: Vec<String>,
    nodes: Vec<Node>,
    pos: Vec<Vec2>,
    vel: Vec<Vec2>,
    edges: Vec<(usize, usize)>,
    degrees: Vec<usize>,
    iterations: usize,
    current_iter: usize,
    repulsion: f64,
    spring_length: f64,
    spring_stiffness: f64,
    center_gravity: f64,
    damping: f64,
    theta: f64,
    declump_iterations: usize,
    declump_padding: f64,
    declump_max_step: f64,
    layout_options: Map<String, Value>,
}

#[derive(Clone, Copy, Default)]
struct Vec2 {
    x: f64,
    y: f64,
}

fn default_node_render_size() -> f64 {
    10.0
}

#[derive(Clone)]
struct QuadCell {
    center: Vec2,
    half_size: f64,
    mass: f64,
    center_of_mass: Vec2,
    point: Option<usize>,
    children: [Option<usize>; 4],
}

struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: if seed == 0 { 42 } else { seed } }
    }

    fn next_f64(&mut self) -> f64 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let v = self.state >> 11;
        (v as f64) / ((u64::MAX >> 11) as f64)
    }
}

thread_local! {
    static SESSIONS: RefCell<HashMap<String, ForceStepper>> = RefCell::new(HashMap::new());
    static SESSION_SEQ: Cell<u64> = const { Cell::new(0) };
}

fn parse_request<T: for<'de> Deserialize<'de> + Default>(raw: &str) -> Result<T, String> {
    if raw.trim().is_empty() {
        return Ok(T::default());
    }
    serde_json::from_str::<T>(raw).map_err(|e| format!("invalid request json: {e}"))
}

fn option_f64(options: &Map<String, Value>, key: &str, fallback: f64) -> f64 {
    options
        .get(key)
        .and_then(|v| v.as_f64())
        .unwrap_or(fallback)
}

fn option_bool(options: &Map<String, Value>, key: &str, fallback: bool) -> bool {
    options
        .get(key)
        .and_then(|v| v.as_bool())
        .unwrap_or(fallback)
}

fn to_positions(ids: &[String], pos: &[Vec2]) -> HashMap<String, Position> {
    let mut out = HashMap::with_capacity(ids.len());
    for (i, id) in ids.iter().enumerate() {
        let p = pos.get(i).copied().unwrap_or_default();
        out.insert(id.clone(), Position { x: p.x, y: p.y });
    }
    out
}

fn node_box_size(node: &Node) -> Vec2 {
    let render_size = node.render_size.max(6.0);
    let label_chars = node.label.chars().count() as f64;
    let label_font = (11.0 + ((render_size - 10.0).max(0.0) * 0.22)).min(14.0);
    let label_width = if label_chars > 0.0 {
        (label_chars * label_font * 0.56) + 12.0
    } else {
        0.0
    };
    let width = (render_size * 2.0).max(label_width).max(18.0);
    let height = (render_size * 2.0) + if label_chars > 0.0 { label_font + 10.0 } else { 0.0 };
    Vec2 { x: width, y: height }
}

impl ForceStepper {
    fn new(graph: &Graph, options: &Map<String, Value>) -> Self {
        let n = graph.nodes.len();
        let iterations = option_f64(options, "iterations", 700.0).round().max(1.0) as usize;
        let repulsion = option_f64(options, "repulsion", 18000.0).max(100.0);
        let spring_length = option_f64(options, "spring_length", 110.0).max(1.0);
        let spring_stiffness = option_f64(options, "spring_stiffness", 0.04).max(0.0001);
        let center_gravity =
            option_f64(options, "center_gravity", 0.003).max(0.0) / (n.max(1) as f64).sqrt();
        let damping = option_f64(options, "damping", 0.9).clamp(0.2, 0.995);
        let theta = option_f64(options, "theta", 1.1).clamp(0.2, 2.0);
        let seed = option_f64(options, "seed", 42.0).round().max(1.0) as u64;
        let declump_iterations = option_f64(options, "declump_iterations", 18.0)
            .round()
            .clamp(0.0, 80.0) as usize;
        let declump_padding = option_f64(options, "declump_padding", 24.0).clamp(0.0, 200.0);
        let declump_max_step = option_f64(options, "declump_max_step", 28.0).clamp(1.0, 200.0);

        let mut ids = Vec::with_capacity(n);
        let mut id_to_idx = HashMap::with_capacity(n);
        let mut pos = vec![Vec2::default(); n];
        let vel = vec![Vec2::default(); n];

        // Starting from the previous view's coordinates makes the result depend on
        // whatever was shown before, so it is opt-in.
        let continue_layout = option_bool(options, "continue_layout", false);
        let mut rng = Lcg::new(seed);
        for (i, node) in graph.nodes.iter().enumerate() {
            ids.push(node.id.clone());
            id_to_idx.insert(node.id.clone(), i);
            if continue_layout && (node.x != 0.0 || node.y != 0.0) {
                pos[i] = Vec2 { x: node.x, y: node.y };
            } else {
                let base_radius = (spring_length * (n.max(1) as f64).sqrt() * 0.9).max(180.0);
                let angle = (2.0 * std::f64::consts::PI * i as f64) / (n.max(1) as f64);
                let radius = base_radius + (rng.next_f64() * spring_length.max(20.0) * 0.35);
                pos[i] = Vec2 {
                    x: angle.cos() * radius,
                    y: angle.sin() * radius,
                };
            }
        }

        let mut edges = Vec::with_capacity(graph.edges.len());
        let mut degrees = vec![0usize; n];
        for edge in &graph.edges {
            if let (Some(&a), Some(&b)) = (id_to_idx.get(&edge.source), id_to_idx.get(&edge.target)) {
                if a != b {
                    edges.push((a, b));
                    degrees[a] += 1;
                    degrees[b] += 1;
                }
            }
        }

        Self {
            ids,
            nodes: graph.nodes.clone(),
            pos,
            vel,
            edges,
            degrees,
            iterations,
            current_iter: 0,
            repulsion,
            spring_length,
            spring_stiffness,
            center_gravity,
            damping,
            theta,
            declump_iterations,
            declump_padding,
            declump_max_step,
            layout_options: options.clone(),
        }
    }

    fn build_quadtree(&self) -> Vec<QuadCell> {
        let n = self.pos.len();
        if n == 0 {
            return Vec::new();
        }

        let mut min_x = self.pos[0].x;
        let mut max_x = self.pos[0].x;
        let mut min_y = self.pos[0].y;
        let mut max_y = self.pos[0].y;
        for p in &self.pos {
            min_x = min_x.min(p.x);
            max_x = max_x.max(p.x);
            min_y = min_y.min(p.y);
            max_y = max_y.max(p.y);
        }
        let span = (max_x - min_x).max(max_y - min_y).max(1.0);
        let root = QuadCell {
            center: Vec2 {
                x: (min_x + max_x) / 2.0,
                y: (min_y + max_y) / 2.0,
            },
            half_size: (span / 2.0) + 1.0,
            mass: 0.0,
            center_of_mass: Vec2::default(),
            point: None,
            children: [None, None, None, None],
        };

        let mut tree = vec![root];
        for idx in 0..n {
            self.insert_quad_point(&mut tree, 0, idx, 0);
        }
        self.compute_quad_mass(&mut tree, 0);
        tree
    }

    fn quad_child_index(cell: &QuadCell, pos: Vec2) -> usize {
        let right = pos.x >= cell.center.x;
        let bottom = pos.y >= cell.center.y;
        match (right, bottom) {
            (false, false) => 0,
            (true, false) => 1,
            (false, true) => 2,
            (true, true) => 3,
        }
    }

    fn ensure_quad_children(&self, tree: &mut Vec<QuadCell>, cell_idx: usize) {
        if tree[cell_idx].children[0].is_some() {
            return;
        }
        let center = tree[cell_idx].center;
        let child_half = (tree[cell_idx].half_size / 2.0).max(0.5);
        let offsets = [
            (-child_half, -child_half),
            (child_half, -child_half),
            (-child_half, child_half),
            (child_half, child_half),
        ];
        let mut children = [None, None, None, None];
        for (idx, (ox, oy)) in offsets.into_iter().enumerate() {
            let next_idx = tree.len();
            tree.push(QuadCell {
                center: Vec2 {
                    x: center.x + ox,
                    y: center.y + oy,
                },
                half_size: child_half,
                mass: 0.0,
                center_of_mass: Vec2::default(),
                point: None,
                children: [None, None, None, None],
            });
            children[idx] = Some(next_idx);
        }
        tree[cell_idx].children = children;
    }

    fn insert_quad_point(&self, tree: &mut Vec<QuadCell>, cell_idx: usize, point_idx: usize, depth: usize) {
        const MAX_DEPTH: usize = 24;
        if depth >= MAX_DEPTH {
            tree[cell_idx].point = Some(point_idx);
            return;
        }

        if tree[cell_idx].point.is_none() && tree[cell_idx].children[0].is_none() {
            tree[cell_idx].point = Some(point_idx);
            return;
        }

        if let Some(existing) = tree[cell_idx].point.take() {
            self.ensure_quad_children(tree, cell_idx);
            let existing_child = {
                let cell = &tree[cell_idx];
                let quadrant = Self::quad_child_index(cell, self.pos[existing]);
                cell.children[quadrant].unwrap()
            };
            self.insert_quad_point(tree, existing_child, existing, depth + 1);
        }

        self.ensure_quad_children(tree, cell_idx);
        let child_idx = {
            let cell = &tree[cell_idx];
            let quadrant = Self::quad_child_index(cell, self.pos[point_idx]);
            cell.children[quadrant].unwrap()
        };
        self.insert_quad_point(tree, child_idx, point_idx, depth + 1);
    }

    fn compute_quad_mass(&self, tree: &mut Vec<QuadCell>, cell_idx: usize) -> (f64, Vec2) {
        if let Some(point_idx) = tree[cell_idx].point {
            let pos = self.pos[point_idx];
            tree[cell_idx].mass = 1.0;
            tree[cell_idx].center_of_mass = pos;
            return (1.0, pos);
        }

        let mut mass = 0.0;
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let children = tree[cell_idx].children;
        for child_idx in children.into_iter().flatten() {
            let (child_mass, child_com) = self.compute_quad_mass(tree, child_idx);
            if child_mass <= 0.0 {
                continue;
            }
            mass += child_mass;
            sum_x += child_com.x * child_mass;
            sum_y += child_com.y * child_mass;
        }

        tree[cell_idx].mass = mass;
        if mass > 0.0 {
            tree[cell_idx].center_of_mass = Vec2 {
                x: sum_x / mass,
                y: sum_y / mass,
            };
        } else {
            tree[cell_idx].center_of_mass = tree[cell_idx].center;
        }
        (tree[cell_idx].mass, tree[cell_idx].center_of_mass)
    }

    fn accumulate_repulsion(&self, tree: &[QuadCell], cell_idx: usize, node_idx: usize, acc: &mut Vec2) {
        let cell = &tree[cell_idx];
        if cell.mass <= 0.0 {
            return;
        }
        if cell.point == Some(node_idx) && cell.children[0].is_none() {
            return;
        }

        let dx = cell.center_of_mass.x - self.pos[node_idx].x;
        let dy = cell.center_of_mass.y - self.pos[node_idx].y;
        let mut d2 = (dx * dx) + (dy * dy);
        if d2 < 0.01 {
            d2 = 0.01;
        }
        let d = d2.sqrt();
        let width = cell.half_size * 2.0;
        let is_leaf = cell.children[0].is_none();

        if is_leaf || (width / d) < self.theta {
            let force = self.repulsion * cell.mass / d2;
            acc.x -= (dx / d) * force;
            acc.y -= (dy / d) * force;
            return;
        }

        for child_idx in cell.children.into_iter().flatten() {
            self.accumulate_repulsion(tree, child_idx, node_idx, acc);
        }
    }

    fn step(&mut self, steps: usize) -> (HashMap<String, Position>, bool) {
        let n = self.pos.len();
        if n == 0 {
            return (HashMap::new(), true);
        }

        let step_count = steps.max(1);
        for _ in 0..step_count {
            if self.current_iter >= self.iterations {
                break;
            }

            let mut acc = vec![Vec2::default(); n];
            let tree = self.build_quadtree();

            for i in 0..n {
                self.accumulate_repulsion(&tree, 0, i, &mut acc[i]);
            }

            for (a, b) in &self.edges {
                let dx = self.pos[*b].x - self.pos[*a].x;
                let dy = self.pos[*b].y - self.pos[*a].y;
                let mut d = ((dx * dx) + (dy * dy)).sqrt();
                if d < 0.01 {
                    d = 0.01;
                }
                let delta = d - self.spring_length;
                let degree_scale = ((self.degrees[*a].max(self.degrees[*b]).max(1)) as f64).sqrt();
                let force = (self.spring_stiffness * delta) / degree_scale;
                let fx = (dx / d) * force;
                let fy = (dy / d) * force;
                acc[*a].x += fx;
                acc[*a].y += fy;
                acc[*b].x -= fx;
                acc[*b].y -= fy;
            }

            for i in 0..n {
                acc[i].x += -self.pos[i].x * self.center_gravity;
                acc[i].y += -self.pos[i].y * self.center_gravity;
            }

            let cooling = 1.0 - (self.current_iter as f64 / (self.iterations as f64 + 1.0));
            for i in 0..n {
                self.vel[i].x = (self.vel[i].x + acc[i].x) * self.damping * cooling;
                self.vel[i].y = (self.vel[i].y + acc[i].y) * self.damping * cooling;
                self.pos[i].x += self.vel[i].x;
                self.pos[i].y += self.vel[i].y;
            }

            self.current_iter += 1;
        }

        self.normalize_positions();
        let done = self.current_iter >= self.iterations;
        (to_positions(&self.ids, &self.pos), done)
    }

    fn run_to_completion(mut self) -> HashMap<String, Position> {
        while self.current_iter < self.iterations {
            let _ = self.step(64);
        }
        self.normalize_positions();
        to_positions(&self.ids, &self.pos)
    }

    fn normalize_positions(&mut self) {
        let n = self.pos.len();
        if n == 0 {
            return;
        }

        let mut min_x = self.pos[0].x;
        let mut max_x = self.pos[0].x;
        let mut min_y = self.pos[0].y;
        let mut max_y = self.pos[0].y;
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        for pos in &self.pos {
            min_x = min_x.min(pos.x);
            max_x = max_x.max(pos.x);
            min_y = min_y.min(pos.y);
            max_y = max_y.max(pos.y);
            sum_x += pos.x;
            sum_y += pos.y;
        }

        let center = Vec2 {
            x: sum_x / n as f64,
            y: sum_y / n as f64,
        };
        let current_span = (max_x - min_x).max(max_y - min_y).max(1.0);
        let target_span = (self.spring_length * (n as f64).sqrt() * 2.6).max(self.spring_length * 6.0);
        let scale = (target_span / current_span).max(1.0);

        for pos in &mut self.pos {
            pos.x = (pos.x - center.x) * scale;
            pos.y = (pos.y - center.y) * scale;
        }
    }

    fn declump_options_map(&self) -> Map<String, Value> {
        let mut options = Map::new();
        options.insert("declump_iterations".to_string(), json!(self.declump_iterations));
        options.insert("declump_padding".to_string(), json!(self.declump_padding));
        options.insert("declump_max_step".to_string(), json!(self.declump_max_step));
        options
    }
}

fn declump_positions(graph: &Graph, positions: &mut [Vec2], options: &Map<String, Value>) {
    if positions.len() < 2 {
        return;
    }

    let iterations = option_f64(options, "declump_iterations", 18.0).round().clamp(0.0, 80.0) as usize;
    if iterations == 0 {
        return;
    }
    let padding = option_f64(options, "declump_padding", 24.0).clamp(0.0, 200.0);
    let max_step = option_f64(options, "declump_max_step", 28.0).clamp(1.0, 200.0);

    let boxes: Vec<Vec2> = graph.nodes.iter().map(node_box_size).collect();
    let count = positions.len();
    for _ in 0..iterations {
        let mut offsets = vec![Vec2::default(); count];
        let mut any_overlap = false;

        for a in 0..count {
            for b in (a + 1)..count {
                let dx = positions[b].x - positions[a].x;
                let dy = positions[b].y - positions[a].y;
                let required_x = ((boxes[a].x + boxes[b].x) / 2.0) + padding;
                let required_y = ((boxes[a].y + boxes[b].y) / 2.0) + padding;
                let overlap_x = required_x - dx.abs();
                let overlap_y = required_y - dy.abs();

                if overlap_x <= 0.0 || overlap_y <= 0.0 {
                    continue;
                }
                any_overlap = true;

                let push = overlap_x.min(overlap_y).min(max_step) * 0.5;
                let angle = if dx.abs() >= dy.abs() {
                    Vec2 {
                        x: if dx >= 0.0 { 1.0 } else { -1.0 },
                        y: if dy.abs() < 1.0 { 0.0 } else { dy.signum() * 0.15 },
                    }
                } else {
                    Vec2 {
                        x: if dx.abs() < 1.0 { 0.0 } else { dx.signum() * 0.15 },
                        y: if dy >= 0.0 { 1.0 } else { -1.0 },
                    }
                };

                offsets[a].x -= angle.x * push;
                offsets[a].y -= angle.y * push;
                offsets[b].x += angle.x * push;
                offsets[b].y += angle.y * push;
            }
        }

        for (pos, offset) in positions.iter_mut().zip(offsets.iter()) {
            pos.x += offset.x;
            pos.y += offset.y;
        }

        if !any_overlap {
            break;
        }
    }
}

fn radial_layout(graph: &Graph, options: &Map<String, Value>) -> HashMap<String, Position> {
    let n = graph.nodes.len();
    if n == 0 {
        return HashMap::new();
    }

    let ring_gap = option_f64(options, "ring_gap", 120.0).max(20.0);
    let clockwise = option_bool(options, "clockwise", true);
    let spacing = graph_node_spacing(graph);

    let adj = adjacency(graph);
    let degrees: Vec<usize> = adj.iter().map(|a| a.len()).collect();

    // Rings are breadth-first distance from the query's start nodes; other
    // components continue outward from their best-connected node.
    let mut level = vec![usize::MAX; n];
    let mut roots: Vec<usize> = (0..n).filter(|&i| graph.nodes[i].is_start).collect();
    if roots.is_empty() {
        roots.push((0..n).max_by(|&a, &b| degrees[a].cmp(&degrees[b]).then_with(|| b.cmp(&a))).unwrap_or(0));
    }
    let assign = |sources: &[usize], base: usize, level: &mut Vec<usize>| {
        let mut q = VecDeque::new();
        for &r in sources {
            if level[r] == usize::MAX {
                level[r] = base;
                q.push_back(r);
            }
        }
        let mut deepest = base;
        while let Some(cur) = q.pop_front() {
            for &nb in &adj[cur] {
                if level[nb] == usize::MAX {
                    level[nb] = level[cur] + 1;
                    deepest = deepest.max(level[nb]);
                    q.push_back(nb);
                }
            }
        }
        deepest
    };
    let mut deepest = assign(&roots, 0, &mut level);
    loop {
        let rest = (0..n)
            .filter(|&i| level[i] == usize::MAX)
            .max_by(|&a, &b| degrees[a].cmp(&degrees[b]).then_with(|| b.cmp(&a)));
        match rest {
            Some(r) => deepest = assign(&[r], deepest + 1, &mut level),
            None => break,
        }
    }

    let levels = deepest + 1;
    let mut rings: Vec<Vec<usize>> = vec![Vec::new(); levels];
    for i in 0..n {
        rings[level[i]].push(i);
    }

    let direction = if clockwise { 1.0 } else { -1.0 };
    let mut angle = vec![0.0f64; n];
    let mut out = HashMap::with_capacity(n);
    let mut radius = 0.0f64;
    for (lv, members) in rings.iter_mut().enumerate() {
        if members.is_empty() {
            continue;
        }
        // Order each ring by the mean angle of its neighbours on the ring
        // inside it, so edges between rings cross less.
        if lv > 0 {
            let key: Vec<f64> = members
                .iter()
                .map(|&m| {
                    let (mut sx, mut sy) = (0.0, 0.0);
                    for &nb in &adj[m] {
                        if level[nb] + 1 == lv {
                            sx += angle[nb].cos();
                            sy += angle[nb].sin();
                        }
                    }
                    if sx == 0.0 && sy == 0.0 { f64::MAX } else { sy.atan2(sx).rem_euclid(std::f64::consts::TAU) }
                })
                .collect();
            let mut order: Vec<usize> = (0..members.len()).collect();
            order.sort_by(|&a, &b| key[a].partial_cmp(&key[b]).unwrap_or(std::cmp::Ordering::Equal).then_with(|| members[a].cmp(&members[b])));
            *members = order.into_iter().map(|i| members[i]).collect();
        }
        let count = members.len();
        // A ring is at least one gap outside the previous one and large enough
        // to hold its members without touching.
        let needed = if count == 1 && lv == 0 { 0.0 } else { (count as f64 * spacing) / std::f64::consts::TAU };
        radius = if lv == 0 { needed } else { (radius + ring_gap).max(needed) };
        let offset = if lv > 0 && count > 0 {
            // Start the ring near its first member's preferred angle.
            let first = members[0];
            let (mut sx, mut sy) = (0.0, 0.0);
            for &nb in &adj[first] {
                if level[nb] + 1 == lv {
                    sx += angle[nb].cos();
                    sy += angle[nb].sin();
                }
            }
            if sx == 0.0 && sy == 0.0 { 0.0 } else { sy.atan2(sx) }
        } else {
            0.0
        };
        for (i, &idx) in members.iter().enumerate() {
            let a = offset + direction * (std::f64::consts::TAU * i as f64) / count as f64;
            angle[idx] = a;
            out.insert(graph.nodes[idx].id.clone(), Position { x: radius * a.cos(), y: radius * a.sin() });
        }
    }
    out
}

fn circle_layout(graph: &Graph, options: &Map<String, Value>) -> HashMap<String, Position> {
    let n = graph.nodes.len();
    if n == 0 {
        return HashMap::new();
    }

    let min_radius = option_f64(options, "radius", 360.0).max(20.0);
    let start_angle = option_f64(options, "start_angle_deg", -90.0) * (std::f64::consts::PI / 180.0);
    let clockwise = option_bool(options, "clockwise", true);
    let direction = if clockwise { 1.0 } else { -1.0 };
    let spacing = graph_node_spacing(graph);

    // One ring holds everything if, fitted to the view, neighbours on it stay
    // apart. Otherwise use concentric rings with equal spacing along each.
    let (view_w, view_h) = viewport(options);
    let view = view_w.min(view_h) - 2.0 * FIT_PADDING;
    let on_screen_gap = std::f64::consts::PI * view / n as f64;
    let mut rings: Vec<(f64, usize)> = Vec::new();
    if on_screen_gap >= screen_node_spacing(graph, options) {
        rings.push((min_radius.max(n as f64 * spacing / std::f64::consts::TAU), n));
    } else {
        let mut remaining = n;
        let mut radius = spacing * 1.5;
        while remaining > 0 {
            let capacity = ((std::f64::consts::TAU * radius) / spacing).floor().max(1.0) as usize;
            let count = capacity.min(remaining);
            rings.push((radius, count));
            remaining -= count;
            radius += spacing * 1.25;
        }
        // Fill from the outside in, so the outer ring is full.
        let total_capacity: usize = rings.iter().map(|r| r.1).sum();
        debug_assert_eq!(total_capacity, n);
        rings.reverse();
    }

    let mut out = HashMap::with_capacity(n);
    let mut index = 0usize;
    for (radius, count) in rings {
        for i in 0..count {
            let fraction = (std::f64::consts::TAU * i as f64) / count as f64;
            let angle = start_angle + direction * fraction;
            out.insert(
                graph.nodes[index].id.clone(),
                Position { x: angle.cos() * radius, y: angle.sin() * radius },
            );
            index += 1;
        }
    }
    out
}

fn bfs_distances(roots: &[usize], adjacency: &[Vec<usize>]) -> Vec<Option<usize>> {
    let mut distances = vec![None; adjacency.len()];
    let mut queue = VecDeque::new();
    for &root in roots {
        if root >= adjacency.len() || distances[root].is_some() {
            continue;
        }
        distances[root] = Some(0);
        queue.push_back(root);
    }
    while let Some(current) = queue.pop_front() {
        let next_distance = distances[current].unwrap_or(0) + 1;
        for &next in &adjacency[current] {
            if distances[next].is_some() {
                continue;
            }
            distances[next] = Some(next_distance);
            queue.push_back(next);
        }
    }
    distances
}

fn path_layout(graph: &Graph, options: &Map<String, Value>) -> HashMap<String, Position> {
    let n = graph.nodes.len();
    if n == 0 {
        return HashMap::new();
    }

    let layer_gap = option_f64(options, "layer_gap", 260.0).max(40.0);
    let node_gap = option_f64(options, "node_gap", 52.0).max(10.0);
    let component_gap = option_f64(options, "component_gap", 180.0).max(20.0);

    let mut id_to_idx = HashMap::with_capacity(n);
    for (i, node) in graph.nodes.iter().enumerate() {
        id_to_idx.insert(node.id.clone(), i);
    }

    let mut forward = vec![Vec::new(); n];
    let mut reverse = vec![Vec::new(); n];
    let mut indegree = vec![0usize; n];
    let mut outdegree = vec![0usize; n];
    for edge in &graph.edges {
        if let (Some(&a), Some(&b)) = (id_to_idx.get(&edge.source), id_to_idx.get(&edge.target)) {
            if a == b {
                continue;
            }
            forward[a].push(b);
            reverse[b].push(a);
            outdegree[a] += 1;
            indegree[b] += 1;
        }
    }

    let mut starts: Vec<usize> = graph.nodes.iter().enumerate()
        .filter_map(|(i, node)| if node.is_start { Some(i) } else { None })
        .collect();
    if starts.is_empty() {
        starts = indegree.iter().enumerate()
            .filter_map(|(i, &deg)| if deg == 0 { Some(i) } else { None })
            .collect();
    }
    if starts.is_empty() {
        starts.push(0);
    }

    let mut ends: Vec<usize> = graph.nodes.iter().enumerate()
        .filter_map(|(i, node)| if node.is_end { Some(i) } else { None })
        .collect();
    if ends.is_empty() {
        ends = outdegree.iter().enumerate()
            .filter_map(|(i, &deg)| if deg == 0 { Some(i) } else { None })
            .collect();
    }
    if ends.is_empty() {
        ends.push(n.saturating_sub(1));
    }

    let start_dist = bfs_distances(&starts, &forward);
    let end_dist = bfs_distances(&ends, &reverse);

    let max_start = start_dist.iter().filter_map(|d| *d).max().unwrap_or(0);
    let max_end = end_dist.iter().filter_map(|d| *d).max().unwrap_or(0);
    let max_columns = (max_start + max_end).max(2);
    let mut layers: HashMap<usize, Vec<usize>> = HashMap::new();
    for idx in 0..n {
        let layer = match (start_dist[idx], end_dist[idx]) {
            (Some(0), _) if graph.nodes[idx].is_start => 0,
            (_, Some(0)) if graph.nodes[idx].is_end => max_columns,
            (Some(ds), Some(de)) => {
                let total = (ds + de).max(1) as f64;
                let ratio = ds as f64 / total;
                let mut column = (ratio * max_columns as f64).round() as usize;
                if ds > 0 {
                    column = column.max(1);
                }
                if de > 0 {
                    column = column.min(max_columns.saturating_sub(1));
                }
                column
            }
            (Some(ds), None) => ds.min(max_columns.saturating_sub(1)),
            (None, Some(de)) => max_columns.saturating_sub(de.min(max_columns.saturating_sub(1))),
            (None, None) => max_columns / 2,
        };
        layers.entry(layer).or_default().push(idx);
    }

    let mut ordered_layers: Vec<usize> = layers.keys().copied().collect();
    ordered_layers.sort_unstable();

    let boxes: Vec<Vec2> = graph.nodes.iter().map(node_box_size).collect();
    let mut sorted_layers: Vec<(usize, Vec<usize>)> = Vec::with_capacity(ordered_layers.len());
    for layer in &ordered_layers {
        let mut members = layers.remove(layer).unwrap_or_default();
        members.sort_by(|&a, &b| {
            let a_start = start_dist[a].unwrap_or(usize::MAX);
            let b_start = start_dist[b].unwrap_or(usize::MAX);
            let a_end = end_dist[a].unwrap_or(usize::MAX);
            let b_end = end_dist[b].unwrap_or(usize::MAX);
            let a_pull = outdegree[a] as isize - indegree[a] as isize;
            let b_pull = outdegree[b] as isize - indegree[b] as isize;
            a_start
                .cmp(&b_start)
                .then_with(|| a_end.cmp(&b_end))
                .then_with(|| b_pull.cmp(&a_pull))
                .then_with(|| outdegree[b].cmp(&outdegree[a]))
                .then_with(|| indegree[a].cmp(&indegree[b]))
                .then_with(|| graph.nodes[a].label.cmp(&graph.nodes[b].label))
                .then_with(|| graph.nodes[a].id.cmp(&graph.nodes[b].id))
        });
        sorted_layers.push((*layer, members));
    }

    // A layer taller than the others would make a long thin picture, so layers
    // wrap into sub-columns. The row limit is chosen so the whole layout comes
    // closest to the view's aspect ratio.
    let row_height = boxes.iter().map(|b| b.y).fold(0.0_f64, f64::max) + node_gap;
    let column_widths: Vec<f64> = sorted_layers
        .iter()
        .map(|(_, members)| {
            members.iter().map(|&idx| boxes[idx].x).fold(0.0_f64, f64::max).max(layer_gap * 0.4)
        })
        .collect();
    let sub_gap = node_gap * 1.5;
    let (view_w, view_h) = viewport(options);
    let target_aspect = (view_w / view_h).max(0.2);
    let tallest = sorted_layers.iter().map(|(_, m)| m.len()).max().unwrap_or(1).max(1);
    let size_for = |rows: usize| -> (f64, f64) {
        let mut width = 0.0;
        for (i, (_, members)) in sorted_layers.iter().enumerate() {
            let columns = members.len().div_ceil(rows).max(1) as f64;
            width += columns * column_widths[i] + (columns - 1.0) * sub_gap;
            if i + 1 < sorted_layers.len() {
                width += component_gap;
            }
        }
        (width, rows.min(tallest) as f64 * row_height)
    };
    let mut rows_max = tallest;
    let mut best = f64::MAX;
    for rows in 1..=tallest {
        let (w, h) = size_for(rows);
        let score = ((w / h.max(1.0)) / target_aspect).ln().abs();
        if score < best - 1e-9 {
            best = score;
            rows_max = rows;
        }
    }

    let mut out = HashMap::with_capacity(n);
    let mut x_offset = 0.0;
    for (i, (_, members)) in sorted_layers.iter().enumerate() {
        let columns = members.len().div_ceil(rows_max).max(1);
        let per_column = members.len().div_ceil(columns).max(1);
        for (c, chunk) in members.chunks(per_column).enumerate() {
            let x = x_offset + c as f64 * (column_widths[i] + sub_gap);
            let total_height = chunk.len() as f64 * row_height - node_gap;
            let mut y = -(total_height / 2.0);
            for &idx in chunk {
                y += (row_height - node_gap) / 2.0;
                out.insert(graph.nodes[idx].id.clone(), Position { x, y });
                y += (row_height - node_gap) / 2.0 + node_gap;
            }
        }
        x_offset += columns as f64 * column_widths[i] + (columns as f64 - 1.0) * sub_gap + component_gap;
    }

    out
}

fn max_usize(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

fn clamp_f64(v: f64, lo: f64, hi: f64) -> f64 {
    if v < lo {
        return lo;
    }
    if v > hi {
        return hi;
    }
    v
}

fn node_visual_gap(node: &Node, inter_node_spacing: f64) -> f64 {
    let size = node.render_size.max(0.0);
    (size * 2.8).max(inter_node_spacing * 0.6)
}

fn positions_are_finite(positions: &HashMap<String, Position>) -> bool {
    !positions.is_empty()
        && positions
            .values()
            .all(|pos| pos.x.is_finite() && pos.y.is_finite())
}

fn phyllotaxis_layout(graph: &Graph, spacing: f64) -> HashMap<String, Position> {
    let mut positions = HashMap::with_capacity(graph.nodes.len());
    let golden_angle = std::f64::consts::PI * (3.0 - 5.0_f64.sqrt());
    for (index, node) in graph.nodes.iter().enumerate() {
        let base_gap = node_visual_gap(node, spacing.max(12.0));
        let radius = base_gap * (index as f64 + 1.0).sqrt();
        let angle = index as f64 * golden_angle;
        positions.insert(
            node.id.clone(),
            Position {
                x: angle.cos() * radius,
                y: angle.sin() * radius,
            },
        );
    }
    positions
}

fn build_edge_weights(adj: &[Vec<usize>]) -> Vec<HashMap<usize, f64>> {
    let n = adj.len();
    let mut neighbor_sets: Vec<HashSet<usize>> = Vec::with_capacity(n);
    for neighbors in adj {
        let mut set = HashSet::with_capacity(neighbors.len());
        for nb in neighbors {
            set.insert(*nb);
        }
        neighbor_sets.push(set);
    }
    let mut weights: Vec<HashMap<usize, f64>> = (0..n).map(|_| HashMap::new()).collect();
    for i in 0..n {
        for nb in &adj[i] {
            if weights[i].contains_key(nb) {
                continue;
            }
            let (small, large) = if adj[i].len() <= adj[*nb].len() {
                (i, *nb)
            } else {
                (*nb, i)
            };
            let mut common = 0usize;
            for candidate in &adj[small] {
                if *candidate == large {
                    continue;
                }
                if neighbor_sets[large].contains(candidate) {
                    common += 1;
                }
            }
            let weight = 1.0 + (2.0 * common as f64);
            weights[i].insert(*nb, weight);
            weights[*nb].insert(i, weight);
        }
    }
    weights
}

fn detect_communities(
    ids: &[String],
    adj: &[Vec<usize>],
    edge_weights: &[HashMap<usize, f64>],
    degrees: &[usize],
) -> Vec<usize> {
    let n = ids.len();
    let mut labels: Vec<usize> = (0..n).collect();
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by(|left, right| {
        let dl = degrees[*left];
        let dr = degrees[*right];
        dr.cmp(&dl).then_with(|| ids[*left].cmp(&ids[*right]))
    });
    for _ in 0..12 {
        let mut changed = false;
        for idx in &order {
            if adj[*idx].is_empty() {
                continue;
            }
            let mut scores: HashMap<usize, f64> = HashMap::new();
            for nb in &adj[*idx] {
                let entry = scores.entry(labels[*nb]).or_insert(0.0);
                let weight = edge_weights[*idx].get(nb).copied().unwrap_or(1.0);
                *entry += weight + (0.15 * (max_usize(1, degrees[*nb]) as f64).sqrt());
            }
            let mut best_label = labels[*idx];
            let mut best_score = -1.0f64;
            for (label, score) in scores {
                if score > best_score || ((score - best_score).abs() < 1e-9 && label < best_label) {
                    best_label = label;
                    best_score = score;
                }
            }
            if best_label != labels[*idx] {
                labels[*idx] = best_label;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    labels
}

// ---------------------------------------------------------------------------
// Shared helpers: canonical input order and screen-aware spacing.

/// The UI fits the layout into its view with this margin, in pixels.
const FIT_PADDING: f64 = 30.0;

/// Node icons are drawn at this multiple of the node's size.
const ICON_SCALE: f64 = 1.2;

/// Sorts nodes by label then ID, and edges by their endpoints' positions in
/// that order, so a layout never depends on the order the server sent the
/// graph in. Labels come first because node IDs can change between server runs.
fn canonical_graph(graph: &Graph) -> Graph {
    let mut nodes = graph.nodes.clone();
    nodes.sort_by(|a, b| a.label.cmp(&b.label).then_with(|| a.id.cmp(&b.id)));
    let rank: HashMap<&str, usize> = nodes.iter().enumerate().map(|(i, n)| (n.id.as_str(), i)).collect();
    let mut edges = graph.edges.clone();
    edges.sort_by_key(|e| {
        (
            rank.get(e.source.as_str()).copied().unwrap_or(usize::MAX),
            rank.get(e.target.as_str()).copied().unwrap_or(usize::MAX),
        )
    });
    Graph { nodes, edges }
}

/// Undirected adjacency by node position, without self loops or duplicates.
fn adjacency(graph: &Graph) -> Vec<Vec<usize>> {
    let index: HashMap<&str, usize> = graph.nodes.iter().enumerate().map(|(i, n)| (n.id.as_str(), i)).collect();
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); graph.nodes.len()];
    for e in &graph.edges {
        if let (Some(&a), Some(&b)) = (index.get(e.source.as_str()), index.get(e.target.as_str())) {
            if a != b {
                adj[a].push(b);
                adj[b].push(a);
            }
        }
    }
    for list in &mut adj {
        list.sort_unstable();
        list.dedup();
    }
    adj
}

/// Largest drawn icon radius, in pixels.
fn max_render_radius(graph: &Graph) -> f64 {
    graph.nodes.iter().map(|n| n.render_size.max(4.0) * ICON_SCALE).fold(4.0, f64::max)
}

/// Centre-to-centre spacing between neighbouring nodes in layout units.
fn graph_node_spacing(graph: &Graph) -> f64 {
    2.0 * max_render_radius(graph) + 16.0
}

fn viewport(options: &Map<String, Value>) -> (f64, f64) {
    (
        option_f64(options, "viewport_width", 1400.0).max(200.0),
        option_f64(options, "viewport_height", 1000.0).max(200.0),
    )
}

/// Minimum on-screen distance between two node centres, in pixels.
fn screen_node_spacing(graph: &Graph, options: &Map<String, Value>) -> f64 {
    2.0 * max_render_radius(graph) + option_f64(options, "screen_gap", 6.0).max(0.0)
}

/// Node icons keep their pixel size while the UI scales the layout to fit the
/// view, so spacing that is enough in layout units can still overlap on
/// screen. This pushes apart nodes that would touch once fitted, recomputing
/// the fit as the layout grows. Deterministic for a given input order.
fn screen_declump(graph: &Graph, positions: &mut HashMap<String, Position>, options: &Map<String, Value>) {
    let n = graph.nodes.len();
    if n < 2 {
        return;
    }
    let (view_w, view_h) = viewport(options);
    let gap = option_f64(options, "screen_gap", 6.0).max(0.0);
    let radius: Vec<f64> = graph.nodes.iter().map(|n| n.render_size.max(4.0) * ICON_SCALE).collect();
    let max_radius = radius.iter().copied().fold(4.0, f64::max);
    let mut pos: Vec<Vec2> = graph
        .nodes
        .iter()
        .map(|node| positions.get(&node.id).map(|p| Vec2 { x: p.x, y: p.y }).unwrap_or_default())
        .collect();

    let extent = |pos: &[Vec2]| {
        let (mut min_x, mut max_x, mut min_y, mut max_y) = (f64::MAX, f64::MIN, f64::MAX, f64::MIN);
        for p in pos {
            min_x = min_x.min(p.x);
            max_x = max_x.max(p.x);
            min_y = min_y.min(p.y);
            max_y = max_y.max(p.y);
        }
        (max_x - min_x, max_y - min_y)
    };
    let (w, h) = extent(&pos);
    if w < 1e-6 && h < 1e-6 {
        // Everything on one point: spread it first.
        let spread = phyllotaxis_layout(graph, graph_node_spacing(graph));
        for (i, node) in graph.nodes.iter().enumerate() {
            if let Some(p) = spread.get(&node.id) {
                pos[i] = Vec2 { x: p.x, y: p.y };
            }
        }
    }

    for _ in 0..120 {
        let (w, h) = extent(&pos);
        let fit = ((view_w - 2.0 * FIT_PADDING) / w.max(1e-6)).min((view_h - 2.0 * FIT_PADDING) / h.max(1e-6));
        if !fit.is_finite() || fit <= 0.0 {
            break;
        }
        let cell = (2.0 * max_radius + gap) / fit;
        let key = |p: &Vec2| ((p.x / cell).floor() as i64, (p.y / cell).floor() as i64);
        let mut grid: HashMap<(i64, i64), Vec<usize>> = HashMap::new();
        for (i, p) in pos.iter().enumerate() {
            grid.entry(key(p)).or_default().push(i);
        }
        let mut delta = vec![Vec2::default(); n];
        let mut moved = false;
        for i in 0..n {
            let (cx, cy) = key(&pos[i]);
            for ox in -1..=1 {
                for oy in -1..=1 {
                    let Some(bucket) = grid.get(&(cx + ox, cy + oy)) else { continue };
                    for &j in bucket {
                        if j <= i {
                            continue;
                        }
                        let required = (radius[i] + radius[j] + gap) / fit;
                        let mut dx = pos[j].x - pos[i].x;
                        let mut dy = pos[j].y - pos[i].y;
                        let mut d = (dx * dx + dy * dy).sqrt();
                        if d >= required {
                            continue;
                        }
                        if d < 1e-9 {
                            // Coincident: separate along a direction fixed by the pair.
                            let a = (i * 31 + j * 17) as f64;
                            dx = a.cos();
                            dy = a.sin();
                            d = 1.0;
                        }
                        // Move slightly more than half the overlap each, so
                        // growth of the layout during the pass is absorbed.
                        let push = (required - d) * 0.55;
                        let (ux, uy) = (dx / d, dy / d);
                        delta[i].x -= ux * push;
                        delta[i].y -= uy * push;
                        delta[j].x += ux * push;
                        delta[j].y += uy * push;
                        moved = true;
                    }
                }
            }
        }
        if !moved {
            break;
        }
        for (p, d) in pos.iter_mut().zip(delta.iter()) {
            p.x += d.x;
            p.y += d.y;
        }
    }

    for (i, node) in graph.nodes.iter().enumerate() {
        positions.insert(node.id.clone(), Position { x: pos[i].x, y: pos[i].y });
    }
}

// ---------------------------------------------------------------------------
// Cluster layout: communities laid out internally with the force solver, then
// packed as non-overlapping circles that attract along inter-cluster links.

fn cluster_layout(graph: &Graph, options: &Map<String, Value>) -> HashMap<String, Position> {
    let n = graph.nodes.len();
    if n == 0 {
        return HashMap::new();
    }
    let cluster_padding = option_f64(options, "cluster_padding", 180.0).max(20.0);
    let intra_spacing = option_f64(options, "intra_cluster_spacing", 46.0).max(8.0);
    let inter_node_spacing = option_f64(options, "inter_node_spacing", 180.0).max(8.0);
    let bridge_pull = clamp_f64(option_f64(options, "bridge_pull", 0.7), 0.0, 2.0);
    let iterations = option_f64(options, "iterations", 220.0).max(20.0).round() as usize;
    let seed = option_f64(options, "seed", 42.0).max(1.0).round();

    let ids: Vec<String> = graph.nodes.iter().map(|node| node.id.clone()).collect();
    let adj = adjacency(graph);
    let degrees: Vec<usize> = adj.iter().map(|a| a.len()).collect();
    let edge_weights = build_edge_weights(&adj);
    let labels = detect_communities(&ids, &adj, &edge_weights, &degrees);

    // Group, then fold tiny communities into the neighbour they link to most,
    // so a handful of isolated pairs does not scatter the overview.
    let mut community = labels.clone();
    for _ in 0..3 {
        let mut sizes: HashMap<usize, usize> = HashMap::new();
        for &c in &community {
            *sizes.entry(c).or_default() += 1;
        }
        let mut changed = false;
        for i in 0..n {
            if sizes[&community[i]] >= 3 || adj[i].is_empty() {
                continue;
            }
            let mut links: Vec<(usize, usize)> = Vec::new();
            for &nb in &adj[i] {
                if community[nb] == community[i] {
                    continue;
                }
                match links.iter_mut().find(|(c, _)| *c == community[nb]) {
                    Some(entry) => entry.1 += 1,
                    None => links.push((community[nb], 1)),
                }
            }
            if let Some(&(target, _)) = links.iter().max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0))) {
                if sizes.get(&target).copied().unwrap_or(0) >= sizes[&community[i]] {
                    community[i] = target;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut group_of_label: HashMap<usize, usize> = HashMap::new();
    for i in 0..n {
        let g = *group_of_label.entry(community[i]).or_insert_with(|| {
            groups.push(Vec::new());
            groups.len() - 1
        });
        groups[g].push(i);
    }
    let mut group_of = vec![0usize; n];
    for (g, members) in groups.iter().enumerate() {
        for &m in members {
            group_of[m] = g;
        }
    }

    // Lay out each community with the force solver on its own subgraph.
    let spacing = graph_node_spacing(graph).max(node_visual_gap(&graph.nodes[0], inter_node_spacing) * 0.5);
    let mut local: Vec<Vec<Vec2>> = Vec::with_capacity(groups.len());
    let mut radius: Vec<f64> = Vec::with_capacity(groups.len());
    for members in &groups {
        if members.len() == 1 {
            local.push(vec![Vec2::default()]);
            radius.push(spacing * 0.6);
            continue;
        }
        let member_set: HashMap<&str, ()> = members.iter().map(|&m| (ids[m].as_str(), ())).collect();
        let sub = Graph {
            nodes: members.iter().map(|&m| graph.nodes[m].clone()).collect(),
            edges: graph
                .edges
                .iter()
                .filter(|e| member_set.contains_key(e.source.as_str()) && member_set.contains_key(e.target.as_str()))
                .cloned()
                .collect(),
        };
        let mut sub_options = Map::new();
        sub_options.insert("iterations".to_string(), json!(400));
        sub_options.insert("spring_length".to_string(), json!(intra_spacing.max(spacing)));
        sub_options.insert("repulsion".to_string(), json!(18000.0 * (intra_spacing.max(spacing) / 110.0).powi(2)));
        sub_options.insert("center_gravity".to_string(), json!(0.02));
        sub_options.insert("seed".to_string(), json!(seed));
        let placed = ForceStepper::new(&sub, &sub_options).run_to_completion();
        let mut pts: Vec<Vec2> = sub.nodes.iter().map(|node| placed.get(&node.id).map(|p| Vec2 { x: p.x, y: p.y }).unwrap_or_default()).collect();
        // Scale so the closest pair is one node spacing apart, then centre.
        let mut closest = f64::MAX;
        for a in 0..pts.len() {
            for b in (a + 1)..pts.len() {
                closest = closest.min(((pts[a].x - pts[b].x).powi(2) + (pts[a].y - pts[b].y).powi(2)).sqrt());
            }
        }
        let scale = if closest.is_finite() && closest > 1e-9 { spacing / closest } else { 1.0 };
        let (cx, cy) = pts.iter().fold((0.0, 0.0), |acc, p| (acc.0 + p.x, acc.1 + p.y));
        let (cx, cy) = (cx / pts.len() as f64, cy / pts.len() as f64);
        let mut r: f64 = 0.0;
        for p in &mut pts {
            p.x = (p.x - cx) * scale;
            p.y = (p.y - cy) * scale;
            r = r.max((p.x * p.x + p.y * p.y).sqrt());
        }
        local.push(pts);
        radius.push(r + spacing * 0.6);
    }

    // Communities as circles: links between communities attract, circles never
    // overlap, and communities holding start nodes sit towards the centre.
    let k = groups.len();
    let has_start: Vec<bool> = groups.iter().map(|m| m.iter().any(|&i| graph.nodes[i].is_start)).collect();
    let mut weights: HashMap<(usize, usize), f64> = HashMap::new();
    for (a, list) in adj.iter().enumerate() {
        for &b in list {
            let (ga, gb) = (group_of[a], group_of[b]);
            if ga < gb {
                *weights.entry((ga, gb)).or_default() += 1.0;
            }
        }
    }
    let mut weight_list: Vec<((usize, usize), f64)> = weights.into_iter().collect();
    weight_list.sort_by(|a, b| a.0.cmp(&b.0));

    let mut order: Vec<usize> = (0..k).collect();
    order.sort_by(|&a, &b| has_start[b].cmp(&has_start[a]).then_with(|| groups[b].len().cmp(&groups[a].len())).then_with(|| a.cmp(&b)));
    let mean_radius = radius.iter().sum::<f64>() / k as f64;
    let golden = std::f64::consts::PI * (3.0 - 5.0_f64.sqrt());
    let mut center = vec![Vec2::default(); k];
    for (rank, &g) in order.iter().enumerate() {
        let r = (mean_radius * 2.0 + cluster_padding) * (rank as f64).sqrt();
        let a = rank as f64 * golden;
        center[g] = Vec2 { x: r * a.cos(), y: r * a.sin() };
    }
    for step in 0..iterations {
        let cooling = 1.0 - step as f64 / (iterations as f64 + 1.0);
        let mut acc = vec![Vec2::default(); k];
        for &((a, b), w) in &weight_list {
            let dx = center[b].x - center[a].x;
            let dy = center[b].y - center[a].y;
            let d = (dx * dx + dy * dy).sqrt().max(1e-6);
            let ideal = radius[a] + radius[b] + cluster_padding;
            let pull = 0.02 * (0.5 + bridge_pull) * w.sqrt() * (d - ideal);
            acc[a].x += dx / d * pull;
            acc[a].y += dy / d * pull;
            acc[b].x -= dx / d * pull;
            acc[b].y -= dy / d * pull;
        }
        for g in 0..k {
            let gravity = if has_start[g] { 0.05 } else { 0.015 };
            acc[g].x -= center[g].x * gravity;
            acc[g].y -= center[g].y * gravity;
        }
        for g in 0..k {
            center[g].x += acc[g].x * cooling;
            center[g].y += acc[g].y * cooling;
        }
        separate_circles(&mut center, &radius, cluster_padding);
    }
    for _ in 0..200 {
        if !separate_circles(&mut center, &radius, cluster_padding) {
            break;
        }
    }

    let mut positions = HashMap::with_capacity(n);
    for (g, members) in groups.iter().enumerate() {
        for (i, &m) in members.iter().enumerate() {
            positions.insert(ids[m].clone(), Position { x: center[g].x + local[g][i].x, y: center[g].y + local[g][i].y });
        }
    }
    if positions_are_finite(&positions) {
        positions
    } else {
        phyllotaxis_layout(graph, inter_node_spacing)
    }
}

/// Pushes overlapping circles apart; returns whether anything moved.
fn separate_circles(center: &mut [Vec2], radius: &[f64], padding: f64) -> bool {
    let k = center.len();
    let mut moved = false;
    for a in 0..k {
        for b in (a + 1)..k {
            let mut dx = center[b].x - center[a].x;
            let mut dy = center[b].y - center[a].y;
            let mut d = (dx * dx + dy * dy).sqrt();
            let required = radius[a] + radius[b] + padding;
            if d >= required {
                continue;
            }
            if d < 1e-9 {
                let angle = (a * 31 + b * 17) as f64;
                dx = angle.cos();
                dy = angle.sin();
                d = 1.0;
            }
            let push = (required - d) / 2.0;
            center[a].x -= dx / d * push;
            center[a].y -= dy / d * push;
            center[b].x += dx / d * push;
            center[b].y += dy / d * push;
            moved = true;
        }
    }
    moved
}

/// Layer of each node: breadth-first distance from the start nodes over
/// undirected edges, so every edge joins the same or neighbouring layers.
/// Components without a start node are rooted at their best-connected node.
fn layers_from_starts(graph: &Graph, adj: &[Vec<usize>]) -> Vec<usize> {
    let n = graph.nodes.len();
    let starts: Vec<usize> = (0..n).filter(|&i| graph.nodes[i].is_start).collect();
    let mut layer: Vec<Option<usize>> = bfs_distances(&starts, adj);
    loop {
        let root = (0..n)
            .filter(|&i| layer[i].is_none())
            .max_by(|&a, &b| adj[a].len().cmp(&adj[b].len()).then_with(|| b.cmp(&a)));
        let Some(root) = root else { break };
        for (i, d) in bfs_distances(&[root], adj).into_iter().enumerate() {
            if layer[i].is_none() {
                layer[i] = d;
            }
        }
    }
    layer.into_iter().map(|d| d.unwrap_or(0)).collect()
}

/// Edge crossings between each pair of neighbouring layers, counted as
/// inversions with a Fenwick tree.
fn layer_crossings(layers: &[Vec<usize>], rank: &[usize], layer_of: &[usize], adj: &[Vec<usize>]) -> usize {
    let mut total = 0;
    for l in 0..layers.len().saturating_sub(1) {
        let mut pairs: Vec<(usize, usize)> = Vec::new();
        for &u in &layers[l] {
            for &v in &adj[u] {
                if layer_of[v] == l + 1 {
                    pairs.push((rank[u], rank[v]));
                }
            }
        }
        pairs.sort_unstable();
        let size = layers[l + 1].len() + 1;
        let mut tree = vec![0usize; size + 1];
        for (seen, &(_, b)) in pairs.iter().enumerate() {
            // Earlier pairs with a larger lower end cross this one.
            let mut i = b + 1;
            let mut not_greater = 0;
            while i > 0 {
                not_greater += tree[i];
                i &= i - 1;
            }
            total += seen - not_greater;
            let mut i = b + 1;
            while i <= size {
                tree[i] += 1;
                i += i & i.wrapping_neg();
            }
        }
    }
    total
}

/// Layered layout: layers by distance from the start nodes, left to right.
/// Each layer is reordered against its neighbours in repeated barycenter
/// sweeps, keeping the order with the fewest edge crossings. Nodes are then
/// moved towards their neighbours without changing order, and layers too tall
/// for the view wrap into sub-columns.
fn layered_layout(graph: &Graph, options: &Map<String, Value>) -> HashMap<String, Position> {
    let n = graph.nodes.len();
    if n == 0 {
        return HashMap::new();
    }
    let layer_gap = option_f64(options, "layer_gap", 220.0).max(40.0);
    let node_gap = option_f64(options, "node_gap", 24.0).max(4.0);
    let sweeps = option_f64(options, "sweeps", 24.0).clamp(0.0, 200.0) as usize;

    let adj = adjacency(graph);
    let layer_of = layers_from_starts(graph, &adj);
    let depth = layer_of.iter().copied().max().unwrap_or(0) + 1;
    let mut layers: Vec<Vec<usize>> = vec![Vec::new(); depth];
    for i in 0..n {
        layers[layer_of[i]].push(i);
    }

    let mut rank = vec![0usize; n];
    let set_ranks = |layer: &[usize], rank: &mut [usize]| {
        for (r, &i) in layer.iter().enumerate() {
            rank[i] = r;
        }
    };
    set_ranks(&layers[0], &mut rank);
    let reorder = |layers: &mut [Vec<usize>], rank: &mut [usize], l: usize, against: usize| {
        let mut keyed: Vec<(f64, usize, usize)> = layers[l]
            .iter()
            .map(|&i| {
                let (sum, count) = adj[i]
                    .iter()
                    .filter(|&&j| layer_of[j] == against)
                    .fold((0.0, 0usize), |(s, c), &j| (s + rank[j] as f64, c + 1));
                let key = if count > 0 { sum / count as f64 } else { rank[i] as f64 };
                (key, rank[i], i)
            })
            .collect();
        keyed.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
        layers[l] = keyed.into_iter().map(|(_, _, i)| i).collect();
        set_ranks(&layers[l], rank);
    };
    for l in 1..depth {
        set_ranks(&layers[l], &mut rank);
        reorder(&mut layers, &mut rank, l, l - 1);
    }
    let mut best = layers.clone();
    let mut best_crossings = layer_crossings(&layers, &rank, &layer_of, &adj);
    for sweep in 0..sweeps {
        if best_crossings == 0 {
            break;
        }
        if sweep % 2 == 0 {
            for l in (0..depth.saturating_sub(1)).rev() {
                reorder(&mut layers, &mut rank, l, l + 1);
            }
        } else {
            for l in 1..depth {
                reorder(&mut layers, &mut rank, l, l - 1);
            }
        }
        let crossings = layer_crossings(&layers, &rank, &layer_of, &adj);
        if crossings < best_crossings {
            best_crossings = crossings;
            best = layers.clone();
        }
    }
    let layers = best;

    // Wrap tall layers so the whole picture matches the view's aspect ratio.
    // A wrapped layer fills row by row, so vertical order is kept.
    let boxes: Vec<Vec2> = graph.nodes.iter().map(node_box_size).collect();
    let row_height = boxes.iter().map(|b| b.y).fold(0.0_f64, f64::max) + node_gap;
    let column_width: Vec<f64> = layers
        .iter()
        .map(|m| m.iter().map(|&i| boxes[i].x).fold(0.0_f64, f64::max))
        .collect();
    let sub_gap = node_gap * 1.5;
    let tallest = layers.iter().map(|m| m.len()).max().unwrap_or(1).max(1);
    let (view_w, view_h) = viewport(options);
    let target_aspect = (view_w / view_h).max(0.2);
    let columns_for = |len: usize, rows: usize| len.div_ceil(rows).max(1);
    let mut rows_max = tallest;
    let mut best_score = f64::MAX;
    for rows in 1..=tallest {
        let mut width = 0.0;
        for (l, m) in layers.iter().enumerate() {
            let c = columns_for(m.len(), rows) as f64;
            width += c * column_width[l] + (c - 1.0) * sub_gap + if l + 1 < depth { layer_gap } else { 0.0 };
        }
        let score = ((width / (rows as f64 * row_height)) / target_aspect).ln().abs();
        if score < best_score - 1e-9 {
            best_score = score;
            rows_max = rows;
        }
    }

    let mut ys = vec![0.0_f64; n];
    let mut wrapped = vec![false; depth];
    for (l, m) in layers.iter().enumerate() {
        let columns = columns_for(m.len(), rows_max);
        let rows = m.len().div_ceil(columns);
        wrapped[l] = columns > 1;
        for (k, &i) in m.iter().enumerate() {
            ys[i] = ((k / columns) as f64 - (rows as f64 - 1.0) / 2.0) * row_height;
        }
    }

    // Straighten edges: move each unwrapped layer towards the mean height of
    // its neighbours, keeping order and at least one row between nodes. The
    // forward and backward packings are both feasible, so their mean is too.
    for pass in 0..8 {
        let order: Vec<usize> = if pass % 2 == 0 { (1..depth).collect() } else { (0..depth.saturating_sub(1)).rev().collect() };
        for l in order {
            if wrapped[l] {
                continue;
            }
            let m = &layers[l];
            let desired: Vec<f64> = m
                .iter()
                .map(|&i| {
                    let (sum, count) = adj[i]
                        .iter()
                        .filter(|&&j| layer_of[j] != l)
                        .fold((0.0, 0usize), |(s, c), &j| (s + ys[j], c + 1));
                    if count > 0 { sum / count as f64 } else { ys[i] }
                })
                .collect();
            let mut down = desired.clone();
            for k in 1..m.len() {
                down[k] = down[k].max(down[k - 1] + row_height);
            }
            let mut up = desired;
            for k in (0..m.len().saturating_sub(1)).rev() {
                up[k] = up[k].min(up[k + 1] - row_height);
            }
            for (k, &i) in m.iter().enumerate() {
                ys[i] = (down[k] + up[k]) / 2.0;
            }
        }
    }

    let mut out = HashMap::with_capacity(n);
    let mut x_offset = 0.0;
    for (l, m) in layers.iter().enumerate() {
        let columns = columns_for(m.len(), rows_max);
        for (k, &i) in m.iter().enumerate() {
            let x = x_offset + (k % columns) as f64 * (column_width[l] + sub_gap);
            out.insert(graph.nodes[i].id.clone(), Position { x, y: ys[i] });
        }
        x_offset += columns as f64 * column_width[l] + (columns as f64 - 1.0) * sub_gap + layer_gap;
    }
    out
}

/// Spread-out nodes chosen one at a time, each the farthest from those
/// already chosen. Deterministic: the first is the best-connected node.
fn farthest_pivots(adj: &[Vec<usize>], count: usize) -> Vec<Vec<f64>> {
    let n = adj.len();
    let mut rows: Vec<Vec<f64>> = Vec::with_capacity(count);
    let mut nearest = vec![f64::MAX; n];
    let mut next = (0..n).max_by(|&a, &b| adj[a].len().cmp(&adj[b].len()).then_with(|| b.cmp(&a))).unwrap_or(0);
    for _ in 0..count.min(n) {
        let row = graph_distances(next, adj);
        for i in 0..n {
            nearest[i] = nearest[i].min(row[i]);
        }
        rows.push(row);
        next = (0..n).max_by(|&a, &b| nearest[a].total_cmp(&nearest[b]).then_with(|| b.cmp(&a))).unwrap_or(0);
    }
    rows
}

/// Hop distances from one node. Nodes in other components get one more than
/// the largest distance in the graph, so components sit apart but not far.
fn graph_distances(from: usize, adj: &[Vec<usize>]) -> Vec<f64> {
    let d = bfs_distances(&[from], adj);
    let unreachable = adj.len().min(d.iter().filter_map(|x| *x).max().unwrap_or(0) + 2) as f64;
    d.into_iter().map(|x| x.map_or(unreachable, |v| v as f64)).collect()
}

/// Stress layout: places nodes so their distances on screen match their
/// distances in the graph. Starts from a pivot-based classical scaling and
/// refines by stress majorization. No randomness, so the same graph always
/// gives the same picture. Large graphs keep only the terms for neighbours and
/// for a set of pivots, which keeps the work roughly linear.
fn stress_layout(graph: &Graph, options: &Map<String, Value>) -> HashMap<String, Position> {
    let n = graph.nodes.len();
    let ids: Vec<String> = graph.nodes.iter().map(|node| node.id.clone()).collect();
    if n < 3 {
        let pos: Vec<Vec2> = (0..n).map(|i| Vec2 { x: i as f64 * graph_node_spacing(graph) * 2.0, y: 0.0 }).collect();
        return to_positions(&ids, &pos);
    }
    let edge_length = option_f64(options, "edge_length", 90.0).max(graph_node_spacing(graph));
    let iterations = option_f64(options, "iterations", 300.0).clamp(10.0, 5000.0) as usize;
    let full_limit = option_f64(options, "full_limit", 1500.0).max(3.0) as usize;
    let adj = adjacency(graph);

    // Terms: every pair for small graphs, otherwise neighbours plus pivots.
    let mut terms: Vec<Vec<(usize, f64)>> = vec![Vec::new(); n];
    let pivots = farthest_pivots(&adj, if n <= full_limit { 0 } else { 120 });
    if n <= full_limit {
        for i in 0..n {
            let row = graph_distances(i, &adj);
            terms[i] = (0..n).filter(|&j| j != i).map(|j| (j, row[j])).collect();
        }
    } else {
        for i in 0..n {
            for &j in &adj[i] {
                terms[i].push((j, 1.0));
            }
        }
        for row in &pivots {
            let p = row.iter().position(|&d| d == 0.0).unwrap_or(0);
            for i in 0..n {
                if i != p && row[i] > 1.0 {
                    terms[i].push((p, row[i]));
                    terms[p].push((i, row[i]));
                }
            }
        }
    }

    // Initial placement from classical scaling against up to 50 pivots: the
    // two strongest axes of the double-centred squared distances.
    let init_rows = farthest_pivots(&adj, 50);
    let k = init_rows.len();
    let mut c = vec![0.0_f64; n * k];
    let mut col_mean = vec![0.0; k];
    let mut row_mean = vec![0.0; n];
    let mut all_mean = 0.0;
    for (p, row) in init_rows.iter().enumerate() {
        for i in 0..n {
            let v = row[i] * row[i];
            c[i * k + p] = v;
            col_mean[p] += v / n as f64;
            row_mean[i] += v / k as f64;
            all_mean += v / (n * k) as f64;
        }
    }
    for i in 0..n {
        for p in 0..k {
            c[i * k + p] = -0.5 * (c[i * k + p] - row_mean[i] - col_mean[p] + all_mean);
        }
    }
    let mut ctc = vec![0.0_f64; k * k];
    for i in 0..n {
        for a in 0..k {
            for b in 0..k {
                ctc[a * k + b] += c[i * k + a] * c[i * k + b];
            }
        }
    }
    let mut axes: Vec<Vec<f64>> = Vec::new();
    for axis in 0..2 {
        let mut v: Vec<f64> = (0..k).map(|a| if (a + axis) % 2 == 0 { 1.0 } else { 0.5 }).collect();
        for _ in 0..200 {
            let mut w = vec![0.0; k];
            for a in 0..k {
                for b in 0..k {
                    w[a] += ctc[a * k + b] * v[b];
                }
            }
            for prev in &axes {
                let dot: f64 = w.iter().zip(prev).map(|(x, y)| x * y).sum();
                for a in 0..k {
                    w[a] -= dot * prev[a];
                }
            }
            let norm = w.iter().map(|x| x * x).sum::<f64>().sqrt();
            if norm < 1e-12 {
                break;
            }
            v = w.into_iter().map(|x| x / norm).collect();
        }
        axes.push(v);
    }
    let mut pos: Vec<Vec2> = (0..n)
        .map(|i| {
            let row = &c[i * k..(i + 1) * k];
            Vec2 {
                x: row.iter().zip(&axes[0]).map(|(x, y)| x * y).sum(),
                y: row.iter().zip(&axes[1]).map(|(x, y)| x * y).sum(),
            }
        })
        .collect();
    // Scale so the mean distance of an edge is one edge length, and break
    // ties where scaling put nodes on the same spot.
    let (mut sum, mut count) = (0.0, 0usize);
    for i in 0..n {
        for &j in &adj[i] {
            sum += ((pos[i].x - pos[j].x).powi(2) + (pos[i].y - pos[j].y).powi(2)).sqrt();
            count += 1;
        }
    }
    let scale = if sum > 1e-9 { edge_length * count as f64 / sum } else { edge_length };
    let golden_angle = std::f64::consts::PI * (3.0 - 5.0_f64.sqrt());
    for (i, p) in pos.iter_mut().enumerate() {
        let a = i as f64 * golden_angle;
        p.x = p.x * scale + a.cos() * 1e-3 * edge_length;
        p.y = p.y * scale + a.sin() * 1e-3 * edge_length;
    }

    // Stress majorization, one node at a time with weights 1/d².
    let mut previous = f64::MAX;
    for _ in 0..iterations {
        let mut stress = 0.0;
        for i in 0..n {
            let (mut wx, mut wy, mut wsum) = (0.0, 0.0, 0.0);
            for &(j, d) in &terms[i] {
                let target = d * edge_length;
                let w = 1.0 / (target * target);
                let dx = pos[i].x - pos[j].x;
                let dy = pos[i].y - pos[j].y;
                let dist = (dx * dx + dy * dy).sqrt().max(1e-9);
                wx += w * (pos[j].x + target * dx / dist);
                wy += w * (pos[j].y + target * dy / dist);
                wsum += w;
                stress += w * (dist - target).powi(2);
            }
            if wsum > 0.0 {
                pos[i] = Vec2 { x: wx / wsum, y: wy / wsum };
            }
        }
        if (previous - stress).abs() <= 1e-5 * previous {
            break;
        }
        previous = stress;
    }
    to_positions(&ids, &pos)
}

fn definitions() -> Vec<Definition> {
    vec![
        Definition {
            key: "wasm.cluster_visibility".to_string(),
            label: "Cluster Visibility".to_string(),
            description: "Communities laid out internally and packed without overlap; communities with start nodes towards the centre.".to_string(),
            supports_animation: false,
            options: vec![
                OptionDefinition { key: "cluster_padding".to_string(), label: "Cluster Padding".to_string(), r#type: "range".to_string(), default: json!(180.0), description: "Spacing between detected communities.".to_string(), unit: "px".to_string(), min: Some(40.0), max: Some(1600.0), step: Some(10.0) },
                OptionDefinition { key: "intra_cluster_spacing".to_string(), label: "Cluster Spread".to_string(), r#type: "range".to_string(), default: json!(46.0), description: "Overall spread of nodes inside a cluster.".to_string(), unit: "px".to_string(), min: Some(8.0), max: Some(240.0), step: Some(2.0) },
                OptionDefinition { key: "inter_node_spacing".to_string(), label: "Inter-node Spacing".to_string(), r#type: "range".to_string(), default: json!(180.0), description: "Spacing between rendered nodes inside a cluster.".to_string(), unit: "px".to_string(), min: Some(20.0), max: Some(800.0), step: Some(10.0) },
                OptionDefinition { key: "bridge_pull".to_string(), label: "Bridge Pull".to_string(), r#type: "range".to_string(), default: json!(0.7), description: "Bias bridge nodes toward neighboring communities.".to_string(), unit: String::new(), min: Some(0.0), max: Some(2.0), step: Some(0.05) },
                OptionDefinition { key: "iterations".to_string(), label: "Cluster Iterations".to_string(), r#type: "range".to_string(), default: json!(220.0), description: "Iterations for community-center separation.".to_string(), unit: String::new(), min: Some(20.0), max: Some(2000.0), step: Some(20.0) },
                OptionDefinition { key: "seed".to_string(), label: "Seed".to_string(), r#type: "number".to_string(), default: json!(42.0), description: "Random seed for deterministic placement.".to_string(), unit: String::new(), min: Some(1.0), max: Some(1_000_000.0), step: Some(1.0) },
            ],
        },
        Definition {
            key: "wasm.path".to_string(),
            label: "Path".to_string(),
            description: "Layered layout for query paths from sources to targets.".to_string(),
            supports_animation: false,
            options: vec![
                OptionDefinition { key: "layer_gap".to_string(), label: "Layer Gap".to_string(), r#type: "range".to_string(), default: json!(260.0), description: "Horizontal spacing between path layers.".to_string(), unit: "px".to_string(), min: Some(60.0), max: Some(800.0), step: Some(10.0) },
                OptionDefinition { key: "node_gap".to_string(), label: "Node Gap".to_string(), r#type: "range".to_string(), default: json!(52.0), description: "Vertical spacing between nodes in the same layer.".to_string(), unit: "px".to_string(), min: Some(10.0), max: Some(200.0), step: Some(2.0) },
                OptionDefinition { key: "component_gap".to_string(), label: "Column Gap".to_string(), r#type: "range".to_string(), default: json!(180.0), description: "Extra spacing between columns after label-aware sizing.".to_string(), unit: "px".to_string(), min: Some(20.0), max: Some(400.0), step: Some(10.0) },
            ],
        },
        Definition {
            key: "wasm.circle".to_string(),
            label: "Circle".to_string(),
            description: "Deterministic circular layout; concentric rings when one ring would crowd.".to_string(),
            supports_animation: false,
            options: vec![
                OptionDefinition { key: "radius".to_string(), label: "Radius".to_string(), r#type: "range".to_string(), default: json!(360.0), description: "Minimum distance from the center to the ring. Large graphs use concentric rings.".to_string(), unit: "px".to_string(), min: Some(40.0), max: Some(4000.0), step: Some(10.0) },
                OptionDefinition { key: "start_angle_deg".to_string(), label: "Start Angle".to_string(), r#type: "number".to_string(), default: json!(-90.0), description: "Rotation offset for the first node.".to_string(), unit: "deg".to_string(), min: Some(-360.0), max: Some(360.0), step: Some(5.0) },
                OptionDefinition { key: "clockwise".to_string(), label: "Clockwise".to_string(), r#type: "boolean".to_string(), default: json!(true), description: "Place nodes clockwise around the circle.".to_string(), unit: String::new(), min: None, max: None, step: None },
            ],
        },
        Definition {
            key: "wasm.force".to_string(),
            label: "Organic".to_string(),
            description: "Fast force-directed overview layout.".to_string(),
            supports_animation: true,
            options: vec![
                OptionDefinition { key: "iterations".to_string(), label: "Iterations".to_string(), r#type: "range".to_string(), default: json!(700.0), description: "Number of force-solver steps to run.".to_string(), unit: String::new(), min: Some(100.0), max: Some(5000.0), step: Some(100.0) },
                OptionDefinition { key: "repulsion".to_string(), label: "Repulsion".to_string(), r#type: "range".to_string(), default: json!(18000.0), description: "How strongly nodes push away from each other.".to_string(), unit: String::new(), min: Some(1000.0), max: Some(80000.0), step: Some(500.0) },
                OptionDefinition { key: "spring_length".to_string(), label: "Link Distance".to_string(), r#type: "range".to_string(), default: json!(110.0), description: "Preferred distance between linked nodes. Higher values spread the layout more.".to_string(), unit: "px".to_string(), min: Some(20.0), max: Some(500.0), step: Some(5.0) },
                OptionDefinition { key: "spring_stiffness".to_string(), label: "Link Pull".to_string(), r#type: "range".to_string(), default: json!(0.04), description: "How strongly links pull toward their preferred length.".to_string(), unit: String::new(), min: Some(0.001), max: Some(1.0), step: Some(0.005) },
                OptionDefinition { key: "center_gravity".to_string(), label: "Center Gravity".to_string(), r#type: "range".to_string(), default: json!(0.003), description: "How strongly the graph is pulled toward the origin. Lower values reduce central clumping.".to_string(), unit: String::new(), min: Some(0.0), max: Some(0.2), step: Some(0.001) },
                OptionDefinition { key: "damping".to_string(), label: "Damping".to_string(), r#type: "range".to_string(), default: json!(0.9), description: "Velocity damping applied each step.".to_string(), unit: String::new(), min: Some(0.3), max: Some(0.99), step: Some(0.01) },
                OptionDefinition { key: "theta".to_string(), label: "Approximation".to_string(), r#type: "range".to_string(), default: json!(1.1), description: "Barnes-Hut accuracy versus speed.".to_string(), unit: String::new(), min: Some(0.2), max: Some(2.0), step: Some(0.05) },
                OptionDefinition { key: "declump_iterations".to_string(), label: "Declump Passes".to_string(), r#type: "range".to_string(), default: json!(18.0), description: "Extra overlap-removal passes after the force solve.".to_string(), unit: String::new(), min: Some(0.0), max: Some(80.0), step: Some(1.0) },
                OptionDefinition { key: "declump_padding".to_string(), label: "Declump Gap".to_string(), r#type: "range".to_string(), default: json!(24.0), description: "Extra spacing between node footprints after layout.".to_string(), unit: "px".to_string(), min: Some(0.0), max: Some(120.0), step: Some(2.0) },
                OptionDefinition { key: "declump_max_step".to_string(), label: "Declump Speed".to_string(), r#type: "range".to_string(), default: json!(28.0), description: "Maximum movement per declump pass.".to_string(), unit: "px".to_string(), min: Some(2.0), max: Some(120.0), step: Some(2.0) },
                OptionDefinition { key: "seed".to_string(), label: "Seed".to_string(), r#type: "number".to_string(), default: json!(42.0), description: "Random seed for initial placement.".to_string(), unit: String::new(), min: Some(1.0), max: Some(1_000_000.0), step: Some(1.0) },
                OptionDefinition { key: "continue_layout".to_string(), label: "Continue From Current".to_string(), r#type: "boolean".to_string(), default: json!(false), description: "Start from the positions currently shown instead of a fresh placement. The result then depends on the previous view.".to_string(), unit: String::new(), min: None, max: None, step: None },
            ],
        },
        Definition {
            key: "wasm.radial".to_string(),
            label: "Radial".to_string(),
            description: "Rings by distance from the query's start nodes.".to_string(),
            supports_animation: false,
            options: vec![
                OptionDefinition { key: "ring_gap".to_string(), label: "Ring Gap".to_string(), r#type: "range".to_string(), default: json!(120.0), description: "Distance between concentric rings.".to_string(), unit: "px".to_string(), min: Some(20.0), max: Some(800.0), step: Some(10.0) },
                OptionDefinition { key: "clockwise".to_string(), label: "Clockwise".to_string(), r#type: "boolean".to_string(), default: json!(true), description: "Place ring members clockwise.".to_string(), unit: String::new(), min: None, max: None, step: None },
            ],
        },
        Definition {
            key: "wasm.layered".to_string(),
            label: "Layered".to_string(),
            description: "Columns by distance from the start nodes, reordered to reduce edge crossings.".to_string(),
            supports_animation: false,
            options: vec![
                OptionDefinition { key: "layer_gap".to_string(), label: "Layer Gap".to_string(), r#type: "range".to_string(), default: json!(220.0), description: "Horizontal spacing between layers.".to_string(), unit: "px".to_string(), min: Some(40.0), max: Some(800.0), step: Some(10.0) },
                OptionDefinition { key: "node_gap".to_string(), label: "Node Gap".to_string(), r#type: "range".to_string(), default: json!(24.0), description: "Vertical spacing between nodes in the same layer.".to_string(), unit: "px".to_string(), min: Some(4.0), max: Some(200.0), step: Some(2.0) },
                OptionDefinition { key: "sweeps".to_string(), label: "Ordering Passes".to_string(), r#type: "range".to_string(), default: json!(24.0), description: "Passes spent reordering layers to reduce crossings.".to_string(), unit: String::new(), min: Some(0.0), max: Some(200.0), step: Some(2.0) },
            ],
        },
        Definition {
            key: "wasm.stress".to_string(),
            label: "Stress".to_string(),
            description: "Distances on screen follow distances in the graph. Deterministic.".to_string(),
            supports_animation: false,
            options: vec![
                OptionDefinition { key: "edge_length".to_string(), label: "Link Distance".to_string(), r#type: "range".to_string(), default: json!(90.0), description: "Screen distance for one hop in the graph.".to_string(), unit: "px".to_string(), min: Some(20.0), max: Some(500.0), step: Some(5.0) },
                OptionDefinition { key: "iterations".to_string(), label: "Iterations".to_string(), r#type: "range".to_string(), default: json!(300.0), description: "Maximum refinement passes; stops early once settled.".to_string(), unit: String::new(), min: Some(10.0), max: Some(5000.0), step: Some(10.0) },
            ],
        },
    ]
}

fn encode<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_else(|e| {
        json!({ "ok": false, "error": format!("json marshal failed: {e}") }).to_string()
    })
}

#[wasm_bindgen(js_name = adalancheLayoutDescribe)]
pub fn adalanche_layout_describe() -> String {
    encode(&json!({"ok": true, "layouts": definitions()}))
}

#[wasm_bindgen(js_name = adalancheLayoutRun)]
pub fn adalanche_layout_run(request_json: String) -> String {
    let req = match parse_request::<RunRequest>(&request_json) {
        Ok(v) => v,
        Err(err) => {
            return encode(&RunResponse {
                ok: false,
                error: err,
                positions: HashMap::new(),
            })
        }
    };

    // Layouts see the graph in a canonical order, so the result never depends
    // on the order the nodes and edges arrived in.
    let graph = canonical_graph(&req.graph);
    let mut positions = match req.layout.as_str() {
        "wasm.cluster_visibility" => cluster_layout(&graph, &req.options),
        "wasm.path" => path_layout(&graph, &req.options),
        "wasm.circle" => circle_layout(&graph, &req.options),
        "wasm.force" => {
            let stepper = ForceStepper::new(&graph, &req.options);
            let mut positions = stepper.run_to_completion();
            let mut ordered = graph
                .nodes
                .iter()
                .map(|node| {
                    positions
                        .remove(&node.id)
                        .map(|pos| Vec2 { x: pos.x, y: pos.y })
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>();
            declump_positions(&graph, &mut ordered, &req.options);
            to_positions(&graph.nodes.iter().map(|node| node.id.clone()).collect::<Vec<_>>(), &ordered)
        }
        "wasm.radial" => radial_layout(&graph, &req.options),
        "wasm.layered" => layered_layout(&graph, &req.options),
        "wasm.stress" => stress_layout(&graph, &req.options),
        other => {
            return encode(&RunResponse {
                ok: false,
                error: format!("unknown layout: {other}"),
                positions: HashMap::new(),
            })
        }
    };

    screen_declump(&graph, &mut positions, &req.options);
    encode(&RunResponse {
        ok: true,
        error: String::new(),
        positions,
    })
}

#[wasm_bindgen(js_name = adalancheLayoutAnimationStart)]
pub fn adalanche_layout_animation_start(request_json: String) -> String {
    let req = match parse_request::<RunRequest>(&request_json) {
        Ok(v) => v,
        Err(err) => {
            return encode(&StartAnimationResponse {
                ok: false,
                error: err,
                session_id: String::new(),
            })
        }
    };

    if req.layout != "wasm.force" {
        return encode(&StartAnimationResponse {
            ok: false,
            error: format!("layout does not support animation: {}", req.layout),
            session_id: String::new(),
        });
    }

    let session_id = SESSION_SEQ.with(|seq| {
        let next = seq.get() + 1;
        seq.set(next);
        format!("anim-{next}")
    });

    SESSIONS.with(|sessions| {
        sessions
            .borrow_mut()
            .insert(session_id.clone(), ForceStepper::new(&canonical_graph(&req.graph), &req.options));
    });

    encode(&StartAnimationResponse {
        ok: true,
        error: String::new(),
        session_id,
    })
}

#[wasm_bindgen(js_name = adalancheLayoutAnimationStep)]
pub fn adalanche_layout_animation_step(request_json: String) -> String {
    let req = match parse_request::<StepAnimationRequest>(&request_json) {
        Ok(v) => v,
        Err(err) => {
            return encode(&StepAnimationResponse {
                ok: false,
                error: err,
                positions: HashMap::new(),
                done: false,
            })
        }
    };

    if req.session_id.trim().is_empty() {
        return encode(&StepAnimationResponse {
            ok: false,
            error: "unknown animation session".to_string(),
            positions: HashMap::new(),
            done: false,
        });
    }

    let steps = if req.steps <= 0 { 1usize } else { req.steps as usize };

    let mut response = StepAnimationResponse {
        ok: false,
        error: "unknown animation session".to_string(),
        positions: HashMap::new(),
        done: false,
    };

    SESSIONS.with(|sessions| {
        let mut sessions = sessions.borrow_mut();
        if let Some(stepper) = sessions.get_mut(&req.session_id) {
            let (positions, done) = stepper.step(steps);
            response.ok = true;
            response.error.clear();
            if done {
                let mut ordered = stepper.pos.clone();
                let graph = Graph {
                    nodes: stepper.nodes.clone(),
                    edges: Vec::new(),
                };
                let options = stepper.declump_options_map();
                declump_positions(&graph, &mut ordered, &options);
                let mut positions = to_positions(&stepper.ids, &ordered);
                screen_declump(&graph, &mut positions, &stepper.layout_options);
                response.positions = positions;
            } else {
                response.positions = positions;
            }
            response.done = done;
            if done {
                sessions.remove(&req.session_id);
            }
        }
    });

    encode(&response)
}

#[wasm_bindgen(js_name = adalancheLayoutAnimationStop)]
pub fn adalanche_layout_animation_stop(request_json: String) -> String {
    let req = match parse_request::<StopAnimationRequest>(&request_json) {
        Ok(v) => v,
        Err(err) => {
            return encode(&RunResponse {
                ok: false,
                error: err,
                positions: HashMap::new(),
            })
        }
    };

    SESSIONS.with(|sessions| {
        sessions.borrow_mut().remove(&req.session_id);
    });

    encode(&RunResponse {
        ok: true,
        error: String::new(),
        positions: HashMap::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn force_definition_is_presented_as_organic() {
        let defs = definitions();
        let organic = defs.iter().find(|def| def.key == "wasm.force").expect("wasm.force definition");
        assert_eq!(organic.label, "Organic");
        assert!(organic.options.iter().any(|opt| opt.key == "theta"));
    }

    #[test]
    fn organic_force_stepper_produces_finite_positions() {
        let graph = Graph {
            nodes: (0..32)
                .map(|i| Node {
                    id: format!("n{i}"),
                    x: 0.0,
                    y: 0.0,
                    render_size: 10.0,
                    label: format!("node-{i}"),
                    is_start: i == 0,
                    is_end: i == 31,
                })
                .collect(),
            edges: (1..32)
                .map(|i| Edge {
                    source: "n0".to_string(),
                    target: format!("n{i}"),
                })
                .collect(),
        };
        let options = Map::new();
        let positions = ForceStepper::new(&graph, &options).run_to_completion();
        assert_eq!(positions.len(), 32);
        let mut min_x = f64::INFINITY;
        let mut max_x = f64::NEG_INFINITY;
        let mut min_y = f64::INFINITY;
        let mut max_y = f64::NEG_INFINITY;
        for pos in positions.values() {
            assert!(pos.x.is_finite());
            assert!(pos.y.is_finite());
            min_x = min_x.min(pos.x);
            max_x = max_x.max(pos.x);
            min_y = min_y.min(pos.y);
            max_y = max_y.max(pos.y);
        }
        assert!((max_x - min_x) > 100.0, "expected x spread, got {}", max_x - min_x);
        assert!((max_y - min_y) > 100.0, "expected y spread, got {}", max_y - min_y);
    }

    fn sample_cluster_graph() -> Graph {
        let mut nodes = Vec::new();
        for i in 0..12 {
            nodes.push(Node {
                id: format!("a{i}"),
                x: 0.0,
                y: 0.0,
                render_size: 10.0,
                label: format!("a-{i}"),
                is_start: false,
                is_end: false,
            });
        }
        for i in 0..12 {
            nodes.push(Node {
                id: format!("b{i}"),
                x: 0.0,
                y: 0.0,
                render_size: 10.0,
                label: format!("b-{i}"),
                is_start: false,
                is_end: false,
            });
        }

        let mut edges = Vec::new();
        for i in 1..12 {
            edges.push(Edge {
                source: "a0".to_string(),
                target: format!("a{i}"),
            });
            edges.push(Edge {
                source: "b0".to_string(),
                target: format!("b{i}"),
            });
        }
        edges.push(Edge {
            source: "a0".to_string(),
            target: "b0".to_string(),
        });

        Graph { nodes, edges }
    }

    fn assert_positions_are_spread(positions: &HashMap<String, Position>, expected: usize) {
        assert_eq!(positions.len(), expected);
        let mut min_x = f64::INFINITY;
        let mut max_x = f64::NEG_INFINITY;
        let mut min_y = f64::INFINITY;
        let mut max_y = f64::NEG_INFINITY;
        let mut non_zero = 0usize;
        for pos in positions.values() {
            assert!(pos.x.is_finite());
            assert!(pos.y.is_finite());
            min_x = min_x.min(pos.x);
            max_x = max_x.max(pos.x);
            min_y = min_y.min(pos.y);
            max_y = max_y.max(pos.y);
            if pos.x.abs() > 0.001 || pos.y.abs() > 0.001 {
                non_zero += 1;
            }
        }
        assert!(non_zero > expected / 2, "expected most positions to be non-zero, got {non_zero}/{expected}");
        assert!((max_x - min_x) > 50.0, "expected x spread, got {}", max_x - min_x);
        assert!((max_y - min_y) > 50.0, "expected y spread, got {}", max_y - min_y);
    }

    #[test]
    fn phyllotaxis_layout_produces_finite_positions() {
        let graph = sample_cluster_graph();
        let positions = phyllotaxis_layout(&graph, 32.0);
        assert_positions_are_spread(&positions, graph.nodes.len());
    }

    #[test]
    fn cluster_layout_spreads_nodes() {
        let graph = canonical_graph(&sample_cluster_graph());
        let positions = cluster_layout(&graph, &Map::new());
        assert_positions_are_spread(&positions, graph.nodes.len());
    }

    fn run_layout(layout: &str, graph: &Graph, options: Value) -> HashMap<String, Position> {
        let request = json!({ "layout": layout, "graph": {
            "nodes": graph.nodes.iter().map(|n| json!({"id": n.id, "x": n.x, "y": n.y, "render_size": n.render_size, "label": n.label, "is_start": n.is_start, "is_end": n.is_end})).collect::<Vec<_>>(),
            "edges": graph.edges.iter().map(|e| json!({"source": e.source, "target": e.target})).collect::<Vec<_>>(),
        }, "options": options });
        let response: Value = serde_json::from_str(&adalanche_layout_run(request.to_string())).unwrap();
        assert_eq!(response["ok"], json!(true), "{layout}: {response}");
        serde_json::from_value::<HashMap<String, (f64, f64)>>(
            response["positions"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), json!([v["x"], v["y"]]))).collect::<Map<_, _>>().into(),
        )
        .unwrap()
        .into_iter()
        .map(|(k, (x, y))| (k, Position { x, y }))
        .collect()
    }

    const LAYOUTS: [&str; 7] = ["wasm.cluster_visibility", "wasm.path", "wasm.circle", "wasm.force", "wasm.radial", "wasm.layered", "wasm.stress"];

    #[test]
    fn every_layout_ignores_input_order() {
        let graph = sample_cluster_graph();
        let mut reversed = graph.clone();
        reversed.nodes.reverse();
        reversed.edges.reverse();
        for layout in LAYOUTS {
            let a = run_layout(layout, &graph, json!({}));
            let b = run_layout(layout, &reversed, json!({}));
            for (id, p) in &a {
                let q = &b[id];
                assert!((p.x - q.x).abs() < 1e-9 && (p.y - q.y).abs() < 1e-9, "{layout}: {id} moved with input order");
            }
        }
    }

    #[test]
    fn organic_only_continues_from_current_positions_when_asked() {
        let fresh = sample_cluster_graph();
        let mut moved = fresh.clone();
        for (i, node) in moved.nodes.iter_mut().enumerate() {
            node.x = (i as f64 * 97.0) % 1000.0;
            node.y = (i as f64 * 53.0) % 700.0;
        }
        let a = run_layout("wasm.force", &fresh, json!({}));
        let b = run_layout("wasm.force", &moved, json!({}));
        assert!(a.iter().all(|(id, p)| (p.x - b[id].x).abs() < 1e-9 && (p.y - b[id].y).abs() < 1e-9), "old coordinates leaked in");
        let c = run_layout("wasm.force", &moved, json!({"continue_layout": true}));
        assert!(a.iter().any(|(id, p)| (p.x - c[id].x).abs() > 1e-6), "continue_layout had no effect");
    }

    #[test]
    fn layouts_do_not_overlap_once_fitted() {
        let graph = sample_cluster_graph();
        let (view_w, view_h) = (800.0, 600.0);
        for layout in LAYOUTS {
            let positions = run_layout(layout, &graph, json!({"viewport_width": view_w, "viewport_height": view_h}));
            let pts: Vec<Position> = positions.values().copied().collect();
            let (mut min_x, mut max_x, mut min_y, mut max_y) = (f64::MAX, f64::MIN, f64::MAX, f64::MIN);
            for p in &pts {
                min_x = min_x.min(p.x);
                max_x = max_x.max(p.x);
                min_y = min_y.min(p.y);
                max_y = max_y.max(p.y);
            }
            let fit = ((view_w - 2.0 * FIT_PADDING) / (max_x - min_x).max(1e-6)).min((view_h - 2.0 * FIT_PADDING) / (max_y - min_y).max(1e-6));
            let icon = 10.0 * ICON_SCALE;
            for a in 0..pts.len() {
                for b in (a + 1)..pts.len() {
                    let d = ((pts[a].x - pts[b].x).powi(2) + (pts[a].y - pts[b].y).powi(2)).sqrt() * fit;
                    assert!(d >= 2.0 * icon - 1e-6, "{layout}: icons overlap on screen ({d:.1}px)");
                }
            }
        }
    }

    #[test]
    fn radial_puts_start_nodes_in_the_middle() {
        let mut graph = sample_cluster_graph();
        graph.nodes.iter_mut().find(|n| n.id == "b0").unwrap().is_start = true;
        let positions = run_layout("wasm.radial", &graph, json!({}));
        let start = positions["b0"];
        let start_distance = (start.x * start.x + start.y * start.y).sqrt();
        assert!(positions.iter().filter(|(id, _)| id.as_str() != "b0").all(|(_, p)| (p.x * p.x + p.y * p.y).sqrt() > start_distance));
    }

    #[test]
    fn path_wraps_a_tall_layer() {
        let mut graph = Graph { nodes: Vec::new(), edges: Vec::new() };
        graph.nodes.push(Node { id: "s".into(), render_size: 10.0, label: "s".into(), is_start: true, ..Default::default() });
        for i in 0..60 {
            graph.nodes.push(Node { id: format!("e{i}"), render_size: 10.0, label: format!("e{i}"), is_end: true, ..Default::default() });
            graph.edges.push(Edge { source: "s".into(), target: format!("e{i}") });
        }
        let positions = run_layout("wasm.path", &graph, json!({"viewport_width": 1400, "viewport_height": 1000}));
        let columns: HashSet<i64> = positions.iter().filter(|(id, _)| id.starts_with('e')).map(|(_, p)| p.x.round() as i64).collect();
        assert!(columns.len() > 1, "60 end nodes should wrap into several columns");
    }

    #[test]
    fn unknown_layouts_are_rejected() {
        for removed in ["wasm.grid", "wasm.separated_cluster_visibility"] {
            let response: Value = serde_json::from_str(&adalanche_layout_run(json!({"layout": removed}).to_string())).unwrap();
            assert_eq!(response["ok"], json!(false));
        }
    }

    #[test]
    fn layered_removes_avoidable_crossings() {
        // Two starts whose children are listed crosswise; a good order has none.
        let mut graph = Graph { nodes: Vec::new(), edges: Vec::new() };
        for (id, start) in [("a", true), ("b", true), ("c", false), ("d", false), ("e", false), ("f", false)] {
            graph.nodes.push(Node { id: id.into(), label: id.into(), render_size: 10.0, is_start: start, ..Default::default() });
        }
        for (s, t) in [("a", "f"), ("a", "e"), ("b", "c"), ("b", "d")] {
            graph.edges.push(Edge { source: s.into(), target: t.into() });
        }
        let p = run_layout("wasm.layered", &graph, json!({}));
        let side = |id: &str| p[id].y < (p["c"].y + p["d"].y + p["e"].y + p["f"].y) / 4.0;
        assert!(p["a"].x < p["c"].x, "starts come first");
        assert_eq!(side("a"), side("e"));
        assert_eq!(side("a"), side("f"));
        assert_eq!(side("b"), side("c"));
        assert_ne!(side("a"), side("b"));
    }

    #[test]
    fn stress_matches_graph_distances() {
        // A path graph should come out nearly straight: the ends are far apart.
        let mut graph = Graph { nodes: Vec::new(), edges: Vec::new() };
        for i in 0..12 {
            graph.nodes.push(Node { id: format!("n{i:02}"), label: format!("n{i:02}"), render_size: 10.0, ..Default::default() });
            if i > 0 {
                graph.edges.push(Edge { source: format!("n{:02}", i - 1), target: format!("n{i:02}") });
            }
        }
        let p = run_layout("wasm.stress", &graph, json!({}));
        let dist = |a: &str, b: &str| ((p[a].x - p[b].x).powi(2) + (p[a].y - p[b].y).powi(2)).sqrt();
        assert!(dist("n00", "n11") > 0.9 * 11.0 * dist("n00", "n01"), "path graph is folded");
    }
}
