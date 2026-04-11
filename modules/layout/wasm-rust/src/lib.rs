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

        let mut rng = Lcg::new(seed);
        for (i, node) in graph.nodes.iter().enumerate() {
            ids.push(node.id.clone());
            id_to_idx.insert(node.id.clone(), i);
            if node.x != 0.0 || node.y != 0.0 {
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

    let mut id_to_idx = HashMap::with_capacity(n);
    let mut ids = Vec::with_capacity(n);
    for (i, node) in graph.nodes.iter().enumerate() {
        id_to_idx.insert(node.id.clone(), i);
        ids.push(node.id.clone());
    }

    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
    for edge in &graph.edges {
        if let (Some(&a), Some(&b)) = (id_to_idx.get(&edge.source), id_to_idx.get(&edge.target)) {
            if a != b {
                adj[a].push(b);
                adj[b].push(a);
            }
        }
    }

    let mut level = vec![usize::MAX; n];
    let mut visited = HashSet::new();
    let mut roots: Vec<usize> = (0..n).collect();
    roots.sort_by_key(|i| std::cmp::Reverse(adj[*i].len()));

    let mut q = VecDeque::new();
    for root in roots {
        if visited.contains(&root) {
            continue;
        }
        visited.insert(root);
        level[root] = 0;
        q.push_back(root);
        while let Some(cur) = q.pop_front() {
            for &nb in &adj[cur] {
                if visited.insert(nb) {
                    level[nb] = level[cur] + 1;
                    q.push_back(nb);
                }
            }
        }
    }

    let mut levels: HashMap<usize, Vec<usize>> = HashMap::new();
    for (idx, lv) in level.iter().enumerate() {
        let lv = if *lv == usize::MAX { 0 } else { *lv };
        levels.entry(lv).or_default().push(idx);
    }

    let mut out = HashMap::with_capacity(n);
    for (lv, members) in levels {
        let radius = (lv as f64) * ring_gap;
        let count = members.len().max(1);
        for (i, idx) in members.iter().enumerate() {
            let fraction = (2.0 * std::f64::consts::PI * i as f64) / count as f64;
            let angle = if clockwise { fraction } else { -fraction };
            let x = radius * angle.cos();
            let y = radius * angle.sin();
            out.insert(ids[*idx].clone(), Position { x, y });
        }
    }
    out
}

fn circle_layout(graph: &Graph, options: &Map<String, Value>) -> HashMap<String, Position> {
    let n = graph.nodes.len();
    if n == 0 {
        return HashMap::new();
    }

    let radius = option_f64(options, "radius", 360.0).max(20.0);
    let start_angle = option_f64(options, "start_angle_deg", -90.0) * (std::f64::consts::PI / 180.0);
    let clockwise = option_bool(options, "clockwise", true);
    let mut ids: Vec<String> = graph.nodes.iter().map(|n| n.id.clone()).collect();
    ids.sort();
    let mut out = HashMap::with_capacity(n);
    for (i, id) in ids.iter().enumerate() {
        let fraction = (2.0 * std::f64::consts::PI * i as f64) / n as f64;
        let angle = start_angle + if clockwise { fraction } else { -fraction };
        out.insert(
            id.clone(),
            Position {
                x: angle.cos() * radius,
                y: angle.sin() * radius,
            },
        );
    }
    out
}

fn grid_layout(graph: &Graph, options: &Map<String, Value>) -> HashMap<String, Position> {
    let n = graph.nodes.len();
    if n == 0 {
        return HashMap::new();
    }

    let spacing = option_f64(options, "spacing", 240.0).max(20.0);
    let cols = (n as f64).sqrt().ceil().max(1.0) as usize;
    let rows = (n as f64 / cols as f64).ceil().max(1.0) as usize;
    let center_x = (cols.saturating_sub(1)) as f64 / 2.0;
    let center_y = (rows.saturating_sub(1)) as f64 / 2.0;
    let mut ids: Vec<String> = graph.nodes.iter().map(|n| n.id.clone()).collect();
    ids.sort();
    let mut out = HashMap::with_capacity(n);
    for (i, id) in ids.iter().enumerate() {
        let row = i / cols;
        let col = i % cols;
        out.insert(
            id.clone(),
            Position {
                x: (col as f64 - center_x) * spacing,
                y: (row as f64 - center_y) * spacing,
            },
        );
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
    let mut out = HashMap::with_capacity(n);
    let mut layer_positions = Vec::with_capacity(ordered_layers.len());
    let mut x_offset = 0.0;
    for layer in &ordered_layers {
        let members = layers.get(layer).map(|items| items.as_slice()).unwrap_or(&[]);
        let layer_width = members.iter()
            .map(|&idx| boxes[idx].x)
            .fold(0.0_f64, f64::max)
            .max(layer_gap * 0.4);
        layer_positions.push((*layer, x_offset));
        x_offset += layer_width + component_gap;
    }

    for (layer, x_position) in layer_positions {
        let mut members = layers.remove(&layer).unwrap_or_default();
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
        let total_height = members.iter().enumerate().fold(0.0, |acc, (i, &idx)| {
            acc + boxes[idx].y + if i > 0 { node_gap } else { 0.0 }
        });
        let mut y_cursor = -(total_height / 2.0);

        for idx in members {
            let height = boxes[idx].y;
            y_cursor += height / 2.0;
            out.insert(
                graph.nodes[idx].id.clone(),
                Position {
                    x: x_position,
                    y: y_cursor,
                },
            );
            y_cursor += (height / 2.0) + node_gap;
        }
    }

    out
}

fn circle_positions_for_indices(indices: &[usize], boxes: &[Vec2], radius_hint: f64) -> HashMap<usize, Vec2> {
    let mut out = HashMap::new();
    if indices.is_empty() {
        return out;
    }
    let count = indices.len();
    let total_width: f64 = indices.iter().map(|&idx| boxes[idx].x.max(24.0)).sum();
    let radius = radius_hint.max(total_width / (2.0 * std::f64::consts::PI)).max(60.0);
    for (order, &idx) in indices.iter().enumerate() {
        let angle = (-std::f64::consts::FRAC_PI_2)
            + ((2.0 * std::f64::consts::PI * order as f64) / count as f64);
        out.insert(
            idx,
            Vec2 {
                x: angle.cos() * radius,
                y: angle.sin() * radius,
            },
        );
    }
    out
}

fn grid_positions_for_indices(indices: &[usize], boxes: &[Vec2], gap: f64) -> HashMap<usize, Vec2> {
    let mut out = HashMap::new();
    if indices.is_empty() {
        return out;
    }
    let cols = (indices.len() as f64).sqrt().ceil().max(1.0) as usize;
    let mut col_widths = vec![0.0_f64; cols];
    let rows = (indices.len() as f64 / cols as f64).ceil().max(1.0) as usize;
    let mut row_heights = vec![0.0_f64; rows];
    for (order, &idx) in indices.iter().enumerate() {
        let row = order / cols;
        let col = order % cols;
        col_widths[col] = col_widths[col].max(boxes[idx].x);
        row_heights[row] = row_heights[row].max(boxes[idx].y);
    }
    let total_width = col_widths.iter().sum::<f64>() + gap * (cols.saturating_sub(1)) as f64;
    let total_height = row_heights.iter().sum::<f64>() + gap * (rows.saturating_sub(1)) as f64;

    let mut y = -(total_height / 2.0);
    for row in 0..rows {
        let row_height = row_heights[row];
        let mut x = -(total_width / 2.0);
        for col in 0..cols {
            let order = row * cols + col;
            if order >= indices.len() {
                break;
            }
            let idx = indices[order];
            let col_width = col_widths[col];
            out.insert(
                idx,
                Vec2 {
                    x: x + (col_width / 2.0),
                    y: y + (row_height / 2.0),
                },
            );
            x += col_width + gap;
        }
        y += row_height + gap;
    }
    out
}

fn cluster_local_layout(indices: &[usize], boxes: &[Vec2], gap: f64) -> HashMap<usize, Vec2> {
    if indices.len() <= 10 {
        return circle_positions_for_indices(indices, boxes, gap * indices.len() as f64 * 0.35);
    }
    grid_positions_for_indices(indices, boxes, gap)
}

fn cluster_layout(graph: &Graph, options: &Map<String, Value>) -> HashMap<String, Position> {
    let n = graph.nodes.len();
    if n == 0 {
        return HashMap::new();
    }

    let connector_factor = option_f64(options, "connector_factor", 2.2).clamp(1.2, 6.0);
    let cluster_gap = option_f64(options, "cluster_gap", 420.0).max(80.0);
    let intra_gap = option_f64(options, "intra_gap", 60.0).max(10.0);

    let mut id_to_idx = HashMap::with_capacity(n);
    for (i, node) in graph.nodes.iter().enumerate() {
        id_to_idx.insert(node.id.clone(), i);
    }

    let mut undirected = vec![Vec::new(); n];
    let mut degrees = vec![0usize; n];
    for edge in &graph.edges {
        if let (Some(&a), Some(&b)) = (id_to_idx.get(&edge.source), id_to_idx.get(&edge.target)) {
            if a == b {
                continue;
            }
            undirected[a].push(b);
            undirected[b].push(a);
            degrees[a] += 1;
            degrees[b] += 1;
        }
    }

    let avg_degree = if n > 0 {
        degrees.iter().sum::<usize>() as f64 / n as f64
    } else {
        0.0
    };
    let connector_threshold = ((avg_degree * connector_factor).ceil() as usize).max(6);
    let connectors: Vec<bool> = degrees.iter().map(|&degree| degree >= connector_threshold).collect();

    let mut cluster_id_of = vec![usize::MAX; n];
    let mut clusters: Vec<Vec<usize>> = Vec::new();
    let mut queue = VecDeque::new();

    for start in 0..n {
        if connectors[start] || cluster_id_of[start] != usize::MAX {
            continue;
        }
        let cluster_id = clusters.len();
        clusters.push(Vec::new());
        cluster_id_of[start] = cluster_id;
        queue.push_back(start);
        while let Some(current) = queue.pop_front() {
            clusters[cluster_id].push(current);
            for &next in &undirected[current] {
                if connectors[next] || cluster_id_of[next] != usize::MAX {
                    continue;
                }
                cluster_id_of[next] = cluster_id;
                queue.push_back(next);
            }
        }
    }

    for idx in 0..n {
        if cluster_id_of[idx] != usize::MAX {
            continue;
        }
        let mut neighbor_counts: HashMap<usize, usize> = HashMap::new();
        for &next in &undirected[idx] {
            let cluster_id = cluster_id_of[next];
            if cluster_id != usize::MAX {
                *neighbor_counts.entry(cluster_id).or_insert(0) += 1;
            }
        }
        let cluster_id = neighbor_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(cluster_id, _)| cluster_id)
            .unwrap_or_else(|| {
                let next_cluster = clusters.len();
                clusters.push(Vec::new());
                next_cluster
            });
        cluster_id_of[idx] = cluster_id;
        clusters[cluster_id].push(idx);
    }

    let boxes: Vec<Vec2> = graph.nodes.iter().map(node_box_size).collect();
    let mut cluster_widths = Vec::with_capacity(clusters.len());
    let mut cluster_heights = Vec::with_capacity(clusters.len());
    let mut local_positions: Vec<HashMap<usize, Vec2>> = Vec::with_capacity(clusters.len());
    for cluster in &clusters {
        let positions = cluster_local_layout(cluster, &boxes, intra_gap);
        let mut min_x = 0.0;
        let mut max_x = 0.0;
        let mut min_y = 0.0;
        let mut max_y = 0.0;
        let mut first = true;
        for &idx in cluster {
            let pos = positions.get(&idx).copied().unwrap_or_default();
            let half_w = boxes[idx].x / 2.0;
            let half_h = boxes[idx].y / 2.0;
            let x1 = pos.x - half_w;
            let x2 = pos.x + half_w;
            let y1 = pos.y - half_h;
            let y2 = pos.y + half_h;
            if first {
                min_x = x1;
                max_x = x2;
                min_y = y1;
                max_y = y2;
                first = false;
            } else {
                min_x = min_x.min(x1);
                max_x = max_x.max(x2);
                min_y = min_y.min(y1);
                max_y = max_y.max(y2);
            }
        }
        cluster_widths.push((max_x - min_x).max(80.0));
        cluster_heights.push((max_y - min_y).max(80.0));
        local_positions.push(positions);
    }

    let mut meta_edges = HashSet::new();
    for edge in &graph.edges {
        if let (Some(&a), Some(&b)) = (id_to_idx.get(&edge.source), id_to_idx.get(&edge.target)) {
            let ca = cluster_id_of[a];
            let cb = cluster_id_of[b];
            if ca != cb {
                let edge_key = if ca < cb { (ca, cb) } else { (cb, ca) };
                meta_edges.insert(edge_key);
            }
        }
    }

    let meta_graph = Graph {
        nodes: clusters
            .iter()
            .enumerate()
            .map(|(idx, cluster)| Node {
                id: format!("cluster-{idx}"),
                x: 0.0,
                y: 0.0,
                render_size: (cluster.len() as f64).sqrt() * 18.0,
                label: format!("cluster-{idx}"),
                is_start: false,
                is_end: false,
            })
            .collect(),
        edges: meta_edges
            .into_iter()
            .map(|(a, b)| Edge {
                source: format!("cluster-{a}"),
                target: format!("cluster-{b}"),
            })
            .collect(),
    };

    let mut meta_options = Map::new();
    meta_options.insert("iterations".to_string(), json!(500.0));
    meta_options.insert("repulsion".to_string(), json!(36000.0));
    meta_options.insert("spring_length".to_string(), json!(cluster_gap));
    meta_options.insert("spring_stiffness".to_string(), json!(0.06));
    meta_options.insert("center_gravity".to_string(), json!(0.001));
    meta_options.insert("damping".to_string(), json!(0.88));
    meta_options.insert("theta".to_string(), json!(1.0));
    meta_options.insert("seed".to_string(), json!(42.0));
    let mut meta_positions = ForceStepper::new(&meta_graph, &meta_options).run_to_completion();

    let mut ordered_meta = meta_graph
        .nodes
        .iter()
        .map(|node| {
            meta_positions
                .remove(&node.id)
                .map(|pos| Vec2 { x: pos.x, y: pos.y })
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();

    let meta_box_graph = Graph {
        nodes: meta_graph
            .nodes
            .iter()
            .enumerate()
            .map(|(idx, node)| Node {
                id: node.id.clone(),
                x: 0.0,
                y: 0.0,
                render_size: cluster_widths[idx].max(cluster_heights[idx]) / 2.0,
                label: String::new(),
                is_start: false,
                is_end: false,
            })
            .collect(),
        edges: Vec::new(),
    };
    let mut declump_meta_options = Map::new();
    declump_meta_options.insert("declump_iterations".to_string(), json!(32.0));
    declump_meta_options.insert("declump_padding".to_string(), json!(cluster_gap * 0.2));
    declump_meta_options.insert("declump_max_step".to_string(), json!(cluster_gap * 0.2));
    declump_positions(&meta_box_graph, &mut ordered_meta, &declump_meta_options);

    let mut out = HashMap::with_capacity(n);
    for (cluster_id, cluster) in clusters.iter().enumerate() {
        let center = ordered_meta.get(cluster_id).copied().unwrap_or_default();
        for &idx in cluster {
            let local = local_positions[cluster_id].get(&idx).copied().unwrap_or_default();
            out.insert(
                graph.nodes[idx].id.clone(),
                Position {
                    x: center.x + local.x,
                    y: center.y + local.y,
                },
            );
        }
    }

    out
}

fn definitions() -> Vec<Definition> {
    vec![
        Definition {
            key: "wasm.cluster".to_string(),
            label: "Cluster".to_string(),
            description: "Distributed cluster layout with connector-aware separation.".to_string(),
            supports_animation: false,
            options: vec![
                OptionDefinition { key: "connector_factor".to_string(), label: "Connector Bias".to_string(), r#type: "range".to_string(), default: json!(2.2), description: "How aggressively high-degree nodes get treated as connectors between clusters.".to_string(), unit: "x".to_string(), min: Some(1.2), max: Some(6.0), step: Some(0.1) },
                OptionDefinition { key: "cluster_gap".to_string(), label: "Cluster Gap".to_string(), r#type: "range".to_string(), default: json!(420.0), description: "Preferred spacing between distributed clusters.".to_string(), unit: "px".to_string(), min: Some(80.0), max: Some(1400.0), step: Some(20.0) },
                OptionDefinition { key: "intra_gap".to_string(), label: "Intra Gap".to_string(), r#type: "range".to_string(), default: json!(60.0), description: "Spacing between nodes within each cluster.".to_string(), unit: "px".to_string(), min: Some(10.0), max: Some(240.0), step: Some(2.0) },
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
            description: "Deterministic circular layout.".to_string(),
            supports_animation: false,
            options: vec![
                OptionDefinition { key: "radius".to_string(), label: "Radius".to_string(), r#type: "range".to_string(), default: json!(360.0), description: "Distance from the center to the ring.".to_string(), unit: "px".to_string(), min: Some(40.0), max: Some(4000.0), step: Some(10.0) },
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
            ],
        },
        Definition {
            key: "wasm.grid".to_string(),
            label: "Grid".to_string(),
            description: "Deterministic grid layout.".to_string(),
            supports_animation: false,
            options: vec![
                OptionDefinition { key: "spacing".to_string(), label: "Spacing".to_string(), r#type: "range".to_string(), default: json!(240.0), description: "Distance between neighboring grid cells.".to_string(), unit: "px".to_string(), min: Some(40.0), max: Some(4000.0), step: Some(10.0) },
            ],
        },
        Definition {
            key: "wasm.radial".to_string(),
            label: "Radial".to_string(),
            description: "Simple BFS ring layout.".to_string(),
            supports_animation: false,
            options: vec![
                OptionDefinition { key: "ring_gap".to_string(), label: "Ring Gap".to_string(), r#type: "range".to_string(), default: json!(120.0), description: "Distance between concentric rings.".to_string(), unit: "px".to_string(), min: Some(20.0), max: Some(800.0), step: Some(10.0) },
                OptionDefinition { key: "clockwise".to_string(), label: "Clockwise".to_string(), r#type: "boolean".to_string(), default: json!(true), description: "Place ring members clockwise.".to_string(), unit: String::new(), min: None, max: None, step: None },
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

    let positions = match req.layout.as_str() {
        "wasm.cluster" => cluster_layout(&req.graph, &req.options),
        "wasm.path" => path_layout(&req.graph, &req.options),
        "wasm.circle" => circle_layout(&req.graph, &req.options),
        "wasm.force" => {
            let stepper = ForceStepper::new(&req.graph, &req.options);
            let mut positions = stepper.run_to_completion();
            let mut ordered = req
                .graph
                .nodes
                .iter()
                .map(|node| {
                    positions
                        .remove(&node.id)
                        .map(|pos| Vec2 { x: pos.x, y: pos.y })
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>();
            declump_positions(&req.graph, &mut ordered, &req.options);
            to_positions(&req.graph.nodes.iter().map(|node| node.id.clone()).collect::<Vec<_>>(), &ordered)
        }
        "wasm.grid" => grid_layout(&req.graph, &req.options),
        "wasm.radial" => radial_layout(&req.graph, &req.options),
        other => {
            return encode(&RunResponse {
                ok: false,
                error: format!("unknown layout: {other}"),
                positions: HashMap::new(),
            })
        }
    };

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
            .insert(session_id.clone(), ForceStepper::new(&req.graph, &req.options));
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
                response.positions = to_positions(&stepper.ids, &ordered);
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
}
