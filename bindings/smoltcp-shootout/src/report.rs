//! Markdown tables for the report.

pub struct Table {
    head: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new<S: Into<String>>(head: impl IntoIterator<Item = S>) -> Self {
        Self {
            head: head.into_iter().map(Into::into).collect(),
            rows: Vec::new(),
        }
    }

    pub fn row<S: Into<String>>(&mut self, cells: impl IntoIterator<Item = S>) {
        self.rows.push(cells.into_iter().map(Into::into).collect());
    }

    pub fn print(&self) {
        let w = |s: &str| s.chars().count();
        let mut width: Vec<usize> = self.head.iter().map(|h| w(h)).collect();
        for r in &self.rows {
            for (i, c) in r.iter().enumerate() {
                if i < width.len() {
                    width[i] = width[i].max(w(c));
                }
            }
        }
        let line = |cells: &[String]| {
            let mut s = String::from("|");
            for (i, c) in cells.iter().enumerate() {
                let pad = width.get(i).copied().unwrap_or(0).saturating_sub(w(c));
                s += &format!(" {c}{} |", " ".repeat(pad));
            }
            println!("{s}");
        };
        line(&self.head);
        let sep: Vec<String> = width.iter().map(|&n| "-".repeat(n.max(3))).collect();
        println!(
            "|{}|",
            sep.iter()
                .map(|s| format!(" {s} "))
                .collect::<Vec<_>>()
                .join("|")
        );
        for r in &self.rows {
            line(r);
        }
        println!();
    }
}

pub fn mbps(bytes_per_sec: f64) -> String {
    format!("{:.1}", bytes_per_sec * 8.0 / 1e6)
}

pub fn secs(s: f64) -> String {
    if s < 1.0 {
        format!("{:.0} ms", s * 1e3)
    } else {
        format!("{s:.2} s")
    }
}
