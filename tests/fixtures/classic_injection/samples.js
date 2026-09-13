// A mix of safe and unsafe sinks for the classic-injection detector.

// SAFE: parameterized query — must NOT be flagged.
export async function safeLookup(db, id) {
  return db.query("select * from users where id = $1", [id]);
}

// UNSAFE: raw SQL built with a template literal interpolation.
export async function search(db, term) {
  return db.query(`select * from products where name like '%${term}%'`);
}

// UNSAFE: dynamic ORDER BY — column name cannot be parameterized.
export async function sorted(db, col) {
  return db.query("select * from items order by " + col);
}

// UNSAFE: shell-out with interpolation.
import { exec } from "child_process";
export function convert(file) {
  exec(`convert ${file} out.png`);
}

// UNSAFE: dynamic code evaluation.
export function compute(expr) {
  return eval(expr + "");
}
