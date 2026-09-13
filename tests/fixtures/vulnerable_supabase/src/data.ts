import { createClient } from "@supabase/supabase-js";

const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!);

// Reads invoices directly from the browser — the only guard is the (permissive) RLS policy.
export async function getInvoice(id: string) {
  const { data, error } = await supabase
    .from("invoices")
    .select("*")
    .eq("id", id)
    .single();
  if (error) throw error;
  return data;
}

// Reads notes directly — the notes table has RLS disabled entirely.
export async function listNotes() {
  const { data } = await supabase.from("notes").select("id, body");
  return data;
}

// Reads a self-readable table (profiles has a correct auth.uid() policy).
export async function myProfile(userId: string) {
  const { data } = await supabase.from("profiles").select("*").eq("user_id", userId);
  return data;
}

// Reads intentionally-public content.
export async function listPosts() {
  const { data } = await supabase.from("public_posts").select("*");
  return data;
}

// A write path (should be classified as write, not a read hole).
export async function addNote(body: string) {
  await supabase.from("notes").insert({ body });
}
