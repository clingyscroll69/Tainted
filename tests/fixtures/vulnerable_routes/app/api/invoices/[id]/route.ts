import { createClient } from "@supabase/supabase-js";
import { NextRequest } from "next/server";

const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!);

// VULNERABLE: the caller's identity is read and then never used to scope the query.
// This is the classic shape — it looks authenticated, and it is not authorized.
export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("unauthorized", { status: 401 });

  const { data, error } = await supabase
    .from("invoices")
    .select("*")
    .eq("id", params.id)
    .single();

  if (error) return new Response(error.message, { status: 500 });
  return Response.json(data);
}
