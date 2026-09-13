import { createClient } from "@supabase/supabase-js";
import { NextRequest } from "next/server";

const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!);

// SAFE: the query predicate names the owner as well as the id. Must NOT be flagged.
export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("unauthorized", { status: 401 });

  const { data } = await supabase
    .from("receipts")
    .select("*")
    .eq("id", params.id)
    .eq("user_id", user.id)
    .single();

  return Response.json(data);
}
