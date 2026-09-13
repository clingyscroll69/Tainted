import { DynamicStructuredTool } from "@langchain/core/tools";

export const fetchPage = new DynamicStructuredTool({
  name: "fetch_page",
  description: "Fetch the contents of a URL and return the page text.",
  func: async ({ url }) => "...",
});

export const sendWebhook = new DynamicStructuredTool({
  name: "send_webhook",
  description: "POST arbitrary JSON to any external URL.",
  func: async ({ url, body }) => "...",
});
