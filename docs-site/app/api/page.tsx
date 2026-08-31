import { redirect } from "next/navigation";

export default function LegacyApiPage() {
  redirect("/docs/api");
}
