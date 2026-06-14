import { scoreText, verdict } from "./scorer.js";

const $ = (id) => document.getElementById(id);
const result = $("result");

function analyse() {
  const text = $("msg").value.trim();
  if (!text) { $("msg").focus(); return; }

  const { score, reasons } = scoreText(text);
  const v = verdict(score);

  $("scoreNum").textContent = score;
  const badge = $("badge");
  badge.textContent = v.label;
  badge.className = "badge " + (v.key === "safe" ? "safe" : v.key === "doubt" ? "doubt" : "risky");
  $("needle").style.left = `calc(${score}% - 1.5px)`;

  const list = $("reasons");
  list.innerHTML = "";
  if (reasons.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "Aucun indicateur de risque notable détecté.";
    list.appendChild(li);
  } else {
    for (const r of reasons) {
      const li = document.createElement("li");
      const dot = document.createElement("span");
      dot.className = "dot " + r.sev;
      const span = document.createElement("span");
      span.textContent = r.label; // textContent: user input never becomes HTML
      li.append(dot, span);
      list.appendChild(li);
    }
  }
  result.classList.add("show");
}

$("check").addEventListener("click", analyse);
$("msg").addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") analyse();
});
