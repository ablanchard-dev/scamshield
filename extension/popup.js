document.getElementById('check').addEventListener('click', async () => {
  const msg = document.getElementById('msg').value.trim();
  if (!msg) { alert('Paste some text first.'); return; }
  // Placeholder: in week 3 we will wire this to FastAPI.
  alert('Local scoring coming next step. For now, use the Streamlit app.');
});
