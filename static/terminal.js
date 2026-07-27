let termHistory = [];
let termHistoryIdx = -1;

function toggleTerminal() {
  const panel = document.getElementById('term-panel');
  panel.classList.toggle('open');
  if (panel.classList.contains('open')) {
    document.getElementById('term-input').focus();
  }
}

function termAppend(text, cls) {
  const out = document.getElementById('term-output');
  const line = document.createElement('div');
  if (cls) line.className = cls;
  line.textContent = text;
  out.appendChild(line);
  out.scrollTop = out.scrollHeight;
}

async function termRun(cmd) {
  termAppend('$ ' + cmd, 'term-cmd');
  try {
    const res = await fetch('/api/terminal/exec', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({cmd})
    });
    const data = await res.json();
    if (data.output) termAppend(data.output, 'term-result');
    if (data.cwd) document.getElementById('term-prompt').textContent = data.cwd + ' $';
  } catch (e) {
    termAppend('Error: ' + e, 'term-result');
  }
}

function longestCommonPrefix(strs) {
  if (!strs.length) return '';
  let prefix = strs[0];
  for (let i = 1; i < strs.length; i++) {
    while (!strs[i].startsWith(prefix)) {
      prefix = prefix.slice(0, -1);
      if (!prefix) return '';
    }
  }
  return prefix;
}

async function termComplete(input) {
  const text = input.value;
  try {
    const res = await fetch('/api/terminal/complete', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({text})
    });
    const data = await res.json();
    const candidates = data.candidates || [];
    if (candidates.length === 0) {
      return; // no match, do nothing (like bash)
    }
    if (candidates.length === 1) {
      input.value = data.prefix + candidates[0] + ' ';
      return;
    }
    // multiple matches: extend to common prefix, and list them like bash does
    const common = longestCommonPrefix(candidates);
    if (common && common.length > data.partial.length) {
      input.value = data.prefix + common;
    } else {
      termAppend('$ ' + text, 'term-cmd');
      termAppend(candidates.join('  '), 'term-result');
    }
  } catch (e) { console.error(e); }
}

document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('term-input');
  if (!input) return;
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const cmd = input.value;
      if (cmd.trim()) {
        termHistory.push(cmd);
        termHistoryIdx = termHistory.length;
        termRun(cmd);
      }
      input.value = '';
    } else if (e.key === 'ArrowUp') {
      if (termHistoryIdx > 0) {
        termHistoryIdx--;
        input.value = termHistory[termHistoryIdx] || '';
      }
      e.preventDefault();
    } else if (e.key === 'ArrowDown') {
      if (termHistoryIdx < termHistory.length - 1) {
        termHistoryIdx++;
        input.value = termHistory[termHistoryIdx] || '';
      } else {
        termHistoryIdx = termHistory.length;
        input.value = '';
      }
      e.preventDefault();
    } else if (e.key === 'Tab') {
      e.preventDefault();
      termComplete(input);
    }
  });
});
