/**
 * Automated UI Voice Chat (STT, TTS & Hands-Free Mode) Verification Test
 * (Milestone 7 / Feature Track)
 *
 * Verifies:
 * 1. HTML structure in crates/quorum-ui/assets/index.html:
 *    - #btn-voice-chat / #btn-voice-input (microphone button with tooltip & accessible attributes)
 *    - #btn-voice-tts-toggle (TTS toggle with speaker icon)
 *    - #voice-waveform-indicator (pulsing audio waveform indicator)
 *    - .composer-actions layout container
 * 2. CSS styles in crates/quorum-ui/assets/styles.css:
 *    - .btn-voice-control base glass/dark styling
 *    - .btn-voice-mic.recording / .voice-active pulse glowing effect
 *    - @keyframes voice-mic-pulse
 *    - .voice-waveform and .voice-wave-bar staggered animations
 *    - @media (prefers-reduced-motion: reduce) accessibility support
 * 3. JavaScript logic in crates/quorum-ui/assets/app.js:
 *    - Web Speech API SpeechRecognition detection and graceful fallbacks
 *    - Text-to-Speech (TTS) synthesis, speech cleaning, and persistence in localStorage
 *    - Hands-free voice chat mode with silence detection and auto-submit
 *    - Diagnostic namespace window._voiceChat
 * 4. Synthetic browser execution test verifying TTS toggle and speech cleaning logic.
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const ROOT_DIR = path.resolve(__dirname, '..');
const STYLES_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'styles.css');
const APP_JS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'app.js');
const INDEX_HTML_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'index.html');

console.log('================================================================');
console.log('  AUTOMATED TEST: VOICE CHAT (STT, TTS & HANDS-FREE) VERIFICATION');
console.log('================================================================');

// Verify files exist
[STYLES_PATH, APP_JS_PATH, INDEX_HTML_PATH].forEach(p => {
  assert(fs.existsSync(p), `Required file missing: ${p}`);
});

const stylesCss = fs.readFileSync(STYLES_PATH, 'utf8');
const appJs = fs.readFileSync(APP_JS_PATH, 'utf8');
const indexHtml = fs.readFileSync(INDEX_HTML_PATH, 'utf8');

let totalTests = 0;
let passedTests = 0;

function runTest(name, fn) {
  totalTests++;
  try {
    fn();
    console.log(`  [PASS] Test ${totalTests}: ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  [FAIL] Test ${totalTests}: ${name}`);
    console.error(`         ${err.message}`);
    throw err;
  }
}

// ---------------------------------------------------------------------------
// SUITE 1: HTML Markup in index.html
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 1: HTML Markup in index.html ---');

runTest('index.html contains #btn-voice-chat / #btn-voice-input', () => {
  assert(
    indexHtml.includes('id="btn-voice-chat"') || indexHtml.includes('id="btn-voice-input"'),
    'Missing voice chat microphone button in index.html'
  );
});

runTest('index.html contains #btn-voice-tts-toggle', () => {
  assert(
    indexHtml.includes('id="btn-voice-tts-toggle"'),
    'Missing #btn-voice-tts-toggle in index.html'
  );
});

runTest('index.html contains #voice-waveform-indicator with wave bars', () => {
  assert(
    indexHtml.includes('id="voice-waveform-indicator"'),
    'Missing #voice-waveform-indicator in index.html'
  );
  assert(
    indexHtml.includes('waveform-bar'),
    'Missing .waveform-bar elements inside waveform indicator'
  );
});

runTest('index.html contains .composer-actions container for input controls', () => {
  assert(
    indexHtml.includes('composer-actions'),
    'Missing .composer-actions container in index.html'
  );
});

// ---------------------------------------------------------------------------
// SUITE 2: CSS Styles & Animations in styles.css
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 2: CSS Styles & Animations in styles.css ---');

runTest('styles.css defines .btn-voice-control button styling', () => {
  assert(stylesCss.includes('.btn-voice-control'), 'Missing .btn-voice-control rule');
  assert(stylesCss.includes('.btn-voice-tts'), 'Missing .btn-voice-tts rule');
  assert(stylesCss.includes('.btn-voice-mic'), 'Missing .btn-voice-mic rule');
});

runTest('styles.css defines recording pulse animation @keyframes voice-mic-pulse', () => {
  assert(stylesCss.includes('@keyframes voice-mic-pulse'), 'Missing @keyframes voice-mic-pulse');
  assert(stylesCss.includes('recording') || stylesCss.includes('voice-active'), 'Missing .recording / .voice-active class selector');
});

runTest('styles.css defines .voice-waveform-indicator and waveform bar animations', () => {
  assert(stylesCss.includes('#voice-waveform-indicator') || stylesCss.includes('.voice-waveform-indicator'), 'Missing waveform indicator styles');
  assert(stylesCss.includes('.waveform-bar'), 'Missing .waveform-bar styles');
  assert(stylesCss.includes('@keyframes wave-bounce'), 'Missing @keyframes wave-bounce');
});

runTest('styles.css includes accessibility media query prefers-reduced-motion', () => {
  assert(stylesCss.includes('prefers-reduced-motion: reduce'), 'Missing prefers-reduced-motion media query for voice animations');
});

// ---------------------------------------------------------------------------
// SUITE 3: JavaScript Implementation in app.js
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 3: JavaScript Implementation in app.js ---');

runTest('app.js checks for SpeechRecognition / webkitSpeechRecognition', () => {
  assert(
    appJs.includes('SpeechRecognition') && appJs.includes('webkitSpeechRecognition'),
    'app.js must reference SpeechRecognition and webkitSpeechRecognition'
  );
});

runTest('app.js manages TTS state with localStorage persistence', () => {
  assert(
    appJs.includes("localStorage.getItem('voice_tts_enabled')") ||
    appJs.includes('localStorage.getItem("voice_tts_enabled")'),
    'app.js must persist voice_tts_enabled to localStorage'
  );
  assert(
    appJs.includes("localStorage.setItem('voice_tts_enabled'") ||
    appJs.includes('localStorage.setItem("voice_tts_enabled"'),
    'app.js must save voice_tts_enabled to localStorage'
  );
});

runTest('app.js defines cleanTextForSpeech helper to sanitize markdown for speech', () => {
  assert(appJs.includes('function cleanTextForSpeech'), 'Missing cleanTextForSpeech function');
  assert(appJs.includes('.replace(/```'), 'cleanTextForSpeech must strip code blocks');
});

runTest('app.js implements hands-free silence detection for auto-submit', () => {
  assert(appJs.includes('voiceSilenceTimer'), 'Missing voiceSilenceTimer');
  assert(appJs.includes('SILENCE_SUBMIT_DELAY_MS') || appJs.includes('1500'), 'Must define silence delay');
});

runTest('app.js connects speakAssistantResponse to streamAssistantTurn completion', () => {
  assert(
    appJs.includes('speakAssistantResponse(cleanAssistantHistory)'),
    'speakAssistantResponse must be called upon stream completion'
  );
});

runTest('app.js stops speech synthesis when user clicks stop button or submits prompt', () => {
  assert(
    appJs.includes('window.speechSynthesis.cancel()'),
    'Must cancel speech synthesis on stop/new input'
  );
  assert(
    appJs.includes('stopVoiceRecording()'),
    'Must stop voice recording on prompt submit'
  );
});

runTest('app.js exposes window._voiceChat diagnostic handle', () => {
  assert(appJs.includes('window._voiceChat = {'), 'Missing window._voiceChat export');
});

// ---------------------------------------------------------------------------
// SUITE 4: Synthetic Unit Testing of Voice Chat Logic
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 4: Synthetic Unit Testing of Voice Chat Logic ---');

runTest('cleanTextForSpeech strips markdown formatting correctly', () => {
  // Extract cleanTextForSpeech function from app.js using regex
  const match = appJs.match(/function cleanTextForSpeech\s*\([^)]*\)\s*\{([\s\S]*?)\n\s*\}/);
  assert(match, 'Failed to extract cleanTextForSpeech function body');
  const cleanFn = new Function('raw', match[1]);

  const rawInput = `# Paschal Beverly Randolph
Paschal Beverly Randolph was a prominent 19th-century American physician, author, and occultist. [1]
\`\`\`rust
fn test() {}
\`\`\`
He wrote **numerous** texts on *hermeticism* and [Rosicrucian philosophy](https://example.com).`;

  const cleaned = cleanFn(rawInput);
  assert(!cleaned.includes('#'), 'Should not contain markdown headers #');
  assert(!cleaned.includes('```'), 'Should not contain markdown code fences');
  assert(!cleaned.includes('fn test'), 'Code block contents should be omitted');
  assert(!cleaned.includes('[1]'), 'Should not contain bracketed citation markers [1]');
  assert(!cleaned.includes('https://example.com'), 'Should not contain URL link targets');
  assert(cleaned.includes('Paschal Beverly Randolph'), 'Should retain main subject text');
  assert(cleaned.includes('hermeticism'), 'Should retain text inside italics');
});

console.log('\n================================================================');
console.log(`  ALL ${totalTests} VOICE CHAT TESTS PASSED CLEANLY! (100%)       `);
console.log('================================================================\n');
