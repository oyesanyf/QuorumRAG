// Live verification of /api/chat endpoint with peer diagnostic extraction
const http = require('http');

async function testLiveQuery() {
  console.log('Sending query: "tell me about Paschal Beverly Randolph" to http://127.0.0.1:3031/api/chat');

  const postData = JSON.stringify({
    prompt: "tell me about Paschal Beverly Randolph",
    search_mode: "Hybrid",
    model_family: "AutoFusion",
    top_k: 12,
    access_tier: 0
  });

  const req = http.request('http://127.0.0.1:3031/api/chat', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData),
      'Accept': 'text/event-stream'
    }
  }, (res) => {
    console.log(`Response status: ${res.statusCode}`);
    console.log('Headers:');
    console.log('  x-quorum-local-peer-id:', res.headers['x-quorum-local-peer-id']);
    console.log('  x-quorum-mesh-peers:', res.headers['x-quorum-mesh-peers']);
    console.log('  x-quorum-contributing-peers:', res.headers['x-quorum-contributing-peers']);

    let buffer = '';
    const events = [];
    let answerText = '';

    res.on('data', (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop();

      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith('data:')) {
          const jsonStr = trimmed.substring(5).trim();
          try {
            const parsed = JSON.parse(jsonStr);
            events.push(parsed);

            const eventType = parsed.event || parsed.event_type;
            const data = parsed.data || parsed;

            if (eventType === 'token_delta') {
              const delta = data.delta || data.token || '';
              answerText += delta;
              process.stdout.write(delta);
            } else if (eventType === 'retrieval_completed') {
              console.log('\n[EVENT: retrieval_completed]');
              console.log('  Retrieved:', data.retrieved_count, 'Local:', data.local_count, 'Remote:', data.remote_count);
              if (data.peer_diagnostics) {
                console.log('  Peer diagnostics:', JSON.stringify(data.peer_diagnostics, null, 2));
              }
            } else if (eventType === 'citation') {
              console.log('\n[EVENT: citation]');
              console.log('  Citation:', JSON.stringify(data.citation || data, null, 2));
            } else if (eventType === 'final_answer') {
              answerText = data.content || answerText;
            } else if (eventType === 'execution_finished') {
              console.log('\n[EVENT: execution_finished]');
              console.log('  Responder peer:', data.responder_peer_id);
              if (data.peer_diagnostics) {
                console.log('  Peer diagnostics:', JSON.stringify(data.peer_diagnostics, null, 2));
              }
            }
          } catch (e) {
            // ignore non-json lines
          }
        }
      }
    });

    res.on('end', () => {
      console.log('\n\n================================================================');
      console.log('                      LIVE QUERY SUMMARY                        ');
      console.log('================================================================');
      console.log('Total SSE events received:', events.length);
      console.log('\nGenerated Answer (length ' + answerText.length + ' chars):');
      console.log(answerText.substring(0, 500) + '...');

      // Find citations
      const citations = events
        .filter(e => (e.event === 'citation'))
        .map(e => e.data && e.data.citation ? e.data.citation : e.data);

      console.log('\nCitations count:', citations.length);
      citations.forEach((c, idx) => {
        console.log(`  [${idx + 1}] File: ${c.file_path || c.document_id} | Source: ${c.source_peer || 'local'}`);
      });

      const remoteCitations = citations.filter(c => c.source_peer && c.source_peer !== 'local');
      console.log('\nRemote peer citations count:', remoteCitations.length);
      remoteCitations.forEach(c => {
        console.log(`  -> Remote Peer ID: ${c.source_peer} | File: ${c.file_path}`);
      });

      console.log('================================================================\n');
    });
  });

  req.on('error', (e) => {
    console.error('Request error:', e);
  });

  req.write(postData);
  req.end();
}

testLiveQuery();
