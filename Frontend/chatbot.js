/* Frontend/chatbot.js — KavachNet AI Chatbot Logic */

(function() {
    // Inject HTML if not present
    if (!document.getElementById('chatbotWindow')) {
        const widgetHtml = `
            <div class="chatbot-toggle" id="chatbotToggle">
                <i class="bi bi-chat-dots-fill"></i>
            </div>
            <div class="chatbot-window" id="chatbotWindow">
                <div class="chatbot-header">
                    <div class="chatbot-title"><i class="bi bi-robot"></i> KavachNet AI</div>
                    <div class="chatbot-close" id="chatbotClose"><i class="bi bi-x-lg"></i></div>
                </div>
                <div class="chatbot-messages" id="chatbotMessages">
                    <div class="chat-msg ai">Hello! I am the KavachNet AI Assistant. I can help you scan URLs for threats, explain security results, and guide you through the platform. How can I assist you?</div>
                </div>
                <div class="chatbot-input-area">
                    <input type="text" id="chatbotInput" class="chatbot-input" placeholder="Ask me anything..." />
                    <button id="chatbotSend" class="chatbot-send"><i class="bi bi-send-fill"></i></button>
                </div>
            </div>
        `;
        const container = document.createElement('div');
        container.innerHTML = widgetHtml;
        document.body.appendChild(container);
    }

    const chatbotToggle = document.getElementById('chatbotToggle');
    const chatbotWindow = document.getElementById('chatbotWindow');
    const chatbotClose = document.getElementById('chatbotClose');
    const chatbotMessages = document.getElementById('chatbotMessages');
    const chatbotInput = document.getElementById('chatbotInput');
    const chatbotSend = document.getElementById('chatbotSend');

    let isLoaded = false;

    function getToken() {
        return sessionStorage.getItem('kn_token');
    }

    // Helper: Add message bubble
    function addMessage(sender, content, isHtml = false) {
        const msgDiv = document.createElement('div');
        msgDiv.className = `chat-msg ${sender}`;
        
        if (isHtml) {
            msgDiv.innerHTML = content;
        } else {
            msgDiv.textContent = content;
        }
        
        chatbotMessages.appendChild(msgDiv);
        chatbotMessages.scrollTop = chatbotMessages.scrollHeight;
        return msgDiv;
    }

    // Helper: Show/Hide typing
    let typingIndicator = null;
    function showTyping() {
        if (typingIndicator) return;
        typingIndicator = document.createElement('div');
        typingIndicator.className = 'typing';
        typingIndicator.innerHTML = '<span></span><span></span><span></span>';
        chatbotMessages.appendChild(typingIndicator);
        chatbotMessages.scrollTop = chatbotMessages.scrollHeight;
    }

    function hideTyping() {
        if (typingIndicator) {
            typingIndicator.remove();
            typingIndicator = null;
        }
    }

    // Load History
    async function loadHistory() {
        if (isLoaded) return;
        const token = getToken();
        if (!token) {
            addMessage('ai', 'Please log in to see your chat history and access advanced AI scanning.');
            return;
        }

        try {
            const baseUrl = window.KAVACH_API_BASE || '/api/v1';
            const res = await fetch(`${baseUrl}/ai/history`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                if (data.history && data.history.length > 0) {
                    chatbotMessages.innerHTML = ''; // Clear welcome
                    data.history.forEach(msg => {
                        addMessage('user', msg.message);
                        addMessage('ai', msg.reply);
                    });
                }
                isLoaded = true;
            }
        } catch (e) {
            console.error('Failed to load history', e);
        }
    }

    // Send Message
    async function sendMessage() {
        const text = chatbotInput.value.trim();
        if (!text) return;

        const token = getToken();
        if (!token) {
            addMessage('user', text);
            addMessage('ai', 'Authentication required. Please log in to chat with KavachNet AI.');
            chatbotInput.value = '';
            return;
        }

        addMessage('user', text);
        chatbotInput.value = '';
        showTyping();

        try {
            const baseUrl = window.KAVACH_API_BASE || '/api/v1';
            const res = await fetch(`${baseUrl}/ai/chat`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ message: text })
            });

            hideTyping();
            if (res.ok) {
                const data = await res.json();
                renderResponse(data.reply);
            } else {
                addMessage('ai', 'The AI engine is currently busy. Please try again in a moment.');
            }
        } catch (e) {
            hideTyping();
            addMessage('ai', 'Connection error. Check your internet or login status.');
        }
    }

    // Render AI Response (handles scan results)
    function renderResponse(reply) {
        if (reply.type === 'scan_results') {
            addMessage('ai', reply.message);
            reply.results.forEach(res => {
                const l1 = res.layers.layer1 || {};
                const l2 = res.layers.layer2 || { verdict: 'skipped', score: 0 };
                const l3 = res.layers.layer3 || { verdict: 'skipped', score: 0 };
                
                let html = `
                    <div class="scan-card">
                        <span class="scan-badge badge-${res.verdict}">${res.verdict}</span>
                        <span class="scan-url">${res.url}</span>
                        
                        <div class="layer-breakdown">
                            <div class="layer-item">
                                <span class="layer-name">Layer 1: Heuristics</span>
                                <span class="layer-status status-${l1.verdict === 'safe' ? 'active' : 'danger'}">${l1.verdict}</span>
                            </div>
                            <div class="layer-details">${l1.flags ? l1.flags.join(' · ') : 'No flags'}</div>
                            
                            <div class="layer-item">
                                <span class="layer-name">Layer 2: NLP Deep Learning</span>
                                <span class="layer-status status-${l2.verdict === 'safe' ? 'active' : l2.verdict === 'skipped' ? 'warn' : 'danger'}">${l2.verdict}</span>
                            </div>
                            <div class="layer-details">Score: ${l2.score}% · ${l2.model || 'Model ready'}</div>
                            
                            <div class="layer-item">
                                <span class="layer-name">Layer 3: Threat Intel</span>
                                <span class="layer-status status-${l3.verdict === 'safe' ? 'active' : l3.verdict === 'skipped' ? 'warn' : 'danger'}">${l3.verdict}</span>
                            </div>
                            <div class="layer-details">${l3.status || (l3.indicators ? l3.indicators.join(' · ') : 'No active threats')}</div>
                        </div>

                        ${res.blocked_details ? `
                            <div class="blocked-warning" style="background:#1e1b1b; border:1px solid #ef4444; border-radius:8px; padding:12px; margin-top:10px;">
                                <div style="color:#ef4444; font-weight:700; margin-bottom:8px;"><i class="bi bi-shield-slash-fill"></i> ${res.blocked_details.status}</div>
                                <div style="font-size:12px; margin-bottom:4px;"><b>Type:</b> ${res.blocked_details.threat_type}</div>
                                <div style="font-size:12px; margin-bottom:4px;"><b>Risk:</b> ${res.blocked_details.risk_level}</div>
                                <div style="font-size:12px; margin-bottom:8px; color:#94a3b8;"><b>Why:</b> ${res.blocked_details.why_risky}</div>
                                
                                <div style="color:#f87171; font-weight:600; font-size:11px; margin-bottom:10px;">
                                    ⚠️ This content has been identified as potentially harmful. It may compromise your data or security. Proceeding is not recommended.
                                </div>
                                
                                <div class="override-actions" style="display:flex; gap:8px;">
                                    <button class="btn-cancel" onclick="this.closest('.chat-msg').remove()" style="flex:1; background:#334155; border:none; color:white; padding:6px; border-radius:4px; font-size:11px; cursor:pointer;">Cancel</button>
                                    <button class="btn-proceed" data-url="${res.url}" data-risk="${res.blocked_details.risk_level}" style="flex:1; background:#ef4444; border:none; color:white; padding:6px; border-radius:4px; font-size:11px; cursor:pointer;">Proceed Anyway</button>
                                </div>
                            </div>
                        ` : ''}

                        ${res.neutralization ? `<div class="scan-flag" style="color:#10b981; margin-top:10px; font-weight:700;"><i class="bi bi-shield-fill-check"></i> Neutralized: ${res.neutralization.summary}</div>` : ''}
                    </div>
                `;
                const cardMsg = addMessage('ai', html, true);
                
                // Attach event listener for the proceed button
                const proceedBtn = cardMsg.querySelector('.btn-proceed');
                if (proceedBtn) {
                    proceedBtn.addEventListener('click', async () => {
                        const url = proceedBtn.getAttribute('data-url');
                        const risk = proceedBtn.getAttribute('data-risk');
                        const card = proceedBtn.closest('.blocked-warning');
                        
                        // Safety check: ensure URL has protocol for the link
                        const safeUrl = url.startsWith('http') ? url : 'http://' + url;

                        card.style.borderColor = '#fbbf24';
                        card.innerHTML = `
                            <div style="color:#fbbf24; font-weight:600; font-size:12px; margin-bottom:8px;">
                                <i class="bi bi-exclamation-triangle-fill"></i> Access Granted (User Override)
                            </div>
                            <div style="font-size:11px; color:#e2e8f0; margin-bottom:10px;">
                                You are accessing this content at your own risk. Kavach Net has logged this action for security audit.
                            </div>
                            <a href="${safeUrl}" target="_blank" rel="noopener noreferrer" 
                               style="display:block; text-align:center; background:#fbbf24; color:#000; text-decoration:none; padding:8px; border-radius:4px; font-weight:700; font-size:12px;">
                               Open Link <i class="bi bi-box-arrow-up-right ms-1"></i>
                            </a>
                        `;
                        
                        try {
                            const token = getToken();
                            const baseUrl = window.KAVACH_API_BASE || '/api/v1';
                            const logRes = await fetch(`${baseUrl}/ai/log-override`, {
                                method: 'POST',
                                headers: { 
                                    'Content-Type': 'application/json',
                                    'Authorization': `Bearer ${token}`
                                },
                                body: JSON.stringify({ url, risk })
                            });
                            
                            if (logRes.ok) {
                                const logData = await logRes.json();
                                if (logData.escalated) {
                                    const escMsg = document.createElement('div');
                                    escMsg.style.marginTop = '10px';
                                    escMsg.style.padding = '10px';
                                    escMsg.style.background = 'rgba(239, 68, 68, 0.1)';
                                    escMsg.style.border = '1px solid #ef4444';
                                    escMsg.style.borderRadius = '6px';
                                    escMsg.style.color = '#ef4444';
                                    escMsg.style.fontSize = '11px';
                                    escMsg.style.fontWeight = '700';
                                    escMsg.innerHTML = `<i class="bi bi-shield-fill-exclamation"></i> ${logData.message}`;
                                    card.parentNode.appendChild(escMsg);
                                }
                            }
                        } catch (e) {
                            console.error("Failed to log override", e);
                        }
                    });
                }
            });
        } else if (reply.type === 'help') {
            let html = `<b>Available Commands:</b><br><ul style="padding-left:15px; margin-top:5px;">`;
            reply.commands.forEach(c => {
                html += `<li><code>${c.cmd}</code>: ${c.desc}</li>`;
            });
            html += `</ul>`;
            addMessage('ai', html, true);
        } else {
            addMessage('ai', reply.message);
        }
    }

    // Events
    chatbotToggle.addEventListener('click', () => {
        const isActive = chatbotWindow.classList.toggle('active');
        chatbotToggle.classList.toggle('active');
        if (isActive) {
            chatbotInput.focus();
            loadHistory();
        }
    });

    chatbotClose.addEventListener('click', () => {
        chatbotWindow.classList.remove('active');
        chatbotToggle.classList.remove('active');
    });

    chatbotSend.addEventListener('click', sendMessage);
    chatbotInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

})();
