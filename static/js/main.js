// CodeConnect Main JavaScript - Fixed Version

// Global modal helpers
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.style.display = 'flex';
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.style.display = 'none';
}

window.openModal = openModal;
window.closeModal = closeModal;

// Small HTML-escape helper to avoid injecting raw content
function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';
    return String(unsafe)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

document.addEventListener('DOMContentLoaded', () => {
    // Global variables
    let socket = null;
    let myPrivateKey = null;
    const sessionKeys = {};
    
    const currentUserId = parseInt(document.body.dataset.userId || '-1');
    const currentUsername = document.body.dataset.username || null;
    let csrfToken = null;

    // Initialize all components
    initializeSocket();
    initializeTheme();
    initializeNotifications();
    initializeCodeHighlighting();
    initializeAutoResizeTextareas();
    initializeGlobalEventListeners();
    
    if (currentUserId !== -1) {
        fetchCsrfToken();
    }

    // CSRF Token Handling
    async function fetchCsrfToken() {
        try {
            const response = await fetch('/api/csrf_token');
            if (response.ok) {
                const data = await response.json();
                csrfToken = data.csrf_token;
                console.log("CSRF token fetched.");
            } else {
                console.error("Failed to fetch CSRF token:", response.status);
            }
        } catch (error) {
            console.error("Error fetching CSRF token:", error);
        }
    }

    function getFetchOptions(options = {}) {
        const headers = new Headers(options.headers || {});
        if (options.body && !(options.body instanceof FormData)) {
            headers.set('Content-Type', 'application/json');
        }
        if (csrfToken) {
            headers.set('X-CSRFToken', csrfToken);
        }
        return { ...options, headers };
    }
    
    window.getFetchOptions = getFetchOptions;

    // Ensure the user has an RSA keypair stored locally and upload the public key
    // to the server so others can initiate E2EE key exchange. This function will
    // generate keys if they don't exist and call the profile update API.
    async function ensureKeyPair(username) {
        if (!username) throw new Error('Username required for key generation');

        if (typeof generateKeyPair !== 'function' || typeof exportKeyToBase64 !== 'function' || typeof storePrivateKey !== 'function') {
            throw new Error('Encryption helpers are not available');
        }

        // Generate a fresh RSA keypair (if the user doesn't already have one)
        const keyPair = await generateKeyPair();
        if (!keyPair) throw new Error('Key pair generation failed');

        // Export public (SPKI) and private (PKCS8) keys to base64
        const publicSpkiB64 = await exportKeyToBase64(keyPair.publicKey, 'spki');
        const privatePkcs8B64 = await exportKeyToBase64(keyPair.privateKey, 'pkcs8');

        if (!publicSpkiB64 || !privatePkcs8B64) throw new Error('Key export failed');

        // Store the private key locally (never send private key to server)
        try {
            storePrivateKey(username, privatePkcs8B64);
        } catch (err) {
            console.error('Failed to store private key locally:', err);
            throw err;
        }

        // Upload the public key to the server via the profile update API
        try {
            const resp = await fetch('/api/update_profile', getFetchOptions({
                method: 'POST',
                body: JSON.stringify({ public_key: publicSpkiB64 })
            }));
            const result = await resp.json();
            if (!result.success) {
                console.error('Server refused public key upload:', result);
                throw new Error(result.message || 'Public key upload failed');
            }
            console.log('Public key uploaded to server successfully');
        } catch (err) {
            console.error('Failed to upload public key to server:', err);
            throw err;
        }
    }

    // Expose ensureKeyPair so it can be invoked manually from the console if needed
    window.ensureKeyPair = ensureKeyPair;

    // Expose for pages (e.g., messages) to use when filtering the conversation list
    window.filterConversations = function(query) {
        const q = (query || '').toLowerCase().trim();
        document.querySelectorAll('.conversation-item').forEach(item => {
            const name = (item.querySelector('.conv-info h4')?.textContent || '').toLowerCase();
            const username = (item.dataset.recipientUsername || '').toLowerCase();
            const preview = (item.querySelector('.last-message')?.textContent || '').toLowerCase();
            const match = !q || name.includes(q) || username.includes(q) || preview.includes(q);
            item.style.display = match ? '' : 'none';
        });
    };

    // Live user search (autocomplete) for messages page
    function debounce(fn, delay) {
        let t = null;
        return (...args) => {
            clearTimeout(t);
            t = setTimeout(() => fn(...args), delay);
        };
    }

    async function fetchUserSuggestions(q) {
        if (!q || q.length < 2) return [];
        try {
            const resp = await fetch(`/api/search_users?q=${encodeURIComponent(q)}`, getFetchOptions());
            if (!resp.ok) return [];
            const data = await resp.json();
            if (!data.success) return [];
            return data.results || [];
        } catch (e) {
            console.error('User search failed:', e);
            return [];
        }
    }

    function renderSearchResults(results, container) {
        container.innerHTML = '';
        if (!results || results.length === 0) {
            container.style.display = 'none';
            return;
        }
        results.forEach(r => {
            const div = document.createElement('div');
            div.className = 'search-result-item';
            div.innerHTML = `
                <div class="sr-avatar">${r.avatar ? `<img src="${r.avatar}" alt="${escapeHtml(r.display_name)}"/>` : '<div class="avatar-placeholder">' + escapeHtml((r.display_name||r.username)[0]) + '</div>'}</div>
                <div class="sr-info"><strong>${escapeHtml(r.display_name)}</strong><div class="sr-username">@${escapeHtml(r.username)}</div></div>
            `;
            div.addEventListener('click', async () => {
                // Start conversation and open it
                try {
                    const startResp = await fetch(`/api/start_conversation/${encodeURIComponent(r.username)}`, getFetchOptions({ method: 'POST', body: JSON.stringify({}) }));
                    const startData = await startResp.json();
                    if (startResp.ok && startData.success) {
                        const conv = {
                            conv_id: startData.client_conv_id,
                            conversation_id: startData.conversation_id,
                            other_user: startData.other_user,
                            last_message: ''
                        };
                        if (window.addConversationToList) window.addConversationToList(conv);
                        if (window.startOrOpenChat) window.startOrOpenChat(startData.other_user.id, startData.other_user.username, startData.client_conv_id);
                        window.showNotification(`Started chat with ${r.username}`, 'success');
                    } else {
                        window.showNotification(startData.message || 'Could not start conversation', 'error');
                    }
                } catch (e) {
                    console.error('Failed to start conversation from search result:', e);
                    window.showNotification('Could not start conversation', 'error');
                }
            });
            container.appendChild(div);
        });
        container.style.display = 'block';
    }

    // Wire up search input for live suggestions (if present)
    const convSearchInput = document.getElementById('conversationSearch');
    const searchResultsContainer = document.getElementById('searchResults');
    if (convSearchInput && searchResultsContainer) {
        const handler = debounce(async () => {
            const q = convSearchInput.value.trim();
            // First apply local filter
            if (window.filterConversations) window.filterConversations(q);
            if (q.length < 2) {
                renderSearchResults([], searchResultsContainer);
                return;
            }
            const results = await fetchUserSuggestions(q);
            renderSearchResults(results, searchResultsContainer);
        }, 250);

        convSearchInput.addEventListener('input', handler);

        // Hide suggestions when the input loses focus after a small delay
        convSearchInput.addEventListener('blur', () => setTimeout(() => renderSearchResults([], searchResultsContainer), 200));
    }

    // Socket.IO Initialization
    function initializeSocket() {
        if (typeof io === 'undefined') {
            console.error("Socket.IO client library not found.");
            return;
        }
        if (currentUserId === -1) {
            console.log("User not logged in, Socket.IO connection skipped.");
            return;
        }

        socket = io();

        socket.on('connect', async () => {
            console.log('Connected to Socket.IO server!');
            // Let the client announce the authenticated user (if available)
            socket.emit('user_online_announce');

            if (currentUsername) {
                // Try to load the local private key. If it's missing, generate a new
                // keypair, store the private key locally and upload the public key
                // to the server so other users can initiate E2EE key exchange.
                myPrivateKey = await loadPrivateKey(currentUsername);
                if (!myPrivateKey) {
                    console.log('No local private key found — generating one and uploading public key.');
                    try {
                        await ensureKeyPair(currentUsername);
                        myPrivateKey = await loadPrivateKey(currentUsername);
                        if (myPrivateKey) console.log('Private key generated and loaded.');
                        else console.error('Private key still not available after generation.');
                    } catch (err) {
                        console.error('Keypair generation/upload failed:', err);
                    }
                } else {
                    console.log('Private key loaded successfully.');
                }
            }
        });

        socket.on('disconnect', (reason) => {
            console.log('Disconnected from Socket.IO server:', reason);
        });

        socket.on('error', (data) => {
            console.error("Socket.IO Server error:", data.message || data);
            showNotification(`Server error: ${data.message || 'Unknown error'}`, 'error');
        });

        socket.on('new_message', handleNewMessage);
        socket.on('key_exchange', handleKeyExchange);
        socket.on('key_established', (data) => {
        console.log('Key established ack from:', data);
        const otherId = data.other_user_id;
        if (sessionKeys[otherId]) {
            const inputArea = document.getElementById('messageInputArea');
            if (inputArea) inputArea.style.display = 'flex';
            addSystemMessage(`Secure session established with ${data.other_username}.`);
        }
    });


        socket.on('notification', (data) => {
            showNotification(data.message, data.type || 'info');
        });
    }

    // E2EE Chat Logic
    let currentChatRecipient = { userId: null, username: null, publicKey: null };
    
    window.startOrOpenChat = async function(recipientId, recipientUsername, conversationId = null) {
        if (!myPrivateKey) {
            alert("Your encryption key isn't loaded. Cannot start secure chat.");
            return;
        }
        if (recipientId == currentUserId) {
            alert("You cannot chat with yourself.");
            return;
        }

        console.log(`Starting/opening chat with User ID: ${recipientId} (${recipientUsername})`);
        
    const tempConvId = conversationId || findOrCreateConversationId(currentUserId, recipientId);
    // Join the conversation room. The server will accept the join and map it.
    socket.emit('join_conversation', { conversation_id: tempConvId });

    displayChatWindow(recipientId, recipientUsername, tempConvId);

        currentChatRecipient.userId = recipientId;
        currentChatRecipient.username = recipientUsername;
        currentChatRecipient.publicKey = null;

        if (sessionKeys[recipientId]) {
            console.log(`E2EE session key already exists for user ${recipientId}.`);
            addSystemMessage(`Secure session re-established with ${recipientUsername}.`);
            return;
        }

        console.log(`No session key found. Initiating key exchange with ${recipientUsername}.`);
        try {
            const response = await fetch(`/api/user/${recipientUsername}/public_key`);
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `Failed to get public key (${response.status})`);
            }
            const data = await response.json();
            const recipientPublicKey = await importPublicKey(data.public_key);
            if (!recipientPublicKey) {
                throw new Error("Could not import recipient's public key.");
            }
            currentChatRecipient.publicKey = recipientPublicKey;

            const newSessionKey = await generateSessionKey();
            if (!newSessionKey) {
                throw new Error("Failed to generate session key.");
            }
            sessionKeys[recipientId] = newSessionKey;

            const encryptedKeyB64 = await encryptSessionKey(newSessionKey, recipientPublicKey);
            if (!encryptedKeyB64) {
                throw new Error("Failed to encrypt session key.");
            }

            socket.emit('exchange_keys', {
                recipient_id: recipientId,
                encrypted_key: encryptedKeyB64
            });

            console.log(`Sent encrypted session key to user ${recipientId}.`);
            addSystemMessage(`Initiating secure session with ${recipientUsername}...`);

        } catch (error) {
            console.error("E2EE Key Exchange initiation failed:", error);
            addSystemMessage(`Error initiating secure session: ${error.message}`, 'error');
            currentChatRecipient = { userId: null, username: null, publicKey: null };
            const inputArea = document.getElementById('messageInputArea');
            if(inputArea) inputArea.style.display = 'none';
        }
    }

    // Adds a conversation entry to the left-hand list (if missing)
    window.addConversationToList = function(conv) {
        try {
            const list = document.querySelector('.conversations-list');
            if (!list) return;

            // Avoid duplicates
            if (document.querySelector(`.conversation-item[data-conv-id="${conv.conv_id}"]`)) return;

            const item = document.createElement('div');
            item.className = 'conversation-item';
            item.setAttribute('data-conv-id', conv.conv_id);
            item.setAttribute('data-recipient-id', conv.other_user.id);
            item.setAttribute('data-recipient-username', conv.other_user.username);

            const avatarDiv = document.createElement('div');
            avatarDiv.className = 'conv-avatar';
            if (conv.other_user.avatar) {
                const img = document.createElement('img');
                img.src = conv.other_user.avatar;
                img.alt = conv.other_user.display_name;
                avatarDiv.appendChild(img);
            } else {
                const ph = document.createElement('div');
                ph.className = 'avatar-placeholder';
                ph.textContent = (conv.other_user.display_name || 'U')[0];
                avatarDiv.appendChild(ph);
            }

            const info = document.createElement('div');
            info.className = 'conv-info';
            info.innerHTML = `<h4>${escapeHtml(conv.other_user.display_name || conv.other_user.username)}</h4><p class="last-message">${escapeHtml(conv.last_message || 'No messages yet')}</p>`;

            const timeDiv = document.createElement('div');
            timeDiv.className = 'conv-time';
            timeDiv.textContent = '';

            item.appendChild(avatarDiv);
            item.appendChild(info);
            item.appendChild(timeDiv);

            // Wire click handler
            item.addEventListener('click', () => {
                if (window.startOrOpenChat) {
                    window.startOrOpenChat(conv.other_user.id, conv.other_user.username, conv.conv_id);
                }
            });

            list.prepend(item);
        } catch (e) {
            console.error('Failed to add conversation to list:', e);
        }
    }

    // Key section of main.js - Fixed message sending and receiving

// Inside the handleSendMessage function - FIXED VERSION
async function handleSendMessage(e) {
    e.preventDefault();
    const messageInput = document.getElementById('messageInput');
    if (!messageInput) return;

    const plaintext = messageInput.value.trim();
    const recipientId = currentChatRecipient.userId;
    const conversationId = document.getElementById('currentConversationId').value;

    if (!plaintext || !recipientId || !conversationId) {
        console.error('Missing message data:', { plaintext: !!plaintext, recipientId, conversationId });
        return;
    }

    const sessionKey = sessionKeys[recipientId];
    if (!sessionKey) {
        addSystemMessage("Error: No secure session. Cannot send.", 'error');
        console.error('No session key for recipient:', recipientId);
        return;
    }

    try {
        console.log('Encrypting message:', { length: plaintext.length, recipientId });
        
        // Encrypt the message
        const encryptedData = await encryptChatMessage(plaintext, sessionKey);
        if (!encryptedData || !encryptedData.iv || !encryptedData.ciphertext) {
            throw new Error("Encryption returned invalid data");
        }

        console.log('Message encrypted:', {
            ivLength: encryptedData.iv.length,
            ciphertextLength: encryptedData.ciphertext.length
        });

        // Send via socket with proper structure
        socket.emit('send_message', {
            conversation_id: conversationId,
            content: encryptedData.ciphertext,
            message_type: 'text',
            metadata: { 
                iv: encryptedData.iv  // Critical: IV must be sent with message
            }
        });

        console.log('Message sent to socket');

        // Add to UI immediately (optimistic update)
        addMessageToUI({
            id: `temp_${Date.now()}`,
            content: plaintext,
            isDecrypted: true,
            message_type: 'text',
            sender: { 
                id: currentUserId, 
                username: currentUsername, 
                display_name: currentUsername 
            },
            created_at: new Date().toISOString()
        });

        // Clear input
        messageInput.value = '';
        messageInput.style.height = 'auto';

    } catch (e) {
        console.error("Sending message failed:", e);
        addSystemMessage(`Error sending message: ${e.message}`, 'error');
    }
}

// FIXED handleNewMessage function
async function handleNewMessage(data) {
    console.log("Received new message data:", data);
    
    const senderId = data.sender.id;
    
    // Skip messages sent by current user (already in UI from optimistic update)
    if (senderId === currentUserId) {
        console.log('Ignoring server echo of message sent by current user');
        return;
    }

    const relevantUserId = senderId;
    const sessionKey = sessionKeys[relevantUserId];

    const isCurrentChat = (data.conversation_id === document.getElementById('currentConversationId')?.value);
    
    let plaintext = "[Encrypted Message]";
    let isDecrypted = false;

    // Attempt decryption
    if (!sessionKey) {
        console.warn(`Received message from user ${senderId} but no session key found.`);
        plaintext = "[Waiting for encryption key...]";
    } else {
        try {
            // CRITICAL FIX: Validate metadata structure
            if (!data.metadata || !data.metadata.iv) {
                throw new Error("Message missing IV in metadata");
            }

            console.log('Decrypting message:', {
                messageId: data.id,
                senderId: senderId,
                hasIV: !!data.metadata.iv,
                hasContent: !!data.content,
                ivLength: data.metadata.iv?.length,
                contentLength: data.content?.length
            });

            // Decrypt with IV from metadata
            plaintext = await decryptChatMessage(
                data.metadata.iv,      // IV from metadata
                data.content,          // Encrypted content
                sessionKey            // Session key for this user
            );
            
            isDecrypted = true;
            console.log('Message decrypted successfully:', {
                messageId: data.id,
                plaintextPreview: plaintext.substring(0, 50)
            });

        } catch (e) {
            console.error(`Failed to decrypt message ${data.id}:`, e);
            console.error('Decryption context:', {
                messageId: data.id,
                senderId: senderId,
                hasSessionKey: !!sessionKey,
                metadataKeys: Object.keys(data.metadata || {}),
                ivPresent: !!(data.metadata && data.metadata.iv),
                contentLength: data.content?.length
            });
            plaintext = "[Decryption Failed]";
        }
    }

    if (isCurrentChat) {
        // Add message to current chat UI
        addMessageToUI({
            ...data,
            content: plaintext,
            isDecrypted: isDecrypted
        });
    } else {
        console.log(`Message received for inactive chat (Sender: ${senderId}).`);

        // Update conversation list
        const convItem = document.querySelector(`.conversation-item[data-conv-id="${data.conversation_id}"]`);
        if (!convItem) {
            // Create new conversation item if it doesn't exist
            const conv = {
                conv_id: data.conversation_id,
                conversation_id: null,
                other_user: {
                    id: data.sender.id,
                    username: data.sender.username,
                    display_name: data.sender.display_name,
                    avatar: data.sender.avatar || null
                },
                last_message: plaintext || ''
            };
            if (window.addConversationToList) window.addConversationToList(conv);
        } else {
            updateConversationListPreview(
                data.conversation_id, 
                data.sender.display_name, 
                plaintext, 
                data.created_at
            );
        }

        updateConversationListNotification(data.conversation_id, true);
        showNotification(`New message from ${data.sender.display_name}`, 'message');
    }
}

    // Handle receiving an encrypted session key from another user
    async function handleKeyExchange(data) {
        const senderId = data.sender_id;
        const senderUsername = data.sender_username;
        const encryptedKeyB64 = data.encrypted_key;

        console.log(`Received encrypted session key from ${senderUsername} (ID: ${senderId}).`);

        if (!myPrivateKey) {
            console.error("Cannot decrypt session key: Private key not loaded.");
            if (senderId === currentChatRecipient.userId) {
                addSystemMessage(`Received session key from ${senderUsername}, but your private key isn't loaded.`, 'error');
            }
            return;
        }

        try {
            const decryptedSessionKey = await decryptSessionKey(encryptedKeyB64, myPrivateKey);
            if (!decryptedSessionKey) {
                throw new Error("Session key decryption returned null.");
            }

            // Store decrypted AES session key for this sender
            sessionKeys[senderId] = decryptedSessionKey;
            console.log(`Successfully decrypted and stored session key for ${senderUsername} (ID: ${senderId}).`);

            // ✅ ACKNOWLEDGE SUCCESSFUL IMPORT TO SERVER
            socket.emit('key_established', { 
                other_user_id: senderId, 
                other_username: senderUsername 
            });
            console.log('Emitted key_established ack to server for senderId:', senderId);

            if (senderId === currentChatRecipient.userId) {
                addSystemMessage(`Secure session established with ${senderUsername}.`);
            }
        } catch (e) {
            console.error(`Failed to decrypt/import session key from ${senderUsername}:`, e);
            if (senderId === currentChatRecipient.userId) {
                addSystemMessage(`Failed to establish secure session with ${senderUsername}.`, 'error');
            }
        }
    }




    // UI Update Functions for Chat
    function displayChatWindow(recipientId, recipientUsername, conversationId) {
        const noConvEl = document.getElementById('noConversation');
        const convViewEl = document.getElementById('conversationView');
        const messagesArea = document.getElementById('messagesArea');
        const inputArea = document.getElementById('messageInputArea');
        const convUserName = document.getElementById('convUserName');
        const convAvatar = document.getElementById('convAvatar');
        const currentConvIdInput = document.getElementById('currentConversationId');

        if (noConvEl) noConvEl.style.display = 'none';
        if (convViewEl) convViewEl.style.display = 'flex';
        if (convUserName) convUserName.textContent = recipientUsername;
        if (convAvatar) convAvatar.textContent = recipientUsername[0].toUpperCase();
        if (messagesArea) messagesArea.innerHTML = '';
        if (inputArea) inputArea.style.display = 'flex';
        if (currentConvIdInput) currentConvIdInput.value = conversationId;

        document.querySelectorAll('.conversation-item').forEach(item => {
            item.classList.remove('active');
            if (item.dataset.recipientId == recipientId) {
                item.classList.add('active');
                updateConversationListNotification(item.dataset.convId, false);
            }
        });
    }

    function addMessageToUI(message) {
        const messagesArea = document.getElementById('messagesArea');
        if (!messagesArea) return;

        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${(message.sender.id == currentUserId) ? 'sent' : 'received'}`;
        
        const contentP = document.createElement('p');
        contentP.textContent = message.content;
        if (!message.isDecrypted) {
            contentP.style.fontStyle = 'italic';
            contentP.style.opacity = '0.7';
        }

        const timeSpan = document.createElement('span');
        timeSpan.className = 'message-time';
        timeSpan.textContent = new Date(message.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        const messageContentDiv = document.createElement('div');
        messageContentDiv.className = 'message-content';
        messageContentDiv.appendChild(contentP);
        messageContentDiv.appendChild(timeSpan);

        messageDiv.appendChild(messageContentDiv);
        messagesArea.appendChild(messageDiv);
        messagesArea.scrollTop = messagesArea.scrollHeight;
    }

    function addSystemMessage(text, type = 'info') {
        const messagesArea = document.getElementById('messagesArea');
        if (!messagesArea) return;

        const systemDiv = document.createElement('div');
        systemDiv.className = `message system-message ${type}`;
        systemDiv.textContent = text;
        messagesArea.appendChild(systemDiv);
        messagesArea.scrollTop = messagesArea.scrollHeight;
    }

    function findOrCreateConversationId(userId1, userId2) {
        const convItem = document.querySelector(`.conversation-item[data-recipient-id="${userId2}"]`);
        if (convItem) {
            return convItem.dataset.convId;
        }
        const ids = [userId1, userId2].sort();
        return `conv_${ids[0]}_${ids[1]}`;
    }

    function updateConversationListPreview(conversationId, senderName, lastMessageText, timestamp) {
        const convItem = document.querySelector(`.conversation-item[data-conv-id="${conversationId}"]`);
        if (convItem) {
            const lastMsgEl = convItem.querySelector('.last-message');
            const timeEl = convItem.querySelector('.conv-time');
            const prefix = (senderName === currentUsername) ? "You: " : "";
            
            if (lastMsgEl) lastMsgEl.textContent = prefix + (lastMessageText.substring(0, 25) + (lastMessageText.length > 25 ? '...' : ''));
            if (timeEl) timeEl.textContent = new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            
            convItem.parentElement.prepend(convItem);
        }
    }

    function updateConversationListNotification(conversationId, hasUnread) {
        const convItem = document.querySelector(`.conversation-item[data-conv-id="${conversationId}"]`);
        if (convItem) {
            convItem.classList.toggle('unread', hasUnread);
        }
    }

    // Event Listeners for Chat
    const messageForm = document.getElementById('messageForm');
    if (messageForm) {
        messageForm.addEventListener('submit', handleSendMessage);
        const msgInput = document.getElementById('messageInput');
        if (msgInput) {
            msgInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleSendMessage(e);
                }
            });
        }
    }

    // Profile Page Follow/Unfollow
    const followBtn = document.getElementById('profile-follow-btn');
    if (followBtn) {
        followBtn.addEventListener('click', async () => {
            const username = followBtn.dataset.username;
            const action = followBtn.dataset.action;
            const url = `/api/${action}/${username}`;

            followBtn.disabled = true;

            try {
                const response = await fetch(url, getFetchOptions({ method: 'POST' }));
                const data = await response.json();

                if (data.success) {
                    if (action === 'follow') {
                        followBtn.textContent = 'Unfollow';
                        followBtn.dataset.action = 'unfollow';
                        followBtn.classList.remove('btn-primary');
                        followBtn.classList.add('btn-secondary');
                    } else {
                        followBtn.textContent = 'Follow';
                        followBtn.dataset.action = 'follow';
                        followBtn.classList.remove('btn-secondary');
                        followBtn.classList.add('btn-primary');
                    }
                    const followerCountEl = document.getElementById('follower-count-display');
                    if(followerCountEl) followerCountEl.textContent = data.follower_count;
                } else {
                    showNotification(`Error: ${data.message || 'Action failed'}`, 'error');
                }
            } catch (err) {
                console.error('Follow/unfollow action failed:', err);
                showNotification('A network error occurred.', 'error');
            } finally {
                followBtn.disabled = false;
            }
        });
    }

    // Post Liking
    document.querySelectorAll('.like-btn').forEach(button => {
        button.addEventListener('click', async () => {
            const postCard = button.closest('.post-card');
            const postId = postCard?.dataset.postId;
            if (!postId) return;

            button.disabled = true;

            try {
                const response = await fetch(`/api/like_post/${postId}`, getFetchOptions({ method: 'POST' }));
                const data = await response.json();

                if (data.success) {
                    const countSpan = button.querySelector('.like-count');
                    if(countSpan) countSpan.textContent = data.likes;
                    button.classList.toggle('liked', data.liked);
                } else {
                    showNotification(`Error: ${data.message || 'Like failed'}`, 'error');
                }
            } catch (err) {
                console.error('Like action failed:', err);
                showNotification('A network error occurred.', 'error');
            } finally {
                button.disabled = false;
            }
        });
    });

    // Post Commenting: open comment area, load comments, submit new comment
    document.querySelectorAll('.comment-btn').forEach(button => {
        button.addEventListener('click', async () => {
            const postCard = button.closest('.post-card');
            const postId = postCard?.dataset.postId;
            if (!postId) return;

            const commentsSection = postCard.querySelector('.comments-section');
            if (!commentsSection) return;

            // Toggle visibility
            const isVisible = commentsSection.style.display === 'block';
            if (isVisible) {
                commentsSection.style.display = 'none';
                return;
            }

            // Show and load comments
            commentsSection.style.display = 'block';
            const commentsList = commentsSection.querySelector('.comments-list');
            commentsList.innerHTML = '<p style="opacity:.6">Loading comments...</p>';

            try {
                const resp = await fetch(`/api/post/${postId}/comments`);
                const data = await resp.json();
                if (!data.success) {
                    throw new Error(data.message || 'Failed to load comments');
                }

                commentsList.innerHTML = '';
                if (data.comments.length === 0) {
                    commentsList.innerHTML = '<p style="opacity:.7">No comments yet. Be the first!</p>';
                } else {
                    data.comments.forEach(c => {
                        const div = document.createElement('div');
                        div.className = 'comment-item';
                        div.style.padding = '.5rem 0';
                        div.innerHTML = `<strong>${escapeHtml(c.author.display_name)}</strong> <span style="color:#666; font-size:.85rem;">${new Date(c.created_at).toLocaleString()}</span><div>${escapeHtml(c.content)}</div>`;
                        commentsList.appendChild(div);
                    });
                }
            } catch (err) {
                console.error('Loading comments failed:', err);
                commentsList.innerHTML = '<p style="color:var(--danger, #c00)">Could not load comments.</p>';
            }

            // Hook form submit
            const form = commentsSection.querySelector('.comment-form');
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const input = form.querySelector('.comment-input');
                const text = (input.value || '').trim();
                if (!text) return;
                try {
                    const response = await fetch(`/api/post/${postId}/comments`, getFetchOptions({
                        method: 'POST',
                        body: JSON.stringify({ content: text })
                    }));
                    const res = await response.json();
                    if (!res.success) {
                        throw new Error(res.message || 'Failed to post comment');
                    }
                    // Add to UI (prepend)
                    const newDiv = document.createElement('div');
                    newDiv.className = 'comment-item';
                    newDiv.style.padding = '.5rem 0';
                    newDiv.innerHTML = `<strong>${escapeHtml(currentUsername || 'You')}</strong> <span style="color:#666; font-size:.85rem;">just now</span><div>${escapeHtml(text)}</div>`;
                    // If 'No comments yet' message present, remove it
                    if (commentsList.querySelector('p') && commentsList.children.length === 1) commentsList.innerHTML = '';
                    commentsList.appendChild(newDiv);
                    input.value = '';

                    // Update comments count on post card
                    const countSpan = postCard.querySelector('.comment-btn span');
                    if (countSpan) {
                        const num = parseInt(countSpan.textContent || '0') + 1;
                        countSpan.textContent = num;
                    }
                } catch (err) {
                    console.error('Posting comment failed:', err);
                    showNotification('Could not post comment: ' + (err.message || ''), 'error');
                }
            }, { once: true });
        });
    });

    // Repo Starring
    document.querySelectorAll('.star-btn').forEach(button => {
        button.addEventListener('click', async () => {
            const repoId = button.dataset.repoId;
            if (!repoId) return;

            button.disabled = true;

            try {
                const response = await fetch(`/api/star_repo/${repoId}`, getFetchOptions({ method: 'POST' }));
                const data = await response.json();

                if (data.success) {
                    const iconSpan = button.querySelector('.star-icon');
                    const countSpan = button.querySelector('.star-count');
                    if (iconSpan) iconSpan.textContent = data.starred ? '⭐' : '☆';
                    if (countSpan) countSpan.textContent = data.stars;
                    button.classList.toggle('starred', data.starred);
                } else {
                    showNotification(`Error: ${data.message || 'Star failed'}`, 'error');
                }
            } catch (err) {
                console.error('Star action failed:', err);
                showNotification('A network error occurred.', 'error');
            } finally {
                button.disabled = false;
            }
        });
    });

    // Notification System
    function initializeNotifications() {
        if (!document.querySelector('.toast-container')) {
            const container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
    }

    function showNotification(message, type = 'info') {
        const container = document.querySelector('.toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        const icon = { info: 'ℹ️', success: '✅', warning: '⚠️', error: '❌', message: '💬' }[type] || 'ℹ️';

        toast.innerHTML = `
            <div class="toast-content">
                <span class="toast-icon">${icon}</span>
                <span class="toast-message">${message}</span>
                <button class="toast-close">&times;</button>
            </div>
        `;
        container.appendChild(toast);

        const removeToast = () => {
            toast.classList.add('removing');
            toast.addEventListener('animationend', () => {
                if (toast.parentNode) toast.parentNode.removeChild(toast);
            });
        };
        
        toast.querySelector('.toast-close').addEventListener('click', removeToast);
        setTimeout(removeToast, 5000);
    }
    
    window.showNotification = showNotification;

    // Theme Management
    function initializeTheme() {
        const savedTheme = localStorage.getItem('codeconnect-theme') || 'light';
        applyTheme(savedTheme);
        const themeToggleBtn = document.getElementById('theme-toggle-btn');
        if (themeToggleBtn) {
            themeToggleBtn.addEventListener('click', toggleTheme);
        }
    }

    function toggleTheme() {
        const currentTheme = document.body.getAttribute('data-theme') || 'light';
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        applyTheme(newTheme);
        localStorage.setItem('codeconnect-theme', newTheme);
    }

    function applyTheme(theme) {
        document.body.setAttribute('data-theme', theme);
        const themeToggleBtn = document.getElementById('theme-toggle-btn');
        if (themeToggleBtn) {
            themeToggleBtn.querySelector('.nav-icon').textContent = theme === 'light' ? '🌙' : '☀️';
        }
    }

    // Misc UI Helpers
    function initializeCodeHighlighting() {
        if (typeof Prism !== 'undefined') {
            Prism.highlightAll();
        } else {
            console.warn("Prism syntax highlighter not found.");
        }
    }

    function initializeAutoResizeTextareas() {
        document.querySelectorAll('textarea').forEach(textarea => {
            const listener = () => {
                textarea.style.height = 'auto';
                textarea.style.height = `${textarea.scrollHeight}px`;
            };
            textarea.addEventListener('input', listener);
            textarea.addEventListener('focus', listener);
            listener();
        });
    }

    function initializeGlobalEventListeners() {
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal').forEach(modal => {
                    if (modal.style.display === 'flex') {
                        closeModal(modal.id);
                    }
                });
            }
        });

        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) closeModal(modal.id);
            });
        });
    }

});