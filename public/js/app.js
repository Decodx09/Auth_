const API_URL = '/api';

let state = {
    accessToken: localStorage.getItem('access_token'),
    refreshToken: localStorage.getItem('refresh_token'),
    user: null
};

const setTokens = (access, refresh) => {
    localStorage.setItem('access_token', access);
    localStorage.setItem('refresh_token', refresh);
    state.accessToken = access;
    state.refreshToken = refresh;
};

const clearTokens = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    state.accessToken = null;
    state.refreshToken = null;
    state.user = null;
};

const showAlert = (message, isError = true) => {
    const alertEl = document.getElementById('alert');
    if (!alertEl) return;
    
    alertEl.textContent = message;
    alertEl.className = `alert ${isError ? 'alert-error' : 'alert-success'} show`;
    
    setTimeout(() => {
        alertEl.classList.remove('show');
    }, 5000);
};

const api = async (endpoint, options = {}) => {
    const defaultHeaders = {
        'Content-Type': 'application/json'
    };

    if (state.accessToken) {
        defaultHeaders['Authorization'] = `Bearer ${state.accessToken}`;
    }

    try {
        let response = await fetch(`${API_URL}${endpoint}`, {
            ...options,
            headers: { ...defaultHeaders, ...options.headers }
        });

        // Soft refresh logic
        if (response.status === 401 && state.refreshToken && endpoint !== '/auth/refresh-token') {
            const refreshRes = await fetch(`${API_URL}/auth/refresh-token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refresh_token: state.refreshToken })
            });

            if (refreshRes.ok) {
                const { access_token } = await refreshRes.json();
                setTokens(access_token, state.refreshToken);
                
                defaultHeaders['Authorization'] = `Bearer ${access_token}`;
                response = await fetch(`${API_URL}${endpoint}`, {
                    ...options,
                    headers: { ...defaultHeaders, ...options.headers }
                });
            } else {
                clearTokens();
                renderLogin();
                throw new Error("Session expired. Please log in again.");
            }
        }

        const data = await response.json().catch(() => ({}));
        
        if (!response.ok) {
            throw new Error(data.error || 'Something went wrong');
        }
        
        return data;
    } catch (error) {
        throw error;
    }
};

const appContainer = document.getElementById('app');

const renderHTML = (html) => {
    appContainer.innerHTML = html;
};

// --- View Actions Wrapper ---
const handleAction = async (e, endpoint, body, btnText, onSuccess) => {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    const ogText = btn.textContent;
    btn.textContent = btnText;
    btn.disabled = true;

    try {
        const res = await api(endpoint, {
            method: 'POST',
            body: JSON.stringify(body)
        });
        await onSuccess(res);
    } catch (err) {
        showAlert(err.message);
        btn.textContent = ogText;
        btn.disabled = false;
    }
};

const renderLogin = () => {
    renderHTML(`
        <div class="glass-card">
            <div class="view-header">
                <h1>Welcome Back</h1>
                <p>Sign in to your account securely</p>
            </div>
            <div id="alert" class="alert"></div>
            <form id="loginForm">
                <div class="form-group">
                    <label>Email Address</label>
                    <input type="email" id="email" required placeholder="you@example.com">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="password" required placeholder="••••••••">
                </div>
                <button type="submit" class="btn btn-primary">Sign In</button>
            </form>
            <div class="auth-links">
                <a class="link" onclick="renderRegister()">Create an account</a>
                <a class="link" onclick="renderForgotPassword()">Forgot your password?</a>
            </div>
        </div>
    `);

    document.getElementById('loginForm').addEventListener('submit', (e) => {
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        handleAction(e, '/auth/login', { email, password }, 'Signing in...', async (res) => {
            setTokens(res.access_token, res.refresh_token);
            await loadProfile();
        });
    });
};

const renderRegister = () => {
    renderHTML(`
        <div class="glass-card">
            <div class="view-header">
                <h1>Create Account</h1>
                <p>Start your journey today</p>
            </div>
            <div id="alert" class="alert"></div>
            <form id="registerForm">
                <div class="form-group">
                    <label>Email Address</label>
                    <input type="email" id="email" required placeholder="you@example.com">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="password" required placeholder="••••••••" minlength="8">
                </div>
                <button type="submit" class="btn btn-primary">Sign Up</button>
            </form>
            <div class="auth-links">
                <a class="link" onclick="renderLogin()">Already have an account? Sign in</a>
            </div>
        </div>
    `);

    document.getElementById('registerForm').addEventListener('submit', (e) => {
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        handleAction(e, '/auth/register', { email, password }, 'Creating...', (res) => {
            showAlert(res.message, false);
            e.target.querySelector('button').textContent = 'Check your email';
            setTimeout(renderLogin, 3000);
        });
    });
};

const renderForgotPassword = () => {
    renderHTML(`
        <div class="glass-card">
            <div class="view-header">
                <h1>Reset Password</h1>
                <p>We'll send you a recovery link</p>
            </div>
            <div id="alert" class="alert"></div>
            <form id="forgotForm">
                <div class="form-group">
                    <label>Email Address</label>
                    <input type="email" id="email" required placeholder="you@example.com">
                </div>
                <button type="submit" class="btn btn-primary">Send Reset Link</button>
            </form>
            <div class="auth-links">
                <a class="link" onclick="renderLogin()">Back to Sign In</a>
            </div>
        </div>
    `);

    document.getElementById('forgotForm').addEventListener('submit', (e) => {
        const email = document.getElementById('email').value;
        handleAction(e, '/auth/forgot-password', { email }, 'Sending...', (res) => {
            showAlert(res.message, false);
            e.target.querySelector('button').textContent = 'Link Sent';
        });
    });
};

const renderDashboard = () => {
    if (!state.user) return renderLogin();

    const isAdmin = state.user.role === 'admin';
    const roleBadge = isAdmin ? 'badge-admin' : 'badge-user';

    renderHTML(`
        <div class="glass-card" style="width: 100%;">
            <div class="view-header">
                <h1>Dashboard</h1>
                <p>Manage your active sessions</p>
            </div>
            <div id="alert" class="alert"></div>
            
            <div class="dashboard-stats">
                <div class="stat-row">
                    <span class="stat-label">Email Context</span>
                    <span class="stat-value">${state.user.email}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">Clearance</span>
                    <span class="stat-value"><span class="badge ${roleBadge}">${state.user.role.toUpperCase()}</span></span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">System State</span>
                    <span class="stat-value" style="color: var(--success-color)">Healthy & Active</span>
                </div>
            </div>

            <div style="display: flex; flex-direction: column; gap: 0.75rem;">
                <button onclick="handleLogout()" class="btn btn-secondary">Logout Current Session</button>
                <button onclick="handleLogoutAll()" class="btn btn-secondary">Terminate ALL Sessions</button>
                <button onclick="handleDeactivate()" class="btn btn-danger" style="margin-top: 1rem; border-radius: 8px;">Deactivate Account</button>
                
                ${isAdmin ? '<div style="margin-top: 2rem"><p style="font-size:0.8rem; color:var(--error-color); margin-bottom: 0.5rem">Admin Danger Zone</p><button onclick="handleForceLogoutAllUsers()" class="btn btn-danger">Wipe Session Map (Global)</button></div>' : ''}
            </div>
        </div>
    `);
};

// Application Flow & Triggers
window.handleLogout = async () => {
    api('/user/logout', { method: 'POST', body: JSON.stringify({ refresh_token: state.refreshToken }) }).catch(()=>{});
    clearTokens();
    renderLogin();
};

window.handleLogoutAll = async () => {
    try {
        await api('/user/logout-all', { method: 'POST' });
        clearTokens();
        renderLogin();
    } catch (e) { showAlert(e.message); }
};

window.handleDeactivate = async () => {
    if(!confirm("Are you sure? This immediately locks you out.")) return;
    try {
        await api('/user/deactivate', { method: 'POST' });
        clearTokens();
        renderLogin();
        setTimeout(() => showAlert("Account deactivated successfully.", false), 100);
    } catch (e) { showAlert(e.message); }
};

window.handleForceLogoutAllUsers = async () => {
    if (!confirm("CRITICAL WARNING: This forces a global sign out action on all logged in users. Proceed?")) return;
    try {
        const res = await api('/admin/logout-all-users', { method: 'POST' });
        showAlert(res.message, false);
    } catch (e) { showAlert(e.message); }
};

const loadProfile = async () => {
    try {
        const data = await api('/user/profile');
        state.user = data.user;
        renderDashboard();
    } catch (error) {
        clearTokens();
        renderLogin();
    }
};

const urlParams = new URLSearchParams(window.location.search);
if (window.location.pathname === '/verify-email') {
    const token = urlParams.get('token');
    api('/auth/verify-email?token=' + token)
        .then(res => {
            renderLogin();
            setTimeout(() => showAlert(res.message, false), 100);
        })
        .catch(err => {
            renderLogin();
            setTimeout(() => showAlert(err.message), 100);
        });
} else if (window.location.pathname === '/reset-password') {
    const token = urlParams.get('token');
    renderHTML(`
        <div class="glass-card">
            <div class="view-header">
                <h1>Set Password</h1>
                <p>Provide a fresh string</p>
            </div>
            <div id="alert" class="alert"></div>
            <form id="resetForm">
                <div class="form-group">
                    <label>New Password</label>
                    <input type="password" id="password" required placeholder="••••••••" minlength="8">
                </div>
                <button type="submit" class="btn btn-primary">Reset Credentials</button>
            </form>
        </div>
    `);

    document.getElementById('resetForm').addEventListener('submit', (e) => {
        const new_password = document.getElementById('password').value;
        handleAction(e, '/auth/reset-password', { token, new_password }, 'Resetting...', () => {
            renderLogin();
            setTimeout(() => showAlert("Password restored. Please sign in.", false), 100);
        });
    });
} else {
    // Normal start
    if (state.accessToken) {
        loadProfile();
    } else {
        renderLogin();
    }
}
