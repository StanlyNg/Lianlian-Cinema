// 密码保护配置
const PASSWORD_CONFIG = {
    localStorageKey: 'libretv_password_verified',
    adminLocalStorageKey: 'libretv_admin_verified',
    verificationTTL: 20 * 60 * 60 * 1000 // 20小时
};

/**
 * 检查是否设置了密码保护
 */
function isPasswordProtected() {
    const pwd = window.__ENV__?.PASSWORD;
    const adminPwd = window.__ENV__?.ADMINPASSWORD;

    const isPwdValid = typeof pwd === 'string' && pwd.length === 64 && !/^0+$/.test(pwd);
    const isAdminPwdValid = typeof adminPwd === 'string' && adminPwd.length === 64 && !/^0+$/.test(adminPwd);

    return isPwdValid || isAdminPwdValid;
}

/**
 * SHA-256 哈希函数
 */
async function sha256(message) {
    if (window.crypto?.subtle?.digest) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    if (typeof window._jsSha256 === 'function') {
        return window._jsSha256(message);
    }
    throw new Error('No SHA-256 implementation available.');
}

/**
 * 验证密码
 */
async function verifyPassword(password, passwordType = 'PASSWORD') {
    try {
        const correctHash = window.__ENV__?.[passwordType];
        if (!correctHash) return false;

        const inputHash = await sha256(password);
        const isValid = inputHash === correctHash;

        if (isValid) {
            const storageKey = passwordType === 'PASSWORD'
                ? PASSWORD_CONFIG.localStorageKey
                : PASSWORD_CONFIG.adminLocalStorageKey;

            localStorage.setItem(storageKey, JSON.stringify({
                verified: true,
                timestamp: Date.now(),
                passwordHash: correctHash
            }));
        }
        return isValid;
    } catch (error) {
        console.error(`验证${passwordType}密码时出错:`, error);
        return false;
    }
}

/**
 * 检查验证状态
 */
function isVerified(passwordType = 'PASSWORD') {
    try {
        if (!isPasswordProtected()) return true;

        const storageKey = passwordType === 'PASSWORD'
            ? PASSWORD_CONFIG.localStorageKey
            : PASSWORD_CONFIG.adminLocalStorageKey;

        const stored = localStorage.getItem(storageKey);
        if (!stored) return false;

        const { timestamp, passwordHash } = JSON.parse(stored);
        const currentHash = window.__ENV__?.[passwordType];

        return timestamp && passwordHash === currentHash &&
            Date.now() - timestamp < PASSWORD_CONFIG.verificationTTL;
    } catch (error) {
        console.error(`检查${passwordType}验证状态时出错:`, error);
        return false;
    }
}

/**
 * 显示密码验证弹窗
 */
function showPasswordModal(isAdmin = false) {
    const passwordModal = document.getElementById('passwordModal');
    if (!passwordModal) return;

    // 隐藏豆瓣区域防止滚动问题
    document.getElementById('doubanArea')?.classList.add('hidden');
    
    // 设置标题
    const title = passwordModal.querySelector('h2');
    if (title) {
        title.textContent = isAdmin ? '管理员验证' : '访问验证';
    }

    // 设置表单提交处理
    const form = document.getElementById('passwordForm');
    if (form) {
        form.onsubmit = async function(e) {
            e.preventDefault();
            const password = document.getElementById('passwordInput')?.value.trim() || '';
            
            if (await verifyPassword(password, isAdmin ? 'ADMINPASSWORD' : 'PASSWORD')) {
                hidePasswordModal();
                if (isAdmin) {
                    document.getElementById('settingsPanel')?.classList.add('show');
                }
                document.dispatchEvent(new CustomEvent('passwordVerified'));
            } else {
                showPasswordError();
                const passwordInput = document.getElementById('passwordInput');
                if (passwordInput) {
                    passwordInput.value = '';
                    passwordInput.focus();
                }
            }
        };
    }

    passwordModal.style.display = 'flex';
    
    // 自动聚焦输入框
    setTimeout(() => {
        const passwordInput = document.getElementById('passwordInput');
        if (passwordInput) {
            passwordInput.focus();
        }
    }, 100);
}

/**
 * 隐藏密码验证弹窗
 */
function hidePasswordModal() {
    const passwordModal = document.getElementById('passwordModal');
    if (passwordModal) {
        hidePasswordError();
        
        const passwordInput = document.getElementById('passwordInput');
        if (passwordInput) passwordInput.value = '';

        passwordModal.style.display = 'none';

        // 恢复豆瓣区域显示
        if (localStorage.getItem('doubanEnabled') === 'true') {
            document.getElementById('doubanArea')?.classList.remove('hidden');
        }
    }
}

/**
 * 显示密码错误
 */
function showPasswordError() {
    const errorElement = document.getElementById('passwordError');
    if (errorElement) {
        errorElement.textContent = '密码错误，请重试';
        errorElement.classList.remove('hidden');
    }
}

/**
 * 隐藏密码错误
 */
function hidePasswordError() {
    const errorElement = document.getElementById('passwordError');
    if (errorElement) {
        errorElement.classList.add('hidden');
    }
}

/**
 * 初始化密码保护系统
 */
function initPasswordProtection() {
    if (!isPasswordProtected()) return;

    const hasNormalPassword = window.__ENV__?.PASSWORD && 
                           window.__ENV__.PASSWORD.length === 64 && 
                           !/^0+$/.test(window.__ENV__.PASSWORD);
    
    // 需要普通密码验证时显示弹窗
    if (hasNormalPassword && !isVerified('PASSWORD')) {
        showPasswordModal();
    }
    
    // 设置按钮点击处理
    const settingsBtn = document.querySelector('[onclick="toggleSettings(event)"]');
    if (settingsBtn) {
        settingsBtn.addEventListener('click', function(e) {
            if (hasNormalPassword && !isVerified('PASSWORD')) {
                e.preventDefault();
                e.stopPropagation();
                showPasswordModal();
            } else if (window.__ENV__?.ADMINPASSWORD && !isVerified('ADMINPASSWORD')) {
                e.preventDefault();
                e.stopPropagation();
                showPasswordModal(true);
            }
        });
    }
}

// 全局导出
window.isPasswordProtected = isPasswordProtected;
window.isPasswordVerified = () => isVerified('PASSWORD');
window.isAdminVerified = () => isVerified('ADMINPASSWORD');
window.verifyPassword = verifyPassword;
window.showPasswordModal = showPasswordModal;
window.hidePasswordModal = hidePasswordModal;

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', initPasswordProtection);