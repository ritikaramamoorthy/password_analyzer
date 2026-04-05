// Password Security Analyzer
// Privacy-first: All processing happens client-side

class PasswordAnalyzer {
    constructor() {
        this.passwordInput = document.getElementById('password-input');
        this.strengthBar = document.getElementById('strength-bar');
        this.strengthLabel = document.getElementById('strength-label');
        this.entropyBits = document.getElementById('entropy-bits');
        this.timeToCrack = document.getElementById('time-to-crack');
        this.feedbackList = document.getElementById('feedback-list');
        this.toggleVisibility = document.getElementById('toggle-visibility');
        
        this.init();
    }
    
    init() {
        this.passwordInput.addEventListener('input', () => this.analyzePassword());
        this.toggleVisibility.addEventListener('click', () => this.togglePasswordVisibility());
        this.analyzePassword(); // Initial analysis
    }
    
    analyzePassword() {
        const password = this.passwordInput.value;
        const entropy = this.calculateEntropy(password);
        const patterns = this.detectPatterns(password);
        const timeToCrack = this.estimateTimeToCrack(entropy);
        
        this.updateUI(entropy, patterns, timeToCrack);
    }
    
    calculateEntropy(password) {
        if (!password) return 0;
        
        const length = password.length;
        let poolSize = 0;
        
        // Check character types
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasDigits = /\d/.test(password);
        const hasSymbols = /[^a-zA-Z\d]/.test(password);
        
        if (hasLower) poolSize += 26;
        if (hasUpper) poolSize += 26;
        if (hasDigits) poolSize += 10;
        if (hasSymbols) poolSize += 32; // Approximate for common symbols
        
        if (poolSize === 0) return 0;
        
        // Shannon Entropy: H = L * log2(R)
        const entropy = length * Math.log2(poolSize);
        return Math.round(entropy * 100) / 100; // Round to 2 decimal places
    }
    
    detectPatterns(password) {
        const patterns = [];
        
        // Sequential characters (lowercase)
        const sequentialLower = /(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/gi;
        if (sequentialLower.test(password)) {
            patterns.push('Contains sequential lowercase letters');
        }
        
        // Sequential characters (uppercase)
        const sequentialUpper = /(?:ABC|BCD|CDE|DEF|EFG|FGH|GHI|HIJ|IJK|JKL|KLM|LMN|MNO|NOP|OPQ|PQR|QRS|RST|STU|TUV|UVW|VWX|WXY|XYZ)/g;
        if (sequentialUpper.test(password)) {
            patterns.push('Contains sequential uppercase letters');
        }
        
        // Sequential digits
        const sequentialDigits = /(?:012|123|234|345|456|567|678|789|890|901)/g;
        if (sequentialDigits.test(password)) {
            patterns.push('Contains sequential digits');
        }
        
        // Keyboard rows
        const keyboardRows = [
            /qwerty|asdf|zxcv/gi,
            /qwertyuiop|asdfghjkl|zxcvbnm/gi,
            /1234567890/gi
        ];
        
        for (const row of keyboardRows) {
            if (row.test(password)) {
                patterns.push('Contains keyboard row patterns');
                break;
            }
        }
        
        // Repeated characters
        const repeatedChars = /(.)\1{2,}/g;
        if (repeatedChars.test(password)) {
            patterns.push('Contains repeated characters (3+ in a row)');
        }
        
        // Repeated strings
        const repeatedStrings = /(.{2,})\1+/gi;
        if (repeatedStrings.test(password)) {
            patterns.push('Contains repeated strings');
        }
        
        // Common patterns
        const commonPatterns = [
            /password|admin|user|login/gi,
            /123456|qwerty|abc123/gi,
            /iloveyou|sunshine|princess/gi
        ];
        
        for (const pattern of commonPatterns) {
            if (pattern.test(password)) {
                patterns.push('Contains common dictionary words or patterns');
                break;
            }
        }
        
        // Short password
        if (password.length < 8) {
            patterns.push('Password is too short (less than 8 characters)');
        }
        
        // Only one character type
        const charTypes = [/[a-z]/.test(password), /[A-Z]/.test(password), /\d/.test(password), /[^a-zA-Z\d]/.test(password)].filter(Boolean).length;
        if (charTypes < 2) {
            patterns.push('Uses only one type of character');
        }
        
        return patterns;
    }
    
    estimateTimeToCrack(entropy) {
        if (entropy === 0) return 'Instant';
        
        // Assuming 10^12 attempts per second (modern supercomputer)
        const attemptsPerSecond = 1e12;
        const totalAttempts = Math.pow(2, entropy);
        const seconds = totalAttempts / attemptsPerSecond;
        
        if (seconds < 1) return 'Less than 1 second';
        if (seconds < 60) return `${Math.round(seconds)} seconds`;
        if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
        if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
        if (seconds < 315360000) return `${Math.round(seconds / 31536000)} years`;
        return `${Math.round(seconds / 315360000)} centuries`;
    }
    
    updateUI(entropy, patterns, timeToCrack) {
        // Update entropy
        this.entropyBits.textContent = entropy;
        
        // Update time to crack
        this.timeToCrack.textContent = timeToCrack;
        
        // Update strength meter
        let strength = 'Very Weak';
        let color = '#ff4757';
        let percentage = 0;
        
        if (entropy >= 128) {
            strength = 'Excellent';
            color = '#2ed573';
            percentage = 100;
        } else if (entropy >= 100) {
            strength = 'Very Strong';
            color = '#ffa502';
            percentage = 80;
        } else if (entropy >= 80) {
            strength = 'Strong';
            color = '#ffa502';
            percentage = 60;
        } else if (entropy >= 60) {
            strength = 'Good';
            color = '#ffa502';
            percentage = 40;
        } else if (entropy >= 40) {
            strength = 'Fair';
            color = '#ff6348';
            percentage = 20;
        }
        
        this.strengthLabel.textContent = strength;
        document.documentElement.style.setProperty('--strength-color', color);
        document.documentElement.style.setProperty('--strength-percentage', `${percentage}%`);
        
        // Update feedback
        this.feedbackList.innerHTML = '';
        if (patterns.length === 0 && entropy > 0) {
            const li = document.createElement('li');
            li.textContent = 'Password looks good! No obvious weaknesses detected.';
            li.style.color = '#2ed573';
            this.feedbackList.appendChild(li);
        } else {
            patterns.forEach(pattern => {
                const li = document.createElement('li');
                li.textContent = pattern;
                this.feedbackList.appendChild(li);
            });
        }
    }
    
    togglePasswordVisibility() {
        const type = this.passwordInput.type === 'password' ? 'text' : 'password';
        this.passwordInput.type = type;
        
        // Update icon (simple eye/eye-off toggle)
        const svg = this.toggleVisibility.querySelector('svg');
        if (type === 'text') {
            svg.innerHTML = '<path d="M17.293 13.293A8 8 0 016.707 2.707a1 1 0 00-1.414 1.414 6 6 0 008.486 8.486l1.414-1.414zm-1.414-1.414L12 10.586l-1.879-1.879a3 3 0 00-4.243 4.243l-1.414 1.414a5 5 0 007.07-7.07z"/><path d="M12 6a3 3 0 100 6 3 3 0 000-6z"/>';
        } else {
            svg.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>';
        }
    }
}

// Initialize the analyzer when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new PasswordAnalyzer();
});