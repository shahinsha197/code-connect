// File management utilities for CodeConnect

class FileManager {
    constructor() {
        // Expanded list to match Prism autoloader capabilities somewhat
        this.supportedLanguages = {
            'js': 'javascript', 'jsx': 'jsx', 'ts': 'typescript', 'tsx': 'tsx',
            'py': 'python', 'java': 'java', 'c': 'c', 'cpp': 'cpp', 'cs': 'csharp', 'go': 'go',
            'rb': 'ruby', 'php': 'php', 'swift': 'swift', 'kt': 'kotlin', 'rs': 'rust',
            'html': 'html', 'xml': 'xml', 'svg': 'svg',
            'css': 'css', 'scss': 'scss', 'less': 'less',
            'json': 'json', 'yaml': 'yaml', 'yml': 'yaml', 'toml': 'toml',
            'md': 'markdown', 'sh': 'bash', 'bash': 'bash', 'sql': 'sql',
            'dockerfile': 'docker', 'gitignore': 'ignore',
            'txt': 'text', // Fallback
        };
        this.languageIcons = {
            'javascript': '📄', 'jsx': '📄', 'typescript': '📄', 'tsx': '📄',
            'python': '🐍', 'java': '☕', 'c': '🇨', 'cpp': '🇨', 'csharp':'♯', 'go': '🐹',
            'ruby': '💎', 'php': '🐘', 'swift': '🐦', 'kotlin': '🤖', 'rust': '🦀',
            'html': '🌐', 'xml': '📰', 'svg': '📊',
            'css': '🎨', 'scss': '🎨', 'less': '🎨',
            'json': '📋', 'yaml': '⚙️', 'yml': '⚙️', 'toml': '⚙️',
            'markdown': '📝', 'bash': '💲', 'sql': '💾',
            'docker': '🐳', 'ignore': '🚫',
            'text': '📄', // Default
        };
    }

    getFileExtension(filename = '') {
        return filename.split('.').pop().toLowerCase();
    }

    getLanguageFromFilename(filename = '') {
        const ext = this.getFileExtension(filename);
        return this.supportedLanguages[ext] || 'text'; // Default to text
    }

    getFileIcon(filename = '') {
        const lang = this.getLanguageFromFilename(filename);
        return this.languageIcons[lang] || '📄'; // Default icon
    }

    isValidFileType(filename = '') {
        const ext = this.getFileExtension(filename);
        // Consider allowing files with no extension?
        // return ext === filename || Object.keys(this.supportedLanguages).includes(ext);
        return Object.keys(this.supportedLanguages).includes(ext);
    }

    formatFileSize(bytes = 0) {
        if (bytes < 0) return 'Invalid size';
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']; // Added TB
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        // Ensure index is within bounds
        const index = Math.min(i, sizes.length - 1);
        return parseFloat((bytes / Math.pow(k, index)).toFixed(2)) + ' ' + sizes[index];
    }

    async readFile(file) {
        return new Promise((resolve, reject) => {
            if (!(file instanceof Blob)) {
                return reject(new Error("Input must be a File or Blob."));
            }
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target?.result); // Safely access result
            reader.onerror = (e) => reject(reader.error || new Error("File reading failed"));
            reader.readAsText(file); // Assuming text files for now
        });
    }

    // --- File Tree Logic (More complex for UI) ---
    // This creates a data structure. Rendering requires more specific UI code.
    createFileTreeData(files = []) {
        const tree = { name: '/', type: 'directory', children: {} };

        files.forEach(file => {
            // Assumes file.filename includes full path like 'src/components/Button.js'
            const parts = (file.filename || '').split('/').filter(p => p); // Remove empty parts
            let currentLevel = tree.children;
            let currentPath = '';

            parts.forEach((part, index) => {
                currentPath = currentPath ? `${currentPath}/${part}` : part;
                if (index === parts.length - 1) {
                    // It's a file
                    currentLevel[part] = {
                        name: part,
                        type: 'file',
                        path: currentPath,
                        data: file // Attach original file data
                    };
                } else {
                    // It's a directory
                    if (!currentLevel[part]) {
                        currentLevel[part] = {
                            name: part,
                            type: 'directory',
                            path: currentPath,
                            children: {}
                        };
                    } else if (currentLevel[part].type !== 'directory') {
                        // Conflict: a file exists with the same name as a directory path part
                        console.warn(`File tree conflict: ${currentPath} is both file and directory`);
                        // Overwrite with directory for consistency? Or handle error?
                        currentLevel[part] = {
                             name: part,
                             type: 'directory',
                             path: currentPath,
                             children: {}
                         };
                    }
                    currentLevel = currentLevel[part].children;
                }
            });
        });
        return tree; // Return the root object
    }

    // Example of rendering tree to simple nested UL (needs CSS for styling)
    renderFileTreeHTML(treeNode, initialLevel = 0) {
        let html = '';
        const isRoot = initialLevel === 0;

        // Sort children: directories first, then files, alphabetically
        const children = Object.values(treeNode.children || {}).sort((a, b) => {
            if (a.type !== b.type) return a.type === 'directory' ? -1 : 1;
            return a.name.localeCompare(b.name);
        });

        if (!isRoot && children.length === 0 && treeNode.type === 'directory') {
             // Optional: Render empty directory differently or not at all?
        }

        html += `<ul class="file-tree-level-${initialLevel}">`;

        children.forEach(item => {
            const icon = item.type === 'directory' ? '📁' : this.getFileIcon(item.name);
            const dataAttrs = `data-path="${item.path}" data-type="${item.type}" ${item.type === 'file' ? `data-file-id="${item.data.id}"` : ''}`;

            html += `<li ${dataAttrs}>`;
            html += `<span class="file-tree-icon">${icon}</span>`;
            html += `<span class="file-tree-name">${item.name}</span>`;

            if (item.type === 'directory' && item.children && Object.keys(item.children).length > 0) {
                 // Recursively render children
                 html += this.renderFileTreeHTML(item, initialLevel + 1);
            }
            html += `</li>`;
        });

        html += `</ul>`;
        return html;
    }


    highlightCode(code, language) {
        const lang = language || 'text'; // Default to text
        if (typeof Prism !== 'undefined' && Prism.languages[lang]) {
            try {
                return Prism.highlight(code, Prism.languages[lang], lang);
            } catch (e) {
                 console.warn(`Prism highlighting failed for language ${lang}:`, e);
                 // Fallback: escape HTML entities
                 return code.replace(/</g, "&lt;").replace(/>/g, "&gt;");
            }
        }
         // Fallback: escape HTML entities if Prism or language not available
        return code.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    downloadFile(filename, content, mimeType = 'text/plain') {
        try {
            const blob = new Blob([content], { type: mimeType });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        } catch(e) {
            console.error("File download failed:", e);
            alert("Could not initiate file download.");
        }
    }
}

// Make available globally or export if using modules
window.FileManager = new FileManager(); // Instantiate and attach to window