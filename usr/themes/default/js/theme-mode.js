(function () {
    var STORAGE_KEY = 'blog-theme-mode';
    var MODE_AUTO = 'auto';
    var MODE_LIGHT = 'light';
    var MODE_DARK = 'dark';
    var MODES = [MODE_LIGHT, MODE_DARK, MODE_AUTO];
    var root = document.documentElement;
    var mediaQuery = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

    function resolveTheme(mode) {
        if (mode === MODE_DARK) {
            return MODE_DARK;
        }
        if (mode === MODE_LIGHT) {
            return MODE_LIGHT;
        }
        if (mediaQuery && mediaQuery.matches) {
            return MODE_DARK;
        }
        return MODE_LIGHT;
    }

    function normalizeMode(mode) {
        if (mode === MODE_LIGHT || mode === MODE_DARK || mode === MODE_AUTO) {
            return mode;
        }
        return MODE_LIGHT;
    }

    function nextMode(mode) {
        var current = normalizeMode(mode);
        var currentIndex = MODES.indexOf(current);
        return MODES[(currentIndex + 1) % MODES.length];
    }

    function getStoredMode() {
        try {
            return normalizeMode(localStorage.getItem(STORAGE_KEY));
        } catch (e) {
            return MODE_LIGHT;
        }
    }

    function saveMode(mode) {
        try {
            localStorage.setItem(STORAGE_KEY, mode);
        } catch (e) {
            // Ignore storage failures in restricted browsers.
        }
    }

    function applyMode(mode) {
        var normalizedMode = normalizeMode(mode);
        var effectiveTheme = resolveTheme(normalizedMode);

        root.setAttribute('data-theme-mode', normalizedMode);
        root.setAttribute('data-theme', effectiveTheme);
    }

    function getModeMeta(mode) {
        if (mode === MODE_LIGHT) {
            return { label: '白天模式', icon: 'fa-sun' };
        }
        if (mode === MODE_DARK) {
            return { label: '夜间模式', icon: 'fa-moon' };
        }
        return { label: '跟随系统', icon: 'fa-desktop' };
    }

    function syncCycleButton(mode) {
        var button = document.querySelector('.theme-mode-cycle');
        if (!button) {
            return;
        }
        var icon = button.querySelector('i');
        var meta = getModeMeta(mode);

        button.setAttribute('data-theme-mode', mode);
        button.setAttribute('aria-label', meta.label);
        button.setAttribute('title', meta.label);

        if (icon) {
            icon.className = 'fas ' + meta.icon;
        }
    }

    function refreshCurrentMode() {
        var mode = getStoredMode();
        applyMode(mode);
        syncCycleButton(mode);
    }

    function initCycleButton() {
        var button = document.querySelector('.theme-mode-cycle');
        if (!button) {
            return;
        }

        refreshCurrentMode();

        button.addEventListener('click', function () {
            var current = getStoredMode();
            var next = nextMode(current);
            saveMode(next);
            applyMode(next);
            syncCycleButton(next);
        });
    }

    function syncAutoModeWithSystem() {
        if (getStoredMode() === MODE_AUTO) {
            refreshCurrentMode();
        }
    }

    if (mediaQuery) {
        if (typeof mediaQuery.addEventListener === 'function') {
            mediaQuery.addEventListener('change', syncAutoModeWithSystem);
        } else if (typeof mediaQuery.addListener === 'function') {
            mediaQuery.addListener(syncAutoModeWithSystem);
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        initCycleButton();
    });
})();
