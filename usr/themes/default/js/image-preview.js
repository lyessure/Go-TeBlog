(function () {
    var previewRoot;
    var previewImage;
    var closeButton;
    var activeTrigger = null;

    function ensurePreview() {
        if (previewRoot) {
            return;
        }

        previewRoot = document.createElement('div');
        previewRoot.className = 'image-preview';
        previewRoot.setAttribute('aria-hidden', 'true');
        previewRoot.innerHTML = '<button type="button" class="image-preview__close" aria-label="关闭图片预览">&times;</button><div class="image-preview__stage"><img class="image-preview__image" alt=""></div>';
        document.body.appendChild(previewRoot);

        previewImage = previewRoot.querySelector('.image-preview__image');
        closeButton = previewRoot.querySelector('.image-preview__close');

        previewRoot.addEventListener('click', function (event) {
            if (event.target === previewRoot || event.target === previewImage || event.target === closeButton) {
                closePreview();
            }
        });
    }

    function openPreview(sourceImage) {
        ensurePreview();

        activeTrigger = sourceImage;
        previewImage.src = sourceImage.currentSrc || sourceImage.src;
        previewImage.alt = sourceImage.alt || '';
        previewRoot.classList.add('is-active');
        previewRoot.setAttribute('aria-hidden', 'false');
        document.body.classList.add('image-preview-open');
        closeButton.focus();
    }

    function closePreview() {
        if (!previewRoot || !previewRoot.classList.contains('is-active')) {
            return;
        }

        previewRoot.classList.remove('is-active');
        previewRoot.setAttribute('aria-hidden', 'true');
        previewImage.removeAttribute('src');
        document.body.classList.remove('image-preview-open');
        if (activeTrigger) {
            activeTrigger.focus();
            activeTrigger = null;
        }
    }

    function bindArticleImages() {
        var images = document.querySelectorAll('.post-content img');
        if (!images.length) {
            return;
        }

        ensurePreview();

        images.forEach(function (image) {
            if (image.dataset.previewBound === 'true') {
                return;
            }

            image.dataset.previewBound = 'true';
            image.tabIndex = 0;

            image.addEventListener('click', function (event) {
                event.preventDefault();
                event.stopPropagation();
                openPreview(image);
            });

            image.addEventListener('keydown', function (event) {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    openPreview(image);
                }
            });
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        bindArticleImages();

        document.addEventListener('keydown', function (event) {
            if (event.key === 'Escape') {
                closePreview();
            }
        });
    });
})();
