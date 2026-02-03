// 移动端导航菜单功能
document.addEventListener('DOMContentLoaded', function() {
    const mobileToggle = document.querySelector('.mobile-menu-toggle');
    const navMenu = document.querySelector('#nav-menu');
    
    if (!mobileToggle || !navMenu) return;
    
    // 创建移动端导航
    const mobileNav = document.createElement('div');
    mobileNav.className = 'mobile-nav';
    mobileNav.innerHTML = navMenu.innerHTML;
    document.body.appendChild(mobileNav);
    
    // 切换菜单显示状态
    function toggleMenu() {
        const isOpen = mobileNav.classList.contains('active');
        mobileNav.classList.toggle('active');
        mobileToggle.classList.toggle('active');
        document.body.style.overflow = isOpen ? '' : 'hidden';
    }
    
    // 绑定事件
    mobileToggle.addEventListener('click', toggleMenu);
    
    // 点击链接时关闭菜单
    mobileNav.addEventListener('click', function(e) {
        if (e.target.tagName === 'A' || e.target === mobileNav) {
            toggleMenu();
        }
    });
    
    // ESC 键关闭菜单
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && mobileNav.classList.contains('active')) {
            toggleMenu();
        }
    });
}); 