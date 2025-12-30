// static/js/dashboard.js
class DashboardSidebar {
    constructor() {
        this.sidebar = document.getElementById('sidebar');
        this.toggleBtn = document.getElementById('mobile-toggle');
        this.content = document.getElementById('content');
        
        this.init();
    }
    
    init() {
        if (this.toggleBtn && this.sidebar) {
            // Remover eventos previos para evitar duplicados
            this.toggleBtn.removeEventListener('click', this.toggle.bind(this));
            this.toggleBtn.addEventListener('click', this.toggle.bind(this));
            
            // Cerrar al hacer clic en enlaces
            document.querySelectorAll('#sidebar .nav-link').forEach(link => {
                link.addEventListener('click', this.close.bind(this));
            });
            
            // Cerrar al hacer clic fuera
            document.addEventListener('click', (e) => {
                if (this.isOpen() && 
                    !this.sidebar.contains(e.target) && 
                    e.target !== this.toggleBtn) {
                    this.close();
                }
            });
            
            // Reset en resize
            window.addEventListener('resize', () => {
                if (window.innerWidth >= 768) this.close();
            });
        }
    }
    
    toggle() {
        this.sidebar.classList.toggle('active');
        if (window.innerWidth < 768) {
            if (this.sidebar.classList.contains('active')) {
                this.content.style.opacity = '0.7';
            } else {
                this.content.style.opacity = '1';
            }
        }
    }
    
    close() {
        this.sidebar.classList.remove('active');
        this.content.style.opacity = '1';
    }
    
    isOpen() {
        return this.sidebar.classList.contains('active');
    }
}

// Inicializar cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', () => {
    new DashboardSidebar();
});