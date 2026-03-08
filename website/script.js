document.addEventListener('DOMContentLoaded', () => {
    // Copy to clipboard functionality
    const copyBtn = document.querySelector('.copy-btn');
    const codeBlock = document.querySelector('.code-block code');

    if (copyBtn && codeBlock) {
        copyBtn.addEventListener('click', () => {
            const code = codeBlock.innerText;
            navigator.clipboard.writeText(code).then(() => {
                const originalIcon = copyBtn.innerHTML;
                copyBtn.innerHTML = '<i class="fas fa-check"></i>';
                copyBtn.style.color = '#27c93f';
                
                setTimeout(() => {
                    copyBtn.innerHTML = originalIcon;
                    copyBtn.style.color = '';
                }, 2000);
            });
        });
    }

    // Mobile menu toggle
    const mobileBtn = document.querySelector('.mobile-menu-btn');
    const nav = document.querySelector('.navbar nav');

    if (mobileBtn && nav) {
        mobileBtn.addEventListener('click', () => {
            nav.classList.toggle('active');
            
            // Toggle icon
            const icon = mobileBtn.querySelector('i');
            if (icon) {
                if (nav.classList.contains('active')) {
                    icon.classList.remove('fa-bars');
                    icon.classList.add('fa-times');
                } else {
                    icon.classList.remove('fa-times');
                    icon.classList.add('fa-bars');
                }
            }
        });
    }

    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
                // Close mobile menu if open
                if (nav.classList.contains('active') && window.innerWidth <= 768) {
                    nav.classList.remove('active');
                    const icon = mobileBtn.querySelector('i');
                    if (icon) {
                        icon.classList.remove('fa-times');
                        icon.classList.add('fa-bars');
                    }
                }
            }
        });
    });

    // Fetch and display contributors
    fetchContributors();
});

async function fetchContributors() {
    // GUARD: Check if contributors grid element exists before attempting any DOM writes
    // If this script runs on a page without the #contributors-grid element, grid will be null
    // and subsequent operations (grid.innerHTML, grid.appendChild) will throw an unhandled exception
    const grid = document.getElementById('contributors-grid');
    if (!grid) {
        console.warn('Contributors grid element not found. Skipping contributor loading.');
        return;
    }
    
    const repo = 'mdhaarishussain/chaos-kitten';
    // NOTE: GitHub API rate limiting issue - unauthenticated requests are limited to 60/hour
    // Current approach lacks:
    // 1. Authentication (via server-side proxy or token) to increase rate limit to 5000/hour
    // 2. Proper pagination handling - while per_page=100 covers current 17 contributors,
    //    growing contributor count or high page traffic could exhaust the rate limit
    // 3. Link header parsing for multi-page results
    // TODO: Implement one of the following:
    //   - Add server-side proxy to authenticate requests
    //   - Implement proper pagination with Link header handling
    //   - Add response caching with expiration
    const contributorsUrl = `https://api.github.com/repos/${repo}/contributors?per_page=100`;

    try {
        const response = await fetch(contributorsUrl);
        if (!response.ok) throw new Error('Failed to fetch contributors');
        
        const contributors = await response.json();
        
        // Clear loading skeletons
        grid.innerHTML = '';
        
        // Display contributors
        contributors.forEach(contributor => {
            const card = createContributorCard(contributor);
            grid.appendChild(card);
        });
    } catch (error) {
        console.error('Error fetching contributors:', error);
        // Display error message or default contributors
        grid.innerHTML = '<p style="text-align: center; color: var(--text-muted); grid-column: 1/-1;">Failed to load contributors. Please check back later.</p>';
    }
}

function createContributorCard(contributor) {
    const card = document.createElement('div');
    card.className = 'contributor-card';
    
    const name = contributor.login;
    const avatarUrl = contributor.avatar_url;
    const profileUrl = contributor.html_url;
    const contributions = contributor.contributions;
    
    card.innerHTML = `
        <div class="contributor-avatar">
            <img src="${avatarUrl}" alt="${name}" title="${name}">
        </div>
        <div class="contributor-name">${name}</div>
        <div class="contributor-role">${contributions} contribution${contributions !== 1 ? 's' : ''}</div>
        <div class="contributor-links">
            <a href="${profileUrl}" target="_blank" rel="noopener noreferrer" class="contributor-link" title="GitHub Profile">
                <i class="fab fa-github"></i>
            </a>
        </div>
    `;
    
    return card;
}
