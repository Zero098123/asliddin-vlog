document.addEventListener("DOMContentLoaded", () => {
    const modal = document.getElementById("about-modal");
    const trigger = document.getElementById("about-trigger");
    const closeBtn = document.querySelector("#about-modal .close");

    if (!modal || !trigger || !closeBtn) {
        console.error("Modal JS: Missing elements!");
        return;
    }

    // Open modal
    trigger.addEventListener("click", (e) => {
        e.preventDefault();
        modal.style.display = "block";
    });

    // Close modal (X button)
    closeBtn.addEventListener("click", () => {
        modal.style.display = "none";
    });

    // Close when clicking outside modal content
    window.addEventListener("click", (e) => {
        if (e.target === modal) {
            modal.style.display = "none";
        }
    });
});
