const getPreferredTheme = () => {
    const storedTheme = getpref("theme", "auto");
    if (storedTheme == "auto") {
        // console.log("Auto detected theme");
        // console.log(window.matchMedia("(prefers-color-scheme: dark)"));

        return window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
    }

    return storedTheme;
};

const setTheme = (theme) => {
    document.documentElement.setAttribute("data-bs-theme", theme);
    if (cy) {
        applyEdgeStyles(cy);
        applyNodeStyles(cy);
    }
};

// Init to the right one
setTheme(getPreferredTheme());

var lasttheme = getPreferredTheme(); // Store the last theme for comparison

// jquery ready
$(document).ready(function () {
    $("input[name='theme']").on("change", function () {
        var selectedTheme = $("input[name='theme']:checked").val();
        console.log("theme is "+ selectedTheme+", was "+lasttheme);
        if (selectedTheme != lasttheme) {
            console.log("theme changed");
            setTheme(getPreferredTheme());
        }

        lasttheme = selectedTheme; // Update the last theme after setting it
    });
});

