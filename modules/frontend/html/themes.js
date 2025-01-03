const translateAutoTheme = (theme) => {
    if (theme == "auto") {
        console.log("Auto detecting theme from browser: ");
        console.log(window.matchMedia("(prefers-color-scheme: dark)"));

        return window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
    }

    return theme;
};

const setTheme = (theme) => {
    document.documentElement.setAttribute("data-bs-theme", theme);
    if (cy) {
        applyEdgeStyles(cy);
        applyNodeStyles(cy);
    }
};

var lasttheme = ""; // Store the last theme for comparison

// jquery ready
$(document).ready(function () {
    $("input[name='theme']").on("change", function () {
        var selectedTheme = $("input[name='theme']:checked").val();
        console.log("theme is "+ selectedTheme+", was "+lasttheme);
        if (selectedTheme != lasttheme) {
            console.log("theme changed to "+ selectedTheme);
            setTheme(translateAutoTheme(selectedTheme));
        }

        lasttheme = selectedTheme; // Update the last theme after setting it
    });
});

// Apply correct theme when preferences are loaded
$(document).on("prefereces.loaded", function (evt) {
  setTheme(translateAutoTheme(getpref("theme", "auto")));
});
