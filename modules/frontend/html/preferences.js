let prefs = {};

function loadprefs() {
    $.ajax({
        url: "/api/preferences",
        dataType: "json",
        success: function (data) {
            prefs = data;
            // Apply all preferences
            $("[preference]").each(function () {
                updatecontrol($(this))
            })
            $(document).trigger("preferences.loaded")
        },
    });
}

function updatecontrol(ele) {
    val = getpref(ele.attr("preference"), ele.data("defaultpref"))
    if (val != null) {
        if (ele.attr("type") == "checkbox") {
            ele.prop("checked", val)
        } else {
            ele.val(val)
        }
    }
}

function onchangepreference(ele) {
    if (ele.attr("type") == "checkbox") {
        setpref(ele.attr("preference"), ele.prop("checked"))
    } else {
        setpref(ele.attr("preference"), ele.val())
    }
    saveprefs()
}

function saveprefs() {
    $.ajax({
      method: "POST",
      url: "/api/preferences",
      dataType: "json",
      data: JSON.stringify(prefs),
    });
}

function getpref(key, defvalue) {
    if (prefs == undefined) {
        return defvalue;
    };
    var value = prefs[key];
    if (value != null) {
        return value
    }
    return defvalue;
}

function setpref(key, value) {
    prefs[key] = value;
    saveprefs();
}

$(function () {
    // Load preferences
    loadprefs();

    // Create an observer instance.
    var prefobserver = new MutationObserver(function (mutations) {
        mutations.forEach(function (mutation) {
            ele = $(mutation.target)
            console.log(ele)
            if (ele.attr("preference") != null) {
                updatecontrol(ele)
            }
        })
    });

    // Pass in monitoring for everything
    $('[preference]').each(function () {
        prefobserver.observe(this, {
            childList: true,
        })
    });

    // Dynamically save preferences
    $('[preference]').change(function () {
        onchangepreference($(this));
    });
});
