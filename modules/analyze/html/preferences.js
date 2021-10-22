var prefs = {};
var prefsloaded = 0;

function loadprefs() {
    prefsloaded = 1; // Loading
    $.ajax({
        url: "preferences",
        dataType: "json",
        success: function (data) {
            prefs = data;
            // Apply all preferences
            $("[preference]").each(function () {
                val = getpref($(this).attr("preference"), $(this).attr("defaultpref"))
                if (val != null) {
                    if ($(this).attr("type") == "checkbox") {
                        $(this).prop("checked", val)
                    } else {
                        $(this).val(val)
                    }
                }
            })
            $(document).trigger("preferences.loaded")
        },
    });
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
        url: "preferences",
        dataType: "json",
        data: JSON.stringify(prefs),
    });
}

function getpref(key, defvalue) {
    value = prefs[key];
    if (value != null) {
        return value
    }
    return defvalue;
}

function setpref(key, value) {
    prefs[key] = value;
    saveprefs();
}
