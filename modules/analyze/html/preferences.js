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
                if ($(this).attr("type")=="checkbox") {
                    $(this).prop("checked", getpref($(this).attr("preference"), $(this).attr("defaultpref"))==true)
                } else {
                    $(this).val(getpref($(this).attr("preference"), $(this).attr("defaultpref")))
                }
            })
            prefsloaded = 2;
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
    // for (prefsloaded != 2) {
        
    // }

    value = prefs[key];
    if (value != null) {
        return value
    }
    return defvalue;
}

function setpref(key, value) {
    prefs[key]=value;
    saveprefs();
}
