let prefs = {};

function loadprefs() {
    return $.ajax({
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
    defaultval = $('input[name="'+ele.attr("name")+'"][defaultpref]').attr("defaultpref");
    val = getpref(ele.attr("preference"), defaultval);
    // console.log(
    //   "Loaded settings for " +
    //     ele.attr("preference") +
    //     " with default value " +
    //     defaultval + " value " + val
    // );
    if (val != null) {
        if (ele.attr("type") == "checkbox") {
            ele.prop("checked", val)
        } else if (ele.attr("type") == "radio") {
            $('[type=radio][name="'+ele.attr("name")+'"]').each(function (index, radioitem) {
                // console.log(radioitem);
                $(this).prop("checked", $(this).attr("value") == val);
            });
        } else {
            ele.val(val)
        }
        console.log("Triggering change event for element with preference "+ele.attr("preference")+" with value "+val);
        ele.trigger("change");
    }
}

function onchangepreference(ele) {
    if (ele.attr("type") == "checkbox") {
        setpref(ele.attr("preference"), ele.prop("checked"))
    } else if (ele.attr("type") == "radio") {
        $('input[name="'+ele.attr("name")+'"]:checked').each(function( index, checkedele ) {
            // console.log("Updating radio to "+$(this).val());
            setpref(ele.attr("preference"), $(this).val());
        });
    } else {
        setpref(ele.attr("preference"), ele.val())
    }
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
    $.ajax({
        method: "GET",
        url: `/api/preferences/${key}/${value}`,
    });
}

function prefsinit() {
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
};
