let prefs = {};

function loadprefs() {
    return $.ajax({
        url: "/api/preferences",
        dataType: "json",
        success: function (data) {
            // convert all values with text "true" to boolean true, "false" to boolean false, and integers and floats to their respective types
            for (let key in data) {
                let value = data[key];
                if (value === "true") {
                    data[key] = true;
                } else if (value === "false") {
                    data[key] = false;
                } else if (!isNaN(value)) {
                    data[key] = Number(value);
                }
            }

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
    triggerevent = true;
    if (val != null) {
        if (ele.attr("type") == "checkbox") {
            if (val === "false") {
                val = false;
            }
            ele.prop("checked", val)
        } else if (ele.attr("type") == "radio") {
            $('[type=radio][name="'+ele.attr("name")+'"]').each(function (index, radioitem) {
                $(this).prop("checked", $(this).attr("value") == val);
                if ($(this).attr("value") == val) {
                    ele.trigger("prefupdate");
                }
            });
        } else {
            ele.val(val)
            ele.trigger("prefupdate");
        }
        console.log("Triggering change event for element with preference "+ele.attr("preference")+" with value "+val);
    }
}

function onUIPreferenceChange(ele) {
    if (ele.attr("type") == "checkbox") {
        setpref(ele.attr("preference"), ele.prop("checked"))
        ele.trigger("prefupdate");
    } else if (ele.attr("type") == "radio") {
        $('input[name="'+ele.attr("name")+'"]:checked').each(function( index, checkedele ) {
            setpref(ele.attr("preference"), $(this).val());
            $(this).trigger("prefupdate");
        });
    } else {
        setpref(ele.attr("preference"), ele.val())
        ele.trigger("prefupdate");
    }
}

function getpref(key, defvalue) {
    var value = prefs[key];
    if (value != null) {
        return value;
    }
    uidefvalue = $("[preference='" + key + "'][defaultpref]").data("defaultpref");
    if (uidefvalue !== undefined) {
        return uidefvalue;
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
        onUIPreferenceChange($(this));
    });
};
