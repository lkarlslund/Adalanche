function makePopper(ele) {
    let ref = ele.popperRef(); // used only for positioning
    ele.tippy = tippy(ref, { // tippy options:
        content: () => {
            let content = document.createElement('div');
            content.innerHTML = ele.id();
            return content;
        },
        trigger: 'manual' // probably want manual mode
    });
}

function setquery(query, depth, methods, mode, maxoutgoing, minprobability, prune) {
    if (query) {
        $('#querytext').val(query);
    }
    if (depth) {
        $('#maxdepth').val(query);
    }
    if (methods) {
        // Clear all
        $('#pwnfilter > div > label .active').button("toggle");
        marr = methods.split(" ")
        if (marr.indexOf("default") > -1) {
            $('#pwnfilter > div > label > input [default]').button("toggle");
        }
        for (i in marr) {
            if (marr[i].startsWith("!")) {
                // finds the input checkbox, we need to toggle the label
                $('#' + marr[i].substring(1)) + " .active".parent().button("toggle");
            } else {
                // finds the input checkbox, we need to toggle the label
                $('#' + marr[i]).parent().button("toggle");
            }
        }
    }
    if (mode) {
        setquerymode(mode)
    }
    if (maxoutgoing) {
        $('#maxoutgoing').val(maxoutgoing);
    }
    if (minprobability) {
        $('#minprobability').val(minprobability);
    }
    if (prune) {
        $('#prune').val(prune);
    }
}

function set_querymode(mode) {
    $("#querymode_normal").prop('checked', mode == "normal");
    $("#querymode_reverse").prop('checked', mode == "reverse");
    $("#querymode_sourcetarget").prop('checked', mode == "sourcetarget");
}

function setquerymode(mode) {
    normal = (mode == "Normal")
    $("#querymode_normal").prop('checked', normal);
    $("#querymode_reverse").prop('checked', !normal);
}

function newwindow(id, title, contents) {
    mywindow = $("#windows #window_" + id)[0]
    itsnew = false
    // add the new one
    if (mywindow == undefined) {
        itsnew = true
        // mywindow = $(`<div class="window position-absolute shadow p-5 bg-dark border pointer-events-auto" id="window_`+id+`">` +
        // `<table><td id="title" class="w-full"></td><td class="no-wrap"><button id="rollup" class="btn btn-primary btn-sm">_</button> <button id="close" class="btn btn-primary btn-sm">X</button></td></tr>`+
        // `<tr><td colspan=2 id="contents" class="overflow-auto"></td></tr></table>` +
        // `</div>`);
        mywindow = $(`<div class="window position-absolute shadow p-5 bg-dark border pointer-events-auto" id="window_` + id + `">` +
            `<div id="wrapper"><div><span id="title" class="w-full"></span><span class="no-wrap"><button id="rollup" class="btn btn-primary btn-sm">_</button> <button id="close" class="btn btn-primary btn-sm">X</button></span></div>` +
            `<div id="contents"></div></div></div>`);

        // roll up
        $("#rollup", mywindow).click(function (event) {
            $("#contents", $(this).parents(".window")).slideToggle("slow", "swing")
        })

        // closing
        $("#close", mywindow).click(function (event) {
            $(this).parents(".window").remove()
        })

        mywindow.mousedown(function () {
            if (!$(this).hasClass("window-front")) {
                $("#windows div").removeClass("window-front")
                $(this).addClass("window-front")
            }
        })

        mywindow.draggable().resizable({
            containment: "#windows",
            // animate: true,
            // helper: "ui-resizable-helper",
            // maxHeight: 50,
            // maxWidth: 350,
            // minHeight: 150,
            // minWidth: 200,
        });
    }

    $("#title", mywindow).html(title)
    $("#contents", mywindow).html(contents)

    if (itsnew) {
        $("#windows").append(mywindow)
    }
}

function analyze(e) {
    $("#status").html(`<span class="text-center">Analyzing</span>
        <div class="sk-center sk-chase">
  <div class="sk-chase-dot"></div>
  <div class="sk-chase-dot"></div>
  <div class="sk-chase-dot"></div>
  <div class="sk-chase-dot"></div>
  <div class="sk-chase-dot"></div>
  <div class="sk-chase-dot"></div>
</div>`).show()

    $.ajax({
        type: "POST",
        url: "cytograph.json",
        contentType: "charset=utf-8",
        data: JSON.stringify($("#queryform, #optionsform").serializeArray().reduce(function (m, o) { m[o.name] = o.value; return m; }, {})),
        dataType: "json",
        success: function (data) {
            if (data.total == 0) {
                $("#status").html(
                    "No results"
                ).show()
            } else {
                // Remove all windows
                $("#windows div").remove();

                // Hide status
                $("#status").hide();

                info = data.targets + " targets can " + (!data.reversed ? "be reached via " : "reach ") + data.links + " possible pwns " + (!data.reversed ? "from" : "to") + ":<hr/>";
                for (let objecttype in data.resulttypes) {
                    info += data.resulttypes[objecttype] + " " + objecttype + "<br>"
                }
                info += data.total + " total objects in analysis"

                newwindow("results", "Query results", info)

                if ($("infowrap").prop("width") == 0) {
                    $("#infowrap").animate({ width: 'toggle' }, 400);
                }

                if ($("#hideoptionsonanalysis").prop('checked') && $("#optionswrap").prop("width") != 0) {
                    $("#optionswrap").animate({ width: 'toggle' }, 400);
                }

                if ($("#hidequeryonanalysis").prop('checked') && $("#querydiv").prop("height") != 0) {
                    $("#querydiv").slideToggle("fast")
                }

                initgraph(data.elements);
            }
        },
        error: function (xhr, status, error) {
            $("#status").html("Problem loading graph:<br>" + xhr.responseText).show()
        }
    });
}

// When we´re ready ...
$(function () {
    // Initial GUI setup
    $("#infopop").on("click", function () {
        $("#infowrap").animate({ width: 'toggle' }, 400);
    })

    $("#optionspop").on("click", function () {
        $("#optionswrap").animate({ width: 'toggle' }, 400);
    })

    $("#explore").on("click", function () {
        newwindow("explore", "Explore objects", "<div id='exploretree' class='jstree-default-dark'></div>")
        $("#exploretree").jstree({
            'core': {
                'multiple': false,
                'data': {
                    'url': '/tree',
                    'dataType': 'json',
                    'data': function (node) {
                        return { 'id': node.id };
                    }
                }
            },
            "types": {
                "default": {
                    "icon": "glyphicon glyphicon-flash"
                },
                "demo": {
                    "icon": "glyphicon glyphicon-ok"
                }
            },
            "state": { "key": "adalanche_explore" },
            "plugins": ["sort", "types", "state", "wholerow"],
        });

    })

    // Predefined queries dropdown button
    $("#predefinedqueries").on("click", "a", function (event) {
        console.log("You clicked the drop downs", event.target)
        setquery(
            event.target.getAttribute("query"),
            event.target.getAttribute("depth"),
            event.target.getAttribute("methods"),
            event.target.getAttribute("mode"),
            event.target.getAttribute("maxoutgoing"),
            event.target.getAttribute("minprobability"),
            event.target.getAttribute("prune"),
        );

        $("#queriesbutton").toggleClass("active")
        $("#queriesdropdown").toggleClass("show")
    })

    // QUERY FORM
    // $("#querydiv").slideUp("fast")
    $("#querypop").on("click", function () {
        $("#querydiv").slideToggle("fast")
    })

    // $('[data-toggle="tooltip"]').tooltip()

    var changetimer;
    $('#querytext').on("input", function () {
        clearTimeout(changetimer);
        changetimer = setTimeout(function () {
            // check query for errors when user has been idle for 200ms
            $.ajax({
                type: "GET",
                url: "/validatequery",
                data: {
                    "query": $("#querytext").val()
                },
                success: function (data) {
                    console.log(data);
                    $("#querysubmit").attr("disabled", false);
                    $("#queryerror").hide();
                },
                error: function (xhr, status, error) {
                    $("#querysubmit").attr("disabled", true);
                    $("#queryerror").html(xhr.responseText).show();
                }
            });
        }, 200);
    });

    // Display stats on screen
    $.ajax({
        url: "statistics",
        dataType: "json",
        success: function (data) {
            $("#status").html("<div class='text-center'><h2>adalanche</h2><b>commit " + data.adalanche.commit + " build " + data.adalanche.builddate + "</b><p>" +
                data.statistics.Total + " objects, " +

                data.statistics.User + " users, " +
                data.statistics.Group + " groups, " +
                data.statistics.Computer + " computers" +
                "</p></div>").show();
        },
        error: function (xhr, status, error) {
            $("#status").html("guru meditation:<br>" + xhr.responseText).show()
        }
    });

    // Load preferences
    loadprefs();

    // Dynamically save preferences
    $("[preference]").change(function () {
        onchangepreference($(this))
    })

    $("#graphlayout").change(function () {
        layout = $(this).val();
        if (cy) {
            // render graph with new layout if there is one
            getGraphlayout(layout).run();
        }
    });

    $("#graphlabels").change(function () {
        cy.style().update()
    });

    $.ajax({
        type: "GET",
        url: "/filteroptions",
        dataType: "json",
        success: function (data) {
            buttons = `<table class="w-full">`;
            for (i in data.methods) {
                method = data.methods[i]

                buttons += '<tr class="pb-5">';

                buttons += `<td class="overflow-hidden font-size-12 align-middle">` + method.name; `</td>`;

                buttons += '<td class="checkbox-button no-wrap">';
                buttons += `<input type="checkbox" ` + (method.defaultenabled_f ? "checked" : "") + ` id="` + method.name + `_f" name="pwn_` + method.name + `_f" autocomplete="off">`;
                buttons += `<label for="` + method.name + `_f" class ="btn btn-sm mb-0">F</label>`;
                buttons += `<input type="checkbox" ` + (method.defaultenabled_m ? "checked" : "") + ` id="` + method.name + `_m" name="pwn_` + method.name + `_m" autocomplete="off">`;
                buttons += `<label for="` + method.name + `_m" class ="btn btn-sm mb-0">M</label>`;
                buttons += `<input type="checkbox" ` + (method.defaultenabled_l ? "checked" : "") + ` id="` + method.name + `_l" name="pwn_` + method.name + `_l" autocomplete="off">`;
                buttons += `<label for="` + method.name + `_l" class ="btn btn-sm mb-0">L</label>`;
                buttons += '</td>';

                buttons += '</tr>';
            }
            buttons += "</table>";
            $("#pwnfilter").html(buttons);

            buttons = `<table class="w-full">`;
            for (i in data.objecttypes) {
                objecttype = data.objecttypes[i]

                buttons += '<tr class="pb-5">';

                buttons += `<td class="overflow-hidden font-size-12 align-middle">` + objecttype.name; `</td>`;
                buttons += '<td class="checkbox-button no-wrap pb-5">';

                buttons += `<input type="checkbox" ` + (objecttype.defaultenabled_f ? "checked" : "") + ` id="` + objecttype.name + `_f" name="type_` + objecttype.name + `_f" autocomplete="off">`;
                buttons += `<label for="` + objecttype.name + `_f" class ="btn btn-sm mb-0">F</label>`;
                buttons += `<input type="checkbox" ` + (objecttype.defaultenabled_m ? "checked" : "") + ` id="` + objecttype.name + `_m" name="type_` + objecttype.name + `_m" autocomplete="off">`;
                buttons += `<label for="` + objecttype.name + `_m" class ="btn btn-sm mb-0">M</label>`;
                buttons += `<input type="checkbox" ` + (objecttype.defaultenabled_l ? "checked" : "") + ` id="` + objecttype.name + `_l" name="type_` + objecttype.name + `_l" autocomplete="off">`;
                buttons += `<label for="` + objecttype.name + `_l" class ="btn btn-sm mb-0">L</label>`;

                buttons += '</td>';

                buttons += '</tr>';
            }
            buttons += "</table>";
            $("#objecttypefilter").html(buttons);

        }
    });

    if ($("#querytext").val() == "") {
        console.log("Setting default query ...")
        setquery(
            $("#defaultquery").attr("query"),
            $("#defaultquery").attr("depth"),
            $("#defaultquery").attr("methods"),
            $("#defaultquery").attr("mode"),
            $("#defaultquery").attr("maxoutgoing"),
            $("#defaultquery").attr("minprobability"),
            $("#defaultquery").attr("prune"),
        );
    }

    $(document).on("prefereces.loaded", function (evt) {
        if (getpref("run.query.on.startup")) {
            analyze();
        }
    });

    // End of on document loaded function    
});




