function makePopper(ele) {
    var ref = ele.popperRef(); // used only for positioning
    ele.tippy = tippy(ref, {
        // tippy options:
        content: () => {
            let content = document.createElement('div');
            content.innerHTML = ele.id();
            return content;
        },
        trigger: 'manual', // probably want manual mode
    });
}

window.onpopstate = function (event) {
    $('body').html(event.state);
}

function setquery(
    query,
    depth,
    methods,
    mode,
    maxoutgoing,
    minprobability,
    prune
) {
    if (query) {
        $('#querytext').val(query);
    }
    if (depth) {
        $('#maxdepth').val(query);
    }
    if (methods) {
        // Clear all
        $('#pwnfilter > div > label .active').button('toggle');
        var marr = methods.split(' ');
        if (marr.indexOf('default') > -1) {
            $('#pwnfilter > div > label > input [default]').button('toggle');
        }
        for (i in marr) {
            if (marr[i].startsWith('!')) {
                // finds the input checkbox, we need to toggle the label
                $('#' + marr[i].substring(1)) + ' .active'.parent().button('toggle');
            } else {
                // finds the input checkbox, we need to toggle the label
                $('#' + marr[i])
                    .parent()
                    .button('toggle');
            }
        }
    }
    if (mode) {
        set_querymode(mode);
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
    mode = mode.toLowerCase();
    console.log('set_querymode', mode);
    if (mode == 'normal') {
        $('#querymode_normal').prop('checked', true).change();
    } else if (mode == 'reverse') {
        $('#querymode_reverse').prop('checked', true).change();
    } else if (mode == 'sourcetarget') {
        $('#querymode_sourcetarget').prop('checked', true).change();
    }
}

function dragMoveListener(event) {
    var target = event.target,
        // keep the dragged position in the data-x/data-y attributes
        x = (parseFloat(target.getAttribute('data-x')) || 0) + event.dx,
        y = (parseFloat(target.getAttribute('data-y')) || 0) + event.dy;

    // translate the element
    target.style.webkitTransform =
        target.style.transform =
        'translate(' + x + 'px, ' + y + 'px)';

    // update the posiion attributes
    target.setAttribute('data-x', x);
    target.setAttribute('data-y', y);

    if (!target.classList.contains('window-front')) {
        console.log($('.window-front'));
        $('.window-front').removeClass('window-front');
        console.log($('.window-front'));
        target.classList.add('window-front');
    }
}

function newwindow(id, title, content, height, width) {
    // Other windows are not in front
    console.log($('.window-front'));
    $('.window-front').removeClass('window-front');
    console.log($('.window-front'));

    var mywindow = $(`#windows #window_${id}`);
    var itsnew = false;

    var maxheight = $(window).height() * 0.8;
    var maxwidth = $(window).width() * 0.6;

    // add the new one
    if (mywindow.length == 0) {
        mywindow = $(
            `<div class="window bg-dark shadow border pointer-events-auto window-front" id="window_${id}">
            <div id='header' class='window-header mb-1 bg-primary text-dark p-1'>
            <span id="title" class="col">${title}</span><span id="close" class="border float-end cursor-pointer">X</span>
            </div>
            <div class="window-wrapper">
            <div class="window-content p-1" id="contents">${content}</div>
            </div>
            </div>`
        );

        $('#windows').append(mywindow);

        // closing
        $('#close', mywindow).click(function (event) {
            $(this).parents('.window').remove();
        });

        interact("#window_" + id)
            // .origin('self')
            .resizable({
                edges: { left: true, right: true, bottom: true, top: true },
                margin: 5,
                origin: self,
                listeners: {
                    move(event) {
                        var target = event.target
                        var x = (parseFloat(target.getAttribute('data-x')) || 0)
                        var y = (parseFloat(target.getAttribute('data-y')) || 0)

                        // update the element's style
                        target.style.width = event.rect.width + 'px'
                        target.style.height = event.rect.height + 'px'

                        if (!target.classList.contains('window-front')) {
                            $('.window-front').removeClass('window-front');
                            target.classList.add('window-front');
                        }

                        // translate when resizing from top or left edges
                        x += event.deltaRect.left
                        y += event.deltaRect.top

                        target.style.transform = 'translate(' + x + 'px,' + y + 'px)'

                        target.setAttribute('data-x', x)
                        target.setAttribute('data-y', y)
                    }
                },
                modifiers: [
                    // keep the edges inside the parent
                    interact.modifiers.restrictEdges({
                        outer: 'parent'
                    }),

                    // min and max size
                    interact.modifiers.restrictSize({
                        min: { width: 200, height: 150 },
                        max: { width: maxwidth, height: maxheight },
                    })
                ],

                inertia: true
            })
            .draggable({
                onmove : window.dragMoveListener,
                modifiers: [
                    interact.modifiers.restrictRect({
                        restriction: 'parent',
                        endOnly: true
                    })
                ],
                allowFrom: '.window-header',
            })

        if (height) {
            mywindow.height(height);
        }
        if (width) {
            mywindow.width(width);
        }

        if (mywindow.height() > maxheight) {
            mywindow.height(maxheight)
        }
        if (mywindow.width() > maxwidth) {
            mywindow.width(maxwidth)
        }

    } else {
        $('#title', mywindow).html(title);
        $('#contents', mywindow).html(content);
        mywindow.addClass('window-front');
    }

    // Bring to front on mouse down
    mywindow.mousedown(function () {
        var win = $(this);
        if (!win.hasClass('window-front')) {
            $('#windows div').removeClass('window-front');
            win.addClass('window-front');
        }
    });

    return itsnew;
}

function busystatus(busytext) {
    $('#status')
        .html(
            `<div class="text-center pb-3">`+busytext+`</div>
            <div class="p-2">
        <div class="sk-center sk-chase">
  <div class="sk-chase-dot"></div>
  <div class="sk-chase-dot"></div>
  <div class="sk-chase-dot"></div>
  <div class="sk-chase-dot"></div>
  <div class="sk-chase-dot"></div>
  <div class="sk-chase-dot"></div>
</div>
            </div>`
        )
        .show();
}

function analyze(e) {
    busystatus("Analyzing")

    $.ajax({
        type: 'POST',
        url: 'analyzegraph',
        contentType: 'charset=utf-8',
        data: JSON.stringify(
            $('#queryform, #analysisoptionsform, #analysispwnform, #analysistypeform')
                .serializeArray()
                .reduce(function (m, o) {
                    m[o.name] = o.value;
                    return m;
                }, {})
        ),
        dataType: 'json',
        success: function (data) {
            if (data.total == 0) {
                $('#status').html('No results').show();
            } else {
                // Remove all windows
                $('#windows div').remove();

                // Hide status
                $('#status').hide();

                var info =
                    data.targets +
                    ' target nodes can ' +
                    (!data.reversed ? 'be reached via ' : 'reach ') +
                    data.links +
                    ' edges ' +
                    (!data.reversed ? 'from' : 'to') +
                    ':<hr/><table class="w-100">';
                for (var objecttype in data.resulttypes) {
                    info += '<tr><td class="text-right pr-5">'+ data.resulttypes[objecttype] + '</td><td>' + objecttype + '</td></tr>';
                }
                info += '<tr><td class="text-right pr-5">' + data.total + '</td><td>total nodes in analysis</td></tr>';
                if (data.removed>0) {
                    info += '<tr><td class="text-right pr-5"><b>' + data.removed + '</b></td><td><b>nodes were removed by node limiter</b></td></tr>';
                }
                info += '</table>';

                newwindow('results', 'Query results', info);

                if ($('infowrap').prop('width') == 0) {
                    $('#infowrap').animate({ width: 'toggle' }, 400);
                }

                if (
                    $('#hideoptionsonanalysis').prop('checked') &&
                    $('#optionspanel').prop('width') != 0
                ) {
                    $('#optionspanel').animate({ width: 'toggle' }, 400);
                }

                if (
                    $('#hidequeryonanalysis').prop('checked') &&
                    $('#querydiv').prop('height') != 0
                ) {
                    $('#querydiv').slideToggle('fast');
                }

                initgraph(data.elements);

                history.pushState($('body').html(), 'adalanche')
            }
        },
        error: function (xhr, status, error) {
            $('#status')
                .html('Problem loading graph:<br>' + xhr.responseText)
                .show();
        },
    });
}

function refreshStatus() {
    var lastwasidle = false
    $.ajax({
        type: "GET",
        url: "/progress",
        dataType: "json",
        timeout: 5000,
        success: function (progressbars) {
            $("#offlineblur").hide()
            if (progressbars.length > 0) {
                lastwasidle = false
                keepProgressbars = new Set()
                for (i in progressbars) {
                    progressbar = progressbars[i]
                    if (progressbar.Done) {
                        continue
                    }
                    keepProgressbars.add(progressbar.ID)

                    // find progressbar
                    pb = $("#"+progressbar.ID)
                    if (pb.length == 0 && !progressbar.Done) {
                        $("#progressbars").append(`<div class="progress-group"><span class="progress-group-label">` + progressbar.Title + `</span><div class="progress"><div id="` + progressbar.ID + `" class="progress-bar rounded-0" role="progressbar" aria-valuemin="0" aria-valuemax="100"></div></div><span class="progress-group-label"></span></div>`)
                        pb = $("#" + progressbar.ID)
                    }

                    // Update progressbar
                    pb.attr("aria-valuenow", progressbar.Percent.toFixed(0))
                    pb.css("width", progressbar.Percent.toFixed(0)+"%")
                    pb.parent().next().html(progressbar.Percent.toFixed(2)+"%")
                }
                // remove old progressbars
                $("#progressbars .progress-bar").each(function (index) {
                    id = $(this).attr('id')
                    if (!keepProgressbars.has(id)) {
                        $(this).parent().parent().slideUp("slow", function () { $(this).remove(); })
                    }
                })

                $("#upperstatus").show()
                $("#progressbars").show()
                $("#backendstatus").html("Adalanche is processing")
            } else {
                if (!lastwasidle) {
                    $("#progressbars").empty().hide()
                    $("#backendstatus").html("Adalanche backend is idle")
                    $("#upperstatus").fadeOut("slow")
                }
                lastwasidle = true
            }
        },
        error: function (xhr, status, error) {
            $("#backendstatus").html("Adalanche backend is offline")
            $("#progressbars").empty().hide()
            $("#offlineblur").show()
        }
    });
    $()

    setTimeout(refreshStatus, 1000);
}

function toast(title, contents) {
    toastcontent = $(`<div id="live-toast" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
                                <div class="toast-header">
                                    <img src="..." class="rounded me-2" alt="...">
                                        <strong class="me-auto">`+title+`</strong>
                                        <!--small>Just now</small-->
                                        <button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button>
                                </div>
                                <div class="toast-body">
                                    `+contents+`
                                </div>
                            </div>`);
    $("#toasts").append(toastcontent);
    const toast = bootstrap.Toast.getOrCreateInstance(toastcontent);
    toast.show();
}

// When we´re ready ...
$(function () {
    // Initial GUI setup
    $('#infopop').on('click', function () {
        $('#infowrap').animate({ width: 'toggle' }, 400);
    });

    $('#optionstogglevisibility').on('click', function () {
        $('#optionspanel').animate({ width: 'toggle' }, 400);
    });

    $("[data-bs-toggle='tooltip']").each(function () {
        new bootstrap.Tooltip($(this));
    });

    // autosize($('#querytext'));

    $('#explore').on('click', function () {
        newwindow(
            'explore',
            'Explore objects',
            "<div id='exploretree' class='jstree-default-dark'></div>"
        );
        $('#exploretree').jstree({
            core: {
                multiple: false,
                data: {
                    url: '/tree',
                    dataType: 'json',
                    data: function (node) {
                        return { id: node.id };
                    },
                },
            },
            types: {
                default: {
                    icon: 'glyphicon glyphicon-flash',
                },
                demo: {
                    icon: 'glyphicon glyphicon-ok',
                },
            },
            state: { key: 'adalanche_explore' },
            plugins: ['sort', 'types', 'state', 'wholerow'],
        }).on('select_node.jstree', function (e, d) {
            if (d.event == undefined) {
                return
            }
            if (d.event.type == 'click') {
                $.ajax({
                    type: "GET",
                    url: "details/id/" + d.node.id, // n123 format -> 123
                    dataType: "json",
                    success: function (data) {
                        // details = rendernode(data)
                        var details = renderdetails(data)
                        newwindow("details_"+d.node.id, "Item details", details);
                    },
                    // error: function (xhr, status, error) {
                    //     newwindow("details", "Node details", rendernode(evt.target) + "<div>Couldn't load details:" + xhr.responseText + "</div>");
                    // }
                });
            }
        });
    });

    // Predefined queries dropdown button
    $('#predefinedqueries').on('click', 'li', function (event) {
        console.log('You clicked the drop downs', event.target);
        setquery(
            event.target.getAttribute('query'),
            event.target.getAttribute('depth'),
            event.target.getAttribute('methods'),
            event.target.getAttribute('mode'),
            event.target.getAttribute('maxoutgoing'),
            event.target.getAttribute('minprobability'),
            event.target.getAttribute('prune')
        );

        $('#queriesbutton').toggleClass('active');
        $('#queriesdropdown').toggleClass('show');
    });

    // QUERY FORM
    // $("#querydiv").slideUp("fast")
    $('#querypop').on('click', function () {
        $('#querydiv').slideToggle('fast');
    });

    // $('[data-toggle="tooltip"]').tooltip()

    var changetimer;
    $('#querytext, #queryexclude, #queryexcludelast').on('input', function (e) {
        clearTimeout(changetimer);
        changetimer = setTimeout(function () {
            // check query for errors when user has been idle for 200ms
            $.ajax({
                type: 'GET',
                url: '/validatequery',
                data: {
                    query: e.target.value,
                },
                success: function (data) {
                    console.log(data);
                    $('#querysubmit').attr('disabled', false);
                    $('#queryerror').hide();
                },
                error: function (xhr, status, error) {
                    $('#querysubmit').attr('disabled', true);
                    $('#queryerror').html(xhr.responseText).show();
                },
            });
        }, 200);
    });

    // Display stats on screen
    $.ajax({
        url: 'statistics',
        dataType: 'json',
        success: function (data) {
            statustext = "<div class='text-center pt-10'><img height=128 src='icons/adalanche-logo.svg'></div><div class='text-center'><h2>" + data.adalanche.program + "</h2><b>" +
                data.adalanche.shortversion +
                '</b><p>' +
                data.statistics.Total +
                ' objects connected by '+data.statistics.PwnConnections+' links</p><p>';

            first = true
            for (datatype in data.statistics) {
                if ((datatype == "PwnConnections") || (datatype == "Total")) {
                    continue
                }
                if (!first) {
                    statustext += ", "
                }
                count = data.statistics[datatype];
                statustext += count + " " + datatype
                first=false
            }

            statustext += '</p></div>';

            $('#status').html(statustext).show().delay(15000).fadeOut(2000);
            $('#programinfo').html(data.adalanche.program+" "+data.adalanche.shortversion);
        },
        error: function (xhr, status, error) {
            $('#status')
                .html('guru meditation:<br>' + xhr.responseText)
                .show();
        },
    });

    $('#graphlayout').change(function () {
        layout = $(this).val();
        if (cy) {
            // render graph with new layout if there is one
            getGraphlayout(layout).run();
        }
    });

    $('#nodesizes').change(function () {
        if (cy) {
            applyNodeStyles(cy);
        }
    });
    
    $('#nodelabels').change(function () {
        if (cy) {
            cy.style().update();
        }
    });

    $.ajax({
        type: 'GET',
        url: '/filteroptions',
        dataType: 'json',
        success: function (data) {
            buttons = `<table class="w-100">`;
            data.methods.sort((a, b) => (a.name > b.name) ? 1 : -1)
            for (i in data.methods) {
                method = data.methods[i];

                buttons += '<tr class="pb-1">';

                buttons +=
                    `<td class="overflow-hidden font-size-12 w-100" lookup="`+method.name+`">` +
                    method.name;
                `</td>`;

                buttons += '<td class="checkbox-button no-wrap">';
                buttons +=
                    `<input type="checkbox" data-column="first" data-default=`+method.defaultenabled_f+` ` +
                    (method.defaultenabled_f ? 'checked' : '') +
                    ` id="` +
                    method.lookup +
                    `_f" name="pwn_` +
                    method.lookup +
                    `_f" autocomplete="off">`;
                buttons +=
                    `<label for="` +
                    method.lookup +
                    `_f" class ="btn btn-sm mb-0">F</label>`;
                buttons +=
                    ` <input type="checkbox" data-column="middle" data-default=` + method.defaultenabled_m +` ` +
                    (method.defaultenabled_m ? 'checked' : '') +
                    ` id="` +
                    method.lookup +
                    `_m" name="pwn_` +
                    method.lookup +
                    `_m" autocomplete="off">`;
                buttons +=
                    `<label for="` +
                    method.lookup +
                    `_m" class ="btn btn-sm mb-0">M</label>`;
                buttons +=
                    ` <input type="checkbox" data-column="last" data-default=` + method.defaultenabled_l +` ` +
                    (method.defaultenabled_l ? 'checked' : '') +
                    ` id="` +
                    method.lookup +
                    `_l" name="pwn_` +
                    method.lookup +
                    `_l" autocomplete="off">`;
                buttons +=
                    `<label for="` +
                    method.lookup +
                    `_l" class ="btn btn-sm mb-0">L</label>`;
                buttons += '</td>';

                buttons += '</tr>';
            }
            buttons += '</table>';
            $('#pwnfilter').html(buttons);

            data.objecttypes.sort((a, b) => (a.name > b.name) ? 1 : -1)
            buttons = `<table class="w-100">`;
            for (i in data.objecttypes) {
                objecttype = data.objecttypes[i];

                buttons += '<tr class="pb-1">';

                buttons +=
                    `<td class="overflow-hidden font-size-12 w-100" lookup="`+objecttype.name+`">` +
                    objecttype.name;
                `</td>`;
                buttons += '<td class="checkbox-button no-wrap">';

                buttons +=
                    `<input type="checkbox" data-column="first" data-default=` + objecttype.defaultenabled_f +` ` +
                    (objecttype.defaultenabled_f ? 'checked' : '') +
                    ` id="` +
                    objecttype.lookup +
                    `_f" name="type_` +
                    objecttype.lookup +
                    `_f" autocomplete="off">`;
                buttons +=
                    `<label for="` +
                    objecttype.lookup +
                    `_f" class ="btn btn-sm mb-0">F</label>`;
                buttons +=
                    ` <input type="checkbox" data-column="middle" data-default=` + objecttype.defaultenabled_m +` `+
                    (objecttype.defaultenabled_m ? 'checked' : '') +
                    ` id="` +
                    objecttype.lookup +
                    `_m" name="type_` +
                    objecttype.lookup +
                    `_m" autocomplete="off">`;
                buttons +=
                    `<label for="` +
                    objecttype.lookup +
                    `_m" class ="btn btn-sm mb-0">M</label>`;
                buttons +=
                    ` <input type="checkbox" data-column="last" data-default=` + objecttype.defaultenabled_l +` `+
                    (objecttype.defaultenabled_l ? 'checked' : '') +
                    ` id="` +
                    objecttype.lookup +
                    `_l" name="type_` +
                    objecttype.lookup +
                    `_l" autocomplete="off">`;
                buttons +=
                    `<label for="` +
                    objecttype.lookup +
                    `_l" class ="btn btn-sm mb-0">L</label>`;

                buttons += '</td>';

                buttons += '</tr>';
            }
            buttons += '</table>';
            $('#objecttypefilter').html(buttons);
        },
    });

    if ($('#querytext').val() == '') {
        console.log('Setting default query ...');
        setquery(
            $('#defaultquery').attr('query'),
            $('#defaultquery').attr('depth'),
            $('#defaultquery').attr('methods'),
            $('#defaultquery').attr('mode'),
            $('#defaultquery').attr('maxoutgoing'),
            $('#defaultquery').attr('minprobability'),
            $('#defaultquery').attr('prune')
        );
    }

    $(document).on('prefereces.loaded', function (evt) {
        if (getpref('run.query.on.startup')) {
            analyze();
        }
    });

    refreshStatus();
    // End of on document loaded function
});

