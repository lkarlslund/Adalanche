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
    $('#querymode_normal').prop('checked', mode == 'normal');
    $('#querymode_reverse').prop('checked', mode == 'reverse');
    $('#querymode_sourcetarget').prop('checked', mode == 'sourcetarget');
}


function newwindow(id, title, content, height, width) {
    // Other windows are not in from
    $('#windows div').removeClass('window-front');

    var mywindow = $(`#windows #window_${id}`);
    var itsnew = false;

    var maxheight = $(window).height() * 0.8;
    var maxwidth = $(window).width() * 0.5;

    // add the new one
    if (mywindow.length == 0) {
       itsnew = true;
        // `< div class="window d-inline-block position-absolute shadow p-5 bg-dark border pointer-events-auto container-fluid window-front" id="window_${id}">

        mywindow = $(
            `<div class="window d-inline-block position-absolute shadow bg-dark border pointer-events-auto window-front" style id="window_${id}">
            <div class="s ui-resizable-handle ui-resizable-s"></div>
            <div class="e ui-resizable-handle ui-resizable-e"></div>
            <div class="se ui-resizable-handle ui-resizable-se ui-icon ui-icon-gripsmall-diagonal-se"></div>
                <div id="wrapper" class="p-5 d-inline-block">
                    <div id='header' class='row mb-5'>
                        <div id="title" class="col"></div>
                        <div class="col-auto-1 no-wrap"><!-- button id="rollup" class="btn btn-primary btn-sm">_</button --> <button id="close" class="btn btn-primary btn-sm">X</button></div>
                    </div>
                    <div id="rollup-wrapper" class='overflow-hidden'>
                        <div class="overflow-auto" id="contents"></div>
                    </div>
                </div>
            </div>`
        );

        // roll up
        $('#rollup', mywindow).click(function (event) {
            $('#rollup-wrapper', $(this).parents('.window')).slideToggle('slow', 'swing');
        });

        // closing
        $('#close', mywindow).click(function (event) {
            $(this).parents('.window').remove();
        });

        mywindow.draggable({
            scroll: false,
            cancel: '#contents',
        });


        mywindow.resizable({
            containment: '#windows',
            handles: {
                'se': '.se',
                'e': '.e',
                's': '.s',
            },
            create: function (event, ui) { 
                // ui has no data
            },
            resize: function (event, ui) {
                // console.log(event)
                $('#contents', ui.element).width(ui.size.width-12);
                $('#contents', ui.element).height(ui.size.height-$('#header', ui.element).height()-12);
            },

            maxHeight: maxheight,
            maxWidth: maxwidth,
            minHeight: 150,
            minWidth: 200,
        });

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

    }

    $('#title', mywindow).html(title);
    $('#contents', mywindow).html(content);

    if (itsnew) {
        $('#windows').append(mywindow);

        // Fix initial content size
        
        if ($('#contents', mywindow).width() > maxwidth-12) {
            $('#contents', mywindow).width(maxwidth-12);
        }

        if ($('#contents', mywindow).height() > maxheight-$('#header', mywindow).height()-12) {
            $('#contents', mywindow).height(maxheight-$('#header', mywindow).height()-12);
        }
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

function analyze(e) {
    $('#status')
        .html(
            `<div class="text-center">Analyzing</div>
            <div class="p-10">
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

    $.ajax({
        type: 'POST',
        url: 'cytograph.json',
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
                    ' targets can ' +
                    (!data.reversed ? 'be reached via ' : 'reach ') +
                    data.links +
                    ' possible pwns ' +
                    (!data.reversed ? 'from' : 'to') +
                    ':<hr/>';
                for (var objecttype in data.resulttypes) {
                    info += data.resulttypes[objecttype] + ' ' + objecttype + '<br>';
                }
                info += data.total + ' total objects in analysis';

                newwindow('results', 'Query results', info);

                if ($('infowrap').prop('width') == 0) {
                    $('#infowrap').animate({ width: 'toggle' }, 400);
                }

                if (
                    $('#hideoptionsonanalysis').prop('checked') &&
                    $('#optionswrap').prop('width') != 0
                ) {
                    $('#optionswrap').animate({ width: 'toggle' }, 400);
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

// When we´re ready ...
$(function () {
    // Initial GUI setup
    $('#infopop').on('click', function () {
        $('#infowrap').animate({ width: 'toggle' }, 400);
    });

    $('#optionspop').on('click', function () {
        $('#optionswrap').animate({ width: 'toggle' }, 400);
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
    $('#querytext').on('input', function () {
        clearTimeout(changetimer);
        changetimer = setTimeout(function () {
            // check query for errors when user has been idle for 200ms
            $.ajax({
                type: 'GET',
                url: '/validatequery',
                data: {
                    query: $('#querytext').val(),
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

    // Load preferences
    loadprefs();

    // Dynamically save preferences
    $('[preference]').change(function () {
        onchangepreference($(this));
    });

    $('#graphlayout').change(function () {
        layout = $(this).val();
        if (cy) {
            // render graph with new layout if there is one
            getGraphlayout(layout).run();
        }
    });

    $('#graphlabels').change(function () {
        cy.style().update();
    });

    $.ajax({
        type: 'GET',
        url: '/filteroptions',
        dataType: 'json',
        success: function (data) {
            buttons = `<table class="w-full">`;
            data.methods.sort((a, b) => (a.name > b.name) ? 1 : -1)
            for (i in data.methods) {
                method = data.methods[i];

                buttons += '<tr class="pb-5">';

                buttons +=
                    `<td class="overflow-hidden font-size-12 align-middle" lookup="`+method.name+`">` +
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
                    `<input type="checkbox" data-column="middle" data-default=` + method.defaultenabled_m +` ` +
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
                    `<input type="checkbox" data-column="last" data-default=` + method.defaultenabled_l +` ` +
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
            buttons = `<table class="w-full">`;
            for (i in data.objecttypes) {
                objecttype = data.objecttypes[i];

                buttons += '<tr class="pb-5">';

                buttons +=
                    `<td class="overflow-hidden font-size-12 align-middle" lookup="`+objecttype.name+`">` +
                    objecttype.name;
                `</td>`;
                buttons += '<td class="checkbox-button no-wrap pb-5">';

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
                    `<input type="checkbox" data-column="middle" data-default=` + objecttype.defaultenabled_m +` `+
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
                    `<input type="checkbox" data-column="last" data-default=` + objecttype.defaultenabled_l +` `+
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

    // End of on document loaded function
});
