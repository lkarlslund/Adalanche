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

function setquery(query, depth, methods, mode) {
    if (query) {
        $('#querytext').val(query);
    }
    if (depth) {
        $('#maxdepth').val(query);
    }
    if (methods) {
        // Clear all
        $('#pwnfilter > div > label .active').button("toggle");
        if (methods == "default") {
            $('#pwnfilter > div > label > input [default]').button("toggle");
        } else {
            marr = methods.split(" ")
            for (i in marr) {
                // finds the input checkbox, we need to toggle the label
                $('#' + marr[i]).parent().button("toggle");
            }
        }
    }
    if (mode) {
        $("#querymode").val(mode)
    }
}

$(function() {
    $("#route").hide();
    $("#details").hide();
    /*
        $.getJSON("statistics", function (stats) {
            $.toast(
                stats.statistics.Total + " objects<br>" +
                stats.statistics.User + " users<br>" +
                stats.statistics.Group + " groups<br>" +
                stats.statistics.Computer + " computers<br>"
            )
        });
    */

    var cy
    var nodemenu

    // Our layout options
    var coselayout = {
        name: 'cose',
        idealEdgeLength: 100,
        nodeOverlap: 30,
        refresh: 20,
        fit: true,
        padding: 30,
        randomize: false,
        componentSpacing: 120,
        nodeRepulsion: 4400000,
        edgeElasticity: 100,
        nestingFactor: 5,
        gravity: 10,
        numIter: 2000,
        initialTemp: 600,
        coolingFactor: 0.95,
        minTemp: 1.0
    }

    var dagrelayout = {
        name: 'dagre',
        // dagre algo options, uses default value on undefined
        nodeSep: undefined, // the separation between adjacent nodes in the same rank
        edgeSep: undefined, // the separation between adjacent edges in the same rank
        rankSep: undefined, // the separation between each rank in the layout
        rankDir: 'LR', // 'TB' for top to bottom flow, 'LR' for left to right,
        ranker: 'longest-path', // Type of algorithm to assign a rank to each node in the input graph. Possible values: 'network-simplex', 'tight-tree' or 'longest-path'
        minLen: function(edge) { return 1; }, // number of ranks to keep between the source and target of the edge
        edgeWeight: function(edge) { return 1; }, // higher weight edges are generally made shorter and straighter than lower weight edges

        // general layout options
        fit: false, // whether to fit to viewport
        padding: 30, // fit padding
        spacingFactor: undefined, // Applies a multiplicative factor (>0) to expand or compress the overall area that the nodes take up
        nodeDimensionsIncludeLabels: false, // whether labels should be included in determining the space used by a node
        animate: false, // whether to transition the node positions
        animateFilter: function(node, i) { return true; }, // whether to animate specific nodes when animation is on; non-animated nodes immediately go to their final positions
        animationDuration: 500, // duration of animation in ms if enabled
        animationEasing: undefined, // easing of animation if enabled
        boundingBox: undefined, // constrain layout bounds; { x1, y1, x2, y2 } or { x1, y1, w, h }
        transform: function(node, pos) { return pos; }, // a function that applies a transform to the final node position
        ready: function() {}, // on layoutready
        stop: function() {} // on layoutstop
    }

    var fcoselayout = {
        name: 'fcose',

        // 'draft', 'default' or 'proof' 
        // - "draft" only applies spectral layout 
        // - "default" improves the quality with incremental layout (fast cooling rate)
        // - "proof" improves the quality with incremental layout (slow cooling rate) 
        quality: "proof",
        // Use random node positions at beginning of layout
        // if this is set to false, then quality option must be "proof"
        randomize: true,
        // Whether or not to animate the layout
        animate: true,
        // Duration of animation in ms, if enabled
        animationDuration: 1000,
        // Easing of animation, if enabled
        animationEasing: undefined,
        // Fit the viewport to the repositioned nodes
        fit: true,
        // Padding around layout
        padding: 30,
        // Whether to include labels in node dimensions. Valid in "proof" quality
        nodeDimensionsIncludeLabels: false,
        // Whether or not simple nodes (non-compound nodes) are of uniform dimensions
        uniformNodeDimensions: false,
        // Whether to pack disconnected components - valid only if randomize: true
        packComponents: true,

        /* spectral layout options */

        // False for random, true for greedy sampling
        samplingType: true,
        // Sample size to construct distance matrix
        sampleSize: 25,
        // Separation amount between nodes
        // nodeSeparation: 125,
        nodeSeparation: 75,
        // Power iteration tolerance
        piTol: 0.0000001,

        /* incremental layout options */

        // Node repulsion (non overlapping) multiplier
        nodeRepulsion: 4500,
        // Ideal edge (non nested) length
        idealEdgeLength: 150,
        // Divisor to compute edge forces
        edgeElasticity: 0.45,
        // Nesting factor (multiplier) to compute ideal edge length for nested edges
        nestingFactor: 0.5,
        // Maximum number of iterations to perform
        numIter: 2500,
        // For enabling tiling
        tile: true,
        // Represents the amount of the vertical space to put between the zero degree members during the tiling operation(can also be a function)
        tilingPaddingVertical: 10,
        // Represents the amount of the horizontal space to put between the zero degree members during the tiling operation(can also be a function)
        tilingPaddingHorizontal: 10,
        // Gravity force (constant)
        gravity: 0.25,
        // Gravity range (constant) for compounds
        gravityRangeCompound: 1.5,
        // Gravity force (constant) for compounds
        gravityCompound: 1.0,
        // Gravity range (constant)
        gravityRange: 3.8,
        // Initial cooling factor for incremental layout  
        initialEnergyOnIncremental: 0.3,

        /* layout event callbacks */
        ready: () => {}, // on layoutready
        stop: () => {} // on layoutstop
    }

    var ciselayout = {
        name: 'cise',

        // ClusterInfo can be a 2D array contaning node id's or a function that returns cluster ids. 
        // For the 2D array option, the index of the array indicates the cluster ID for all elements in 
        // the collection at that index. Unclustered nodes must NOT be present in this array of clusters.
        // 
        // For the function, it would be given a Cytoscape node and it is expected to return a cluster id  
        // corresponding to that node. Returning negative numbers, null or undefined is fine for unclustered
        // nodes.  
        // e.g
        // Array:                                     OR          function(node){
        //  [ ['n1','n2','n3'],                                       ...
        //    ['n5','n6']                                         }
        //    ['n7', 'n8', 'n9', 'n10'] ]                         
        // clusters: clusterInfo,
        animate: false,
        refresh: 10,
        animationDuration: undefined,
        animationEasing: undefined,
        fit: true,
        padding: 30,
        nodeSeparation: 12.5,
        idealInterClusterEdgeLengthCoefficient: 1.4,
        allowNodesInsideCircle: false,
        maxRatioOfNodesInsideCircle: 0.1,
        springCoeff: 0.45,
        nodeRepulsion: 4500,
        gravity: 0.25,
        gravityRange: 3.8,
        // Layout event callbacks; equivalent to `layout.one('layoutready', callback)` for example
        ready: function() {}, // on layoutready
        stop: function() {}, // on layoutstop
    }

    var randomlayout = {
        name: 'random'
    }

    function getGraphlayout(choice) {
        switch (choice) {
            case "cose":
                return coselayout
            case "dagre":
                return dagrelayout
            case "fcose":
                return fcoselayout
            case "random":
                return randomlayout
            case "cise":
                return ciselayout
        }
        return fcoselayout
    }

    // Choose this as default layout
    // var layoutoptions = fcoselayout;
    var layoutoptions = getGraphlayout($("#graphlayout").val());

    $("#graphlayout").change(function() {
        layoutoptions = getGraphlayout($(this).val());
        layout = cy.makeLayout(layoutoptions)
        layout.run();
    });

    function initgraph(data) {
        cy = (window.cy = cytoscape({
            container: document.getElementById("cy"),
            style: [{
                    selector: "node",
                    style: {
                        content: "data(label)",
                        color: "white",
                        "background-width": "80%",
                        "background-height": "80%"
                    }
                },
                {
                    selector: "node.target",
                    style: {
                        "border-color": "white",
                        "border-width": 3
                    }
                },
                {
                    selector: "node.source",
                    style: {
                        "border-color": "green",
                        "border-width": 2
                    }
                },
                {
                    selector: 'node[name="Attacker"]',
                    style: {
                        "background-image": "icons/attacker.svg",
                        "background-color": "purple"
                    }
                },
                {
                    selector: 'node[_type="Group"]',
                    style: {
                        shape: "cut-rectangle",
                        "background-image": "icons/people-fill.svg",
                        "background-color": "yellow"
                    }
                },
                {
                    selector: 'node[_type="User"][!_accountdisabled]',
                    style: {
                        shape: "rectangle",
                        "background-image": "icons/person-fill.svg",
                        "background-color": "green"
                    }
                },
                {
                    selector: 'node[_type="User"][?_accountdisabled]',
                    style: {
                        shape: "rectangle",
                        "background-image": "icons/person-x-fill.svg",
                        "background-color": "lightblue"
                    }
                },
                {
                    selector: 'node[_type="GroupPolicyContainer"]',
                    style: {
                        shape: "rectangle",
                        "background-image": "icons/gpo.svg",
                        "background-color": "lightpurple"
                    }
                },
                {
                    selector: 'node[_type="Computer"][?_workstation]',
                    style: {
                        shape: "hexagon",
                        "background-image": "icons/tv-fill.svg",
                        "background-color": "lightgreen"
                    }
                },
                {
                    selector: 'node[_type="Computer"][?_server]',
                    style: {
                        shape: "hexagon",
                        "background-image": "icons/server.svg",
                        "background-color": "lightgreen"
                    }
                },
                {
                    selector: "node[?_querytarget]",
                    style: {
                        "background-color": "red"
                    }
                },
                {
                    selector: 'node[[indegree>4]]',
                    style: {
                        width: 40,
                        height: 40
                    }
                },
                {
                    selector: 'node[[indegree>8]]',
                    style: {
                        width: 60,
                        height: 60
                    }
                },
                {
                    selector: 'node[[indegree>20]]',
                    style: {
                        width: 80,
                        height: 80
                    }
                },
                {
                    selector: "edge",
                    style: {
                        _content: "data(methods)",
                        color: "white",
                        "curve-style": "haystack",
                        // "curve-style": "bezier",
                        "target-arrow-shape": "triangle"
                    }
                },
                {
                    selector: 'edge[pwn_aclcontainsdeny]',
                    style: {
                        "line-style": "dotted"
                    }
                },
                {
                    selector: 'edge[pwn_memberofgroup]',
                    style: {
                        "target-arrow-color": "orange",
                        "line-color": "orange"
                    }
                },
                {
                    selector: 'edge[pwn_resetpassword]',
                    style: {
                        "target-arrow-color": "red",
                        "line-color": "red"
                    }
                },
                {
                    selector: 'edge[pwn_canaddmember]',
                    style: {
                        "target-arrow-color": "yellow",
                        "line-color": "yellow"
                    }
                },
                {
                    selector: 'edge[pwn_takeownership]',
                    style: {
                        "target-arrow-color": "lightgreen",
                        "line-color": "lightgreen"
                    }
                },
                {
                    selector: 'edge[pwn_owns]',
                    style: {
                        "target-arrow-color": "green",
                        "line-color": "green"
                    }
                },
                {
                    selector: "node:selected",
                    style: {
                        "border-color": "white",
                        "border-width": 8
                    }
                },
                {
                    selector: "edge:selected",
                    style: {
                        "target-arrow-color": "white",
                        "line-color": "white",
                        "width": 8
                    }
                }
            ],
            layout: layoutoptions,
            elements: data
        }));

        // cy.json({ elements: data.elements });     

        cy.ready(function() {
            nodemenu = cy.contextMenus({
                // Customize event to bring up the context menu
                // Possible options https://js.cytoscape.org/#events/user-input-device-events
                evtType: 'cxttapstart',
                // List of initial menu items
                // A menu item must have either onClickFunction or submenu or both
                menuItems: [{
                        id: 'target', // ID of menu item
                        content: 'Set as route target', // Display content of menu item
                        tooltipText: 'Node is set as target of routing operation', // Tooltip text for menu item
                        // image: {src : "remove.svg", width : 12, height : 12, x : 6, y : 4}, // menu icon
                        // Filters the elements to have this menu item on cxttap
                        // If the selector is not truthy no elements will have this menu item on cxttap
                        selector: 'node',
                        onClickFunction: function(event) { // The function to be executed on click
                            // console.log("Toggling target: ", ele.id()); // `ele` holds the reference to the active element
                            cy.$("node.target").toggleClass("target")
                            event.target.toggleClass("target")
                            nodemenu.enableMenuItem("source")
                        },
                        disabled: false, // Whether the item will be created as disabled
                        show: true, // Whether the item will be shown or not
                        hasTrailingDivider: false, // Whether the item will have a trailing divider
                        coreAsWell: false // Whether core instance have this item on cxttap
                    },
                    {
                        id: 'source',
                        content: 'Route to target',
                        tooltipText: 'Find shortest route to target selected previously',
                        selector: 'node',
                        onClickFunction: function(event) {
                            findroute(event.target);
                        }
                    },
                    {
                        id: 'whatcanipwn',
                        content: 'What can this node pwn?',
                        tooltipText: 'Does inverse search on this node (clears graph)',
                        selector: 'node',
                        onClickFunction: function(event) {
                            $("#querytext").val("(distinguishedname=" + event.target.attr("distinguishedname") + ")")
                            $("#querymode").val('inverted');
                            $("#queryform").submit();
                        }
                    },
                    {
                        id: 'whocanpwn',
                        content: 'Who can pwn this node?',
                        tooltipText: 'Does normal search for this node (clears graph)',
                        selector: 'node',
                        onClickFunction: function(event) {
                            $("#querytext").val("(distinguishedname=" + event.target.attr("distinguishedname") + ")")
                            $("#querymode").val('normal');
                            $("#queryform").submit();
                        }
                    }


                ],
                // css classes that menu items will have
                menuItemClasses: [
                    // add class names to this list
                    "bg-primary", "text-white"
                ],
                // css classes that context menu will have
                contextMenuClasses: [
                    // add class names to this list
                ],
                // Indicates that the menu item has a submenu. If not provided default one will be used
                submenuIndicator: { src: 'submenu-indicator-default.svg', width: 12, height: 12 }
            });

            cy.on('click', 'node', function(evt) {
                console.log('clicked node ' + this.id());
                $("#details").html(rendernode(this)).show();
            });

            cy.on('click', 'edge', function(evt) {
                console.log('clicked edge ' + this.id());
                $("#details").html(renderedge(this)).show();
            });

            cy.on('click', function(evt) {
                var evtTarget = evt.target;
                if (evtTarget === cy) {
                    $("#details").hide();
                    $("#route").hide();
                    $("#optionsdiv").slideUp("fast");
                    $("#querydiv").slideUp("fast");
                }
            });
        });
    }

    function renderedge(ele) {
        return rendernode(ele.source()) + rendermethods(ele.data("methods")) + rendernode(ele.target());
    }

    function rendermethods(methods) {
        s = ""
        for (i in methods) {
            s += '<span class="badge badge-warning">' + methods[i] + '</span>';
        }
        return s
    }

    function rendernode(ele) {
        s = '<h5>' +
            ele.data("name") + ' (' + ele.data("samaccountname") + ')</h5><h6>' +
            ele.data("distinguishedname") + '</h6>' +
            '';
        return s
    }

    function findroute(source) {
        // var source = cy.$("node.source")
        var target = cy.$("node.target")
        if (target.length == 0) {
            return
        }
        var dfs = cy.elements().aStar({
            root: source,
            goal: target,
            weight: function(ele) {
                if (ele.target().data("accountdisabled") && !(ele.target().data("pwn_writedacl") || ele.target().data("pwn_writeall") || ele.target().data("pwn_writepropertyall") || ele.target().data("pwn_takeownership") || ele.target().data("pwn_owns"))) {
                    // Account disabled, but this route does not allow us to enable it
                    return 10000
                }
                if (ele.data("pwn_aclcontainsdeny")) {
                    // Use this as a hint to avoid
                    return 10
                }
                if (ele.data("pwn_memberof")) {
                    return 0
                }
                if (ele.data("pwn_writedacl")) {
                    return 1
                }
                if (ele.data("pwn_owns")) {
                    return 1
                }
                if (ele.data("pwn_allextendedrights")) {
                    return 2
                }
                if (ele.data("pwn_writeall")) {
                    return 2
                }
                if (ele.data("pwn_writepropertyall")) {
                    return 2
                }
                if (ele.data("pwn_takeownership")) {
                    return 3
                }
                if (ele.data("pwn_resetpassword")) {
                    return 5
                }
                return 1
            },
            directed: true
        })
        if (dfs.path) {
            dfs.path.select();
            console.log(dfs.distance);
            $("#route").html("Path details<br>").show();
            dfs.path.forEach(function(ele) {
                if (ele.isNode()) {
                    $("#route").append(rendernode(ele));
                } else if (ele.isEdge()) {
                    $("#route").append(rendermethods(ele.data("methods")));
                }
            })
        } else {
            $("#route").html("No path found").show()
        }
    }

    // QUERY FORM

    $("#querydiv").slideUp("fast")
    $("#optionsdiv").slideUp("fast")

    $("#querypop").on("click", function() {
        $("#querydiv").slideToggle("fast")
    })
    $("#optionspop").on("click", function() {
        $("#optionsdiv").slideToggle("fast")
    })

    $('[data-toggle="tooltip"]').tooltip()

    $("#queryform").submit(function analyze(e) {
        e.preventDefault(); // avoid to execute the actual submit of the form.

        $("#status").html("Loading ...").show()

        $.ajax({
            type: "GET",
            url: "cytograph.json",
            data: $("#queryform, #optionsform").serialize(),
            dataType: "json",
            success: function(data) {
                $("#route").hide();
                $("#details").hide();
                $("#status").html(
                    data.targets + " targets can " + (!$("#inverted").is(":checked") ? "be reached via " : "reach ") + data.links + " possible pwns " + (!$("#inverted").is(":checked") ? "from" : "to") + ":<hr/>" +
                    data.users + " users<br>" +
                    data.computers + " computers<br>" +
                    data.groups + " groups<br>" +
                    data.others + " others<hr/>" +
                    data.total + " total objects in analysis"
                ).show()

                initgraph(data.elements);
            },
            error: function(xhr, status, error) {
                $("#status").html("Problem loading graph:<br>" + xhr.responseText).show()
            }
        });
    });

    if ($("#querytext").val() == "") {
        console.log("Setting default query ...")
        setquery($("#defaultquery").attr("query"), $("#defaultquery").attr("depth"), $("#defaultquery").attr("methods"), $("#defaultquery").attr("mode"));
        // $("#querytext").val($("#defaultquery").attr("query"))
    }

    var changetimer;
    $('#querytext').on("input", function() {
        clearTimeout(changetimer);
        changetimer = setTimeout(function() {
            $.ajax({
                type: "GET",
                url: "/validatequery",
                data: {
                    "query": $("#querytext").val()
                },
                success: function(data) {
                    console.log(data);
                    $("#querysubmit").attr("disabled", false);
                    $("#queryerror").hide();
                },
                error: function(xhr, status, error) {
                    $("#querysubmit").attr("disabled", true);
                    $("#queryerror").html(xhr.responseText).show();
                }
            });
            // do stuff when user has been idle for 1 second
        }, 200);
    });

    // Predefined queries dropdown button
    $("#predefinedqueries").on("click", "a", function(event) {
        console.log("You clicked the drop downs", event.target)
        setquery(event.target.getAttribute("query"), event.target.getAttribute("depth"), event.target.getAttribute("methods"), event.target.getAttribute("mode"));
    })

    $.ajax({
        type: "GET",
        url: "/pwnmethods",
        dataType: "json",
        success: function(methods) {
            // buttons = '<div class="w-50 col-sm btn-group" data-toggle="buttons">';
            buttons = "";
            for (i in methods) {
                // buttons += `<button type="checkbox" name="` + methods[i].name + `" class="w-50 btn btn-primary btm-xs` + (methods[i].defaultenabled ? " active" : "") + `" data-toggle="button" aria-pressed="` + (methods[i].defaultenabled ? "true" : "false") + `" autocomplete="off">` + methods[i].name + `</button>`;
                buttons += `
                <div class="btn-group-toggle d-inline" data-toggle="buttons">
                    <label class="btn btn-light btn-xs w-auto` + (methods[i].defaultenabled ? " active" : "") + `">
                        <input type="checkbox" ` + (methods[i].defaultenabled ? "default" : "") + ` id="` + methods[i].name + `" name="` + methods[i].name + `"` + (methods[i].defaultenabled ? " checked" : "") + `>` +
                    methods[i].name +
                    `</label>
                </div>`;
                // class="w-50 btn btn-primary btm-xs` + (methods[i].defaultenabled ? " active" : "") + `" data-toggle="button" aria-pressed="` + (methods[i].defaultenabled ? "true" : "false") + `" autocomplete="off">` + methods[i].name + `</button>`;
            }
            // buttons += '</div>';
            $("#pwnfilter").html(buttons);

            {
                /* checkboxes = `<div class="d-inline">`;
                            for (i in methods) {
                                if (i % 2 == 0) {
                                    checkboxes += `<div class="row m-0">`;
                                }
                                checkboxes += `<div class="w-50 col-sm form-check form-check-inline">
                      <input class="form-check-input" type="checkbox" ` + (methods[i].defaultenabled ? "checked " : "") + `id="inlineCheckbox` + methods[i].name + `" name="` + methods[i].name + `" value="true">
                      <label class="form-check-label" for="inlineCheckbox` + methods[i].name + `">` + methods[i].name + `</label>
                    </div>`;
                                if (i % 2 == 1) {
                                    checkboxes += `</div>`;
                                }
                            }
                            checkboxes += `</div>`; 
                            $("#pwnfilter").html(checkboxes); */
            }
            // Refresh styling after dynamic load
            $("[data-toggle='toggle']").bootstrapToggle('destroy')
            $("[data-toggle='toggle']").bootstrapToggle();
            $("#querymode").val("normal");
            // Run initial query
            $("#queryform").submit();
        }
    });

    // End of on document loaded function    
});