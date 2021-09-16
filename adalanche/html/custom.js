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

function setquery(query, depth, methods, mode, maxoutgoing, minprobability) {
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
        normal = (mode == "Normal")
        $("#querymode_normal").prop('checked', normal);
        $("#querymode_reverse").prop('checked', !normal);
    }
    if (maxoutgoing) {
        $('#maxoutgoing').val(maxoutgoing);
    }
    if (minprobability) {
        $('#minprobability').val(minprobability);
    }
}

function edgeprobability(ele) {
    maxprobability = -1
    for (i in ele.data()) {
        if (i.startsWith("method_")) {
            probability = ele.data(i)
            if (probability > maxprobability) {
                maxprobability = probability
            }
        }
    }
    return maxprobability
}


var cy
var nodemenu

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

    // Configure


    var d3forcelayout = {
        name: "d3-force",
        animate: true, // whether to show the layout as it's running; special 'end' value makes the layout animate like a discrete layout
        maxIterations: 0, // max iterations before the layout will bail out
        maxSimulationTime: 0, // max length in ms to run the layout
        ungrabifyWhileSimulating: false, // so you can't drag nodes during layout
        fixedAfterDragging: false, // fixed node after dragging
        fit: false, // on every layout reposition of nodes, fit the viewport
        padding: 30, // padding around the simulation
        boundingBox: undefined, // constrain layout bounds; { x1, y1, x2, y2 } or { x1, y1, w, h }
        /**d3-force API**/
        alpha: 0.4, // sets the current alpha to the specified number in the range [0,1]
        alphaMin: 0.001, // sets the minimum alpha to the specified number in the range [0,1]
        alphaDecay: 1 - Math.pow(0.001, 1 / 200), // sets the alpha decay rate to the specified number in the range [0,1]
        alphaTarget: 0, // sets the current target alpha to the specified number in the range [0,1]
        velocityDecay: 0.4, // sets the velocity decay factor to the specified number in the range [0,1]
        collideRadius: 60, // sets the radius accessor to the specified number or function
        collideStrength: 0.7, // sets the force strength to the specified number in the range [0,1]
        collideIterations: 1, // sets the number of iterations per application to the specified number
        linkId: function id(d) {
            // return d.index;
            return d.id;
        }, // sets the node id accessor to the specified function
        linkDistance: 40, // sets the distance accessor to the specified number or function
        linkStrength: function strength(link) {
            // return 1 / Math.min(count(link.source), count(link.target));
            return 1 / link.methods.length;
        }, // sets the strength accessor to the specified number or function
        linkIterations: 1, // sets the number of iterations per application to the specified number
        manyBodyStrength: -600, // sets the strength accessor to the specified number or function
        manyBodyTheta: 0.5, // sets the Barnes–Hut approximation criterion to the specified number
        manyBodyDistanceMin: 1, // sets the minimum distance between nodes over which this force is considered
        manyBodyDistanceMax: Infinity, // sets the maximum distance between nodes over which this force is considered
        xStrength: 0.1, // sets the strength accessor to the specified number or function
        xX: 0, // sets the x-coordinate accessor to the specified number or function
        yStrength: 0.1, // sets the strength accessor to the specified number or function
        yY: 0, // sets the y-coordinate accessor to the specified number or function
        radialStrength: 0.1, // sets the strength accessor to the specified number or function
        radialRadius: 5, // sets the circle radius to the specified number or function
        radialX: 0, // sets the x-coordinate of the circle center to the specified number
        radialY: 0, // sets the y-coordinate of the circle center to the specified number
        // layout event callbacks
        ready: function() {}, // on layoutready
        stop: function() {}, // on layoutstop
        tick: function(progress) {}, // on every iteration
        // positioning options
        randomize: false, // use random node positions at beginning of layout
        // infinite layout options
        infinite: false // overrides all other options for a forces-all-the-time mode
    }

    // Our layout options
    var coselayout = {
        name: 'cose',
        animate: true,
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
        animate: true,
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
        animate: true,

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
        animate: true,
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
            case "d3force":
                return d3forcelayout
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
            wheelSensitivity: 0.2,
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
                        "background-color": "orange"
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
                        "background-color": "purple"
                    }
                },
                {
                    selector: 'node[_type="CertificateTemplate"]',
                    style: {
                        shape: "rectangle",
                        "background-image": "icons/certificate.svg",
                        "background-color": "pink"
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
                    selector: "node[?_canexpand]",
                    style: {
                        "font-style": "italic",
                        "color": "yellow",
                        "background-color": "yellow"
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
                        // _content: "data(methods)",
                        color: "white",
                        // "curve-style": "haystack",
                        // "curve-style": "bezier",
                        "curve-style": "straight",
                        "target-arrow-shape": "triangle"
                    }
                },
                {
                    selector: 'edge[_maxprob<=90]',
                    style: {
                        "line-style": "dashed",
                        "line-dash-pattern": [9, 1]
                    }
                },
                {
                    selector: 'edge[_maxprob<=80]',
                    style: {
                        "line-style": "dashed",
                        "line-dash-pattern": [8, 2]
                    }
                },
                {
                    selector: 'edge[_maxprob<=70]',
                    style: {
                        "line-style": "dashed",
                        "line-dash-pattern": [7, 3]
                    }
                },
                {
                    selector: 'edge[_maxprob<=60]',
                    style: {
                        "line-style": "dashed",
                        "line-dash-pattern": [6, 4]
                    }
                },
                {
                    selector: 'edge[_maxprob<=50]',
                    style: {
                        "line-style": "dashed",
                        "line-dash-pattern": [5, 5]
                    }
                },
                {
                    selector: 'edge[_maxprob<=40]',
                    style: {
                        "line-style": "dashed",
                        "line-dash-pattern": [4, 6]
                    }
                },
                {
                    selector: 'edge[_maxprob<=30]',
                    style: {
                        "line-style": "dashed",
                        "line-dash-pattern": [3, 7]
                    }
                },
                {
                    selector: 'edge[_maxprob<=20]',
                    style: {
                        "line-style": "dashed",
                        "line-dash-pattern": [2, 8]
                    }
                },
                {
                    selector: 'edge[_maxprob<=10]',
                    style: {
                        "line-style": "dashed",
                        "line-dash-pattern": [1, 9]
                    }
                },
                {
                    selector: 'edge[?method_MemberOfGroup]',
                    style: {
                        "target-arrow-color": "orange",
                        "line-color": "orange"
                    }
                },
                {
                    selector: 'edge[?method_ResetPassword]',
                    style: {
                        "target-arrow-color": "red",
                        "line-color": "red"
                    }
                },
                {
                    selector: 'edge[?method_AddMember]',
                    style: {
                        "target-arrow-color": "yellow",
                        "line-color": "yellow"
                    }
                },
                {
                    selector: 'edge[?method_Takeownership]',
                    style: {
                        "target-arrow-color": "lightgreen",
                        "line-color": "lightgreen"
                    }
                },
                {
                    selector: 'edge[method_Owns]',
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
                        },
                        hasTrailingDivider: true, // Whether the item will have a trailing divider
                    },
                    {
                        id: 'expand', // ID of menu item
                        content: 'Expand node', // Display content of menu item
                        tooltipText: 'Load missing edges and nodes', // Tooltip text for menu item
                        // image: {src : "remove.svg", width : 12, height : 12, x : 6, y : 4}, // menu icon
                        // Filters the elements to have this menu item on cxttap
                        // If the selector is not truthy no elements will have this menu item on cxttap
                        selector: 'node[_canexpand>0]',
                        onClickFunction: function(event) { // The function to be executed on click
                            // console.log("Toggling target: ", ele.id()); // `ele` holds the reference to the active element
                            expanddata = $("#queryform, #optionsform").serializeArray()
                            expanddata.push({ name: "expanddn", value: event.target.attr("distinguishedname") })

                            $.ajax({
                                type: "POST",
                                url: "cytograph.json",
                                data: JSON.stringify(expanddata.reduce(function(m, o) { m[o.name] = o.value; return m; }, {})),
                                dataType: "json",
                                success: function(data) {
                                    neweles = cy.add(data.elements)
                                    replaceele = neweles.getElementById(event.target.attr("id"))
                                    cy.elements().merge(neweles) // merge adds what is missing
                                    cy.elements().add(replaceele) // then we forcibly update the old object

                                    event.target.removeData('_canexpand')

                                    // Apply layout again
                                    cy.elements().layout(getGraphlayout($("#graphlayout").val())).run()
                                },
                                error: function(xhr, status, error) {
                                    $("#status").html("Problem loading graph:<br>" + xhr.responseText).show()
                                }
                            });


                        },
                        hasTrailingDivider: true, // Whether the item will have a trailing divider
                    },
                    {
                        id: 'whatcanipwn',
                        content: 'What can this node pwn?',
                        tooltipText: 'Does reverse search on this node (clears graph)',
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
        return rendernode(ele.source()) + rendermethods(ele) + rendernode(ele.target());
    }

    function rendermethods(methods) {
        s = '<span class="badge bg-secondary">' + edgeprobability(methods) + '%</span>'
        for (i in methods.data()) {
            if (i.startsWith("method_")) {
                s += '<span class="badge bg-warning text-dark">' + i.substr(7) + '</span>';
            }
        }
        return s
    }

    function rendernode(ele) {
        s = '<h5>' + ele.data("label");
        if (ele.data("sAMAccountName")) s += ' (' + ele.data("sAMAccountName") + ')';
        s += '</h5>';
        if (ele.data("distinguishedName")) s += '<h6>' + ele.data("distinguishedName") + '</h6>';
        return s
    }

    function findroute(source) {
        // var source = cy.$("node.source")
        var target = cy.$("node.target")
        if (target.length == 0) {
            return
        }

        cy.elements().unselect() // unselect everything

        var dfs = cy.elements().aStar({
            root: source,
            goal: target,
            weight: function(ele) {
                maxprobability = edgeprobability(ele)
                if (maxprobability != -1) {
                    return maxprobability - 100 // higher probability equals lower priority number
                }

                if (ele.target().data("accountdisabled") && !(ele.target().data("pwn_writedacl") || ele.target().data("pwn_writeall") || ele.target().data("pwn_writepropertyall") || ele.target().data("pwn_takeownership") || ele.target().data("pwn_owns"))) {
                    // Account disabled, but this route does not allow us to enable it
                    return 10000
                }
                if (ele.data("methods.ACLContainsDeny")) {
                    // Use this as a hint to avoid
                    return 10
                }
                if (ele.data("method_MemberOfGroup")) {
                    return 0
                }
                if (ele.data("method_WriteDACL")) {
                    return 1
                }
                if (ele.data("method_Owns")) {
                    return 1
                }
                if (ele.data("method_AddMember")) {
                    return 1
                }
                if (ele.data("method_AllExtenededRights")) {
                    return 2
                }
                if (ele.data("method_WriteAll")) {
                    return 2
                }
                if (ele.data("method_WritePropertyAll")) {
                    return 2
                }
                if (ele.data("method_Takeownership")) {
                    return 3
                }
                if (ele.data("method_ResetPassword")) {
                    return 5
                }
                return 8
            },
            directed: true
        })
        if (dfs.path) {
            dfs.path.select();
            console.log(dfs.distance);
            pathprobability = 1.0
            dfs.path.forEach(function(ele) {
                if (ele.isEdge()) {
                    pathprobability = pathprobability * (edgeprobability(ele) / 100);
                }
            })
            pathprobability = pathprobability * 100 // Back to percentages
            $("#route").html('Path details - probability ' + pathprobability.toFixed(2) + '%<br>').show();
            // Show path information
            dfs.path.forEach(function(ele) {
                if (ele.isNode()) {
                    $("#route").append(rendernode(ele));
                } else if (ele.isEdge()) {
                    $("#route").append(rendermethods(ele));
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
            type: "POST",
            url: "cytograph.json",
            data: JSON.stringify($("#queryform, #optionsform").serializeArray().reduce(function(m, o) { m[o.name] = o.value; return m; }, {})),
            dataType: "json",
            success: function(data) {
                if (data.total == 0) {
                    $("#status").html(
                        "No results"
                    ).show()
                } else {
                    $("#route").hide();
                    $("#details").hide();
                    $("#status").html(
                        data.targets + " targets can " + (!data.reversed ? "be reached via " : "reach ") + data.links + " possible pwns " + (!data.reversed ? "from" : "to") + ":<hr/>" +
                        data.users + " users<br>" +
                        data.computers + " computers<br>" +
                        data.groups + " groups<br>" +
                        data.others + " others<hr/>" +
                        data.total + " total objects in analysis"
                    ).show()

                    initgraph(data.elements);
                }
            },
            error: function(xhr, status, error) {
                $("#status").html("Problem loading graph:<br>" + xhr.responseText).show()
            }
        });
    });

    if ($("#querytext").val() == "") {
        console.log("Setting default query ...")
        setquery($("#defaultquery").attr("query"), $("#defaultquery").attr("depth"), $("#defaultquery").attr("methods"), $("#defaultquery").attr("mode"));
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
        setquery(event.target.getAttribute("query"), event.target.getAttribute("depth"), event.target.getAttribute("methods"), event.target.getAttribute("mode"), event.target.getAttribute("maxoutgoing"), event.target.getAttribute("minprobability"));
    })

    $.ajax({
        type: "GET",
        url: "/pwnmethods",
        dataType: "json",
        success: function(methods) {
            buttons = "";
            for (i in methods) {
                buttons += `<input type="checkbox" ` + (methods[i].defaultenabled ? "checked" : "") + ` class="btn-check" id="` + methods[i].name + `" name="` + methods[i].name + `"  autocomplete="off">` +
                    `<label class="btn btn-outline-light btn-sm mb-2 me-2" for="` + methods[i].name + `">` + methods[i].name + `</label>`;
            }
            $("#pwnfilter").html(buttons);

            // Refresh styling after dynamic load
            $("#querymode").val("normal");
            // Run initial query
            $("#queryform").submit();
        }
    });

    // End of on document loaded function    
});