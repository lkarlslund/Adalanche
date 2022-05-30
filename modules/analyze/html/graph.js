var cy
var nodemenu

// Configure
var d3forcelayout = {
    name: "d3-force",
    animate: true, // whether to show the layout as it's running; special 'end' value makes the layout animate like a discrete layout
    maxIterations: 0, // max iterations before the layout will bail out
    maxSimulationTime: 0, // max length in ms to run the layout
    ungrabifyWhileSimulating: false, // so you can't drag nodes during layout
    fixedAfterDragging: false, // fixed node after dragging
    fit: true, // on every layout reposition of nodes, fit the viewport
    padding: 30, // padding around the simulation
    boundingBox: undefined, // constrain layout bounds; { x1, y1, x2, y2 } or { x1, y1, w, h }
    /**d3-force API**/
    alpha: 0.4, // sets the current alpha to the specified number in the range [0,1]
    alphaMin: 0.001, // sets the minimum alpha to the specified number in the range [0,1]
    alphaDecay: 0.1,
    // alphaDecay: 1 - Math.pow(0.001, 1 / 200), // sets the alpha decay rate to the specified number in the range [0,1]
    alphaTarget: 0, // sets the current target alpha to the specified number in the range [0,1]
    velocityDecay: 0.2, // sets the velocity decay factor to the specified number in the range [0,1]
    collideRadius: 80, // sets the radius accessor to the specified number or function
    collideStrength: 0.7, // sets the force strength to the specified number in the range [0,1]
    collideIterations: 1, // sets the number of iterations per application to the specified number
    linkId: function id(d) {
        // return d.index;
        return d.id;
    }, // sets the node id accessor to the specified function
    linkDistance: 20, // sets the distance accessor to the specified number or function
    linkStrength: function strength(link) {
        // return 1 / Math.min(count(link.source), count(link.target));
        return 8 / link._maxprob;
    }, // sets the strength accessor to the specified number or function
    linkIterations: 25, // sets the number of iterations per application to the specified number
    manyBodyStrength: -1500, // sets the strength accessor to the specified number or function
    manyBodyTheta: 0.5, // sets the Barnes–Hut approximation criterion to the specified number
    manyBodyDistanceMin: 10, // sets the minimum distance between nodes over which this force is considered
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
    // ready: function () { }, // on layoutready
    // stop: function () { }, // on layoutstop
    tick: function (progress) { }, // on every iteration
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
    minLen: function (edge) { return 1; }, // number of ranks to keep between the source and target of the edge
    edgeWeight: function (edge) { return 1; }, // higher weight edges are generally made shorter and straighter than lower weight edges

    // general layout options
    fit: false, // whether to fit to viewport
    padding: 30, // fit padding
    spacingFactor: undefined, // Applies a multiplicative factor (>0) to expand or compress the overall area that the nodes take up
    nodeDimensionsIncludeLabels: false, // whether labels should be included in determining the space used by a node
    animateFilter: function (node, i) { return true; }, // whether to animate specific nodes when animation is on; non-animated nodes immediately go to their final positions
    animationDuration: 500, // duration of animation in ms if enabled
    animationEasing: undefined, // easing of animation if enabled
    boundingBox: undefined, // constrain layout bounds; { x1, y1, x2, y2 } or { x1, y1, w, h }
    transform: function (node, pos) { return pos; }, // a function that applies a transform to the final node position
    ready: function () { }, // on layoutready
    stop: function () { } // on layoutstop
}

var fcoselayout = {
    name: 'fcose',
    // 'draft', 'default' or 'proof' 
    // - "draft" only applies spectral layout 
    // - "default" improves the quality with incremental layout (fast cooling rate)
    // - "proof" improves the quality with incremental layout (slow cooling rate) 
    quality: "default",
    // Use random node positions at beginning of layout
    // if this is set to false, then quality option must be "proof"
    randomize: true,
    // Whether or not to animate the layout
    animate: false,
    // Duration of animation in ms, if enabled
    animationDuration: 5000,
    // Easing of animation, if enabled
    animationEasing: undefined,
    // Fit the viewport to the repositioned nodes
    fit: true,
    // Padding around layout
    padding: 30,
    // Whether to include labels in node dimensions. Valid in "proof" quality
    nodeDimensionsIncludeLabels: true,
    // Whether or not simple nodes (non-compound nodes) are of uniform dimensions
    uniformNodeDimensions: false,
    // Whether to pack disconnected components - valid only if randomize: true
    packComponents: true,

    /* spectral layout options */

    // False for random, true for greedy sampling
    samplingType: true,
    // Sample size to construct distance matrix
    sampleSize: 100,
    // Separation amount between nodes
    // nodeSeparation: 125,
    nodeSeparation: 125,
    // Power iteration tolerance
    piTol: 0.0000001,

    /* incremental layout options */

    // Node repulsion (non overlapping) multiplier
    nodeRepulsion: 4500,
    // Ideal edge (non nested) length
    idealEdgeLength: 100,
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
    ready: () => { }, // on layoutready
    stop: () => { } // on layoutstop
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
    ready: function () { }, // on layoutready
    stop: function () { }, // on layoutstop
}

var randomlayout = {
    name: 'random'
}

var cytostyle = [{
    selector: "node",
    style: {
        label: function (ele) { return nodelabel(ele); },
        color: "white",
        "min-zoomed-font-size": 12,
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
    selector: 'node[type="Group"]',
    style: {
        shape: "cut-rectangle",
        "background-image": "icons/people-fill.svg",
        "background-color": "orange"
    }
},
{
    selector: 'node[type="User"][!_disabled]',
    style: {
        "background-image": "icons/person-fill.svg",
        "background-color": "green"
    }
},
{
    selector: 'node[type="User"][?_disabled]',
    style: {
        "background-image": "icons/no_accounts_black_48dp.svg",
        "background-color": "darkgreen"
    }
},
{
    selector: 'node[type="ManagedServiceAccount"]',
    style: {
        "background-image": "icons/manage_accounts_black_24dp.svg",
        "background-color": "lightgreen"
    }
},
    {
        selector: 'node[type="GroupManagedServiceAccount"]',
        style: {
            "background-image": "icons/manage_accounts_black_24dp.svg",
            "background-color": "lightgreen"
        }
    },
{
    selector: 'node[type="ForeignSecurityPrincipal"]',
    style: {
        "background-image": "icons/badge_black_24dp.svg",
        "background-color": "lightgreen"
    }
},
{
    selector: 'node[type="Service"]',
    style: {
        shape: "diamond",
        "background-image": "icons/service.svg",
        "background-color": "lightgreen"
    }
},
{
    selector: 'node[type="Directory"]',
    style: {
        shape: "diamond",
        "background-image": "icons/source_black_24dp.svg",
        "background-color": "lightblue"
    }
},
{
    selector: 'node[type="File"]',
    style: {
        shape: "diamond",
        "background-image": "icons/article_black_24dp.svg",
        "background-color": "lightblue"
    }
},
    {
        selector: 'node[type="Executable"]',
        style: {
            shape: "rectangle",
            "background-image": "icons/binary-code-binary-svgrepo-com.svg",
            "background-color": "lightgreen"
        }
    },

{
    selector: 'node[type="GroupPolicyContainer"]',
    style: {
        shape: "rectangle",
        "background-image": "icons/gpo.svg",
        "background-color": "purple"
    }
},
{
    selector: 'node[type="OrganizationalUnit"]',
    style: {
        shape: "rectangle",
        "background-image": "icons/source_black_24dp.svg",
        "background-color": "lightgray"
    }
},
{
    selector: 'node[type="Container"]',
    style: {
        shape: "rectangle",
        "background-image": "icons/folder_black_24dp.svg",
        "background-color": "lightgray"
    }
},
{
    selector: 'node[type="CertificateTemplate"]',
    style: {
        shape: "rectangle",
        "background-image": "icons/certificate.svg",
        "background-color": "pink"
    }
},
{
    selector: 'node[type="DNSNode"]',
    style: {
        shape: "rectangle",
        "background-image": "icons/dns.svg",
    }
},
{
    selector: 'node[type="Computer"]', // [? _workstation]
    style: {
        shape: "round-octagon",
        "background-image": "icons/tv-fill.svg",
        "background-color": "lightgreen"
    }
},
// {
//     selector: 'node[type="Computer"][?_server]',
//     style: {
//         shape: "hexagon",
//         "background-image": "icons/server.svg",
//         "background-color": "lightgreen"
//     }
// },
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
    selector: 'edge[?method_ForeignIdentity]',
    style: {
        "target-arrow-color": "lightgreen",
        "line-color": "lightgreen"
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
        "background-color": "white"
        // "border-color": "white",
        // "border-width": 8
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
];

function getGraphlayout(choice) {
    var layouttemplate = fcoselayout
    switch (choice) {
        case "cose":
            layouttemplate = coselayout
            break
        case "dagre":
            layouttemplate = dagrelayout
            break
        case "fcose":
            layouttemplate = fcoselayout
            break
        case "d3force":
            layouttemplate = d3forcelayout
            break
        case "random":
            layouttemplate = randomlayout
            break
        case "cise":
            layouttemplate = ciselayout
            break
    }

    var layout = cy.layout(layouttemplate)

    layout.on("layoutstart", function (event) {
        $("#status").html(`<div>Running graph layout</div>
            <div class= "p-10" >
            <div class="sk-center sk-chase">
                <div class="sk-chase-dot"></div>
                <div class="sk-chase-dot"></div>
                <div class="sk-chase-dot"></div>
                <div class="sk-chase-dot"></div>
                <div class="sk-chase-dot"></div>
                <div class="sk-chase-dot"></div>
            </div>
            </div>`).show()
    })
    layout.on("layoutstop", function (event) {
        $("#status").hide()
    })
    return layout
}

function nodelabel(ele) {
    switch ($("#graphlabels").val()) {
        case "normal":
            return ele.data("label");
        case "off":
            return "";
        case "anonymize":
            return anonymizer.anonymize(ele.data("label"));
    }
    return "error";
}

var anonymizer = new DataAnonymizer();

function renderedge(ele) {
    return rendernode(ele.source()) + rendermethods(ele) + rendernode(ele.target());
}

function rendermethods(methods) {
    var prob = edgeprobability(methods);
    var s = '<span class="badge badge-';
    if (prob < 33) {
        s += 'danger';
    } else if (prob < 67) {
        s += 'secondary';
    } else {
        s += 'success';
    }
    s += '">' + prob + '%</span>'
    for (i in methods.data()) {
        if (i.startsWith("method_")) {
            s += '<span class="badge badge-secondary">' + i.substr(7) + '</span>';
        }
    }
    return s
}

function rendernode(ele) {
    var s = '<div>' + nodelabel(ele);
    if (ele.data("engine.SAMAccountName")) s += ' (' + ele.data("engine.SAMAccountName") + ')';
    s += '</div>';
    if (ele.data("distinguishedName")) s += '<div>' + ele.data("distinguishedName") + '</div>';
    return s
}

// Object with values from AD and possibly other places
function renderdetails(data) {
    var result = "<table>"
    for (var attr in data.attributes) {
        result += "<tr><td>" + attr + "</td><td>"
        attrvalues = data.attributes[attr]
        for (var i in attrvalues) {
            if ($("#graphlabels").val() == "anonymize") {
                result += anonymizer.anonymize(attrvalues[i]) + "</br>";
            } else {
                result += attrvalues[i] + "</br>";
            }
        }
        result += "</td></tr>"
    }
    result += "</table>"
    return result
}

function edgeprobability(ele) {
    if (ele.data("_maxprob")) {
        return (ele.data("_maxprob"))
    }
    return -1
}

function initgraph(data) {
    cy = (window.cy = cytoscape({
        container: document.getElementById("cy"),
        wheelSensitivity: 0.2,
        style: cytostyle,
    }));

    cy.ready(function () {
        $("#status").hide();

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
                onClickFunction: function (event) { // The function to be executed on click
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
                onClickFunction: function (event) {
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
                onClickFunction: function (event) { // The function to be executed on click
                    // console.log("Toggling target: ", ele.id()); // `ele` holds the reference to the active element
                    expanddata = $("#queryform, #optionsform").serializeArray()
                    expanddata.push({ name: "expanddn", value: event.target.attr("distinguishedName") })

                    $.ajax({
                        type: "POST",
                        url: "cytograph.json",
                        data: JSON.stringify(expanddata.reduce(function (m, o) { m[o.name] = o.value; return m; }, {})),
                        dataType: "json",
                        success: function (data) {
                            neweles = cy.add(data.elements)
                            replaceele = neweles.getElementById(event.target.attr("id"))
                            cy.elements().merge(neweles) // merge adds what is missing
                            cy.elements().add(replaceele) // then we forcibly update the old object

                            event.target.removeData('_canexpand')

                            // Apply layout again
                            getGraphlayout($("#graphlayout").val()).run()
                        },
                        error: function (xhr, status, error) {
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
                onClickFunction: function (evt) {
                    $.ajax({
                        type: "GET",
                        url: "details/id/" + evt.target.id().substring(1), // n123 format -> 123
                        dataType: "json",
                        success: function (data) {
                            if (data.attributes["distinguishedName"]) {
                                $("#querytext").val("(distinguishedname=" + data.attributes["distinguishedName"] + ")")
                            } else if (data.attributes["objectSid"]) {
                                $("#querytext").val("(objectSid=" + data.attributes["objectSid"] + ")")
                            } else if (data.attributes["objectGuid"]) {
                                $("#querytext").val("(objectGuid=" + data.attributes["objectGuid"] + ")")
                            } else {
                                $("#querytext").val("(_id=" + evt.target.id().substring(1) + ")")
                            }
                            set_querymode('reverse');

                            analyze();
                        },
                        error: function (xhr, status, error) {
                            halfmoon.initStickyAlert({
                                content: "There was a problem doing node lookup in the backend",
                                title: "Node not found in backend",
                                alertType: "alert-danger",
                                fillType: "filled",
                                hasDismissButton: true,
                                timeShown: 5000
                            });
                        }
                    })
                }
            },
            {
                id: 'whocanpwn',
                content: 'Who can pwn this node?',
                tooltipText: 'Does normal search for this node (clears graph)',
                selector: 'node',
                onClickFunction: function (evt) {
                    $.ajax({
                        type: "GET",
                        url: "details/id/" + evt.target.id().substring(1), // n123 format -> 123
                        dataType: "json",
                        success: function (data) {
                            if (data.attributes["distinguishedName"]) {
                                $("#querytext").val("(distinguishedname=" + data.attributes["distinguishedName"] + ")")
                            } else if (data.attributes["objectSid"]) {
                                $("#querytext").val("(objectSid=" + data.attributes["objectSid"] + ")")
                            } else if (data.attributes["objectGuid"]) {
                                $("#querytext").val("(objectGuid=" + data.attributes["objectGuid"] + ")")
                            } else {
                                $("#querytext").val("(_id=" + evt.target.id().substring(1) + ")")
                            }
                            set_querymode('normal');

                            analyze();
                        },
                        error: function (xhr, status, error) {
                            halfmoon.initStickyAlert({
                                content: "There was a problem doing node lookup in the backend",
                                title: "Node not found in backend",
                                alertType: "alert-danger",
                                fillType: "filled",
                                hasDismissButton: true,
                                timeShown: 5000
                            });
                        }
                    })
                },
            }
            ],
            // css classes that menu items will have
            menuItemClasses: [
                // add class names to this list
                "bg-primary"
            ],
            // css classes that context menu will have
            contextMenuClasses: [
                // add class names to this list
            ],
            // Indicates that the menu item has a submenu. If not provided default one will be used
            submenuIndicator: { src: 'submenu-indicator-default.svg', width: 12, height: 12 }
        });

        cy.on('click', 'node', function (evt) {
            // console.log('clicked node ' + this.id());
            $.ajax({
                type: "GET",
                url: "details/id/" + (evt.target.id().substring(1)), // n123 format -> 123
                dataType: "json",
                success: function (data) {
                    details = rendernode(evt.target)
                    details += renderdetails(data)
                    newwindow("details", "Node details", details);
                },
                error: function (xhr, status, error) {
                    newwindow("details", "Node details", rendernode(evt.target) + "<div>Couldn't load details:" + xhr.responseText + "</div>");
                }
            });
        });

        cy.on('click', 'edge', function (evt) {
            // console.log('clicked edge ' + this.id());
            newwindow("details", "Edge details", renderedge(this));
        });

        cy.on('click', function (evt) {
            var evtTarget = evt.target;
            if (evtTarget === cy) {
                $("#details").hide();
                $("#route").hide();
                // $("#optionsdiv").slideUp("fast");
                // $("#querydiv").slideUp("fast");
            }
        });
    });

    // Load data into Cytoscape
    cy.add(data);

    getGraphlayout($("#graphlayout").val()).run()
}

function findroute(source) {
    var target = cy.$("node.target")
    if (target.length == 0) {
        return
    }

    cy.elements().unselect() // unselect everything

    var dfs = cy.elements().aStar({
        root: source,
        goal: target,
        weight: function (ele) {
            maxprobability = edgeprobability(ele)
            if (maxprobability != -1) {
                return 101 - maxprobability // higher probability equals lower priority number
            }
            return 0
        },
        directed: true
    })
    if (dfs.path) {
        dfs.path.select();
        console.log(dfs.distance);
        pathprobability = 1.0
        dfs.path.forEach(function (ele) {
            if (ele.isEdge()) {
                pathprobability = pathprobability * (edgeprobability(ele) / 100);
            }
        })
        pathprobability = pathprobability * 100 // Back to percentages

        // Show path information
        routecontents = ""
        dfs.path.forEach(function (ele) {
            if (ele.isNode()) {
                routecontents += rendernode(ele);
            } else if (ele.isEdge()) {
                routecontents += rendermethods(ele);
            }
        })
        newwindow("route_" + source.id() + "_" + target.id(),
            `Route from ` + nodelabel(source) + ` to ` + nodelabel(target) + ` - ` + pathprobability.toFixed(2) + `% probability`,
            routecontents)
    } else {
        halfmoon.initStickyAlert({
            content: "If your analysis was for multiple targets, there is no guarantee that all results can reach all targets.",
            title: "No route found",
            alertType: "alert-danger",
            fillType: "filled",
            hasDismissButton: true,
            timeShown: 5000
        });
    }
}
