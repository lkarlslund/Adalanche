window.onpopstate = function (event) {
  $("body").html(event.state);
};

function set_query(query) {
  $("#aqlquerytext").val(query);
}

function dragMoveListener(event) {
  var target = event.target,
    // keep the dragged position in the data-x/data-y attributes
    x = (parseFloat(target.getAttribute("data-x")) || 0) + event.dx,
    y = (parseFloat(target.getAttribute("data-y")) || 0) + event.dy;

  // translate the element
  target.style.webkitTransform = target.style.transform =
    "translate(" + x + "px, " + y + "px)";

  // update the posiion attributes
  target.setAttribute("data-x", x);
  target.setAttribute("data-y", y);

  if (!target.classList.contains("window-front")) {
    console.log($(".window-front"));
    $(".window-front").removeClass("window-front");
    console.log($(".window-front"));
    target.classList.add("window-front");
  }
}

function get_window(id) {
  return $("#windows > #window_" + id);
}

function new_window(
  id,
  title,
  content,
  alignment = "topleft",
  height = 0,
  width = 0
) {
  // Other windows are not in front
  $(".window-front").removeClass("window-front");

  var mywindow = $(`#windows #window_${id}`);
  var itsnew = true;

  // Remove the old
  if (mywindow.length != 0) {
    interact(`#window_${id}`).unset();
    mywindow.remove();
  }

  var maxheight = $(window).height() * 0.8;
  var maxwidth = $(window).width() * 0.6;

  offset = $(".window").length + 1; // count windows

  xpos = offset * 24;
  ypos = offset * 16;

  switch (alignment) {
    case "topleft":
      // default
      break;
    case "center":
      xpos = window.innerWidth / 2;
      ypos = window.innerHeight / 2;
      break;
  }

  // Create the new
  mywindow = $(
    `<div class="window bg-dark shadow border pointer-events-auto window-front" style="transform: translate(${xpos}px, ${ypos}px);" data-x=${xpos} data-y=${ypos} id="window_${id}">
          <div id='header' class='window-header bg-primary text-dark p-1'>
          <span id="title" class="col">${title}</span><span id="close" class="float-top float-end cursor-pointer bi-x-square"></span>
          </div>
          <div class="window-wrapper">
          <div class="window-content p-1" id="contents">${content}</div>
          </div>
          </div>`
  );
  $("#windows").append(mywindow);

  // closing
  $("#close", mywindow).click(function (event) {
    interact(`#window_${id}`).unset();
    $(this).parents(".window").remove();
  });

  ni = interact("#window_" + id)
    // .origin('self')
    .resizable({
      edges: { left: true, right: true, bottom: true, top: true },
      margin: 5,
      origin: self,
      listeners: {
        move(event) {
          console.log(event);

          var target = event.target;
          var x = parseFloat(target.getAttribute("data-x")) || 0;
          var y = parseFloat(target.getAttribute("data-y")) || 0;

          // update the element's style
          target.style.width = event.rect.width + "px";
          target.style.height = event.rect.height + "px";

          if (!target.classList.contains("window-front")) {
            $(".window-front").removeClass("window-front");
            target.classList.add("window-front");
          }

          // translate when resizing from top or left edges
          x += event.deltaRect.left;
          y += event.deltaRect.top;

          // Ensure window does not slip too far up or left
          x = Math.max(0, x);
          y = Math.max(0, y);

          target.style.transform = "translate(" + x + "px," + y + "px)";

          target.setAttribute("data-x", x);
          target.setAttribute("data-y", y);
        },
      },
      modifiers: [
        // keep the edges inside the parent
        interact.modifiers.restrictEdges({
          outer: "parent",
        }),

        // min and max size
        interact.modifiers.restrictSize({
          min: { width: 200, height: 150 },
          max: { width: maxwidth, height: maxheight },
        }),
      ],

      inertia: true,
    })
    .draggable({
      onmove: window.dragMoveListener,
      modifiers: [
        interact.modifiers.restrictRect({
          restriction: "parent",
          endOnly: false,
        }),
      ],
      allowFrom: ".window-header",
    });

  // ni.fire({
  //   type: "resizemove",
  //   target: $("#window_" + id).get(0),
  // });

  if (height > 0) {
    mywindow.height(height);
  }
  if (width > 0) {
    mywindow.width(width);
  }

  if (mywindow.height() > maxheight) {
    mywindow.height(maxheight);
  }
  if (mywindow.width() > maxwidth) {
    mywindow.width(maxwidth);
  }

  mywindow.addClass("window-front");

  // Bring to front on mouse down
  mywindow.mousedown(function () {
    var win = $(this);
    if (!win.hasClass("window-front")) {
      $("#windows div").removeClass("window-front");
      win.addClass("window-front");
    }
  });

  return itsnew;
}

function busystatus(busytext) {
  $("#status")
    .html(
      `<div class="text-center pb-3">` +
        busytext +
        `</div>
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

function encodeaqlquery() {
  q = JSON.stringify(
    $("#aqlqueryform, #analysisoptionsform")
      .serializeArray()
      .reduce(function (m, o) {
        // is it a checked checkbox?
        // console.log(o);
        // console.log($("#" + o.name).prop("type"));
        if ($("#" + o.name).is(":checked")) {
          m[o.name] = true;
        } else if ($("#" + o.name).prop("type") == "number") {
          m[o.name] = Number(o.value);
        } else {
          m[o.name] = o.value;
        }
        return m;
      }, {})
  );

  return q;
}

function aqlanalyze(e) {
  busystatus("Analyzing");

  $.ajax({
    type: "POST",
    url: "/api/aql/analyze",
    contentType: "charset=utf-8",
    data: encodeaqlquery(),
    dataType: "json",
    success: function (data) {
      if (data.total == 0) {
        $("#status").html("No results").show();
      } else {
        // Remove all windows
        $("#windows div").remove();

        var info = "";
        if (data.nodecounts["start"] > 0 && data.nodecounts["end"] > 0) {
          info +=
            "Located " +
            data.nodecounts["start"] +
            " start nodes and " +
            data.nodecounts["end"] +
            " end nodes<hr/>";
        }

        info += '<table class="w-100">';
        for (var objecttype in data.resulttypes) {
          info +=
            '<tr><td class="text-right pr-5">' +
            data.resulttypes[objecttype] +
            "</td><td>" +
            objecttype +
            "</td></tr>";
        }
        info +=
          '<tr><td class="text-right pr-5">' +
          data.total +
          "</td><td>total nodes in analysis</td></tr>";
        if (data.removed > 0) {
          info +=
            '<tr><td class="text-right pr-5"><b>' +
            data.removed +
            "</b></td><td><b>nodes were removed by node limiter</b></td></tr>";
        }
        info += "</table>";

        new_window("results", "Query results", info);

        if ($("infowrap").prop("width") == 0) {
          $("#infowrap").animate({ width: "toggle" }, 400);
        }

        if (
          $("#hideoptionsonanalysis").prop("checked") &&
          $("#optionspanel").prop("width") != 0
        ) {
          $("#optionspanel").animate({ width: "toggle" }, 400);
        }

        if (
          $("#hidequeryonanalysis").prop("checked") &&
          $("#querybox").prop("height") != 0
        ) {
          $("#querybox").slideToggle("fast");
        }

        new Promise(resolve=>{
          initgraph(data.elements);
        });

        history.pushState($("body").html(), "adalanche");
      }
    },
    error: function (xhr, status, error) {
      toast("Problem loading graph", xhr.responseText, "error");
      $("#status").empty().hide();
    },
  });
}


let lastwasidle;
let progressSocket;

function connectProgress() {
  if (location.origin.startsWith("https://")) {
    // Polled
    $.ajax({
      url: "/api/backend/progress",
      dataType: "json",
      timeout: 2000,
      success: function (data) {
        handleProgressData(data);
        setTimeout(connectProgress, 2000);
      },
      error: function (e) {
        $("#backendstatus").html("Adalanche backend is offline");
        $("#upperstatus").show();
        $("#progressbars").empty().hide();
        $("#offlineblur").show();

        setTimeout(connectProgress, 10000);
      },
    })
  } else {
    // Websocket
    progressSocket = new WebSocket(
      location.origin.replace(/^http/, "ws") + "/api/backend/ws-progress"
    );

    progressSocket.onopen = function (event) {
      console.log("Open event");  
      console.log(event);
      lastwasidle = false;
    }

    progressSocket.onerror = function (event) {
      console.log("Error event");
      console.log(event);

      $("#backendstatus").html("Adalanche backend is offline");
      $("#upperstatus").show();
      $("#progressbars").empty().hide();
      $("#offlineblur").show();
    };

    progressSocket.onclose = function (event) {
      console.log("Close event");
      console.log(event);

      $("#backendstatus").html("Adalanche backend is offline");
      $("#upperstatus").show();
      $("#progressbars").empty().hide();
      $("#offlineblur").show();
      setTimeout(connectProgress, 3000);
    };

    progressSocket.onmessage = function (message) {
      progress = $.parseJSON(message.data);
      handleProgressData(progress);
    }
  }
}

function handleProgressData(progress) {
  $("#offlineblur").hide();

  if (progress.status == "Ready") {
    if (!data_loaded) {
      data_loaded = true;
      autorun_query();
    }
  }

  progressbars = progress.progressbars;
  if (progressbars.length > 0) {
    lastwasidle = false;
    keepProgressbars = new Set();
    for (i in progressbars) {
      progressbar = progressbars[i];
      if (progressbar.Done) {
        continue;
      }
      keepProgressbars.add(progressbar.ID);

      // find progressbar
      pb = $("#progressbar_" + progressbar.ID);
      if (pb.length == 0 && !progressbar.Done) {
        $("#progressbars").append(
          `<div id="progressbar_` +
            progressbar.ID +
            `" class="progress-group">
            <div class="progress-group-label">` +
            progressbar.Title +
            `
              <div id="pct" class="progress-group-label float-end">` +
            progressbar.Percent.toFixed(2) +
            `%</div>
            </div>
            <div class="progress">
              <div class="progress-bar rounded-0" role="progressbar" aria-valuemin="0" aria-valuemax="100"></div>
            </div>
          </div>`
        );
        pb = $("#progressbar_" + progressbar.ID);
      }

      // Update progressbar
      progbar = pb.find(".progress-bar")
      progbar.attr("aria-valuenow", progressbar.Percent.toFixed(0));
      progbar.css("width", progressbar.Percent.toFixed(0) + "%");
      pb.find("#pct").html(progressbar.Percent.toFixed(2) + "%");
    }
    // remove old progressbars
    $("#progressbars .progress-group").each(function (index) {
      id = $(this).attr("id");
      if (!keepProgressbars.has(id.substring(12))) {
        $(this).slideUp("slow", function () {
          $(this).remove();
        });
      }
    });

    $("#upperstatus").show();
    $("#progressbars").show();
    $("#backendstatus").html("Adalanche is processing");
  } else {
    if (!lastwasidle) {
      $("#progressbars").empty().hide();
      $("#backendstatus").html("Adalanche backend is idle");
      $("#upperstatus").fadeOut("slow");
    }
    lastwasidle = true;
  }
}

// start update cycle
connectProgress();

function toast(title, contents, toastclass) {
  if (!toastclass) {
    toastclass = "info";
  }
  toastbody = contents;
  if (title) {
    toastbody = "<span class='toast-title'>" + title + "</span><br>" + contents;
  }
  // switch (toastclass) {
  //   case "info":
  //     icon = "<i class='fas fa-info-circle'></i>";
  //     break;
  //   case "warning":
  //     toastclass = "toastify-warning";
  //     break;
  //   case "error":
  //     toastclass = "toastify-error";
  //     break;
  //     case "success":

  // }
  Toastify({
    text: toastbody,
    duration: 1000000,
    // avatar: icon,
    // destination: "https://github.com/apvarun/toastify-js",
    newWindow: true,
    close: true,
    className: toastclass,
    escapeMarkup: false,
    gravity: "bottom", // `top` or `bottom`
    position: "left", // `left`, `center` or `right`
    stopOnFocus: true, // Prevents dismissing of toast on hover
    style: {
      // background: "orange",
      // background: "linear-gradient(to right, #00b09b, #96c93d)",
    },
    onClick: function () {}, // Callback after click
  }).showToast();
}

var initial_query_set = false;
var queries;
function updateQueries() {
  $.ajax({
    url: "/api/backend/queries",
    dataType: "json",
    success: function (querylist) {
      queries = querylist;
      dropdowncontent = $("#aqlqueries");
      dropdowncontent.empty();

      for (i in queries) {
        query = queries[i];
        item =
          "<li " +
          (query.default ? 'id="defaultquery"' : "") +
          ' class="dropdown-item" querynum=' +
          i +
          " queryname='"+query.name+"'>" +
          query.name +
          (query.user_defined ? '<i class="float-end bi-eraser"></i>' : "") +
          "</li>";
        dropdowncontent.append(item);
      }

      // Predefined queries dropdown button
      $("#aqlqueries li").on("click", "", function (event) {
        if (event.target !== this) return; // not children, only the li

        console.log("You clicked the drop downs", event.target);

        set_query(queries[event.target.getAttribute("querynum")].query);
        $("#queriesbutton").toggleClass("active");
        $("#queriesdropdown").toggleClass("show");
      });

      // Delete user defined queries
      $("#aqlqueries i").on("click", "", function (event) {
        console.log(jQuery(this).parent().get(0));
        queryname = $(this).parent().get(0).getAttribute("queryname");
        $.ajax({
          type: "DELETE",
          url: "api/backend/queries/" + queryname,
          error: function (xhr, status, error) {
            toast("Error deleting query", error, "error");
          },
          success: function (data) {
            toast("Query deleted successfully", "", "success");
            updateQueries();
          },
        });
        console.log(event);
      });


      if (!initial_query_set) {
        console.log("Setting default query ...");
        set_query(queries[$("#defaultquery").attr("querynum")].query);
        initial_query_set = true;
        autorun_query();
      }
    },
  });
}

// When we´re ready ...
$(function () {
  // save and restore collapsible UI
  $(".collapse, .collapse-panel").on("shown.bs.collapse", function () {
    localStorage.setItem("coll_" + this.id, true);
  });

  $(".collapse, .collapse-panel").on("hidden.bs.collapse", function () {
    localStorage.removeItem("coll_" + this.id);
  });

  $(".collapse, .collapse-panel").each(function () {
    if (localStorage.getItem("coll_" + this.id) === "true") {
      $(this).collapse("show");
    } else {
      $(this).collapse("hide");
    }
  });

  // Initial GUI setup
  $("#infopop").on("click", function () {
    $("#infowrap").animate({ width: "toggle" }, 400);
  });

  $("#optionstogglevisibility").on("click", function () {
    $("#optionspanel").animate({ width: "toggle" }, 400);
  });

  $("[data-bs-toggle='tooltip']").each(function () {
    new bootstrap.Tooltip($(this));
  });

  // autosize($('#querytext'));

  $("#explore").on("click", function () {
    new_window(
      "explore",
      "Explore objects",
      "<div id='exploretree' class='jstree-default-dark'></div>"
    );
    $("#exploretree")
      .jstree({
        core: {
          multiple: false,
          data: {
            url: "/api/tree",
            dataType: "json",
            data: function (node) {
              return { id: node.id };
            },
          },
        },
        types: {
          default: {
            icon: "glyphicon glyphicon-flash",
          },
          demo: {
            icon: "glyphicon glyphicon-ok",
          },
        },
        state: { key: "adalanche_explore" },
        plugins: ["sort", "types", "state", "wholerow"],
      })
      .on("select_node.jstree", function (e, d) {
        if (d.event == undefined) {
          return;
        }
        if (d.event.type == "click") {
          $.ajax({
            type: "GET",
            url: "api/details/id/" + d.node.id, // n123 format -> 123
            dataType: "json",
            success: function (data) {
              // details = rendernode(data)
              var details = renderdetails(data);
              windowname = "details_" + d.node.id
              if (getpref("ui.open.details.in.same.window")) {
                windowname="node_details"
              }
              new_window(windowname, "Item details", details);
            },
            // error: function (xhr, status, error) {
            //     newwindow("details", "Node details", rendernode(evt.target) + "<div>Couldn't load details:" + xhr.responseText + "</div>");
            // }
          });
        }
      });
  });

  $("#node-info").on("click", function () {
    /* get json data and show window on success */
    $.ajax({
      type: "GET",
      url: "backend/nodes",
      dataType: "json",
      success: function (data) {
        var details = renderdetails(data);
        new_window("node_info", "Known Nodes", details);
      },
      error: function (xhr, status, error) {
        toast("API Error", "Couldn't load details:" + xhr.responseText, "error");
      },
    });
  });

  $("#edge-info").on("click", function () {
    /* get json data and show window on success */
    $.ajax({
      type: "GET",
      url: "backend/edges",
      dataType: "json",
      success: function (data) {
        var details = renderdetails(data);
        new_window("edge_info", "Known Edges", details);
      },
      error: function (xhr, status, error) {
        toast("API Error", "Couldn't load details:" + xhr.responseText, "error");
      },
    });
  });


  $("#savequerybutton").on("click", function () {
    // open new windows with the save dialog
    new_window(
      "save_query",
      "Save query",
      `Name: <input type='text' id='savequeryname'>
<div><button id="savequerydialogbutton" class="float-end">Save</button></div>`,
      "center"
    );

    // tie the button handler to the button
    $("#savequerydialogbutton").on("click", function () {
      // POST the encoded query using ajax and display results
      $.ajax({
        url: "/api/backend/queries/" + $("#savequeryname").val(),
        method: "PUT",
        dataType: "json",
        data: encodeaqlquery(),
        error: function (xhr, status, error) {
          toast("Error saving query", error, "error");
        },
        success: function (data) {
          toast("Query saved successfully", "", "success");
          updateQueries(); // refresh the list
        },
        complete: function () {
          get_window("save_query").remove();
        },
      });
    });
  });

  // QUERY FORM
  // $("#querydiv").slideUp("fast")
  $("#togglequeryvisible").on("click", function () {
    $("#querybox").slideToggle("fast");
  });

  $("#highlightbutton").on("click", function () {
    if (
      new_window(
        "highlight",
        "Highlight nodes",
        '<textarea id="highlighttext" class="w-100 mb-2" placeholder="(name=*admin*)"></textarea><div id="highlightqueryerror"></div><button id="searchandhighlight" class="btn btn-primary float-end">Highlight</button>'
      )
    ) {
      var highlightchangetimer;
      $("#highlighttext").on("input", function () {
        clearTimeout(highlightchangetimer);
        highlightchangetimer = setTimeout(function () {
          // check query for errors when user has been idle for 200ms
          $.ajax({
            type: "GET",
            url: "/api/backend/validatequery",
            data: {
              query: $("#highlighttext").val(),
            },
            success: function (data) {
              console.log(data);
              // $("#searchandhighlight").attr("disabled", false);
              $("#highlightqueryerror").hide();
            },
            error: function (xhr, status, error) {
              // $("#searchandhighlight").attr("disabled", true);
              $("#highlightqueryerror")
                .html(xhr.responseText +
                    ", will use (*=" +
                    $("#highlighttext").val()
                   + ") as query").show();
            },
          });
        }, 200);
      });

      $("#searchandhighlight").on("click", function () {
        if (cy) {
          $.ajax({
            type: "GET",
            url: "/api/search/get-ids?query=" + $("#highlighttext").val(),
            contentType: "charset=utf-8",
            data: {
              query: $("#highlighttext").val(),
            },
            dataType: "json",
            success: function (data) {

              cy.$("*").unselect();
              for (var id of data) {
                cy.$("#" + id).select();
              }
            },
          });
        }
      });
    }
  });

  // $('[data-toggle="tooltip"]').tooltip()

  let aqlchangetimer;
  $("#aqlquerytext").on("input", function (e) {
    clearTimeout(aqlchangetimer);
    aqlchangetimer = setTimeout(function () {
      // check query for errors when user has been idle for 200ms
      $.ajax({
        type: "GET",
        url: "/api/aql/validatequery",
        data: {
          query: e.target.value,
        },
        success: function (data) {
          console.log(data);
          $("#aqlanalyzebutton").attr("disabled", false);
          $("#aqlqueryerror").hide();
        },
        error: function (xhr, status, error) {
          $("#aqlanalyzebutton").attr("disabled", true);
          $("#aqlqueryerror").html(xhr.responseText).show();
        },
      });
    }, 200);
  });

  // Display stats on screen
  $.ajax({
    url: "api/backend/statistics",
    dataType: "json",
    success: function (data) {
      statustext =
        "<div class='text-center pt-10'><img class='only-dark' height=128 src='icons/adalanche-logo.svg'><img class='only-light' height=128 src='icons/adalanche-logo-black.svg'></div><div class='text-center'><h2>" +
        data.adalanche.program +
        "</h2><b>" +
        data.adalanche.shortversion +
        "</b></div>";

      $("#status").html(statustext).show().delay(15000).fadeOut(2000);
      $("#programinfo").html(
        data.adalanche.program + " " + data.adalanche.shortversion
      );
    },
    error: function (xhr, status, error) {
      $("#status")
        .html("guru meditation:<br>" + xhr.responseText)
        .show();
    },
  });

  $("#graphlayout").on("prefupdate", function () {
    layout = $(this).val();
    if (cy) {
      // render graph with new layout if there is one
      getGraphlayout(layout).run();
    }
  });

  $("#nodesizes").on("prefupdate", function () {
    if (cy) {
      applyNodeStyles(cy);
    }
  });

  $("#nodelabels").on("prefupdate", function () {
    if (cy) {
      cy.style().update();
    }
  });

  updateQueries();

  $(document).on("preferences.loaded", function (evt) {
    settings_loaded = true;
    autorun_query();
  });

  prefsinit();


  // End of on document loaded function
});

settings_loaded = false;
data_loaded = false;
initial_query_has_run = false;
function autorun_query() {
  if (initial_query_set && settings_loaded && data_loaded && getpref("ui.run.query.on.startup") && !initial_query_has_run) {
    initial_query_has_run = true;
    aqlanalyze();
  }
}
