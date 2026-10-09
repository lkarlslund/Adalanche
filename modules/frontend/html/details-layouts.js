"use strict";

(function () {
  const sections = new Map();
  const mounted = new WeakMap();
  let sequence = 0;
  const common = [["Description", "description"], ["Created", "whenCreated"], ["Changed", "whenChanged"]];
  const account = [["Account", "sAMAccountName"], ["Sign-in name", "userPrincipalName"], ["Status", "$accountStatus"],
    ["Password changed", "pwdLastSet"], ["Last logon recorded", "lastLogonTimestamp", "lastLogon"], ["Expires", "accountExpires"],
    ["Member of", "memberOf", "#count"], ["Service names", "servicePrincipalName"]];
  const host = [["Host name", "dnsHostName", "name"], ["Operating system", "operatingSystem", "productName"],
    ["Version", "operatingSystemVersion", "displayVersion", "version"], ["Addresses", "ipAddress"], ["Domain", "domain"], ["Primary user", "primaryUser"]];
  const file = [["Path", "absolutePath", "fullPath", "path", "relativePath"], ["Size (bytes)", "binarySize", "size"], ["Owner", "owner", "objectSid"]];
  const layouts = new Map();
  function layout(types, title, fields) { for (const type of types) layouts.set(type.toLowerCase(), {title, fields}); }
  layout(["User", "Person"], "User details", account);
  layout(["ManagedServiceAccount", "GroupManagedServiceAccount"], "Service account details", account);
  layout(["Group"], "Group details", [["Account", "sAMAccountName"], ["Group kind", "$groupKind"], ["Scope", "$groupScope"],
    ["Direct members recorded", "member", "#count"], ["Member of", "memberOf", "#count"], ["Managed by", "managedBy"]]);
  layout(["Computer"], "Computer account details", [...host, ["Account", "sAMAccountName"], ["Status", "$accountStatus"], ["Password changed", "pwdLastSet"], ["Service names", "servicePrincipalName"]]);
  layout(["Machine"], "Machine details", [...host, ["Architecture", "architecture"], ["Build", "buildNumber"], ["Collected", "collected"]]);
  layout(["DNSNode", "Dns-Node"], "DNS entry details", [["Name", "name", "dnsHostName"], ["Records collected", "dnsRecord", "#count"], ["Tombstoned", "dNSTombstoned"]]);
  layout(["DNSZone", "Dns-Zone"], "DNS zone details", [["Zone", "name"], ["Zone properties collected", "dnsProperty", "#count"]]);
  layout(["DomainDNS", "Domain-DNS", "BuiltinDomain"], "Domain details", [["Domain", "name", "dnsRoot"], ["Domain SID", "objectSid"],
    ["Functional level", "msDS-Behavior-Version"], ["Minimum password length", "minPwdLength"], ["Password history", "pwdHistoryLength"], ["Lockout threshold", "lockoutThreshold"]]);
  layout(["OrganizationalUnit", "Organizational-Unit", "Container"], "Container details", [["Name", "name"], ["Managed by", "managedBy"], ["Policy links", "gPLink"], ["Policy options", "gPOptions"]]);
  layout(["GroupPolicyContainer", "Group-Policy-Container"], "Policy details", [["Policy name", "displayName", "name"], ["Policy path", "gPCFileSysPath"], ["Version", "versionNumber"], ["Flags", "flags"], ["WMI filter", "gPCWQLFilter"]]);
  layout(["Service", "CallableService", "Callable-Service-Point"], "Service details", [["Service", "displayName", "name"], ["Runs as", "serviceAccount", "startName", "downLevelLogonName"], ["Command", "imagePath", "commandLine"], ["Start type", "startType"], ["Host", "dnsHostName", "machineName"]]);
  layout(["File", "Directory", "Executable"], "File details", file);
  layout(["CertificateTemplate", "PKI-Certificate-Template"], "Certificate template details", [["Template", "displayName", "name"], ["Version", "msPKI-Template-Schema-Version"],
    ["Purposes", "pKIExtendedKeyUsage"], ["Required signatures", "msPKI-RA-Signature"], ["Enrollment flags", "msPKI-Enrollment-Flag"], ["Name flags", "msPKI-Certificate-Name-Flag"]]);
  layout(["CertificationAuthority", "PKIEnrollmentService", "PKI-Enrollment-Service"], "Certificate authority details", [["Authority", "displayName", "name"], ["Host", "dnsHostName"], ["Templates", "certificateTemplates"], ["Flags", "flags"]]);
  layout(["Trust", "Trusted-Domain"], "Trust details", [["Partner", "trustPartner"], ["Direction", "trustDirection"], ["Type", "trustType"], ["Attributes", "trustAttributes"]]);
  layout(["ForeignSecurityPrincipal", "Foreign-Security-Principal"], "External principal details", [["Name", "name"], ["SID", "objectSid"], ["Domain", "domain"]]);
  layout(["AttributeSchema", "Attribute-Schema", "ClassSchema", "Class-Schema", "ControlAccessRight", "Control-Access-Right"], "Schema details", [["LDAP name", "lDAPDisplayName"], ["Schema identifier", "schemaIDGUID", "rightsGuid"], ["Syntax", "attributeSyntax"], ["Base class", "subClassOf"], ["Applies to", "appliesTo"]]);

  function escapeHtml(value) {
    return String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function displayText(value) { return typeof renderlabel === "function" ? renderlabel(String(value ?? "")) : String(value ?? ""); }
  function attributeIndex(data) { return new Map(Object.entries(data.attributes || {}).map(([key, raw]) => [key.toLowerCase(), Array.isArray(raw) ? raw : [raw]])); }
  function objectType(data) { return String(data.type || attributeIndex(data).get("type")?.[0] || "Object"); }
  function integer(values) {
    if (!values || values[0] === "" || values[0] == null) return null;
    const number = Number(values[0]);
    return Number.isSafeInteger(number) ? number : null;
  }
  function essentials(data) {
    const attributes = attributeIndex(data);
    const schema = layouts.get(objectType(data).toLowerCase()) || {title: "Object details", fields: [["Name", "name"], ["Source", "dataSource"], ["Object classes", "objectClass"]]};
    const rows = [];
    for (const [label, ...keys] of [...schema.fields, ...common]) {
      let values;
      let literal = false;
      if (keys[0] === "$accountStatus") {
        const control = integer(attributes.get("useraccountcontrol"));
        if (control !== null) values = [(control & 2) ? "Disabled" : "Enabled"];
        else if (attributes.has("enabled")) values = attributes.get("enabled");
        literal = true;
      } else if (keys[0] === "$groupKind" || keys[0] === "$groupScope") {
        const flags = integer(attributes.get("grouptype"));
        if (flags !== null) values = [keys[0] === "$groupKind" ? ((flags & 0x80000000) ? "Security" : "Distribution") :
          (flags & 1) ? "Built-in" : (flags & 2) ? "Global" : (flags & 4) ? "Domain local" : (flags & 8) ? "Universal" : "Unknown"];
        literal = true;
      } else {
        for (const key of keys) if (attributes.has(key.toLowerCase())) { values = attributes.get(key.toLowerCase()); break; }
        if (keys.includes("#count") && values) { values = [values.length.toLocaleString()]; literal = true; }
      }
      if (!values || values.length === 0) continue;
      const shown = values.slice(0, 3).map(value => escapeHtml(literal ? value : displayText(value))).join("<br>");
      rows.push(`<div class="node-essential"><dt>${escapeHtml(label)}</dt><dd>${shown}${values.length > 3 ? `<span class="node-more-values">+${values.length - 3} more in data</span>` : ""}</dd></div>`);
    }
    return `<section class="node-essentials"><h3>${schema.title}</h3>${rows.length ? `<dl>${rows.join("")}</dl>` : '<p class="small text-body-secondary mb-0">No essential fields collected.</p>'}</section>`;
  }
  function renderIdentity(data, dataAreaID) {
    const type = objectType(data);
    const title = displayText(data.label || type);
    const icon = data.icon || iconPathForType(type, data.attributes);
    const typeLabel = data.typeLabel || (typeof nodeLegendRegistry !== "undefined" ? (nodeLegendRegistry.get(type)?.label || type) : type);
    const identity = data.identityField && data.identity ?
      `<div class="node-identity-field">Identity · ${escapeHtml(data.identityField)}</div><code class="node-identity-value">${escapeHtml(displayText(data.identity))}</code>` :
      `<div class="node-identity-field">No primary identifier</div><span class="small text-body-secondary">Session reference ${escapeHtml(data.id)}</span>`;
    return `<header class="node-identity-card"><div class="node-type-icon"><img src="${escapeHtml(icon)}" width="44" height="44" alt=""></div>
      <div class="node-identity-content"><div class="node-type-label">${escapeHtml(typeLabel)}</div><h2>${escapeHtml(title)}</h2>${identity}</div>
      <button type="button" class="btn btn-sm btn-outline-secondary node-data-toggle" data-view-data aria-expanded="false" aria-controls="${dataAreaID}">View data</button></header>`;
  }

  function mountDataView(card) {
    const button = card.querySelector("[data-view-data]");
    const area = card.querySelector("[data-attribute-area]");
    const input = card.querySelector("[data-attribute-filter]");
    const status = card.querySelector("[data-attribute-status]");
    const body = card.querySelector(".node-attribute-table tbody");
    const more = card.querySelector("[data-attribute-more]");
    const retry = card.querySelector("[data-attribute-retry]");
    let entries = null, visible = 100, timer, controller;
    function render() {
      if (!entries) return;
      const query = input.value.trim().toLocaleLowerCase();
      const matches = entries.filter(entry => entry.search.includes(query));
      const fragment = document.createDocumentFragment();
      for (const {key, value} of matches.slice(0, visible)) {
        const row = document.createElement("tr");
        const heading = document.createElement("th"); heading.scope = "row"; heading.textContent = key;
        const cell = document.createElement("td"); cell.textContent = value;
        row.append(heading, cell); fragment.append(row);
      }
      body.replaceChildren(fragment);
      status.textContent = `${Math.min(matches.length, visible).toLocaleString()} of ${matches.length.toLocaleString()} matching pairs · ${entries.length.toLocaleString()} total`;
      more.hidden = matches.length <= visible;
    }
    async function load() {
      controller?.abort();
      const request = new AbortController();
      controller = request;
      retry.hidden = true; status.textContent = "Loading attribute data…";
      try {
        const response = await fetch(`api/details/nodeid/${encodeURIComponent(card.dataset.nodeDetails)}?format=raw`, {credentials: "same-origin", signal: request.signal});
        if (!response.ok) throw new Error("Could not load attribute data.");
        const data = await response.json();
        if (controller !== request || !card.isConnected) return;
        entries = Object.entries(data.attributes || {}).sort(([a], [b]) => a.localeCompare(b)).flatMap(([key, values]) =>
          (Array.isArray(values) && values.length ? values : [""]).map(raw => {
            const value = displayText(raw);
            return {key, value, search: `${key}\n${value}`.toLocaleLowerCase()};
          }));
        render();
      } catch (error) {
        if (controller === request && error.name !== "AbortError" && card.isConnected) { status.textContent = "Could not load attribute data."; retry.hidden = false; }
      }
    }
    button.addEventListener("click", () => {
      area.hidden = !area.hidden;
      button.setAttribute("aria-expanded", String(!area.hidden));
      button.textContent = area.hidden ? "View data" : "Hide data";
      if (!area.hidden) { input.focus(); if (!entries) load(); }
    });
    input.addEventListener("input", () => { clearTimeout(timer); visible = 100; timer = setTimeout(render, 100); });
    more.addEventListener("click", () => { visible += 100; render(); });
    retry.addEventListener("click", load);
    return () => { clearTimeout(timer); controller?.abort(); };
  }

  document.addEventListener("DOMContentLoaded", () => {
    const findCards = node => node.matches("[data-node-details]") ? [node] : node.querySelectorAll("[data-node-details]");
    new MutationObserver(records => {
      for (const record of records) {
        for (const node of record.removedNodes) if (node instanceof Element) for (const card of findCards(node)) {
          if (!card.isConnected) { mounted.get(card)?.(); mounted.delete(card); }
        }
        for (const node of record.addedNodes) if (node instanceof Element) for (const card of findCards(node)) {
          if (!mounted.has(card)) mounted.set(card, mountDataView(card));
        }
      }
    }).observe(document.body, {childList: true, subtree: true});
  });

  window.DetailsLayouts = {
    registerSection(name, render) { sections.set(name, render); },
    renderDetails(data) {
      if (!data || !data.attributes) return '<div class="p-2">No object details available.</div>';
      const extra = [...sections.values()].map(render => render(data)).join("");
      const id = `node-data-${++sequence}`;
      return `<article class="node-details" data-node-details="${escapeHtml(data.id)}">${renderIdentity(data, id)}${essentials(data)}
        <section id="${id}" data-attribute-area hidden class="node-attributes">
            <label class="small d-block mb-1" for="${id}-filter">Filter attributes and values</label>
            <input id="${id}-filter" data-attribute-filter type="search" class="form-control form-control-sm mb-2" placeholder="Attribute name or value…" autocomplete="off">
            <div class="small text-body-secondary mb-2" data-attribute-status role="status" aria-live="polite"></div>
            <div class="node-attribute-scroll"><table class="node-attribute-table"><thead><tr><th scope="col">Attribute</th><th scope="col">Value</th></tr></thead><tbody></tbody></table></div>
            <button type="button" class="btn btn-sm btn-outline-secondary mt-2" data-attribute-more hidden>Show 100 more</button>
            <button type="button" class="btn btn-sm btn-outline-secondary mt-2" data-attribute-retry hidden>Retry</button>
          </section>${extra}</article>`;
    },
  };
})();
