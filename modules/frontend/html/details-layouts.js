"use strict";

(function () {
  function escapeHtml(value) {
    if (value === null || value === undefined) {
      return "";
    }
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function isRandomized() {
    const labels = document.getElementById("graphlabels");
    return labels && labels.value === "randomize";
  }

  function normalizeValues(raw) {
    if (Array.isArray(raw)) {
      return raw;
    }
    return [raw];
  }

  function renderValueLines(values) {
    return normalizeValues(values)
      .map((v) => {
        const value = isRandomized() ? anonymizer.anonymize(v) : v;
        return "<div>" + escapeHtml(value) + "</div>";
      })
      .join("");
  }

  function renderRows(data, keys) {
    if (!data || !data.attributes) {
      return "";
    }
    var result = "";
    keys.forEach((key) => {
      if (!Object.prototype.hasOwnProperty.call(data.attributes, key)) {
        return;
      }
      result +=
        "<tr><th class='text-nowrap align-top pe-3'>" +
        escapeHtml(key) +
        "</th><td>" +
        renderValueLines(data.attributes[key]) +
        "</td></tr>";
    });
    return result;
  }

  function renderTable(rows) {
    if (!rows) {
      return "";
    }
    return "<table>" + rows + "</table>";
  }

  function renderSection(title, rows) {
    if (!rows) {
      return "";
    }
    return (
      "<div class='mb-2'>" +
      "<div class='fw-semibold'>" +
      escapeHtml(title) +
      "</div>" +
      renderTable(rows) +
      "</div>"
    );
  }

  function objectType(data) {
    if (!data || !data.attributes || !data.attributes.type) {
      return "";
    }
    const raw = data.attributes.type;
    if (Array.isArray(raw) && raw.length > 0) {
      return String(raw[0]);
    }
    return String(raw);
  }

  function renderDefault(data) {
    if (!data || !data.attributes) {
      return "<div>No details</div>";
    }
    return renderTable(renderRows(data, Object.keys(data.attributes)));
  }

  function renderGroup(data) {
    const identityRows = renderRows(data, [
      "name",
      "displayName",
      "samAccountName",
      "distinguishedName",
      "objectSid",
      "objectGuid",
      "domain",
      "type",
    ]);
    const membershipRows = renderRows(data, [
      "member",
      "memberOf",
      "memberOfIndirect",
      "primaryGroupID",
    ]);
    const all = new Set([
      "name",
      "displayName",
      "samAccountName",
      "distinguishedName",
      "objectSid",
      "objectGuid",
      "domain",
      "type",
      "member",
      "memberOf",
      "memberOfIndirect",
      "primaryGroupID",
    ]);
    const otherKeys = Object.keys(data.attributes).filter((k) => !all.has(k));
    const otherRows = renderRows(data, otherKeys);

    return (
      renderSection("Identity", identityRows) +
      renderSection("Membership", membershipRows) +
      renderSection("Other", otherRows)
    );
  }

  function renderPrincipal(data) {
    const identityRows = renderRows(data, [
      "name",
      "displayName",
      "samAccountName",
      "userPrincipalName",
      "distinguishedName",
      "objectSid",
      "objectGuid",
      "domain",
      "type",
    ]);
    const accountRows = renderRows(data, [
      "enabled",
      "accountExpires",
      "pwdLastSet",
      "lastLogon",
      "servicePrincipalName",
      "memberOf",
      "memberOfIndirect",
    ]);
    const all = new Set([
      "name",
      "displayName",
      "samAccountName",
      "userPrincipalName",
      "distinguishedName",
      "objectSid",
      "objectGuid",
      "domain",
      "type",
      "enabled",
      "accountExpires",
      "pwdLastSet",
      "lastLogon",
      "servicePrincipalName",
      "memberOf",
      "memberOfIndirect",
    ]);
    const otherKeys = Object.keys(data.attributes).filter((k) => !all.has(k));
    const otherRows = renderRows(data, otherKeys);

    return (
      renderSection("Identity", identityRows) +
      renderSection("Account", accountRows) +
      renderSection("Other", otherRows)
    );
  }

  function renderComputer(data) {
    const identityRows = renderRows(data, [
      "name",
      "distinguishedName",
      "dnshostname",
      "operatingSystem",
      "operatingSystemVersion",
      "domain",
      "type",
    ]);
    const authRows = renderRows(data, [
      "objectSid",
      "objectGuid",
      "servicePrincipalName",
      "allowedToDelegateTo",
      "msDS-AllowedToActOnBehalfOfOtherIdentity",
    ]);
    const all = new Set([
      "name",
      "distinguishedName",
      "dnshostname",
      "operatingSystem",
      "operatingSystemVersion",
      "domain",
      "type",
      "objectSid",
      "objectGuid",
      "servicePrincipalName",
      "allowedToDelegateTo",
      "msDS-AllowedToActOnBehalfOfOtherIdentity",
    ]);
    const otherKeys = Object.keys(data.attributes).filter((k) => !all.has(k));
    const otherRows = renderRows(data, otherKeys);

    return (
      renderSection("Host", identityRows) +
      renderSection("Auth/Delegation", authRows) +
      renderSection("Other", otherRows)
    );
  }

  function renderDetailsByType(data) {
    if (!data || !data.attributes || typeof data.attributes !== "object") {
      return "<pre>" + escapeHtml(JSON.stringify(data, null, 2)) + "</pre>";
    }

    const t = objectType(data).toLowerCase();
    if (t.includes("group")) {
      return renderGroup(data);
    }
    if (t.includes("person") || t.includes("user")) {
      return renderPrincipal(data);
    }
    if (
      t.includes("computer") ||
      t.includes("machine") ||
      t.includes("service") ||
      t.includes("container")
    ) {
      return renderComputer(data);
    }
    return renderDefault(data);
  }

  window.DetailsLayouts = {
    renderDetails: renderDetailsByType,
  };
})();
