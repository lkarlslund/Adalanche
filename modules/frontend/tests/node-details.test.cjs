const {test} = require("node:test");
const assert = require("node:assert/strict");
const {readFileSync} = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function renderer() {
    const window = {};
    vm.runInNewContext(readFileSync(path.join(__dirname, "../html/details-layouts.js"), "utf8"), {
        window, document: {addEventListener() {}}, renderlabel: value => value, iconPathForType: () => "icons/person-fill.svg",
    });
    return window.DetailsLayouts;
}

test("common card has typed identity, escaped title and lazy raw data", () => {
    const html = renderer().renderDetails({id: 7, type: "User", label: '<img src=x onerror="bad()">', identityField: "distinguishedName",
        identity: "CN=Sample,DC=example,DC=test", attributes: {userAccountControl:["514"], description:["<script>bad()</script>"], large: ["raw-only-value"]}});
    assert.match(html, /node-identity-card/);
    assert.match(html, /distinguishedName/);
    assert.match(html, /User details/);
    assert.match(html, /Disabled/);
    assert.match(html, /&lt;img/);
    assert.doesNotMatch(html, /<script>|raw-only-value/);
    assert.match(html, /aria-expanded="false"/);
    assert.match(html, /View data/);
    assert.match(html, /Filter attributes and values/);
});

test("common object types choose their own essentials", () => {
    for (const [type, title, attributes, expected] of [
        ["Group", "Group details", {groupType:["-2147483646"], member:["a","b"]}, "Security"],
        ["GroupManagedServiceAccount", "Service account details", {sAMAccountName:["sample$"]}, "sample$"],
        ["GroupPolicyContainer", "Policy details", {gPCFileSysPath:["policy-path"]}, "policy-path"],
        ["DNSNode", "DNS entry details", {dnsRecord:["one","two"]}, "Records collected"],
        ["DNSZone", "DNS zone details", {name:["example.test"]}, "example.test"],
        ["Computer", "Computer account details", {DNSHOSTNAME:["host.example.test"]}, "host.example.test"],
        ["Machine", "Machine details", {productName:["Sample OS"]}, "Sample OS"],
        ["CertificateTemplate", "Certificate template details", {"msPKI-RA-Signature":["0"]}, "Required signatures"],
        ["Service", "Service details", {startName:["Sample account"]}, "Sample account"],
        ["Other", "Object details", {description:["Sample description"]}, "Sample description"],
    ]) {
        const html = renderer().renderDetails({id:1,type,label:"Sample",attributes});
        assert.ok(html.includes(title), type);
        assert.ok(html.includes(expected), type);
    }
});

test("missing identity is explicitly session-only and unknown does not become zero", () => {
    const html = renderer().renderDetails({id:3,type:"Group",label:"Sample",attributes:{}});
    assert.match(html, /No primary identifier/);
    assert.match(html, /Session reference 3/);
    assert.match(html, /No essential fields collected/);
    assert.doesNotMatch(html, /Direct members recorded/);
});

test("common sections compose after essentials", () => {
    const layouts=renderer();
    layouts.registerSection("sample",()=>'<section id="extra">Extra</section>');
    const html=layouts.renderDetails({id:1,type:"User",label:"Sample",attributes:{}});
    assert.ok(html.indexOf("node-identity-card") < html.indexOf("User details"));
    assert.ok(html.indexOf("User details") < html.indexOf('id="extra"'));
    assert.ok(html.indexOf("View data") < html.indexOf("User details"));
});
