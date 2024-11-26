import {
  DomainVerification,
  DomainVerificationStore,
} from "./verification_store";

const CHECKMARK = "\u2705";
const CROSS = "\u274C";

document.addEventListener("DOMContentLoaded", async function () {
  const domainResultsTable = document.getElementById("domain-results");
  const domainHeadline = document.getElementById("domain");

  const tabs = await browser.tabs.query({
    active: true,
    currentWindow: true,
  });
  const currentTab = tabs[0];

  if (!currentTab.url) {
    return;
  }

  if (!currentTab.url.startsWith("https://")) {
    return;
  }

  const domainVerification = (await browser.runtime.sendMessage({
    action: "getDomainVerification",
    url: currentTab.url,
  })) as DomainVerification | undefined;

  domainResultsTable.replaceChildren();

  if (domainVerification === undefined) {
    return;
  }

  domainHeadline.textContent = domainVerification.name;
  domainResultsTable.replaceChildren();

  for (const logVerification of domainVerification.logVerifications) {
    const domainRow = document.createElement("div");
    domainRow.className = "row";

    const nameCell = document.createElement("div");
    nameCell.textContent = logVerification.name;
    nameCell.classList.add("cell", "name-cell");

    const validCell = document.createElement("div");
    validCell.textContent = logVerification.valid ? CHECKMARK : CROSS;
    validCell.classList.add("cell", "valid-cell");

    const dateCell = document.createElement("div");
    dateCell.textContent = logVerification.date.toLocaleString();
    dateCell.classList.add("cell", "date-cell");

    domainRow.appendChild(nameCell);
    domainRow.appendChild(validCell);
    domainRow.appendChild(dateCell);

    domainResultsTable.appendChild(domainRow);
  }
});
