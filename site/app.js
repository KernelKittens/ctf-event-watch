(() => {
  "use strict";

  const rawBrand = window.FLAGWATCH_CONFIG || {};
  const brand = {
    productName: String(rawBrand.productName || "Flagwatch").slice(0, 80),
    organizationName: String(rawBrand.organizationName || "").slice(0, 120),
    shortDescription: String(
      rawBrand.shortDescription || "CTF events, official rules, and cited source intelligence.",
    ).slice(0, 240),
    mark: String(rawBrand.mark || "F").slice(0, 3),
    accentColor: String(rawBrand.accentColor || "#006c7a"),
    defaultTimeZone: String(rawBrand.defaultTimeZone || "America/Chicago"),
    logoUrl: rawBrand.logoUrl ? String(rawBrand.logoUrl) : "",
    faviconUrl: rawBrand.faviconUrl ? String(rawBrand.faviconUrl) : "",
    footerLinks: Array.isArray(rawBrand.footerLinks) ? rawBrand.footerLinks.slice(0, 8) : [],
  };
  const FALLBACK_ZONE = brand.defaultTimeZone;
  const ZONE_KEY = "flagwatch.timeZone";
  const SNAPSHOT_KEY = "flagwatch.snapshot.v1";
  const SNAPSHOT_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;
  const FETCH_DELAYS_MS = [0, 250, 750];
  const savedZone = readSavedZone();
  const initialZone = savedZone || detectZone();
  const state = {
    events: [],
    query: "", policy: "candidates", location: "all", teamSize: "all",
    scanSummary: null,
    generatedAt: null,
    month: monthFromUrl(initialZone),
    timeZone: initialZone,
    selectedDate: null,
    expandedDates: new Set(),
  };

  const elements = {
    calendar: document.querySelector("#calendar"),
    heading: document.querySelector("#month-heading"),
    status: document.querySelector("#status"),
    timezoneButton: document.querySelector("#timezone-button"),
    timezoneConfirm: document.querySelector("#timezone-confirm"),
    timezoneChooser: document.querySelector("#timezone-chooser"),
    timezoneSelect: document.querySelector("#timezone-select"),
    detectedTimezone: document.querySelector("#detected-timezone"),
    confirmTimezone: document.querySelector("#confirm-timezone"),
    selectedHeading: document.querySelector("#selected-day-heading"),
    selectedEvents: document.querySelector("#selected-day-events"),
    eventDialog: document.querySelector("#event-dialog"),
    eventTitle: document.querySelector("#event-title"),
    eventBody: document.querySelector("#event-detail-body"),
    scanUpdated: document.querySelector("#scan-updated"),
    scanEvents: document.querySelector("#scan-events"),
    scanSources: document.querySelector("#scan-sources"),
    scanRecheck: document.querySelector("#scan-recheck"),
    scanConfirmed: document.querySelector("#scan-confirmed"),
    brandName: document.querySelector("#brand-name"),
    brandOrganization: document.querySelector("#brand-organization"),
    brandMark: document.querySelector("#brand-mark"),
    homeLink: document.querySelector("#home-link"),
    siteDescription: document.querySelector("#site-description"),
    footerLinks: document.querySelector("#footer-links"),
  };

  function safePublicUrl(value, allowRelative = false) {
    if (!String(value || "").trim()) return null;
    try {
      const url = new URL(String(value || ""), location.origin);
      if (url.protocol !== "https:" && url.protocol !== "http:") return null;
      if (!allowRelative && !String(value).startsWith("http")) return null;
      return url.href;
    } catch (_) {
      return null;
    }
  }

  function hexChannels(value) {
    const match = /^#([0-9a-f]{6})$/i.exec(value);
    if (!match) return null;
    return [0, 2, 4].map((offset) => Number.parseInt(match[1].slice(offset, offset + 2), 16));
  }

  function relativeLuminance(channels) {
    const values = channels.map((value) => {
      const normalized = value / 255;
      return normalized <= 0.04045
        ? normalized / 12.92
        : ((normalized + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * values[0] + 0.7152 * values[1] + 0.0722 * values[2];
  }

  function hasWhiteTextContrast(value) {
    const channels = hexChannels(value);
    if (!channels) return false;
    const luminance = relativeLuminance(channels);
    return 1.05 / (luminance + 0.05) >= 4.5;
  }

  function applyBrand() {
    elements.brandName.textContent = brand.productName;
    elements.brandOrganization.textContent = brand.organizationName || "CTF intelligence";
    elements.siteDescription.textContent = brand.shortDescription;
    elements.homeLink.setAttribute("aria-label", `${brand.productName} home`);
    if (hasWhiteTextContrast(brand.accentColor)) {
      document.documentElement.style.setProperty("--accent", brand.accentColor);
      document.documentElement.style.setProperty("--accent-dark", brand.accentColor);
    }
    const logoUrl = safePublicUrl(brand.logoUrl, true);
    if (logoUrl) {
      const image = document.createElement("img");
      image.src = logoUrl;
      image.alt = "";
      elements.brandMark.replaceChildren(image);
    } else {
      elements.brandMark.textContent = brand.mark;
    }
    const faviconUrl = safePublicUrl(brand.faviconUrl, true);
    if (faviconUrl) {
      const favicon = document.createElement("link");
      favicon.rel = "icon";
      favicon.href = faviconUrl;
      document.head.append(favicon);
    }
    elements.footerLinks.replaceChildren();
    brand.footerLinks.forEach((item) => {
      if (!item || typeof item !== "object") return;
      const url = safePublicUrl(item.url, true);
      const label = String(item.label || "").trim().slice(0, 80);
      if (!url || !label) return;
      const link = document.createElement("a");
      link.href = url;
      link.textContent = label;
      if (new URL(url).origin !== location.origin) {
        link.target = "_blank";
        link.rel = "noopener noreferrer";
      }
      elements.footerLinks.append(link);
    });
  }

  function detectZone() {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || FALLBACK_ZONE;
    } catch (_) {
      return FALLBACK_ZONE;
    }
  }

  function validZone(zone) {
    try {
      new Intl.DateTimeFormat("en-US", {timeZone: zone}).format(new Date());
      return Boolean(zone);
    } catch (_) {
      return false;
    }
  }

  function readSavedZone() {
    const zone = localStorage.getItem(ZONE_KEY);
    if (validZone(zone)) return zone;
    if (zone) localStorage.removeItem(ZONE_KEY);
    return null;
  }

  function partsInZone(date, timeZone) {
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).formatToParts(date);
    return Object.fromEntries(parts.map((part) => [part.type, part.value]));
  }

  function monthForDate(date, timeZone) {
    const parts = partsInZone(date, timeZone);
    return new Date(Date.UTC(Number(parts.year), Number(parts.month) - 1, 1));
  }

  function parseMonth(value) {
    if (!/^\d{4}-\d{2}$/.test(value || "")) return null;
    const [year, month] = value.split("-").map(Number);
    if (month < 1 || month > 12) return null;
    return new Date(Date.UTC(year, month - 1, 1));
  }

  function monthFromUrl(timeZone) {
    const month = new URLSearchParams(location.search).get("month");
    return parseMonth(month) || monthForDate(new Date(), timeZone);
  }

  function monthKey(date) {
    return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}`;
  }

  function dateKey(date, timeZone = state.timeZone) {
    const values = partsInZone(date, timeZone);
    return `${values.year}-${values.month}-${values.day}`;
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function eventDays(event) {
    const startKey = dateKey(new Date(event.starts_at));
    const start = new Date(event.starts_at);
    const finish = new Date(event.finishes_at);
    const occupiedFinish = finish > start ? new Date(finish.getTime() - 1) : finish;
    const finishKey = dateKey(occupiedFinish);
    const days = [];
    let cursor = new Date(`${startKey}T12:00:00Z`);
    const last = new Date(`${finishKey}T12:00:00Z`);
    while (cursor <= last) {
      days.push(cursor.toISOString().slice(0, 10));
      cursor.setUTCDate(cursor.getUTCDate() + 1);
    }
    return days;
  }

  function eventsOn(date) {
    return state.events.filter((event) => matchesFilters(event) && eventDays(event).includes(date)).sort((a, b) => priority(b) - priority(a));
  }

  function updateUrl(values = {}, mode = "replace") {
    const params = new URLSearchParams(location.search);
    params.set("month", monthKey(state.month));
    for (const [key, value] of Object.entries(values)) {
      if (value) {
        params.set(key, value);
      } else {
        params.delete(key);
      }
    }
    const url = `${location.pathname}?${params}`;
    if (mode === "push") {
      history.pushState(null, "", url);
    } else {
      history.replaceState(null, "", url);
    }
  }

  function setMonth(delta) {
    state.month = new Date(
      Date.UTC(state.month.getUTCFullYear(), state.month.getUTCMonth() + delta, 1),
    );
    state.selectedDate = null;
    updateUrl({event: null}, "push");
    renderCalendar();
  }

  function matchesFilters(event) {
    const searchable = [event.title, ...(event.organizers || []), ...(event.categories || [])].join(" ").toLowerCase();
    if (state.query && !searchable.includes(state.query)) return false;
    if (state.location === "online" && !event.online) return false;
    if (state.location === "onsite" && !event.onsite) return false;
    const geography = event.assessment?.location?.geography || "unknown";
    if (state.location === "usa" && !["usa", "missouri", "st_louis"].includes(geography)) return false;
    if (state.location === "missouri" && !["missouri", "st_louis"].includes(geography)) return false;
    if (state.location === "st_louis" && geography !== "st_louis") return false;
    if (state.policy === "candidates" && event.ai_policy === "human_only") return false;
    if (state.policy === "allowed") return ["ai_native", "ai_assisted"].includes(event.ai_policy);
    if (state.policy === "human_only") return event.ai_policy === "human_only";
    if (state.policy === "unknown") return !event.ai_policy || event.ai_policy === "unknown";

    if (state.teamSize === "solo") {
      if (event.team_max !== 1) return false;
    } else if (state.teamSize === "small") {
      if (event.team_max === null || event.team_max < 2 || event.team_max > 4) return false;
    } else if (state.teamSize === "large") {
      if (event.team_max === null || event.team_max < 5) return false;
    } else if (state.teamSize === "unlimited") {
      if (event.team_max !== null && event.team_max !== 0) return false;
    }
    return true;
  }

  function renderCalendar() {
    document.querySelector("#filter-count").textContent = `${state.events.filter(matchesFilters).length} matching CTFs across the collected schedule`;
    elements.heading.textContent = new Intl.DateTimeFormat("en-US", {
      month: "long",
      year: "numeric",
      timeZone: "UTC",
    }).format(state.month);
    document.title = `${elements.heading.textContent} CTFs | ${brand.productName}`;
    elements.calendar.replaceChildren();
    const headerRow = document.createElement("div");
    headerRow.className = "calendar-row";
    headerRow.setAttribute("role", "row");
    ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].forEach((name) => {
      const heading = document.createElement("div");
      heading.className = "weekday";
      heading.setAttribute("role", "columnheader");
      heading.textContent = name;
      headerRow.append(heading);
    });
    elements.calendar.append(headerRow);

    const first = new Date(state.month);
    first.setUTCDate(1 - first.getUTCDay());
    const currentMonth = state.month.getUTCMonth();
    const today = dateKey(new Date());
    let weekRow;
    for (let offset = 0; offset < 42; offset += 1) {
      if (offset % 7 === 0) {
        weekRow = document.createElement("div");
        weekRow.className = "calendar-row";
        weekRow.setAttribute("role", "row");
        elements.calendar.append(weekRow);
      }
      const date = new Date(first);
      date.setUTCDate(first.getUTCDate() + offset);
      const key = date.toISOString().slice(0, 10);
      const cell = document.createElement("div");
      cell.className = "calendar-cell";
      cell.setAttribute("role", "gridcell");
      cell.dataset.date = key;
      if (date.getUTCMonth() !== currentMonth) cell.classList.add("outside");
      if (key === state.selectedDate) cell.classList.add("selected");

      const dayButton = document.createElement("button");
      dayButton.type = "button";
      dayButton.className = `day-select${key === today ? " today" : ""}`;
      dayButton.textContent = String(date.getUTCDate());
      dayButton.setAttribute("aria-label", new Intl.DateTimeFormat("en-US", {
        weekday: "long", month: "long", day: "numeric", year: "numeric", timeZone: "UTC",
      }).format(date));
      dayButton.addEventListener("click", () => selectDay(key));
      cell.append(dayButton);

      const eventList = document.createElement("div");
      eventList.className = "cell-events";
      const events = eventsOn(key);
      const expanded = state.expandedDates.has(key);
      const visible = expanded ? events : events.slice(0, 3);
      visible.forEach((event) => eventList.append(eventButton(event, "event-chip", true)));
      if (!expanded && events.length > 3) {
        const more = document.createElement("button");
        more.type = "button";
        more.className = "more-events";
        more.textContent = `${events.length - 3} more events`;
        more.addEventListener("click", () => {
          state.expandedDates.add(key);
          renderCalendar();
        });
        eventList.append(more);
      }
      cell.append(eventList);
      if (events.length) {
        const markers = document.createElement("span");
        markers.className = "mobile-markers";
        markers.setAttribute("aria-label", `${events.length} event${events.length === 1 ? "" : "s"}`);
        events.slice(0, 5).forEach((event) => {
          const marker = document.createElement("span");
          marker.dataset.verification = verificationState(event);
          marker.setAttribute("aria-hidden", "true");
          markers.append(marker);
        });
        cell.append(markers);
      }
      weekRow.append(cell);
    }
    if (state.selectedDate) renderSelectedDay();
  }

  function eventButton(event, className, includeTime = false) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = className;
    button.dataset.verification = verificationState(event);
    const title = document.createElement("span");
    title.className = "event-name";
    title.textContent = event.title;
    button.append(title);
    const geo = event.assessment?.location?.geography;
    if (["st_louis", "missouri", "usa"].includes(geo)) {
      const bonus = document.createElement("small"); bonus.textContent = {st_louis: "St. Louis", missouri: "Missouri", usa: "USA"}[geo]; button.append(bonus);
    }
    if (includeTime) {
      const time = document.createElement("span");
      time.className = "event-time";
      time.textContent = new Intl.DateTimeFormat("en-US", {
        timeZone: state.timeZone,
        hour: "numeric",
        minute: "2-digit",
      }).format(new Date(event.starts_at));
      button.setAttribute("aria-label", `${event.title}, starts ${time.textContent}`);
      button.append(time);
    }
    button.addEventListener("click", () => openEvent(event));
    return button;
  }

  function selectDay(key) {
    state.selectedDate = key;
    renderCalendar();
  }

  function renderSelectedDay() {
    const date = new Date(`${state.selectedDate}T12:00:00Z`);
    elements.selectedHeading.textContent = new Intl.DateTimeFormat("en-US", {
      weekday: "long", month: "long", day: "numeric", timeZone: "UTC",
    }).format(date);
    elements.selectedEvents.replaceChildren();
    const events = eventsOn(state.selectedDate);
    if (!events.length) {
      const empty = document.createElement("p");
      empty.className = "day-empty";
      empty.textContent = "No CTFs scheduled for this day.";
      elements.selectedEvents.append(empty);
      return;
    }
    events.forEach((event) => {
      const card = document.createElement("article");
      card.className = "event-overview";
      card.append(eventButton(event, "day-event", true));
      const facts = document.createElement("div");
      facts.className = "event-brief";
      const ai = document.createElement("span");
      ai.textContent = policyLabel(event);
      ai.dataset.policy = policyClass(event);

      const team = document.createElement("span");
      team.className = "event-badge-team";
      team.textContent = event.team_max ? (event.team_max === 1 ? "👤 Solo (1)" : `👥 Team max ${event.team_max}`) : "♾️ Open / Unlimited";

      const format = document.createElement("span");
      format.className = "event-badge-format";
      format.textContent = event.format || "Jeopardy";

      const prize = document.createElement("span");
      prize.textContent = `Prize: ${prizePreview(event)}`;
      facts.append(ai, team, format, prize);
      card.append(facts);
      const registration = registrationAction(event);
      if (registration) {
        const link = document.createElement("a");
        link.className = "event-register";
        link.href = registration.url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = registration.label;
        link.setAttribute("aria-label", `${registration.label} for ${event.title}`);
        card.append(link);
      }
      elements.selectedEvents.append(card);
    });
  }

  function prizePreview(event) {
    const value = String(event.prize_summary || "").trim();
    if (!value) return "Not published";
    const lines = value.split(/[\r\n]+/).map((line) => line.trim()).filter(Boolean);
    const money = lines.find((line) => /(?:[$€£]\s?\d|\b(?:USD|EUR|GBP|HKD|CAD|AUD)\s?[\d,]+)/i.test(line));
    const preview = money || lines[0] || value;
    const context = /qualif/i.test(event.title) && /prize.*final round/is.test(value)
      ? "Finals: " : "";
    const summary = `${context}${preview}`;
    return summary.length > 110 ? `${summary.slice(0, 107).trimEnd()}…` : summary;
  }

  function registrationAction(event) {
    const registration = safePublicUrl(event.registration_url);
    const official = safePublicUrl(event.official_url);
    if (registration && registration !== official) return {url: registration, label: "Register"};
    if (official) return {url: official, label: "Event site"};
    return null;
  }

  function eventSnapshot(event) {
    const action = registrationAction(event);
    return `<section class="event-snapshot" aria-label="Event at a glance">
      <div class="snapshot-facts">
        <div><span>AI status</span><strong>${escapeHtml(policyLabel(event))}</strong></div>
        <div><span>Prizes</span><strong>${escapeHtml(prizePreview(event))}</strong></div>
        <div><span>Registration</span><strong>${escapeHtml(display(event.registration_status, action?.label || "Not published"))}</strong></div>
      </div>
      ${action ? `<a class="snapshot-action" href="${escapeHtml(action.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(action.label)} <span aria-hidden="true">↗</span></a>` : ""}
    </section>`;
  }

  function policyLabel(event) {
    if (event.ai_policy_conflicting) return "Conflicting AI rules";
    if (event.analysis_stale) return "AI policy needs rechecking";
    return {
      ai_native: "AI native",
      ai_assisted: "AI assisted",
      human_only: "AI-assisted solving prohibited",
      unknown: "AI policy unknown",
    }[event.ai_policy] || "AI policy unknown";
  }

  function policyIsConfirmed(event) {
    return (
      ["ai_native", "ai_assisted", "human_only"].includes(event.ai_policy) &&
      !event.analysis_stale &&
      !event.ai_policy_conflicting
    );
  }

  function verificationState(event) {
    return policyIsConfirmed(event) ? "verified" : "unverified";
  }

  function formatDateTime(value) {
    return new Intl.DateTimeFormat("en-US", {
      timeZone: state.timeZone,
      month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit",
      timeZoneName: "short",
    }).format(new Date(value));
  }

  function duration(event) {
    const totalMinutes = Math.max(
      0,
      Math.round((new Date(event.finishes_at) - new Date(event.starts_at)) / 60000),
    );
    const days = Math.floor(totalMinutes / 1440);
    const remainingHours = Math.floor((totalMinutes % 1440) / 60);
    const minutes = totalMinutes % 60;
    const parts = [
      days ? `${days} day${days === 1 ? "" : "s"}` : "",
      remainingHours ? `${remainingHours} hour${remainingHours === 1 ? "" : "s"}` : "",
      minutes ? `${minutes} minute${minutes === 1 ? "" : "s"}` : "",
    ];
    return parts.filter(Boolean).join(" ") || "0 minutes";
  }

  function display(value, fallback = "Unknown") {
    if (Array.isArray(value)) return value.length ? value.join(", ") : fallback;
    return value === null || value === undefined || value === "" ? fallback : String(value);
  }

  function eventStatus(event) {
    if (event.status === "cancelled") return "Cancelled";
    if (event.status === "tentative") return "Tentative: confirm schedule";
    const now = Date.now();
    if (now >= new Date(event.finishes_at).getTime()) return "Finished";
    if (now >= new Date(event.starts_at).getTime()) return "Live now";
    return "Upcoming";
  }

  function icsTimestamp(value) {
    return new Date(value)
      .toISOString()
      .replaceAll("-", "")
      .replaceAll(":", "")
      .replace(".000", "");
  }

  function icsText(value) {
    return String(value).replaceAll("\\", "\\\\").replace(/\r\n|\r|\n/g, "\\n")
      .replaceAll(",", "\\,").replaceAll(";", "\\;");
  }

  function foldIcs(line) {
    const encoder = new TextEncoder();
    let current = "", bytes = 0;
    const folded = [];
    for (const character of line) {
      const length = encoder.encode(character).length;
      if (bytes + length > 75) { folded.push(current); current = " "; bytes = 1; }
      current += character; bytes += length;
    }
    folded.push(current);
    return folded.join("\r\n");
  }

  function icsLink(event) {
    const body = [
      "BEGIN:VCALENDAR",
      "VERSION:2.0",
      `PRODID:-//${brand.productName.replace(/[^a-z0-9 ]/gi, " ")} //CTF Calendar//EN`,
      "BEGIN:VEVENT",
      `UID:${icsText(event.event_key)}@flagwatch.local`,
      `DTSTAMP:${icsTimestamp(new Date())}`,
      `STATUS:${event.status === "cancelled" ? "CANCELLED" : event.status === "tentative" ? "TENTATIVE" : "CONFIRMED"}`,
      `DTSTART:${icsTimestamp(event.starts_at)}`,
      `DTEND:${icsTimestamp(event.finishes_at)}`,
      `SUMMARY:${icsText(event.title)}`,
      `URL:${icsText(event.official_url)}`,
      "TRANSP:TRANSPARENT",
      "END:VEVENT",
      "END:VCALENDAR",
    ].map(foldIcs).join("\r\n") + "\r\n";
    return `data:text/calendar;charset=utf-8,${encodeURIComponent(body)}`;
  }

  function slug(value) {
    return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  }

  function policyClass(event) {
    if (event.ai_policy === "human_only") return "banned";
    if (["ai_native", "ai_assisted"].includes(event.ai_policy)) return "allowed";
    if (!event.ai_policy || event.ai_policy === "unknown") return "unknown";
    return "";
  }

  function policyVerdict(event) {
    const confirmed = policyIsConfirmed(event);
    const checkedAt = event.source_checked_at
      ? `Checked ${formatDateTime(event.source_checked_at)}`
      : "Not checked yet";
    const source = event.ai_policy_source
      ? `<a class="policy-source" href="${escapeHtml(event.ai_policy_source)}" target="_blank" rel="noopener noreferrer">Read official AI rules</a>`
      : "";
    return `
      <section class="policy-verdict ${policyClass(event)}" aria-labelledby="ai-rules-title">
        <div class="policy-heading">
          <p class="eyebrow">AI rules</p>
          <span class="policy-status">${confirmed ? "Verified" : "Needs recheck"}</span>
        </div>
        <h3 id="ai-rules-title">${escapeHtml(policyLabel(event))}</h3>
        <p class="policy-reason">${escapeHtml(display(event.ai_policy_reason, "No published AI rule was found."))}</p>
        ${event.ai_policy_evidence ? `<blockquote>${escapeHtml(event.ai_policy_evidence)}</blockquote>` : ""}
        <p class="policy-checked">${escapeHtml(checkedAt)}${event.recheck_due_at ? `; recheck due ${escapeHtml(formatDateTime(event.recheck_due_at))}` : ""}</p>
        ${source ? `<div class="policy-actions">${source}</div>` : ""}
      </section>`;
  }

  function scanLedger(event) {
    const sourceState = event.source_scan_status || "not_checked";
    const sourceMark = sourceState === "read" ? "OK" : "!";
    const sourceClass = sourceState === "read" ? "" : " warn";
    const rulesFound = Number(event.source_rule_pages_found || 0);
    const rulesText = rulesFound
      ? `${rulesFound} dedicated rule page${rulesFound === 1 ? "" : "s"} read.`
      : "No dedicated rules page found.";
    const alertAllowed = event.status !== "cancelled" &&
      ["ai_native", "ai_assisted"].includes(event.ai_policy) &&
      policyIsConfirmed(event);
    const decision = alertAllowed ? "Verified, alerts allowed" : "Unverified, no alert";
    const decisionDetail = alertAllowed
      ? "Current official evidence confirms compatible AI use."
      : `${brand.productName} will recheck this event and will not notify Discord without current official evidence.`;
    const sourceCount = Array.isArray(event.source_refs) && event.source_refs.length
      ? event.source_refs.length
      : 1;
    const sourceSummary = `${sourceCount} event source${sourceCount === 1 ? "" : "s"} imported.`;
    return `
      <section class="scan-ledger" aria-labelledby="source-scan-title">
        <div class="scan-ledger-heading">
          <p class="eyebrow">Source check</p>
          <h3 id="source-scan-title">What the scan found</h3>
        </div>
        <ol>
          <li><span class="scan-mark">OK</span><strong>Event sources</strong><span>${escapeHtml(sourceSummary)}</span></li>
          <li><span class="scan-mark${sourceClass}">${sourceMark}</span><strong>Official source</strong><span>${escapeHtml(display(event.source_scan_reason, "Official source has not been checked yet"))}</span></li>
          <li><span class="scan-mark${rulesFound ? "" : " warn"}">${rulesFound ? "OK" : "!"}</span><strong>Rules discovery</strong><span>${escapeHtml(rulesText)}</span></li>
          <li><span class="scan-mark${alertAllowed ? "" : " warn"}">${alertAllowed ? "OK" : "!"}</span><strong>Alert decision</strong><span>${escapeHtml(decisionDetail)}</span></li>
        </ol>
        <div class="alert-decision${alertAllowed ? "" : " warn"}"><strong>${escapeHtml(decision)}</strong></div>
      </section>`;
  }

  function sourceKindLabel(kind) {
    return {
      official_page: "Official event page",
      organizer_page: "Official organizer page",
      ics: "ICS calendar",
      json_feed: "JSON feed",
      ctfd: "CTFd API",
      rctf: "rCTF API",
      ctftime: "CTFtime API",
    }[kind] || "Public source";
  }

  function sourceRecords(event) {
    const refs = Array.isArray(event.source_refs) ? event.source_refs : [];
    if (!refs.length) return "";
    const items = refs.map((ref) => {
      const url = safePublicUrl(ref.url);
      const label = `${sourceKindLabel(ref.kind)}: ${display(ref.source, "Source")}`;
      const collected = ref.collected_at ? `Collected ${formatDateTime(ref.collected_at)}` : "";
      return `<li>${url
        ? `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`
        : `<span>${escapeHtml(label)}</span>`}<small>${escapeHtml(collected)}</small></li>`;
    }).join("");
    return `
      <section class="source-records" aria-labelledby="source-records-title">
        <p class="eyebrow">Provenance</p>
        <h3 id="source-records-title">Event sources</h3>
        <ul>${items}</ul>
      </section>`;
  }

  function conflictWarnings(event) {
    const conflicts = Array.isArray(event.conflicts) ? event.conflicts : [];
    if (!conflicts.length) return "";
    const items = conflicts.map((conflict) => {
      const chosen = safePublicUrl(conflict.chosen_source_url);
      const other = safePublicUrl(conflict.other_source_url);
      const links = [
        chosen ? `<a href="${escapeHtml(chosen)}" target="_blank" rel="noopener noreferrer">preferred source</a>` : "preferred source",
        other ? `<a href="${escapeHtml(other)}" target="_blank" rel="noopener noreferrer">conflicting source</a>` : "conflicting source",
      ].join(" and ");
      return `<li><strong>${escapeHtml(display(conflict.field))}</strong><span>${escapeHtml(display(conflict.chosen_value))} versus ${escapeHtml(display(conflict.other_value))}</span><small>${links}</small></li>`;
    }).join("");
    return `
      <section class="source-conflicts" aria-labelledby="source-conflicts-title">
        <p class="eyebrow">Conflict warning</p>
        <h3 id="source-conflicts-title">Sources disagree</h3>
        <p>${escapeHtml(brand.productName)} kept the higher-priority value and shows both records here. Safety-sensitive conflicts suppress alerts.</p>
        <ul>${items}</ul>
      </section>`;
  }

  function publicAnalytics(event) {
    const analytics = event.analytics || {};
    const categories = analytics.categories && typeof analytics.categories === "object"
      ? Object.entries(analytics.categories)
      : [];
    const values = [
      ["Challenges", analytics.challenges_total],
      ["Visible solves", analytics.visible_solves],
      ["Scoreboard entries", analytics.scoreboard_entries],
      ["Participants", analytics.participants_total],
      ["Challenge categories", categories.map(([name, count]) => `${name}: ${count}`).join(", ")],
    ].filter(([, value]) => value !== null && value !== undefined && value !== "");
    if (!values.length) return "";
    return `
      <section class="public-analytics" aria-labelledby="public-analytics-title">
        <p class="eyebrow">Public platform data</p>
        <h3 id="public-analytics-title">Event analytics</h3>
        <dl>${values.map(([term, value]) => `<div><dt>${escapeHtml(term)}</dt><dd>${escapeHtml(value)}</dd></div>`).join("")}</dl>
      </section>`;
  }

  function intelTopicLabel(topic) {
    return {
      overview: "Overview",
      eligibility: "Eligibility",
      registration: "Registration",
      format: "Format",
      schedule: "Schedule",
      prizes: "Prizes",
      conduct: "Conduct",
      flag_sharing: "Flag sharing",
      platform: "Platform",
      ai_policy: "AI policy",
      other: "Other rules",
    }[topic] || "Other rules";
  }

  function eventIntelligence(event) {
    const claims = Array.isArray(event.intel_claims) ? event.intel_claims : [];
    if (!claims.length) return "";
    const grouped = new Map();
    claims.forEach((claim) => {
      const topic = intelTopicLabel(claim.topic);
      if (!grouped.has(topic)) grouped.set(topic, []);
      grouped.get(topic).push(claim);
    });
    const groups = [...grouped.entries()].map(([topic, topicClaims]) => `
      <section class="intel-group" aria-labelledby="intel-${slug(topic)}">
        <h4 id="intel-${slug(topic)}">${escapeHtml(topic)}</h4>
        <div class="intel-claims">
          ${topicClaims.map((claim) => `
            <article class="intel-claim">
              <div class="intel-claim-heading">
                <h5>${escapeHtml(claim.label)}</h5>
                <a href="${escapeHtml(claim.source_url)}" target="_blank" rel="noopener noreferrer" aria-label="Source for ${escapeHtml(claim.label)}">Official source</a>
              </div>
              <p class="intel-value">${escapeHtml(claim.value)}</p>
              <blockquote>${escapeHtml(claim.evidence)}</blockquote>
            </article>`).join("")}
        </div>
      </section>`).join("");
    const analyzed = event.intel_analyzed_at
      ? `Checked ${formatDateTime(event.intel_analyzed_at)}`
      : "Analysis time unavailable";
    const model = event.intel_model ? ` with ${event.intel_model}` : "";
    const stale = event.intel_stale ? " Saved intelligence is marked stale." : "";
    return `
      <section class="event-intel" aria-labelledby="event-intel-title">
        <div class="event-intel-heading">
          <p class="eyebrow">Rules dossier</p>
          <h3 id="event-intel-title">Event intelligence</h3>
          <p>Extracted from public event sources${escapeHtml(model)}. Every item includes the supporting quote.</p>
          <small>${escapeHtml(analyzed)}.${escapeHtml(stale)}</small>
        </div>
        ${groups}
      </section>`;
  }

  function scheduleLabel(event) {
    if (event.schedule_mode === "staggered") return "Staggered";
    if (event.schedule_mode === "fixed") return "Fixed";
    return "Unknown";
  }

  function locationLabel(event) {
    if (event.online && event.onsite) return "Online and onsite";
    if (event.onsite) return "Onsite";
    return "Online";
  }

  function priority(event) {
    const geo = {st_louis: 30, missouri: 20, usa: 10}[event.assessment?.location?.geography] || 0;
    const longRunning = new Date(event.finishes_at) - new Date(event.starts_at) > 30 * 86400000;
    return geo + (policyIsConfirmed(event) && event.ai_policy !== "human_only" ? 100 : 0) - (longRunning ? 10 : 0);
  }

  function evidenceState(field) {
    return {corroborated: "Corroborated across sources", single_source: "One source only", conflicting: "Sources disagree", unknown: "Not established"}[field?.state] || "Not established";
  }

  function assessmentDetails(event) {
    const a = event.assessment;
    if (!a) return `<section class="assessment-panel"><h3>Verification pending</h3><p>This event is waiting for its field-by-field check.</p></section>`;
    const labels = {ai_policy: "AI rules", prizes: "Prizes and rewards", participation: "Field size", location: "Location", dates: "Schedule"};
    const fields = Object.entries(labels).map(([key, label]) => {
      const field = a[key] || {};
      const value = key === "prizes" ? display(field.summary, field.reward_state === "none" ? "No reward published in cited evidence" : "Rewards not established")
        : key === "participation" ? (field.count != null ? `${field.count} ${field.kind || "entries"}` : "Size not published")
        : key === "location" ? display(field.place, "Physical location not established")
        : key === "ai_policy" ? policyLabel(event) : `${formatDateTime(event.starts_at)} to ${formatDateTime(event.finishes_at)}`;
      const proofs = (field.evidence || []).filter(e => safePublicUrl(e.source_url)).map(e => `<li><a href="${escapeHtml(safePublicUrl(e.source_url))}" target="_blank" rel="noopener noreferrer">Source</a>${e.checked_at ? `, checked ${escapeHtml(formatDateTime(e.checked_at))}` : ""}<p>${e.kind === "record" ? "Source record: " : "Quote: "}${escapeHtml(e.quote || "")}</p></li>`).join("");
      return `<article class="assessment-field"><h4>${label}</h4><p>${escapeHtml(value)}</p><strong>${escapeHtml(evidenceState(field))}${event.analysis_stale ? "; recheck needed" : ""}</strong>${proofs ? `<details><summary>Evidence</summary><ul>${proofs}</ul></details>` : ""}</article>`;
    }).join("");
    return `<section class="assessment-panel" aria-labelledby="assessment-heading"><h3 id="assessment-heading">Evidence check</h3><p>Two matching reads of one page do not count as independent corroboration. Missing or conflicting evidence stays labeled.</p><div class="assessment-grid">${fields}</div></section>`;
  }

  function competitionScenario(event) {
    const field = event.assessment?.participation;
    const count = field?.kind === "teams" && field?.count > 1 ? field.count : "";
    return `<section class="assessment-panel" aria-labelledby="odds-heading"><h3 id="odds-heading">Team winning scenario</h3><p>Actual winning odds are not calibrated. This calculator shows what a comparable field could imply, using the public WATCHLIST result as a single historical anchor.</p><p><a href="https://ctf.xposedornot.com/scoreboard" target="_blank" rel="noopener noreferrer">Historical result: fourth among 213 scoring teams</a>. One result cannot establish repeatable team strength.</p><label for="scenario-field">${count ? "Published team count, editable scenario" : "Assumed competing teams (no verified team count available)"}</label><input id="scenario-field" type="number" min="2" max="100000" step="1" value="${count}" placeholder="Enter a field size"><label for="scenario-strength">Relative performance assumption</label><select id="scenario-strength"><option value="1">Repeat historical relative performance</option><option value="0.25">Much tougher field: quarter of that strength</option><option value="4">Much easier field: four times that strength</option><option value="baseline">Equal-strength baseline</option></select><p id="scenario-result" aria-live="polite">Enter an assumed field size to calculate a scenario.</p><details><summary>Method and limits</summary><p>The historical rank sets relative strength to (213 - 4) / (4 - 1). A Plackett-Luce scenario gives first-place probability strength / (strength + teams - 1). The easier and tougher options are assumptions, not confidence bounds. Opponent quality, event format, team limits, available members, AI rules and eligibility can change the outcome. Prize chances also depend on award rules. No automatic team-performance bonus is assumed. <a href="https://hturner.r-universe.dev/PlackettLuce/doc/Overview.html" target="_blank" rel="noopener noreferrer">Ranking model reference</a>.</p></details></section>`;
  }

  function updateScenario() {
    const n = Number(document.querySelector("#scenario-field")?.value);
    const choice = document.querySelector("#scenario-strength")?.value;
    const out = document.querySelector("#scenario-result");
    if (!out) return;
    if (!Number.isInteger(n) || n < 2 || n > 100000) { out.textContent = "Enter a whole field size from 2 to 100,000."; return; }
    const strength = choice === "baseline" ? 1 : (213 - 4) / (4 - 1) * Number(choice);
    const probability = 100 * strength / (strength + n - 1);
    out.textContent = `Illustrative first-place scenario: ${probability < 1 ? probability.toFixed(1) : Math.round(probability)}%. Uncalibrated; not a prediction or a confidence interval.`;
  }

  function openEvent(event, updateHistory = true) {
    elements.eventTitle.textContent = event.title;
    const details = [
      ["Status", eventStatus(event)],
      ["Starts", formatDateTime(event.starts_at)],
      ["Ends", formatDateTime(event.finishes_at)],
      ["Duration", duration(event)],
      ["Prizes", display(event.prize_summary)],
      ["Team max", display(event.team_max)],
      ["Divisions", display(event.divisions)],
      ["Format", display(event.format)],
      ["Weight", display(event.weight)],
      ["Schedule", scheduleLabel(event)],
      ["Location", locationLabel(event)],
      ["Registration", display(event.registration_status)],
      ["Categories", display(event.categories)],
      ["Organizers", display(event.organizers)],
      [event.source_refs?.some(ref => ref.source === "hack-the-box-public") ? "Registered players" : "CTFtime interest", display(event.participants)],
      ["Platform", display(event.platform)],
    ];
    const links = [
      [event.official_url, "Official event"],
      [event.registration_url, "Registration link"],
      [event.ctftime_url, "CTFtime listing"],
    ].filter(([url]) => safePublicUrl(url));
    elements.eventBody.innerHTML = `
      ${eventSnapshot(event)}
      ${policyVerdict(event)}
      <dl class="detail-grid">${details.map(([term, value]) => `<div class="detail-item"><dt>${escapeHtml(term)}</dt><dd>${escapeHtml(value)}</dd></div>`).join("")}</dl>
      <nav class="event-links" aria-label="Event links">
        ${links.map(([url, label]) => `<a href="${escapeHtml(safePublicUrl(url))}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`).join("")}
        <a href="${icsLink(event)}" download="${slug(event.title)}.ics">Download ICS</a>
      </nav>
      <details class="research-notes"><summary>Event research</summary>
        ${assessmentDetails(event)}
        ${competitionScenario(event)}
        ${scanLedger(event)}
        ${conflictWarnings(event)}
        ${sourceRecords(event)}
        ${publicAnalytics(event)}
        ${eventIntelligence(event)}
      </details>`;
    document.querySelector("#scenario-field").addEventListener("input", updateScenario);
    document.querySelector("#scenario-strength").addEventListener("change", updateScenario);
    if (event.assessment?.participation?.kind === "teams") updateScenario();
    if (updateHistory) updateUrl({event: event.event_key}, "push");
    if (!elements.eventDialog.open) elements.eventDialog.showModal();
  }

  function closeEvent() {
    if (elements.eventDialog.open) elements.eventDialog.close();
    updateUrl({event: null});
  }

  function populateZones() {
    let zones = [FALLBACK_ZONE, "America/New_York", "America/Denver", "America/Los_Angeles", "Europe/London", "UTC"];
    if (typeof Intl.supportedValuesOf === "function") zones = Intl.supportedValuesOf("timeZone");
    if (!zones.includes(state.timeZone)) zones = [state.timeZone, ...zones];
    elements.timezoneSelect.replaceChildren(...zones.map((zone) => new Option(zone, zone)));
    elements.timezoneSelect.value = state.timeZone;
  }

  function updateTimezoneButton() {
    elements.timezoneButton.textContent = state.timeZone;
    elements.timezoneButton.setAttribute("aria-label", `Change timezone: ${state.timeZone}`);
  }

  function eventFromUrl() {
    const eventKey = new URLSearchParams(location.search).get("event");
    return state.events.find((event) => event.event_key === eventKey);
  }

  function saveZone(zone) {
    state.timeZone = zone || FALLBACK_ZONE;
    localStorage.setItem(ZONE_KEY, state.timeZone);
    updateTimezoneButton();
    populateZones();
    renderCalendar();
    if (elements.eventDialog.open) {
      const event = eventFromUrl();
      if (event) openEvent(event, false);
    }
  }

  function delay(milliseconds) {
    return new Promise((resolve) => setTimeout(resolve, milliseconds));
  }

  function validSnapshot(payload) {
    return Boolean(
      payload &&
      typeof payload.generated_at === "string" &&
      Array.isArray(payload.events),
    );
  }

  function saveSnapshot(payload) {
    try {
      localStorage.setItem(SNAPSHOT_KEY, JSON.stringify({
        saved_at: new Date().toISOString(),
        payload,
      }));
    } catch (_) {
      return;
    }
  }

  function readSnapshot() {
    try {
      const cached = JSON.parse(localStorage.getItem(SNAPSHOT_KEY) || "null");
      if (!cached || !validSnapshot(cached.payload)) return null;
      const savedAt = new Date(cached.saved_at).getTime();
      if (!Number.isFinite(savedAt) || Date.now() - savedAt > SNAPSHOT_MAX_AGE_MS) return null;
      return cached.payload;
    } catch (_) {
      return null;
    }
  }

  async function fetchSnapshot(url) {
    let lastError;
    for (const wait of FETCH_DELAYS_MS) {
      if (wait) await delay(wait);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      try {
        const response = await fetch(url, {
          headers: {Accept: "application/json"},
          cache: "no-store",
          signal: controller.signal,
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json();
        if (!validSnapshot(payload)) throw new Error("Invalid calendar snapshot");
        return payload;
      } catch (error) {
        lastError = error;
      } finally {
        clearTimeout(timeout);
      }
    }
    throw lastError || new Error("Calendar request failed");
  }

  function applySnapshot(payload, forceStale = false) {
    state.events = payload.events.map((event) => {
      const age = Date.now() - new Date(event.source_checked_at).getTime();
      return {...event, analysis_stale: Boolean(forceStale || event.analysis_stale ||
        !event.source_checked_at || !Number.isFinite(age) || (event.recheck_due_at ? Date.now() > new Date(event.recheck_due_at).getTime() : age > 48 * 3600 * 1000) || age < -300000)};
    });
    const sourceNames = {ctftime: "CTFtime", "hack-the-box-public": "Hack The Box", "alpacahack-calendar": "AlpacaHack", "ctfhub": "CTFHub", "uscc-cyberquests": "US Cyber Quests"};
    const coverage = Array.isArray(payload.coverage) ? payload.coverage : [];
    document.querySelector("#source-coverage").textContent = coverage.length
      ? "Connected sources: " + coverage.map((source) => `${sourceNames[source.name] || source.name} (${source.status === "ok" ? "updated" : source.status === "empty" ? "no events returned" : "needs recheck"})`).join("; ") + ". No single feed covers every CTF."
      : "";
    state.scanSummary = payload.scan_summary || null;
    state.generatedAt = payload.generated_at;
    renderScanSummary();
    renderCalendar();
    const event = eventFromUrl();
    if (event) openEvent(event, false);
  }

  async function loadEvents() {
    const apiBase = String(window.FLAGWATCH_API_BASE || "").replace(/\/$/, "");
    for (const [route, url] of [["live", `${apiBase}/api/events`], ["recovery", `${apiBase}/recovery/events.json`]]) {
      try {
        const payload = await fetchSnapshot(url);
        if (route === "live") saveSnapshot(payload);
        applySnapshot(payload, route !== "live");
        elements.status.textContent = route === "live"
          ? `Times shown in ${state.timeZone}.`
          : `Showing saved server data from ${formatDateTime(payload.generated_at)}. Live feed unavailable; details need rechecking. Times shown in ${state.timeZone}.`;
        return;
      } catch (_) {
        // Try the next explicit route; saved data never acquires a fresh timestamp.
      }
    }
    const cached = readSnapshot();
    if (cached) {
      applySnapshot(cached, true);
      elements.status.textContent = `Showing saved calendar data from ${formatDateTime(cached.generated_at)}. Live refresh is temporarily unavailable. Times shown in ${state.timeZone}.`;
      return;
    }
    elements.status.textContent = "The calendar feed and saved copies are unavailable right now. Please try again shortly.";
    renderCalendar();
  }

  function renderScanSummary() {
    const summary = {
      sources_read: state.events.filter((event) => event.source_scan_status === "read" && !event.analysis_stale).length,
      sources_need_recheck: state.events.filter(
        (event) => event.source_scan_status !== "read" || event.analysis_stale,
      ).length,
      policies_confirmed: state.events.filter(
        (event) => ["ai_native", "ai_assisted"].includes(event.ai_policy) &&
          policyIsConfirmed(event),
      ).length,
    };
    elements.scanUpdated.textContent = state.generatedAt
      ? formatDateTime(state.generatedAt)
      : "Not available";
    elements.scanEvents.textContent = `${state.events.length} CTF${state.events.length === 1 ? "" : "s"}`;
    elements.scanSources.textContent = `${summary.sources_read} source${summary.sources_read === 1 ? "" : "s"}`;
    elements.scanRecheck.textContent = `${summary.sources_need_recheck} need recheck`;
    elements.scanConfirmed.textContent = `${summary.policies_confirmed} confirmed`;
  }

  function syncFilterChips() {
    document.querySelectorAll(".filter-chip").forEach((chip) => {
      const filter = chip.dataset.filter;
      const value = chip.dataset.value;
      if (filter && value) {
        chip.classList.toggle("active", state[filter] === value);
      }
    });
  }

  document.querySelector("#event-search").addEventListener("input", (event) => {
    state.query = event.target.value.trim().toLowerCase();
    renderCalendar();
    if (state.selectedDate) renderDayEvents();
  });

  document.querySelectorAll(".filter-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const filter = chip.dataset.filter;
      const value = chip.dataset.value;
      if (!filter || !value) return;
      state[filter] = value;
      if (filter === "policy") {
        const select = document.querySelector("#policy-filter");
        if (select) select.value = value;
      } else if (filter === "teamSize") {
        const select = document.querySelector("#team-filter");
        if (select) select.value = value;
      }
      syncFilterChips();
      renderCalendar();
      if (state.selectedDate) renderDayEvents();
    });
  });

  for (const [id, key] of [["policy-filter", "policy"], ["team-filter", "teamSize"], ["location-filter", "location"]]) {
    const el = document.querySelector(`#${id}`);
    if (el) {
      el.addEventListener("change", (event) => {
        state[key] = event.target.value;
        syncFilterChips();
        renderCalendar();
        if (state.selectedDate) renderDayEvents();
      });
    }
  }

  document.querySelector("#previous-month").addEventListener("click", () => setMonth(-1));
  document.querySelector("#next-month").addEventListener("click", () => setMonth(1));
  document.querySelector("#today").addEventListener("click", () => {
    state.month = monthForDate(new Date(), state.timeZone);
    updateUrl({event: null}, "push");
    renderCalendar();
  });
  document.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", closeEvent));
  elements.eventDialog.addEventListener("close", () => updateUrl({event: null}));
  elements.eventDialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    closeEvent();
  });
  elements.eventDialog.addEventListener("click", (event) => {
    const bounds = elements.eventDialog.getBoundingClientRect();
    const onDialogEdge =
      event.clientX <= bounds.left + 4 ||
      event.clientX >= bounds.right - 4 ||
      event.clientY <= bounds.top + 4 ||
      event.clientY >= bounds.bottom - 4;
    if (event.target === elements.eventDialog || onDialogEdge) closeEvent();
  });
  elements.timezoneButton.addEventListener("click", () => {
    populateZones();
    elements.timezoneChooser.showModal();
  });
  elements.confirmTimezone.addEventListener("click", () => saveZone(state.timeZone));
  document.querySelector("#timezone-form").addEventListener("submit", (event) => {
    if (event.submitter?.value === "save") saveZone(elements.timezoneSelect.value);
  });
  elements.timezoneConfirm.addEventListener("close", () => {
    if (elements.timezoneConfirm.returnValue === "confirm") saveZone(state.timeZone);
    if (elements.timezoneConfirm.returnValue === "choose") {
      populateZones();
      elements.timezoneChooser.showModal();
    }
  });
  addEventListener("popstate", () => {
    state.month = monthFromUrl(state.timeZone);
    renderCalendar();
    const event = eventFromUrl();
    if (event) {
      openEvent(event, false);
    } else if (elements.eventDialog.open) {
      elements.eventDialog.close();
    }
  });

  applyBrand();
  updateTimezoneButton();
  if (!savedZone) {
    elements.detectedTimezone.textContent = state.timeZone;
    elements.confirmTimezone.textContent = `Use ${state.timeZone}`;
    elements.timezoneConfirm.showModal();
  }
  updateUrl();
  loadEvents();
  if ("serviceWorker" in navigator && !window.FLAGWATCH_API_BASE) {
    navigator.serviceWorker.register("/sw.js").catch(() => {
      // Browsers may disable storage. The network calendar still works.
    });
  }
  setInterval(() => { if (!document.hidden && !elements.eventDialog.open) loadEvents(); }, 60000);
})();
