"use client";

import { Command } from "cmdk";
import { Search } from "lucide-react";
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from "react";

const commandGroups = [
  {
    group: "Overview",
    items: [{ label: "Executive Risk Dashboard", value: "risk-dashboard" }],
  },
  {
    group: "Analysis",
    items: [
      { label: "Package Request Timeline", value: "package-request-timeline" },
      { label: "Quarantine Queue", value: "quarantine-queue" },
    ],
  },
  {
    group: "Policy",
    items: [{ label: "Policy Simulator", value: "policy-simulator" }],
  },
  {
    group: "Admin",
    items: [
      { label: "Registry Proxies", value: "registry-proxies" },
      { label: "AI Providers", value: "ai-providers" },
      { label: "Integrations", value: "integrations" },
    ],
  },
];

type CommandPaletteContextValue = {
  openPalette: () => void;
};

const CommandPaletteContext = createContext<CommandPaletteContextValue | null>(null);

export function CommandPaletteProvider({ children }: Readonly<{ children: ReactNode }>) {
  const [open, setOpen] = useState(false);
  const contextValue = useMemo(
    () => ({
      openPalette: () => setOpen(true),
    }),
    [],
  );

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        if (isEditableTarget(event.target)) {
          return;
        }
        event.preventDefault();
        setOpen((current) => !current);
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  return (
    <CommandPaletteContext.Provider value={contextValue}>
      {children}
      {open ? (
        <div className="fixed inset-0 z-50 bg-black/45 px-4 pt-24" onClick={() => setOpen(false)}>
          <Command
            label="Command palette"
            className="mx-auto max-w-2xl overflow-hidden rounded-md border border-(--color-border) bg-(--color-surface) shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="flex items-center gap-2 border-b border-(--color-border) px-4 py-3">
              <Search size={17} className="text-(--color-accent)" />
              <Command.Input
                autoFocus
                placeholder="Search pages and actions"
                className="w-full bg-transparent text-sm outline-none placeholder:text-(--color-muted)"
              />
            </div>
            <Command.List className="max-h-80 overflow-y-auto p-2">
              <Command.Empty className="px-3 py-6 text-center text-sm text-(--color-muted)">
                No command found.
              </Command.Empty>
              {commandGroups.map((group) => (
                <Command.Group key={group.group} heading={group.group} className="command-group">
                  {group.items.map((item) => (
                    <Command.Item
                      key={item.value}
                      value={`${group.group} ${item.label}`}
                      className="cursor-pointer rounded-md px-3 py-2 text-sm data-[selected=true]:bg-white/10"
                      onSelect={() => setOpen(false)}
                    >
                      {item.label}
                    </Command.Item>
                  ))}
                </Command.Group>
              ))}
            </Command.List>
          </Command>
        </div>
      ) : null}
    </CommandPaletteContext.Provider>
  );
}

export function CommandPaletteTrigger() {
  const { openPalette } = useCommandPalette();
  return (
    <button
      type="button"
      className="inline-flex items-center gap-2 rounded-md border border-(--color-border) bg-(--color-surface) px-3 py-2 text-sm text-(--color-muted) hover:text-(--color-text)"
      onClick={openPalette}
    >
      <Search size={16} />
      <span>Command</span>
    </button>
  );
}

export function CommandPalette({ children }: Readonly<{ children?: ReactNode }>) {
  return (
    <CommandPaletteProvider>
      <CommandPaletteTrigger />
      {children}
    </CommandPaletteProvider>
  );
}

function useCommandPalette() {
  const context = useContext(CommandPaletteContext);
  if (!context) {
    throw new Error("CommandPaletteTrigger must be rendered within CommandPaletteProvider");
  }
  return context;
}

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false;
  }
  return Boolean(target.closest("input, textarea, select, [contenteditable='true']"));
}
