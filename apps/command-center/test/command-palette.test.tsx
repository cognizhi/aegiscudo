import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { CommandPalette } from "@/components/command-palette";

describe("CommandPalette", () => {
  it("opens from the root command button and exposes navigation placeholders", () => {
    render(<CommandPalette />);

    fireEvent.click(screen.getByRole("button", { name: /command/i }));

    expect(screen.getByLabelText("Command palette")).toBeInTheDocument();
    expect(screen.getByText("Registry Proxies")).toBeInTheDocument();
    expect(screen.getByText("Policy Simulator")).toBeInTheDocument();
  });

  it("ignores the global shortcut while text fields are active", () => {
    render(
      <CommandPalette>
        <input aria-label="Package" />
      </CommandPalette>,
    );

    screen.getByLabelText("Package").focus();
    fireEvent.keyDown(screen.getByLabelText("Package"), { key: "k", ctrlKey: true });

    expect(screen.queryByLabelText("Command palette")).not.toBeInTheDocument();
  });
});
