import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { DecisionTable } from "@/components/decision-table";
import { TooltipProvider } from "@/components/ui/tooltip";
import { decisions } from "@/lib/mock-data";

describe("DecisionTable", () => {
  it("renders policy decision rows", () => {
    render(
      <TooltipProvider>
        <DecisionTable data={decisions} />
      </TooltipProvider>,
    );
    expect(screen.getByText("QUARANTINE_PENDING_ANALYSIS")).toBeInTheDocument();
    expect(screen.getByText("pkg:pypi/requestz@99.0.0")).toBeInTheDocument();
  });
});