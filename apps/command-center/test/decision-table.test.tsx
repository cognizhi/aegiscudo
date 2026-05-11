import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { DecisionTable } from "@/components/decision-table";
import { TooltipProvider } from "@/components/ui/tooltip";
import { quarantineQueueItems } from "@/lib/mock-data";
import type { QuarantineQueueItem } from "@aegiscudo/shared-types";

describe("DecisionTable", () => {
  it("renders policy decision rows", () => {
    const queryClient = new QueryClient();
    render(
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <DecisionTable initialData={quarantineQueueItems} fetchEnabled={false} />
        </TooltipProvider>
      </QueryClientProvider>,
    );
    const queueTable = within(screen.getByLabelText("Quarantine queue")).getByRole("table");
    expect(within(queueTable).getAllByText("QUARANTINE_PENDING_ANALYSIS")).toHaveLength(1);
    expect(screen.getByText("pkg:pypi/requestz@99.0.0")).toBeInTheDocument();
  });

  it("supports queue sorting, filtering, and pagination controls", () => {
    const queryClient = new QueryClient();
    const baseQuarantineItem = quarantineQueueItems[0]!;
    const baseBlockedItem = quarantineQueueItems[1]!;
    const initialData: QuarantineQueueItem[] = [
      {
        ...baseQuarantineItem,
        artifact_id: "artifact-zeta",
        analysis_job_id: "job-zeta",
        trace_id: "trace-zeta",
        coordinate: { ecosystem: "npm", name: "zeta-package", version: "1.0.0" },
      },
      {
        ...baseBlockedItem,
        artifact_id: "artifact-alpha",
        analysis_job_id: "job-alpha",
        trace_id: "trace-alpha",
        coordinate: { ecosystem: "pypi", name: "alpha-package", version: "2.0.0" },
      },
      {
        ...baseQuarantineItem,
        artifact_id: "artifact-delta",
        analysis_job_id: "job-delta",
        trace_id: "trace-delta",
        coordinate: { ecosystem: "npm", name: "delta-package", version: "3.0.0" },
      },
      {
        ...baseBlockedItem,
        artifact_id: "artifact-beta",
        analysis_job_id: "job-beta",
        trace_id: "trace-beta",
        coordinate: { ecosystem: "npm", name: "beta-package", version: "4.0.0" },
      },
      {
        ...baseQuarantineItem,
        artifact_id: "artifact-epsilon",
        analysis_job_id: "job-epsilon",
        trace_id: "trace-epsilon",
        coordinate: { ecosystem: "pypi", name: "epsilon-package", version: "5.0.0" },
      },
      {
        ...baseBlockedItem,
        artifact_id: "artifact-gamma",
        analysis_job_id: "job-gamma",
        trace_id: "trace-gamma",
        coordinate: { ecosystem: "npm", name: "gamma-package", version: "6.0.0" },
      },
    ];

    render(
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <DecisionTable initialData={initialData} fetchEnabled={false} />
        </TooltipProvider>
      </QueryClientProvider>,
    );

    const queueTable = within(screen.getByLabelText("Quarantine queue")).getByRole("table");

    fireEvent.click(screen.getByRole("button", { name: /Package/i }));
    expect(within(queueTable).getByText("pkg:pypi/alpha-package@2.0.0")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Search quarantine queue"), {
      target: { value: "delta" },
    });
    expect(within(queueTable).getByText("pkg:npm/delta-package@3.0.0")).toBeInTheDocument();
    expect(within(queueTable).queryByText("pkg:npm/zeta-package@1.0.0")).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Search quarantine queue"), {
      target: { value: "" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Next queue page" }));

    expect(screen.getByText("Page 2 of 2")).toBeInTheDocument();
    expect(within(queueTable).getAllByRole("row")).toHaveLength(2);
  });
});