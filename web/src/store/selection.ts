import { create } from "zustand";

interface SelectionState {
  sourceId: string | null;
  alertIds: string[];
  eventIds: string[];
  setSourceId: (sourceId: string | null) => void;
  toggleAlert: (id: string) => void;
  toggleEvent: (id: string) => void;
  clearPicks: () => void;
}

function toggle(list: string[], id: string): string[] {
  return list.includes(id) ? list.filter((item) => item !== id) : [...list, id];
}

export const useSelection = create<SelectionState>((set) => ({
  sourceId: null,
  alertIds: [],
  eventIds: [],
  setSourceId: (sourceId) => set({ sourceId }),
  toggleAlert: (id) => set((state) => ({ alertIds: toggle(state.alertIds, id) })),
  toggleEvent: (id) => set((state) => ({ eventIds: toggle(state.eventIds, id) })),
  clearPicks: () => set({ alertIds: [], eventIds: [] }),
}));
