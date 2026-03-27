import { create } from 'zustand'

export interface Prompt {
  id: string
  title: string
  description: string
  category: string
  tags: string[]
  prompt: string
  variables: string[]
  isFavorite?: boolean
  createdAt?: string
  usageCount?: number
}

interface PromptStore {
  prompts: Prompt[]
  filteredPrompts: Prompt[]
  selectedCategory: string
  searchQuery: string
  selectedPrompt: Prompt | null
  isLoading: boolean
  favorites: string[]
  recentlyUsed: string[]
  
  // Actions
  setPrompts: (prompts: Prompt[]) => void
  setSelectedCategory: (category: string) => void
  setSearchQuery: (query: string) => void
  setSelectedPrompt: (prompt: Prompt | null) => void
  setIsLoading: (loading: boolean) => void
  toggleFavorite: (id: string) => void
  addToRecentlyUsed: (id: string) => void
  filterPrompts: () => void
  addPrompt: (prompt: Prompt) => void
  updatePrompt: (id: string, updates: Partial<Prompt>) => void
  deletePrompt: (id: string) => void
}

export const usePromptStore = create<PromptStore>((set, get) => ({
  prompts: [],
  filteredPrompts: [],
  selectedCategory: 'All',
  searchQuery: '',
  selectedPrompt: null,
  isLoading: true,
  favorites: [],
  recentlyUsed: [],

  setPrompts: (prompts) => {
    set({ prompts })
    get().filterPrompts()
  },

  setSelectedCategory: (category) => {
    set({ selectedCategory: category })
    get().filterPrompts()
  },

  setSearchQuery: (query) => {
    set({ searchQuery: query })
    get().filterPrompts()
  },

  setSelectedPrompt: (prompt) => set({ selectedPrompt: prompt }),

  setIsLoading: (loading) => set({ isLoading: loading }),

  toggleFavorite: (id) => {
    const { favorites } = get()
    const newFavorites = favorites.includes(id)
      ? favorites.filter(fav => fav !== id)
      : [...favorites, id]
    
    set({ favorites: newFavorites })
    
    // Update prompt favorite status
    const { prompts } = get()
    const updatedPrompts = prompts.map(prompt =>
      prompt.id === id ? { ...prompt, isFavorite: !favorites.includes(id) } : prompt
    )
    set({ prompts: updatedPrompts })
    get().filterPrompts()
  },

  addToRecentlyUsed: (id) => {
    const { recentlyUsed } = get()
    const newRecentlyUsed = [id, ...recentlyUsed.filter(used => used !== id)].slice(0, 10)
    set({ recentlyUsed: newRecentlyUsed })
  },

  filterPrompts: () => {
    const { prompts, selectedCategory, searchQuery } = get()
    let filtered = prompts

    // Filter by category
    if (selectedCategory !== 'All') {
      filtered = filtered.filter(prompt => prompt.category === selectedCategory)
    }

    // Filter by search query
    if (searchQuery.trim() !== '') {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(prompt =>
        prompt.title.toLowerCase().includes(query) ||
        prompt.description.toLowerCase().includes(query) ||
        prompt.tags.some(tag => tag.toLowerCase().includes(query))
      )
    }

    set({ filteredPrompts: filtered })
  },

  addPrompt: (prompt) => {
    const { prompts } = get()
    const newPrompt = {
      ...prompt,
      createdAt: new Date().toISOString(),
      usageCount: 0,
      isFavorite: false
    }
    const updatedPrompts = [...prompts, newPrompt]
    set({ prompts: updatedPrompts })
    get().filterPrompts()
  },

  updatePrompt: (id, updates) => {
    const { prompts } = get()
    const updatedPrompts = prompts.map(prompt =>
      prompt.id === id ? { ...prompt, ...updates } : prompt
    )
    set({ prompts: updatedPrompts })
    get().filterPrompts()
  },

  deletePrompt: (id) => {
    const { prompts } = get()
    const updatedPrompts = prompts.filter(prompt => prompt.id !== id)
    set({ prompts: updatedPrompts })
    get().filterPrompts()
  }
}))
