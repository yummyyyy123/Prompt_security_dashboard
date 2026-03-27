'use client'

import { useState } from 'react'
import { Search, Filter, X, ChevronDown } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import * as Select from '@radix-ui/react-select'
import * as Tabs from '@radix-ui/react-tabs'

interface AdvancedSearchProps {
  searchQuery: string
  onSearchChange: (query: string) => void
  selectedCategory: string
  onCategoryChange: (category: string) => void
  categories: string[]
  tags: string[]
  selectedTags: string[]
  onTagsChange: (tags: string[]) => void
  sortBy: string
  onSortChange: (sort: string) => void
}

export const AdvancedSearch: React.FC<AdvancedSearchProps> = ({
  searchQuery,
  onSearchChange,
  selectedCategory,
  onCategoryChange,
  categories,
  tags,
  selectedTags,
  onTagsChange,
  sortBy,
  onSortChange
}) => {
  const [showFilters, setShowFilters] = useState(false)

  const handleTagToggle = (tag: string) => {
    const newTags = selectedTags.includes(tag)
      ? selectedTags.filter(t => t !== tag)
      : [...selectedTags, tag]
    onTagsChange(newTags)
  }

  const clearFilters = () => {
    onSearchChange('')
    onCategoryChange('All')
    onTagsChange([])
    onSortChange('relevance')
  }

  const hasActiveFilters = searchQuery || selectedCategory !== 'All' || selectedTags.length > 0

  return (
    <div className="space-y-4">
      {/* Main Search Bar */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
        <input
          type="text"
          placeholder="Search prompts by title, description, or tags..."
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          className="w-full pl-10 pr-12 py-3 border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:ring-2 focus:ring-emerald-500 focus:border-transparent transition-all duration-200"
        />
        {searchQuery && (
          <button
            onClick={() => onSearchChange('')}
            className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Filter Controls */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <motion.button
            onClick={() => setShowFilters(!showFilters)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg border transition-colors ${
              showFilters || hasActiveFilters
                ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-300'
                : 'border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-700 dark:text-gray-300'
            }`}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <Filter className="w-4 h-4" />
            Filters
            {hasActiveFilters && (
              <span className="w-2 h-2 bg-emerald-500 rounded-full" />
            )}
            <ChevronDown 
              className={`w-4 h-4 transition-transform ${showFilters ? 'rotate-180' : ''}`} 
            />
          </motion.button>

          {hasActiveFilters && (
            <motion.button
              onClick={clearFilters}
              className="text-sm text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 transition-colors"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              Clear all
            </motion.button>
          )}
        </div>

        {/* Sort Dropdown */}
        <Select.Root value={sortBy} onValueChange={onSortChange}>
          <Select.Trigger className="flex items-center gap-2 px-3 py-2 text-sm border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-900 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors">
            <Select.Value />
            <Select.Icon>
              <ChevronDown className="w-4 h-4" />
            </Select.Icon>
          </Select.Trigger>
          
          <Select.Portal>
            <Select.Content className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg shadow-lg p-1 z-50">
              <Select.Item value="relevance" className="px-3 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 rounded cursor-pointer">
                <Select.ItemText>Relevance</Select.ItemText>
              </Select.Item>
              <Select.Item value="newest" className="px-3 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 rounded cursor-pointer">
                <Select.ItemText>Newest First</Select.ItemText>
              </Select.Item>
              <Select.Item value="oldest" className="px-3 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 rounded cursor-pointer">
                <Select.ItemText>Oldest First</Select.ItemText>
              </Select.Item>
              <Select.Item value="popular" className="px-3 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 rounded cursor-pointer">
                <Select.ItemText>Most Popular</Select.ItemText>
              </Select.Item>
            </Select.Content>
          </Select.Portal>
        </Select.Root>
      </div>

      {/* Expandable Filters */}
      <AnimatePresence>
        {showFilters && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="overflow-hidden"
          >
            <div className="p-4 bg-gray-50 dark:bg-gray-800/50 rounded-lg border border-gray-200 dark:border-gray-700">
              <Tabs.Root defaultValue="category" className="w-full">
                <Tabs.List className="flex gap-1 mb-4 bg-gray-100 dark:bg-gray-800 p-1 rounded-lg">
                  <Tabs.Trigger value="category" className="flex-1 px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 rounded-md data-[state=active]:bg-white data-[state=active]:dark:bg-gray-700 data-[state=active]:shadow-sm transition-colors">
                    Category
                  </Tabs.Trigger>
                  <Tabs.Trigger value="tags" className="flex-1 px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 rounded-md data-[state=active]:bg-white data-[state=active]:dark:bg-gray-700 data-[state=active]:shadow-sm transition-colors">
                    Tags
                  </Tabs.Trigger>
                </Tabs.List>

                <Tabs.Content value="category" className="space-y-3">
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                    {categories.map((category) => (
                      <motion.button
                        key={category}
                        onClick={() => onCategoryChange(category)}
                        className={`px-3 py-2 text-sm rounded-lg border transition-colors ${
                          selectedCategory === category
                            ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-300'
                            : 'border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800'
                        }`}
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                      >
                        {category}
                      </motion.button>
                    ))}
                  </div>
                </Tabs.Content>

                <Tabs.Content value="tags" className="space-y-3">
                  <div className="flex flex-wrap gap-2">
                    {tags.map((tag) => (
                      <motion.button
                        key={tag}
                        onClick={() => handleTagToggle(tag)}
                        className={`px-3 py-1.5 text-sm rounded-full border transition-colors ${
                          selectedTags.includes(tag)
                            ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-300'
                            : 'border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800'
                        }`}
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                      >
                        #{tag}
                      </motion.button>
                    ))}
                  </div>
                </Tabs.Content>
              </Tabs.Root>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
