'use client'

import { useDroppable, useDraggable } from '@dnd-kit/core'
import { SortableContext, verticalListSortingStrategy } from '@dnd-kit/sortable'
import { useSortable } from '@dnd-kit/sortable'
import { CSS } from '@dnd-kit/utilities'
import { motion } from 'framer-motion'
import { GripVertical, Star, Copy, Check } from 'lucide-react'
import { Prompt } from '@/store/promptStore'

interface DraggablePromptCardProps {
  prompt: Prompt
  index: number
  isFavorite: boolean
  onToggleFavorite: (id: string) => void
  onCopy: (prompt: string, id: string) => void
  copiedId: string | null
  onClick: (prompt: Prompt) => void
}

export const DraggablePromptCard: React.FC<DraggablePromptCardProps> = ({
  prompt,
  index,
  isFavorite,
  onToggleFavorite,
  onCopy,
  copiedId,
  onClick
}) => {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging
  } = useSortable({ id: prompt.id })

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.5 : 1
  }

  return (
    <motion.div
      ref={setNodeRef}
      style={style}
      {...attributes}
      className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-3 sm:p-6 cursor-pointer group hover:shadow-md hover:border-emerald-500 transition-all duration-200"
      onClick={() => onClick(prompt)}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: index * 0.1 }}
      whileHover={{ y: -2 }}
      layout
    >
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3 mb-3 sm:mb-4">
        <div className="flex items-center gap-2 sm:gap-3 flex-1">
          <div
            {...listeners}
            className="cursor-grab active:cursor-grabbing p-1 sm:p-1.5 rounded hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
          >
            <GripVertical className="w-3 h-3 sm:w-4 sm:h-4 text-gray-400" />
          </div>
          <div className="flex items-center gap-1 sm:gap-2">
            <span className="inline-flex items-center px-1.5 sm:px-2.5 py-0.5 sm:py-1 rounded-full text-xs font-semibold text-white bg-gradient-to-r from-emerald-500 to-teal-600">
              {prompt.category}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-1 sm:gap-2">
          <motion.button
            onClick={(e) => {
              e.stopPropagation()
              onToggleFavorite(prompt.id)
            }}
            className={`p-1.5 sm:p-2 rounded-lg transition-colors ${
              isFavorite
                ? 'bg-emerald-100 dark:bg-emerald-900/20 text-emerald-600 dark:text-emerald-400'
                : 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-emerald-100 dark:hover:bg-emerald-900/20 hover:text-emerald-600 dark:hover:text-emerald-400'
            }`}
            whileHover={{ scale: 1.1 }}
            whileTap={{ scale: 0.9 }}
          >
            <Star className={`w-3 h-3 sm:w-4 sm:h-4 ${isFavorite ? 'fill-current' : ''}`} />
          </motion.button>
          <motion.button
            onClick={(e) => {
              e.stopPropagation()
              onCopy(prompt.prompt, prompt.id)
            }}
            className="p-1.5 sm:p-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-emerald-100 dark:hover:bg-emerald-900/20 hover:text-emerald-600 dark:hover:text-emerald-400 transition-colors"
            whileHover={{ scale: 1.1 }}
            whileTap={{ scale: 0.9 }}
          >
            {copiedId === prompt.id ? (
              <Check className="w-3 h-3 sm:w-4 sm:h-4 text-emerald-600" />
            ) : (
              <Copy className="w-3 h-3 sm:w-4 sm:h-4" />
            )}
          </motion.button>
        </div>
      </div>
      
      <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white mb-2 group-hover:text-emerald-600 dark:group-hover:text-emerald-400 transition-colors line-clamp-2">
        {prompt.title}
      </h3>
      
      <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-400 line-clamp-2 sm:line-clamp-3 mb-3 sm:mb-4">
        {prompt.description}
      </p>
      
      <div className="flex flex-wrap items-center gap-1 sm:gap-2">
        {prompt.tags.slice(0, 3).map((tag, index) => (
          <span
            key={index}
            className="inline-flex items-center px-1.5 sm:px-2 py-0.5 sm:py-1 rounded-full text-xs bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400"
          >
            #{tag}
          </span>
        ))}
        {prompt.tags.length > 3 && (
          <span className="text-xs text-gray-500 dark:text-gray-400">
            +{prompt.tags.length - 3} more
          </span>
        )}
      </div>
      {prompt.usageCount && (
        <span className="text-xs text-gray-500 dark:text-gray-500">
          {prompt.usageCount} uses
        </span>
      )}
    </motion.div>
  )
}

interface DroppablePromptListProps {
  prompts: Prompt[]
  children: (prompt: Prompt, index: number) => React.ReactNode
}

export const DroppablePromptList: React.FC<DroppablePromptListProps> = ({
  prompts,
  children
}) => {
  const { setNodeRef } = useDroppable({
    id: 'prompt-list'
  })

  return (
    <div ref={setNodeRef} className="space-y-4">
      <SortableContext items={prompts.map(p => p.id)} strategy={verticalListSortingStrategy}>
        {prompts.map((prompt, index) => children(prompt, index))}
      </SortableContext>
    </div>
  )
}

interface PromptOrganizerProps {
  prompts: Prompt[]
  onReorder: (oldIndex: number, newIndex: number) => void
  isFavorite: (id: string) => boolean
  onToggleFavorite: (id: string) => void
  onCopy: (prompt: string, id: string) => void
  copiedId: string | null
  onPromptClick: (prompt: Prompt) => void
}

export const PromptOrganizer: React.FC<PromptOrganizerProps> = ({
  prompts,
  onReorder,
  isFavorite,
  onToggleFavorite,
  onCopy,
  copiedId,
  onPromptClick
}) => {
  return (
    <DroppablePromptList prompts={prompts}>
      {(prompt, index) => (
        <DraggablePromptCard
          key={prompt.id}
          prompt={prompt}
          index={index}
          isFavorite={isFavorite(prompt.id)}
          onToggleFavorite={onToggleFavorite}
          onCopy={onCopy}
          copiedId={copiedId}
          onClick={onPromptClick}
        />
      )}
    </DroppablePromptList>
  )
}
