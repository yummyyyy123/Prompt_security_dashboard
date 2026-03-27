'use client'

import { motion, AnimatePresence } from 'framer-motion'
import { X } from 'lucide-react'
import { ReactNode } from 'react'

interface SimpleModalProps {
  isOpen: boolean
  onClose: () => void
  title: string
  children: ReactNode
  size?: 'sm' | 'md' | 'lg' | 'xl'
}

export const SimpleModal: React.FC<SimpleModalProps> = ({
  isOpen,
  onClose,
  title,
  children,
  size = 'lg'
}) => {
  const sizeClasses = {
    sm: 'max-w-md',
    md: 'max-w-2xl',
    lg: 'max-w-4xl',
    xl: 'max-w-6xl'
  }

  if (!isOpen) return null

  return (
    <AnimatePresence>
      <motion.div
        key="modal-backdrop"
        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.2 }}
        onClick={onClose}
      />
      
      <motion.div
        key="modal-content"
        className="fixed inset-0 flex items-center justify-center p-4 z-50"
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        transition={{ duration: 0.2, ease: "easeOut" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className={`${sizeClasses[size]} w-full bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 shadow-2xl overflow-hidden max-h-[90vh] flex flex-col`}>
          <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-800 flex-shrink-0">
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
              {title}
            </h2>
            <button
              onClick={onClose}
              className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          
          <div className="flex-1 overflow-y-auto">
            {children}
          </div>
        </div>
      </motion.div>
    </AnimatePresence>
  )
}
