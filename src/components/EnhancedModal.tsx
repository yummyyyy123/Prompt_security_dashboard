'use client'

import * as Dialog from '@radix-ui/react-dialog'
import { motion, AnimatePresence } from 'framer-motion'
import { X } from 'lucide-react'
import { ReactNode } from 'react'

interface EnhancedModalProps {
  isOpen: boolean
  onClose: () => void
  title: string
  children: ReactNode
  size?: 'sm' | 'md' | 'lg' | 'xl'
}

export const EnhancedModal: React.FC<EnhancedModalProps> = ({
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

  return (
    <Dialog.Root open={isOpen} onOpenChange={onClose}>
      <Dialog.Portal>
        <Dialog.Overlay asChild>
          <motion.div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
          />
        </Dialog.Overlay>
        
        <Dialog.Content asChild>
          <div className="fixed inset-0 flex items-center justify-center p-4 z-50">
            <motion.div
              className={`${sizeClasses[size]} w-full bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 shadow-2xl overflow-hidden max-h-[90vh] flex flex-col`}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.2, ease: "easeOut" }}
            >
              <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-800 flex-shrink-0">
                <Dialog.Title className="text-xl font-semibold text-gray-900 dark:text-white">
                  {title}
                </Dialog.Title>
                <Dialog.Close asChild>
                  <motion.button
                    className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                    whileHover={{ scale: 1.1 }}
                    whileTap={{ scale: 0.9 }}
                  >
                    <X className="w-4 h-4" />
                  </motion.button>
                </Dialog.Close>
              </div>
              
              <div className="flex-1 overflow-y-auto">
                {children}
              </div>
            </motion.div>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

interface ModalTriggerProps {
  children: ReactNode
  asChild?: boolean
}

export const ModalTrigger: React.FC<ModalTriggerProps> = ({ children, asChild = false }) => {
  return (
    <Dialog.Trigger asChild={asChild}>
      {children}
    </Dialog.Trigger>
  )
}
