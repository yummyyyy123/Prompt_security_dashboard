'use client'

import { motion } from 'framer-motion'
import { ReactNode } from 'react'

interface AnimatedCardProps {
  children: ReactNode
  index: number
  onClick?: () => void
  className?: string
}

export const AnimatedCard: React.FC<AnimatedCardProps> = ({ 
  children, 
  index, 
  onClick, 
  className = '' 
}) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ 
        duration: 0.3, 
        delay: index * 0.1,
        ease: "easeOut"
      }}
      whileHover={{ 
        y: -4,
        boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)"
      }}
      whileTap={{ scale: 0.98 }}
      onClick={onClick}
      className={className}
    >
      {children}
    </motion.div>
  )
}

interface AnimatedButtonProps {
  children: ReactNode
  onClick?: () => void
  className?: string
  variant?: 'primary' | 'secondary'
}

export const AnimatedButton: React.FC<AnimatedButtonProps> = ({ 
  children, 
  onClick, 
  className = '',
  variant = 'primary'
}) => {
  return (
    <motion.button
      onClick={onClick}
      className={className}
      whileHover={{ scale: 1.05 }}
      whileTap={{ scale: 0.95 }}
      transition={{ type: "spring", stiffness: 400, damping: 17 }}
    >
      {children}
    </motion.button>
  )
}

interface AnimatedContainerProps {
  children: ReactNode
  className?: string
}

export const AnimatedContainer: React.FC<AnimatedContainerProps> = ({ 
  children, 
  className = '' 
}) => {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
      className={className}
    >
      {children}
    </motion.div>
  )
}

export const slideInVariants = {
  hidden: { opacity: 0, x: -20 },
  visible: { opacity: 1, x: 0 }
}

export const fadeInVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1 }
}

export const scaleInVariants = {
  hidden: { opacity: 0, scale: 0.9 },
  visible: { opacity: 1, scale: 1 }
}
