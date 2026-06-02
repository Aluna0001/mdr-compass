export interface WhatToLookFor {
  label: string
  question: string
}

export interface RelatedProcess {
  name: string
  legitimatePath: string
  suspiciousPath: string
}

export interface Alert {
  id: number
  name: string
  description: string
  killChain: string
  mitreId: string
  whatToLookFor: WhatToLookFor[]
  suspiciousIndicators: string[]
  relatedProcesses: RelatedProcess[]
}