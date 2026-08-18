import { cn } from '@/lib/utils'
import { Search, RotateCcw, ChevronDown, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Download, SlidersHorizontal, RefreshCw, X } from 'lucide-react'
import { fetchUpstreamIdentities, resolvePendingUpstreamIdentities } from '@/lib/api'
import type { Upstream, UpstreamIdentity, IdentitySourceStatus, LogFilter } from '@/lib/api'
import { Suspense, lazy, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table"
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "@/components/ui/tooltip"

interface LogFiltersProps {
    filter: LogFilter
    onSearch: (filter: LogFilter) => void
    onExport?: (filter: LogFilter) => void
    upstreams: Upstream[]
    total: number
    loading?: boolean
    identityAuditEnabled: boolean
    onIdentityResolutionComplete?: () => void
}

const DEFAULT_FILTER: LogFilter = { limit: 20, offset: 0 }
const IDENTITY_PAGE_SIZE = 5

const DateRangePicker = lazy(async () => {
    const module = await import('./DateRangePicker')
    return { default: module.DateRangePicker }
})

function DateRangePickerFallback() {
    return (
        <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:items-center">
            <div className="h-8 rounded-md border border-border bg-background sm:min-w-[170px]" />
            <span className="hidden text-muted-foreground/30 text-sm font-medium mx-1 sm:inline">/</span>
            <div className="h-8 rounded-md border border-border bg-background sm:min-w-[170px]" />
        </div>
    )
}

export function LogFilters({
    filter,
    onSearch,
    onExport,
    upstreams,
    total,
    loading,
    identityAuditEnabled,
    onIdentityResolutionComplete,
}: LogFiltersProps) {
    const { t } = useTranslation()
    const [identityOptions, setIdentityOptions] = useState<UpstreamIdentity[]>([])
    const [identitySources, setIdentitySources] = useState<IdentitySourceStatus[]>([])
    const [identityQuery, setIdentityQuery] = useState('')
    const [identityPage, setIdentityPage] = useState(1)
    const [identityTotal, setIdentityTotal] = useState(0)
    const [identityLoading, setIdentityLoading] = useState(false)
    const [identityError, setIdentityError] = useState('')
    const [selectedIdentity, setSelectedIdentity] = useState<UpstreamIdentity | null>(null)
    const [identityOpen, setIdentityOpen] = useState(false)
    const [resolutionRequesting, setResolutionRequesting] = useState(false)
    const resolutionWasActive = useRef(false)
    const identityPickerRef = useRef<HTMLDivElement>(null)

    // 本地暂存的筛选条件（不触发查询）
    const [draftState, setDraftState] = useState(() => ({
        source: filter,
        draft: { ...filter },
    }))
    let currentDraftState = draftState
    if (draftState.source !== filter) {
        const nextDraftState = {
            source: filter,
            draft: { ...filter },
        }
        setDraftState(nextDraftState)
        currentDraftState = nextDraftState
    }
    const draft = currentDraftState.draft
    const setDraft = (nextDraft: LogFilter) => {
        setDraftState((current) => ({
            ...current,
            draft: nextDraft,
        }))
    }

    const identityUpstream = identityAuditEnabled ? (draft.upstream?.trim() || '') : ''
    const identityOffset = (identityPage - 1) * IDENTITY_PAGE_SIZE
    const identityTotalPages = Math.max(1, Math.ceil(identityTotal / IDENTITY_PAGE_SIZE))

    useEffect(() => {
        if (!identityOpen) return
        const closeOnOutsideClick = (event: PointerEvent) => {
            if (!identityPickerRef.current?.contains(event.target as Node)) setIdentityOpen(false)
        }
        const closeOnEscape = (event: KeyboardEvent) => {
            if (event.key === 'Escape') setIdentityOpen(false)
        }
        document.addEventListener('pointerdown', closeOnOutsideClick)
        document.addEventListener('keydown', closeOnEscape)
        return () => {
            document.removeEventListener('pointerdown', closeOnOutsideClick)
            document.removeEventListener('keydown', closeOnEscape)
        }
    }, [identityOpen])

    useEffect(() => {
        if (!identityUpstream) {
            setIdentityOpen(false)
            setIdentityOptions([])
            setIdentitySources([])
            setIdentityTotal(0)
            setIdentityLoading(false)
            setIdentityError('')
            return
        }
        const controller = new AbortController()
        const timer = window.setTimeout(() => {
            setIdentityLoading(true)
            setIdentityError('')
            fetchUpstreamIdentities({
                upstream: identityUpstream,
                query: identityQuery.trim(),
                offset: identityOffset,
                limit: IDENTITY_PAGE_SIZE,
            })
                .then(response => {
                    if (!controller.signal.aborted) {
                        setIdentityOptions(response.items || [])
                        setIdentitySources(response.sources || [])
                        setIdentityTotal(response.total || 0)
                        const lastPage = Math.max(1, Math.ceil((response.total || 0) / IDENTITY_PAGE_SIZE))
                        if (identityPage > lastPage) setIdentityPage(lastPage)
                    }
                })
                .catch((error: unknown) => {
                    if (!controller.signal.aborted) {
                        setIdentityOptions([])
                        setIdentitySources([])
                        setIdentityTotal(0)
                        setIdentityError(error instanceof Error ? error.message : t('filters.identity_load_failed'))
                    }
                })
                .finally(() => {
                    if (!controller.signal.aborted) setIdentityLoading(false)
                })
        }, 250)
        return () => {
            controller.abort()
            window.clearTimeout(timer)
        }
    }, [identityAuditEnabled, identityOffset, identityPage, identityQuery, identityUpstream, t])

    // 提交查询
    const handleSearch = () => {
        onSearch({ ...draft, offset: 0 })
    }

    // 重置所有条件并立即触发查询
    const handleReset = () => {
        const resetFilter = { ...DEFAULT_FILTER }
        setIdentityQuery('')
        setIdentityPage(1)
        setIdentityTotal(0)
        setSelectedIdentity(null)
        setIdentityOpen(false)
        setDraft(resetFilter)
        onSearch(resetFilter)
    }

    const handleExport = () => {
        onExport?.({ ...draft, offset: 0 })
    }

    // 分页计算
    const pageSize = filter.limit || 50
    const currentPage = Math.floor((filter.offset || 0) / pageSize) + 1
    const totalPages = Math.max(1, Math.ceil(total / pageSize))
    const [pageDraft, setPageDraft] = useState(String(currentPage))

    useEffect(() => {
        setPageDraft(String(currentPage))
    }, [currentPage])

    const goToPage = (page: number) => {
        const nextPage = Math.min(totalPages, Math.max(1, page))
        onSearch({ ...filter, offset: (nextPage - 1) * pageSize })
    }

    const commitPageDraft = () => {
        const parsed = Number.parseInt(pageDraft, 10)
        if (!Number.isFinite(parsed)) {
            setPageDraft(String(currentPage))
            return
        }
        goToPage(parsed)
    }

    // 检查各个字段是否有未提交的更改
    const isPathChanged = (draft.path || '') !== (filter.path || '')
    const isUpstreamChanged = (draft.upstream || '') !== (filter.upstream || '')
    const isMethodChanged = (draft.method || '') !== (filter.method || '')
    const isStatusCodeChanged = (draft.status_code || 0) !== (filter.status_code || 0)
    const isTraceIdChanged = (draft.trace_id || '') !== (filter.trace_id || '')
    const isTagChanged = (draft.tag || '') !== (filter.tag || '')
    const isSavedChanged = (draft.saved ?? undefined) !== (filter.saved ?? undefined)
    const isAnnotationStatusChanged = (draft.annotation_status || '') !== (filter.annotation_status || '')
    const isAnnotationLabelChanged = (draft.annotation_label || '') !== (filter.annotation_label || '')
    const isIdentityChanged = (draft.identity_id || '') !== (filter.identity_id || '') ||
        (draft.identity_upstream || '') !== (filter.identity_upstream || '') ||
        (draft.identity_target || '') !== (filter.identity_target || '')
    const isTimeChanged = (draft.start_time || '') !== (filter.start_time || '') ||
        (draft.end_time || '') !== (filter.end_time || '')
    const hasChanges = isPathChanged || isUpstreamChanged || isMethodChanged || isStatusCodeChanged || isTraceIdChanged || isTagChanged ||
        isSavedChanged || isAnnotationStatusChanged || isAnnotationLabelChanged || isIdentityChanged || isTimeChanged

    const requestedIdentityUpstream = draft.identity_upstream || draft.upstream || ''
    const requestedIdentityTarget = draft.identity_target || ''
    const resolutionCandidates = identitySources.filter(source =>
        (!requestedIdentityUpstream || source.upstream === requestedIdentityUpstream) &&
        (!requestedIdentityTarget || source.target === requestedIdentityTarget),
    )
    const resolutionSource = resolutionCandidates.length === 1 ? resolutionCandidates[0] : undefined
    const resolutionActive = Boolean(resolutionSource?.resolution_queued || resolutionSource?.resolving_logs)

    useEffect(() => {
        if (!resolutionActive || !identityUpstream) return
        const timer = window.setInterval(() => {
            fetchUpstreamIdentities({
                upstream: identityUpstream,
                query: identityQuery.trim(),
                offset: identityOffset,
                limit: IDENTITY_PAGE_SIZE,
            })
                .then(response => {
                    setIdentityOptions(response.items || [])
                    setIdentitySources(response.sources || [])
                    setIdentityTotal(response.total || 0)
                })
                .catch(() => undefined)
        }, 1000)
        return () => window.clearInterval(timer)
    }, [identityOffset, identityQuery, identityUpstream, resolutionActive])

    useEffect(() => {
        if (resolutionWasActive.current && !resolutionActive && resolutionSource?.last_resolution_at) {
            if (resolutionSource.resolution_error) {
                toast.error(t('filters.identity_resolution_failed', { error: resolutionSource.resolution_error }))
            } else {
                toast.success(t('filters.identity_resolution_complete', {
                    resolved: resolutionSource.resolved_logs,
                    unmatched: resolutionSource.unmatched_logs,
                }))
                onIdentityResolutionComplete?.()
            }
        }
        resolutionWasActive.current = resolutionActive
    }, [onIdentityResolutionComplete, resolutionActive, resolutionSource, t])

    const handleResolvePendingIdentities = async () => {
        if (!resolutionSource) {
            setShowAdvanced(true)
            toast.info(t('filters.identity_resolution_select_source'))
            return
        }
        setResolutionRequesting(true)
        try {
            const status = await resolvePendingUpstreamIdentities(resolutionSource.upstream, resolutionSource.target)
            setIdentitySources(current => current.map(source =>
                source.upstream === status.upstream && source.target === status.target ? status : source,
            ))
            toast.success(t('filters.identity_resolution_queued'))
        } catch (error) {
            toast.error(error instanceof Error ? error.message : t('filters.identity_resolution_failed', { error: '' }))
        } finally {
            setResolutionRequesting(false)
        }
    }

    const resolutionTooltip = !resolutionSource
        ? t('filters.identity_resolution_select_source')
        : resolutionActive
            ? t('filters.identity_resolution_running')
            : resolutionSource.last_resolution_at
                ? t('filters.identity_resolution_summary', {
                    resolved: resolutionSource.resolved_logs,
                    unmatched: resolutionSource.unmatched_logs,
                })
                : t('filters.identity_resolution_action')

    // 次级筛选默认收起,但只要有生效的条件就展开,避免"筛了却看不见"
    const activeAdvancedCount = [
        draft.upstream, draft.method, draft.status_code, draft.tag,
        draft.saved, draft.annotation_status, draft.annotation_label,
        identityAuditEnabled ? draft.identity_id : undefined,
    ].filter(value => value !== undefined && value !== '').length
    const [showAdvanced, setShowAdvanced] = useState(activeAdvancedCount > 0)

    return (
        <div className="flex flex-col gap-2 px-0 py-2 sm:px-4 sm:pr-6">
            {/* 工具条：搜索 + 时间 + 筛选开关 + 操作 */}
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                <div className="relative flex-1 group">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground/75 transition-colors group-focus-within:text-primary" />
                    <Input
                        placeholder={t('filters.search_path')}
                        value={draft.path || ''}
                        onChange={(e) => setDraft({ ...draft, path: e.target.value })}
                        onKeyDown={(e) => {
                            if (e.key === 'Enter') handleSearch()
                        }}
                        className={cn(
                            "h-8 pl-9 border border-input bg-background transition-all hover:bg-accent focus-visible:bg-background",
                            isPathChanged && "border-primary/50 ring-1 ring-primary/20"
                        )}
                    />
                </div>

                <div className={cn(
                    "w-full sm:w-auto rounded-md transition-all",
                    isTimeChanged && "ring-1 ring-primary/20"
                )}>
                    <Suspense fallback={<DateRangePickerFallback />}>
                        <DateRangePicker
                            value={{ startTime: draft.start_time, endTime: draft.end_time }}
                            onChange={({ startTime, endTime }) => {
                                setDraft({ ...draft, start_time: startTime, end_time: endTime })
                            }}
                        />
                    </Suspense>
                </div>

                <button
                    type="button"
                    onClick={() => setShowAdvanced(value => !value)}
                    className={cn(
                        'flex h-8 shrink-0 items-center gap-1.5 rounded-md border border-input px-2.5 text-xs transition-colors hover:bg-accent',
                        activeAdvancedCount > 0 ? 'text-foreground' : 'text-muted-foreground',
                    )}
                >
                    <SlidersHorizontal className="h-3.5 w-3.5" />
                    <span>{t('filters.advanced')}</span>
                    {activeAdvancedCount > 0 && (
                        <span className="rounded-sm bg-primary/10 px-1 font-mono text-primary">{activeAdvancedCount}</span>
                    )}
                    <ChevronDown className={cn('h-3.5 w-3.5 transition-transform', showAdvanced && 'rotate-180')} />
                </button>

                <div className="flex shrink-0 items-center gap-1.5">
                    <TooltipProvider delayDuration={200}>
                        <Tooltip>
                            <TooltipTrigger asChild>
                                <Button
                                    variant={hasChanges ? 'default' : 'outline'}
                                    size="icon"
                                    onClick={handleSearch}
                                    disabled={loading}
                                    className={cn(
                                        'h-8 w-8 shrink-0',
                                        // 实心强调色只在有未提交筛选时出现,让这块颜色代表"有东西待应用"
                                        !hasChanges && 'border border-input bg-background text-muted-foreground hover:bg-accent hover:text-foreground',
                                    )}
                                >
                                    <Search className={cn('h-4 w-4', loading && 'animate-spin')} />
                                </Button>
                            </TooltipTrigger>
                            <TooltipContent>
                                <p>{t('filters.search')}</p>
                            </TooltipContent>
                        </Tooltip>

                        {onExport && (
                            <Tooltip>
                                <TooltipTrigger asChild>
                                    <Button
                                        variant="outline"
                                        size="icon"
                                        onClick={handleExport}
                                        className="h-8 w-8 shrink-0 border border-input bg-background text-muted-foreground hover:bg-accent hover:text-foreground"
                                    >
                                        <Download className="h-4 w-4" />
                                    </Button>
                                </TooltipTrigger>
                                <TooltipContent>
                                    <p>{t('filters.export_jsonl')}</p>
                                </TooltipContent>
                            </Tooltip>
                        )}

                        {identityAuditEnabled && <Tooltip>
                            <TooltipTrigger asChild>
                                <Button
                                    type="button"
                                    variant="outline"
                                    size="icon"
                                    className="h-8 w-8 shrink-0 border border-input bg-background text-muted-foreground hover:bg-accent hover:text-foreground"
                                    disabled={!resolutionSource || resolutionRequesting || resolutionActive}
                                    onClick={handleResolvePendingIdentities}
                                    aria-label={t('filters.identity_resolution_action')}
                                >
                                    <RefreshCw className={cn('h-4 w-4', (resolutionRequesting || resolutionActive) && 'animate-spin')} />
                                </Button>
                            </TooltipTrigger>
                            <TooltipContent><p>{resolutionTooltip}</p></TooltipContent>
                        </Tooltip>}

                        <Tooltip>
                            <TooltipTrigger asChild>
                                <Button
                                    variant="outline"
                                    size="icon"
                                    onClick={handleReset}
                                    className="h-8 w-8 shrink-0 border border-input bg-background text-muted-foreground hover:bg-accent hover:text-foreground"
                                >
                                    <RotateCcw className="h-4 w-4" />
                                </Button>
                            </TooltipTrigger>
                            <TooltipContent>
                                <p>{t('filters.reset')}</p>
                            </TooltipContent>
                        </Tooltip>
                    </TooltipProvider>
                </div>
            </div>

            {showAdvanced && (
                <>
                <div className="grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-7">
                    <Select
                        value={draft.upstream || "all"}
                        onValueChange={(val) => {
                            const upstream = val === "all" ? "" : val
                            setIdentityQuery('')
                            setIdentityPage(1)
                            setIdentityTotal(0)
                            setSelectedIdentity(null)
                            setIdentityOpen(false)
                            setDraft({
                                ...draft,
                                upstream,
                                identity_id: undefined,
                                identity_upstream: undefined,
                                identity_target: undefined,
                            })
                        }}
                    >
                        <SelectTrigger className={cn(
                            "w-full h-8 bg-background border border-input hover:bg-accent",
                            isUpstreamChanged && "border-primary/50 ring-1 ring-primary/20"
                        )}>
                            <SelectValue placeholder={t('filters.all_upstreams')} />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="all">{t('filters.all_upstreams')}</SelectItem>
                            {upstreams.map((up) => (
                                <SelectItem key={up.name} value={up.name} className="font-semibold text-xs">
                                    {up.name}
                                </SelectItem>
                            ))}
                        </SelectContent>
                    </Select>

                    {identityAuditEnabled && <div ref={identityPickerRef} className="relative min-w-0">
                        <div className="relative">
                            <button
                                type="button"
                                disabled={!identityUpstream}
                                onClick={() => setIdentityOpen(open => !open)}
                                className={cn(
                                    'flex h-8 w-full items-center justify-between gap-2 rounded-md border border-input bg-background px-3 text-left text-xs transition-colors hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50',
                                    isIdentityChanged && 'border-primary/50 ring-1 ring-primary/20',
                                )}
                            >
                                <span className={cn('truncate', !draft.identity_id && 'text-muted-foreground')}>
                                    {draft.identity_id
                                        ? `${selectedIdentity?.username || selectedIdentity?.email || draft.identity_id} (#${draft.identity_id})`
                                        : identityUpstream
                                            ? t('filters.identity_select_placeholder')
                                            : t('filters.identity_select_upstream_short')}
                                </span>
                                <ChevronDown className={cn('h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform', identityOpen && 'rotate-180')} />
                            </button>
                            {draft.identity_id && (
                                <button
                                    type="button"
                                    className="absolute right-7 top-1/2 -translate-y-1/2 rounded-sm bg-background p-0.5 text-muted-foreground hover:text-foreground"
                                    onClick={(event) => {
                                        event.stopPropagation()
                                        setSelectedIdentity(null)
                                        setDraft({
                                            ...draft,
                                            identity_id: undefined,
                                            identity_upstream: undefined,
                                            identity_target: undefined,
                                        })
                                    }}
                                    aria-label={t('filters.identity_clear')}
                                >
                                    <X className="h-3 w-3" />
                                </button>
                            )}
                        </div>

                        {identityOpen && identityUpstream && (
                            <div className="absolute right-0 top-full z-[70] mt-1 w-[min(640px,calc(100vw-24px))] overflow-hidden border border-border bg-popover text-popover-foreground shadow-lg sm:left-0 sm:right-auto">
                                <div className="flex items-center gap-2 border-b border-border p-2">
                                    <div className="relative min-w-0 flex-1">
                                        <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                                        <Input
                                            autoFocus
                                            value={identityQuery}
                                            placeholder={t('filters.identity_search_placeholder')}
                                            onChange={(event) => {
                                                setIdentityQuery(event.target.value)
                                                setIdentityPage(1)
                                            }}
                                            className="h-7 w-full border border-input bg-background pl-8 text-xs"
                                        />
                                    </div>
                                    <span className="shrink-0 text-xs text-muted-foreground">
                                        {t('filters.identity_total', { count: identityTotal })}
                                    </span>
                                </div>

                                <div className="max-h-[236px] overflow-auto">
                                    <Table className="min-w-[600px] table-fixed">
                                        <TableHeader className="sticky top-0 z-10 bg-muted">
                                            <TableRow>
                                                <TableHead className="w-[140px]">{t('filters.identity_source')}</TableHead>
                                                <TableHead className="w-[110px]">{t('filters.identity_user_id')}</TableHead>
                                                <TableHead>{t('filters.identity_email')}</TableHead>
                                                <TableHead className="w-[140px]">{t('filters.identity_username')}</TableHead>
                                            </TableRow>
                                        </TableHeader>
                                        <TableBody>
                                            {identityLoading ? (
                                                <TableRow>
                                                    <TableCell colSpan={4} className="h-20 text-center text-xs text-muted-foreground">
                                                        {t('filters.identity_loading')}
                                                    </TableCell>
                                                </TableRow>
                                            ) : identityError ? (
                                                <TableRow>
                                                    <TableCell colSpan={4} className="h-20 text-center text-xs text-destructive">
                                                        {identityError}
                                                    </TableCell>
                                                </TableRow>
                                            ) : identityOptions.length === 0 ? (
                                                <TableRow>
                                                    <TableCell colSpan={4} className="h-20 text-center text-xs text-muted-foreground">
                                                        {identityQuery.trim() ? t('filters.identity_no_results') : t('filters.identity_directory_empty')}
                                                    </TableCell>
                                                </TableRow>
                                            ) : identityOptions.map(identity => {
                                                const selected = draft.identity_id === identity.id &&
                                                    draft.identity_upstream === identity.upstream &&
                                                    (draft.identity_target || '') === (identity.target || '')
                                                const selectIdentity = () => {
                                                    setSelectedIdentity(identity)
                                                    setDraft({
                                                        ...draft,
                                                        identity_id: identity.id,
                                                        identity_upstream: identity.upstream,
                                                        identity_target: identity.target || undefined,
                                                    })
                                                    setIdentityOpen(false)
                                                }
                                                return (
                                                    <TableRow
                                                        key={`${identity.upstream}\u0000${identity.target}\u0000${identity.id}`}
                                                        data-state={selected ? 'selected' : undefined}
                                                        className="cursor-pointer text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary"
                                                        role="button"
                                                        tabIndex={0}
                                                        onClick={selectIdentity}
                                                        onKeyDown={event => {
                                                            if (event.key === 'Enter' || event.key === ' ') {
                                                                event.preventDefault()
                                                                selectIdentity()
                                                            }
                                                        }}
                                                    >
                                                        <TableCell className="truncate font-medium" title={identity.target ? `${identity.upstream} / ${identity.target}` : identity.upstream}>
                                                            {identity.upstream}
                                                            {identity.target && <span className="text-muted-foreground"> / {identity.target}</span>}
                                                        </TableCell>
                                                        <TableCell className="truncate font-mono" title={identity.id}>{identity.id}</TableCell>
                                                        <TableCell className="truncate" title={identity.email || ''}>{identity.email || '-'}</TableCell>
                                                        <TableCell className="truncate" title={identity.username || ''}>{identity.username || '-'}</TableCell>
                                                    </TableRow>
                                                )
                                            })}
                                        </TableBody>
                                    </Table>
                                </div>

                                <div className="flex items-center justify-between border-t border-border px-2 py-1.5">
                                    <span className="font-mono text-xs text-muted-foreground">{identityPage} / {identityTotalPages}</span>
                                    <div className="flex items-center gap-1">
                                        <Button type="button" variant="outline" size="icon" className="h-6 w-6" disabled={identityLoading || identityPage <= 1} onClick={() => setIdentityPage(1)} aria-label={t('filters.first_page')}>
                                            <ChevronsLeft className="h-3 w-3" />
                                        </Button>
                                        <Button type="button" variant="outline" size="icon" className="h-6 w-6" disabled={identityLoading || identityPage <= 1} onClick={() => setIdentityPage(page => Math.max(1, page - 1))}>
                                            <ChevronLeft className="h-3 w-3" />
                                        </Button>
                                        <Button type="button" variant="outline" size="icon" className="h-6 w-6" disabled={identityLoading || identityPage >= identityTotalPages} onClick={() => setIdentityPage(page => Math.min(identityTotalPages, page + 1))}>
                                            <ChevronRight className="h-3 w-3" />
                                        </Button>
                                        <Button type="button" variant="outline" size="icon" className="h-6 w-6" disabled={identityLoading || identityPage >= identityTotalPages} onClick={() => setIdentityPage(identityTotalPages)} aria-label={t('filters.last_page')}>
                                            <ChevronsRight className="h-3 w-3" />
                                        </Button>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>}

                    <Select
                        value={draft.method || "all"}
                        onValueChange={(val) => setDraft({ ...draft, method: val === "all" ? "" : val })}
                    >
                        <SelectTrigger className={cn(
                            "w-full h-8 bg-background border border-input hover:bg-accent",
                            isMethodChanged && "border-primary/50 ring-1 ring-primary/20"
                        )}>
                            <SelectValue placeholder={t('filters.all_methods')} />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="all">{t('filters.all_methods')}</SelectItem>
                            {["GET", "POST", "PUT", "DELETE", "PATCH"].map((m) => (
                                <SelectItem key={m} value={m}>{m}</SelectItem>
                            ))}
                        </SelectContent>
                    </Select>

                    <Input
                        type="text"
                        placeholder={t('filters.status_code')}
                        value={draft.status_code || ''}
                        onChange={(e) => {
                            const val = e.target.value.replace(/\D/g, '').slice(0, 3)
                            setDraft({ ...draft, status_code: val ? Number(val) : undefined })
                        }}
                        onKeyDown={(e) => {
                            if (e.key === 'Enter') handleSearch()
                        }}
                        className={cn(
                            "w-full h-8 border border-input bg-background transition-all hover:bg-accent focus-visible:bg-background",
                            isStatusCodeChanged && "border-primary/50 ring-1 ring-primary/20"
                        )}
                    />

                    <Input
                        placeholder={t('filters.tag_placeholder')}
                        value={draft.tag || ''}
                        onChange={(e) => setDraft({ ...draft, tag: e.target.value })}
                        onKeyDown={(e) => {
                            if (e.key === 'Enter') handleSearch()
                        }}
                        className={cn(
                            "w-full h-8 border border-input bg-background transition-all hover:bg-accent focus-visible:bg-background",
                            isTagChanged && "border-primary/50 ring-1 ring-primary/20"
                        )}
                    />

                    <Select
                        value={draft.saved === true ? 'saved' : draft.saved === false ? 'unsaved' : 'all'}
                        onValueChange={(val) => setDraft({
                            ...draft,
                            saved: val === 'all' ? undefined : val === 'saved',
                        })}
                    >
                        <SelectTrigger className={cn(
                            "w-full h-8 bg-background border border-input hover:bg-accent",
                            isSavedChanged && "border-primary/50 ring-1 ring-primary/20"
                        )}>
                            <SelectValue placeholder={t('filters.saved_all')} />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="all">{t('filters.saved_all')}</SelectItem>
                            <SelectItem value="saved">{t('filters.saved_only')}</SelectItem>
                            <SelectItem value="unsaved">{t('filters.unsaved_only')}</SelectItem>
                        </SelectContent>
                    </Select>

                    <Select
                        value={draft.annotation_status || 'all'}
                        onValueChange={(val) => setDraft({ ...draft, annotation_status: val === 'all' ? undefined : val as LogFilter['annotation_status'] })}
                    >
                        <SelectTrigger className={cn(
                            "w-full h-8 bg-background border border-input hover:bg-accent",
                            isAnnotationStatusChanged && "border-primary/50 ring-1 ring-primary/20"
                        )}>
                            <SelectValue placeholder={t('filters.annotation_status')} />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="all">{t('filters.annotation_status')}</SelectItem>
                            <SelectItem value="todo">{t('log_annotation.todo')}</SelectItem>
                            <SelectItem value="done">{t('log_annotation.done')}</SelectItem>
                        </SelectContent>
                    </Select>

                    <Input
                        placeholder={t('filters.annotation_label_placeholder')}
                        value={draft.annotation_label || ''}
                        onChange={(e) => setDraft({ ...draft, annotation_label: e.target.value })}
                        onKeyDown={(e) => {
                            if (e.key === 'Enter') handleSearch()
                        }}
                        className={cn(
                            "w-full h-8 border border-input bg-background transition-all hover:bg-accent focus-visible:bg-background",
                            isAnnotationLabelChanged && "border-primary/50 ring-1 ring-primary/20"
                        )}
                    />
                </div>
                </>
            )}

            {/* 分页 */}
            <div className="flex flex-col gap-3 border-t border-border pt-4 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-2">
                    <span className="text-xs font-medium text-muted-foreground/60">
                        {t('filters.total_count', { count: total })}
                    </span>
                    {total > 0 && (
                        <Badge variant="outline" className="text-xs border-border bg-background text-muted-foreground/75">
                            {t('filters.per_page', { count: pageSize })}
                        </Badge>
                    )}
                </div>

                <div className="flex w-full items-center justify-between gap-2 sm:w-auto sm:justify-end">
                    <Button
                        variant="outline"
                        size="icon"
                        className="h-8 w-8 rounded-md border border-border bg-background hover:bg-accent hover:text-accent-foreground transition-all"
                        onClick={() => goToPage(1)}
                        disabled={currentPage <= 1}
                        aria-label={t('filters.first_page')}
                    >
                        <ChevronsLeft className="h-4 w-4" />
                    </Button>
                    <Button
                        variant="outline"
                        size="icon"
                        className="h-8 w-8 rounded-md border border-border bg-background hover:bg-accent hover:text-accent-foreground transition-all"
                        onClick={() => goToPage(currentPage - 1)}
                        disabled={currentPage <= 1}
                    >
                        <ChevronLeft className="h-4 w-4" />
                    </Button>

                    <div className="flex items-center h-8 rounded-md border border-border bg-background px-2 font-mono text-xs font-medium text-foreground/80">
                        <Input
                            value={pageDraft}
                            inputMode="numeric"
                            aria-label={t('filters.page_number')}
                            onChange={e => setPageDraft(e.target.value.replace(/\D/g, '').slice(0, 5))}
                            onBlur={commitPageDraft}
                            onKeyDown={e => {
                                if (e.key === 'Enter') {
                                    e.currentTarget.blur()
                                }
                                if (e.key === 'Escape') {
                                    setPageDraft(String(currentPage))
                                    e.currentTarget.blur()
                                }
                            }}
                            className="h-6 w-10 border-0 bg-transparent p-0 text-center font-mono text-xs font-medium text-primary shadow-none focus-visible:ring-0"
                        />
                        <span className="mx-2 text-muted-foreground/30">/</span>
                        <span>{totalPages}</span>
                    </div>

                    <Button
                        variant="outline"
                        size="icon"
                        className="h-8 w-8 rounded-md border border-border bg-background hover:bg-accent hover:text-accent-foreground transition-all"
                        onClick={() => goToPage(currentPage + 1)}
                        disabled={currentPage >= totalPages}
                    >
                        <ChevronRight className="h-4 w-4" />
                    </Button>
                    <Button
                        variant="outline"
                        size="icon"
                        className="h-8 w-8 rounded-md border border-border bg-background hover:bg-accent hover:text-accent-foreground transition-all"
                        onClick={() => goToPage(totalPages)}
                        disabled={currentPage >= totalPages}
                        aria-label={t('filters.last_page')}
                    >
                        <ChevronsRight className="h-4 w-4" />
                    </Button>
                </div>
            </div>
        </div>
    )
}

