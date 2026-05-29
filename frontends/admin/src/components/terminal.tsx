import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import useTerminal from "@/hooks/useTerminal"
import { sleep } from "@/lib/utils"
import { FitAddon } from "@xterm/addon-fit"
import { Terminal } from "@xterm/xterm"
import "@xterm/xterm/css/xterm.css"
import { Terminal as TerminalIcon } from "lucide-react"
import {
    JSX,
    forwardRef,
    useCallback,
    useEffect,
    useImperativeHandle,
    useRef,
    useState,
} from "react"
import { useTranslation } from "react-i18next"
import { useParams } from "react-router-dom"
import { toast } from "sonner"

import { FMCard } from "./fm"
import { Button } from "./ui/button"
import { IconButton } from "./xui/icon-button"

interface XtermProps {
    wsUrl: string
    setClose: React.Dispatch<React.SetStateAction<boolean>>
}

function keyboardEventToTerminalData(event: KeyboardEvent): string | undefined {
    if (event.defaultPrevented || event.isComposing) return undefined
    if (event.ctrlKey || event.metaKey) {
        const key = event.key.toLowerCase()
        if (event.metaKey && (key === "v" || key === "c" || key === "x")) return undefined
        if (event.ctrlKey && key === "v") return undefined
        if (key.length === 1 && key >= "a" && key <= "z") {
            return String.fromCharCode(key.charCodeAt(0) - 96)
        }
        if (key === "[") return "\x1b"
        if (key === "]") return "\x1d"
        if (key === "\\") return "\x1c"
        if (key === "^") return "\x1e"
        if (key === "_") return "\x1f"
    }

    switch (event.key) {
    case "Enter":
        return "\r"
    case "Backspace":
        return "\x7f"
    case "Tab":
        return "\t"
    case "Escape":
        return "\x1b"
    case "ArrowUp":
        return "\x1b[A"
    case "ArrowDown":
        return "\x1b[B"
    case "ArrowRight":
        return "\x1b[C"
    case "ArrowLeft":
        return "\x1b[D"
    case "Home":
        return "\x1b[H"
    case "End":
        return "\x1b[F"
    case "Delete":
        return "\x1b[3~"
    case "PageUp":
        return "\x1b[5~"
    case "PageDown":
        return "\x1b[6~"
    default:
        return event.key.length === 1 && !event.altKey ? event.key : undefined
    }
}

export const XtermComponent = forwardRef<HTMLDivElement, XtermProps & JSX.IntrinsicElements["div"]>(
    ({ wsUrl, setClose, ...props }, ref) => {
        const terminalIdRef = useRef<HTMLDivElement>(null)
        const terminalRef = useRef<Terminal | null>(null)
        const wsRef = useRef<WebSocket | null>(null)
        const pendingInputRef = useRef<(string | Uint8Array)[]>([])
        const terminalActiveRef = useRef(false)

        useImperativeHandle(ref, () => {
            return {
                ...terminalIdRef.current!,
                async requestFullscreen() {
                    await terminalIdRef.current?.requestFullscreen()
                },
            }
        }, [])

        const fitAddon = useRef(new FitAddon()).current
        const sendResize = useRef(false)

        const sendTerminalData = useCallback((data: string | Uint8Array) => {
            const ws = wsRef.current
            if (ws?.readyState === WebSocket.OPEN) {
                ws.send(data)
                return
            }

            pendingInputRef.current.push(data)
        }, [])

        const flushPendingInput = useCallback(() => {
            const ws = wsRef.current
            if (ws?.readyState !== WebSocket.OPEN) return

            const pendingInput = pendingInputRef.current.splice(0)
            for (const data of pendingInput) {
                ws.send(data)
            }
        }, [])

        const doResize = useCallback(() => {
            if (!terminalIdRef.current) return

            fitAddon.fit()

            const dimensions = fitAddon.proposeDimensions()

            if (dimensions) {
                const prefix = new Uint8Array([1])
                const resizeMessage = new TextEncoder().encode(
                    JSON.stringify({
                        Rows: dimensions.rows,
                        Cols: dimensions.cols,
                    }),
                )

                const msg = new Uint8Array(prefix.length + resizeMessage.length)
                msg.set(prefix)
                msg.set(resizeMessage, prefix.length)

                sendTerminalData(msg)
            }
        }, [fitAddon, sendTerminalData])

        const onResize = useCallback(async () => {
            if (sendResize.current) return

            sendResize.current = true
            try {
                await sleep(1500)
                doResize()
            } catch (error) {
                console.error("resize error", error)
            } finally {
                sendResize.current = false
            }
        }, [doResize])

        useEffect(() => {
            const container = terminalIdRef.current
            if (!container) return

            const terminal = new Terminal({
                cursorBlink: true,
                fontSize: 16,
            })
            const url = new URL(wsUrl, window.location.origin)
            url.protocol = url.protocol.replace("http", "ws")
            const ws = new WebSocket(url)
            ws.binaryType = "arraybuffer"

            terminalRef.current = terminal
            wsRef.current = ws

            terminal.loadAddon(fitAddon)
            terminal.open(container)
            terminal.focus()
            requestAnimationFrame(() => {
                fitAddon.fit()
                terminal.focus()
            })
            window.addEventListener("resize", onResize)

            const focusTerminal = () => {
                terminalActiveRef.current = true
                container.focus({ preventScroll: true })
                terminal.focus()
            }
            const deactivateTerminal = (event: FocusEvent) => {
                const target = event.target
                if (target instanceof Node && container.contains(target)) return

                terminalActiveRef.current = false
            }
            const shouldHandleTerminalInput = (event: Event) => {
                const target = event.target
                if (target instanceof Node && container.contains(target)) return true

                const activeElement = document.activeElement
                return (
                    terminalActiveRef.current
                    && (activeElement === null
                        || activeElement === document.body
                        || activeElement === document.documentElement)
                )
            }
            const keydownHandler = (event: KeyboardEvent) => {
                if (!shouldHandleTerminalInput(event)) return

                const data = keyboardEventToTerminalData(event)
                if (data === undefined) return

                event.preventDefault()
                event.stopPropagation()
                event.stopImmediatePropagation()
                sendTerminalData(data)
            }
            const dataDisposable = terminal.onData((data) => {
                sendTerminalData(data)
            })
            const binaryDisposable = terminal.onBinary((data) => {
                const bytes = new Uint8Array(data.length)
                for (let index = 0; index < data.length; index += 1) {
                    bytes[index] = data.charCodeAt(index) & 0xff
                }
                sendTerminalData(bytes)
            })
            const pasteHandler = (event: ClipboardEvent) => {
                if (!shouldHandleTerminalInput(event)) return

                const text = event.clipboardData?.getData("text/plain")
                if (!text) return

                event.preventDefault()
                event.stopPropagation()
                event.stopImmediatePropagation()
                sendTerminalData(text.replace(/\r?\n/g, "\r"))
                terminal.focus()
            }
            focusTerminal()
            container.addEventListener("pointerdown", focusTerminal)
            window.addEventListener("focusin", deactivateTerminal)
            window.addEventListener("keydown", keydownHandler, true)
            window.addEventListener("paste", pasteHandler, true)

            ws.onmessage = async (event) => {
                const data = event.data
                if (typeof data === "string") {
                    terminal.write(data)
                    return
                }

                if (data instanceof ArrayBuffer) {
                    terminal.write(new Uint8Array(data))
                    return
                }

                if (data instanceof Blob) {
                    terminal.write(new Uint8Array(await data.arrayBuffer()))
                }
            }
            ws.onopen = () => {
                flushPendingInput()
                terminal.focus()
                onResize()
            }
            ws.onclose = () => {
                terminal.dispose()
                setClose(true)
            }
            ws.onerror = (e) => {
                console.error(e)
                toast("Websocket error", {
                    description: "View console for details.",
                })
            }

            return () => {
                window.removeEventListener("resize", onResize)
                container.removeEventListener("pointerdown", focusTerminal)
                window.removeEventListener("focusin", deactivateTerminal)
                window.removeEventListener("keydown", keydownHandler, true)
                window.removeEventListener("paste", pasteHandler, true)
                dataDisposable.dispose()
                binaryDisposable.dispose()
                ws.onmessage = null
                ws.onopen = null
                ws.onclose = null
                ws.onerror = null
                ws.close()
                terminal.dispose()
                pendingInputRef.current = []
                if (wsRef.current === ws) wsRef.current = null
                if (terminalRef.current === terminal) terminalRef.current = null
            }
        }, [fitAddon, flushPendingInput, onResize, sendTerminalData, setClose, wsUrl])

        return <div ref={terminalIdRef} tabIndex={0} {...props} />
    },
)

export const TerminalPage = () => {
    const { id } = useParams<{ id: string }>()
    const [open, setOpen] = useState(false)
    const terminal = useTerminal(id ? parseInt(id) : undefined)
    const terminalIdRef = useRef<HTMLDivElement>(null)
    return (
        <div className="px-8">
            <div className="flex mt-6 mb-4">
                <h1 className="flex-1 text-3xl font-bold tracking-tight">{`Terminal (${id})`}</h1>
                <div className="flex ml-auto self-end sm:self-auto gap-2 flex-wrap shrink-0">
                    <IconButton
                        icon="expand"
                        onClick={async () => {
                            await terminalIdRef.current?.requestFullscreen()
                        }}
                    />
                    <FMCard id={id} />
                </div>
            </div>
            {terminal?.session_id ? (
                <XtermComponent
                    ref={terminalIdRef}
                    className="h-[calc(100dvh-9rem)] min-h-[320px] mb-5 overflow-hidden rounded-md border bg-black focus:outline-none"
                    wsUrl={`/api/v1/ws/terminal/${terminal?.session_id}`}
                    setClose={setOpen}
                />
            ) : (
                <p>The server does not exist, or have not been connected yet.</p>
            )}
            <AlertDialog open={open} onOpenChange={setOpen}>
                <AlertDialogContent className="sm:max-w-lg">
                    <AlertDialogHeader>
                        <AlertDialogTitle>Session completed</AlertDialogTitle>
                        <AlertDialogDescription>
                            You may close this window now.
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogAction asChild>
                            <Button onClick={window.close}>Close</Button>
                        </AlertDialogAction>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>
        </div>
    )
}

export const TerminalButton = ({ id, menuItem = false }: { id: number; menuItem?: boolean }) => {
    const { t } = useTranslation()
    const handleOpenNewTab = () => {
        window.open(`/dashboard/terminal/${id}`, "_blank")
    }

    if (menuItem) {
        return (
            <button
                type="button"
                onClick={handleOpenNewTab}
                className="flex w-full items-center text-sm px-2 py-2 hover:bg-accent hover:text-accent-foreground"
            >
                <TerminalIcon className="h-4 w-4 mr-2" />
                <span>{t("Terminal")}</span>
            </button>
        )
    }

    return <IconButton variant="outline" icon="terminal" onClick={handleOpenNewTab} />
}
