.class public Lcom/pttbridge/LocSender;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;

# Delivers one GPS fix line to the porto-watchdog daemon over the
# abstract local socket "porto_loc" (connect, write, close - the same
# per-event pattern the daemon uses toward our "ptt_bridge" socket).
# If the daemon is not running or not listening, the connect fails and
# the fix is silently dropped.

.field private msg:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/pttbridge/LocSender;->msg:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public run()V
    .locals 4

    :try_start
    new-instance v0, Landroid/net/LocalSocket;

    invoke-direct {v0}, Landroid/net/LocalSocket;-><init>()V

    new-instance v1, Landroid/net/LocalSocketAddress;

    const-string v2, "porto_loc"

    sget-object v3, Landroid/net/LocalSocketAddress$Namespace;->ABSTRACT:Landroid/net/LocalSocketAddress$Namespace;

    invoke-direct {v1, v2, v3}, Landroid/net/LocalSocketAddress;-><init>(Ljava/lang/String;Landroid/net/LocalSocketAddress$Namespace;)V

    invoke-virtual {v0, v1}, Landroid/net/LocalSocket;->connect(Landroid/net/LocalSocketAddress;)V

    invoke-virtual {v0}, Landroid/net/LocalSocket;->getOutputStream()Ljava/io/OutputStream;

    move-result-object v1

    iget-object v2, p0, Lcom/pttbridge/LocSender;->msg:Ljava/lang/String;

    invoke-virtual {v2}, Ljava/lang/String;->getBytes()[B

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/io/OutputStream;->write([B)V

    invoke-virtual {v1}, Ljava/io/OutputStream;->flush()V

    invoke-virtual {v0}, Landroid/net/LocalSocket;->close()V
    :try_end
    .catch Ljava/lang/Exception; {:try_start .. :try_end} :bail

    :bail
    return-void
.end method
