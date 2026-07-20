.class Lcom/pttbridge/BridgeService$SocketThread;
.super Ljava/lang/Thread;


# instance fields
.field private mService:Lcom/pttbridge/BridgeService;


# direct methods
.method public constructor <init>(Lcom/pttbridge/BridgeService;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Thread;-><init>()V

    iput-object p1, p0, Lcom/pttbridge/BridgeService$SocketThread;->mService:Lcom/pttbridge/BridgeService;

    return-void
.end method


# virtual methods
.method public run()V
    .locals 6

    :goto_0
    :try_start_0
    new-instance v0, Landroid/net/LocalServerSocket;

    const-string v1, "ptt_bridge"

    invoke-direct {v0, v1}, Landroid/net/LocalServerSocket;-><init>(Ljava/lang/String;)V

    :cond_0
    :goto_1
    invoke-virtual {v0}, Landroid/net/LocalServerSocket;->accept()Landroid/net/LocalSocket;

    move-result-object v1

    invoke-virtual {v1}, Landroid/net/LocalSocket;->getInputStream()Ljava/io/InputStream;

    move-result-object v2

    invoke-virtual {v2}, Ljava/io/InputStream;->read()I

    move-result v3

    invoke-virtual {v1}, Landroid/net/LocalSocket;->close()V

    iget-object v4, p0, Lcom/pttbridge/BridgeService$SocketThread;->mService:Lcom/pttbridge/BridgeService;

    const/16 v5, 0x31

    if-ne v3, v5, :cond_1

    const-string v5, "on"

    invoke-virtual {v4, v5}, Lcom/pttbridge/BridgeService;->sendTalk(Ljava/lang/String;)V

    goto :goto_1

    :cond_1
    const/16 v5, 0x30

    if-ne v3, v5, :cond_0

    const-string v5, "off"

    invoke-virtual {v4, v5}, Lcom/pttbridge/BridgeService;->sendTalk(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :catch_0
    move-exception v0

    const-wide/16 v1, 0x3e8

    :try_start_1
    invoke-static {v1, v2}, Ljava/lang/Thread;->sleep(J)V
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_0

    :catch_1
    return-void
.end method
