.class public Lcom/pttbridge/HealthRunner;
.super Ljava/lang/Object;

# interfaces
.implements Ljava/lang/Runnable;


# Self-healing watchdog: once a minute, verify that Mumla and the
# porto-watchdog daemon are alive (by scanning /proc cmdlines) and
# relaunch whichever died. Radios in the field have no adb cable -
# they must recover on their own. On any doubt (unreadable /proc)
# isRunning() reports true so we never spawn duplicates.

# static fields
.field private static started:Z


# instance fields
.field private final svc:Lcom/pttbridge/BridgeService;


# direct methods
.method public constructor <init>(Lcom/pttbridge/BridgeService;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/pttbridge/HealthRunner;->svc:Lcom/pttbridge/BridgeService;

    return-void
.end method

.method static isRunning(Ljava/lang/String;)Z
    .locals 8

    :try_start_all
    new-instance v0, Ljava/io/File;

    const-string v1, "/proc"

    invoke-direct {v0, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/io/File;->listFiles()[Ljava/io/File;

    move-result-object v0

    if-nez v0, :cond_have_list

    const/4 v1, 0x1

    return v1

    :cond_have_list
    array-length v1, v0

    const/4 v2, 0x0

    :goto_loop
    if-ge v2, v1, :cond_ok

    goto :goto_body

    :cond_ok
    const/4 v1, 0x0

    return v1

    :goto_body
    aget-object v3, v0, v2

    invoke-virtual {v3}, Ljava/io/File;->getName()Ljava/lang/String;

    move-result-object v4

    const/4 v5, 0x0

    invoke-virtual {v4, v5}, Ljava/lang/String;->charAt(I)C

    move-result v4

    const/16 v5, 0x30

    if-lt v4, v5, :goto_next

    const/16 v5, 0x39

    if-gt v4, v5, :goto_next

    :try_start_inner
    new-instance v4, Ljava/io/FileInputStream;

    new-instance v5, Ljava/io/File;

    const-string v6, "cmdline"

    invoke-direct {v5, v3, v6}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-direct {v4, v5}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V

    const/16 v5, 0x80

    new-array v5, v5, [B

    invoke-virtual {v4, v5}, Ljava/io/FileInputStream;->read([B)I

    move-result v6

    invoke-virtual {v4}, Ljava/io/FileInputStream;->close()V

    if-lez v6, :goto_next

    const/4 v4, 0x0

    :goto_nul
    if-ge v4, v6, :goto_nul_end

    aget-byte v7, v5, v4

    if-eqz v7, :goto_nul_end

    add-int/lit8 v4, v4, 0x1

    goto :goto_nul

    :goto_nul_end
    new-instance v7, Ljava/lang/String;

    const/4 v3, 0x0

    invoke-direct {v7, v5, v3, v4}, Ljava/lang/String;-><init>([BII)V

    invoke-virtual {p0, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :goto_next

    const/4 v3, 0x1

    return v3
    :try_end_inner
    .catch Ljava/lang/Exception; {:try_start_inner .. :try_end_inner} :catch_inner

    :catch_inner
    move-exception v3

    :goto_next
    add-int/lit8 v2, v2, 0x1

    goto :goto_loop
    :try_end_all
    .catch Ljava/lang/Exception; {:try_start_all .. :try_end_all} :catch_all

    :catch_all
    move-exception v0

    const/4 v1, 0x1

    return v1
.end method


# virtual methods
.method private check()V
    .locals 3

    :try_start_0
    const-string v0, "se.lublin.mumla"

    invoke-static {v0}, Lcom/pttbridge/HealthRunner;->isRunning(Ljava/lang/String;)Z

    move-result v0

    if-nez v0, :cond_daemon

    const-string v0, "pttbridge"

    const-string v1, "heal: mumla not running - relaunching"

    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    iget-object v0, p0, Lcom/pttbridge/HealthRunner;->svc:Lcom/pttbridge/BridgeService;

    invoke-static {v0}, Lcom/pttbridge/BridgeService;->launchMumla(Landroid/content/Context;)V

    new-instance v0, Ljava/lang/Thread;

    new-instance v1, Lcom/pttbridge/BridgeService$HomeRunner;

    iget-object v2, p0, Lcom/pttbridge/HealthRunner;->svc:Lcom/pttbridge/BridgeService;

    invoke-direct {v1, v2}, Lcom/pttbridge/BridgeService$HomeRunner;-><init>(Lcom/pttbridge/BridgeService;)V

    invoke-direct {v0, v1}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    :cond_daemon
    const-string v0, "/data/local/tmp/ptt_bridge"

    invoke-static {v0}, Lcom/pttbridge/HealthRunner;->isRunning(Ljava/lang/String;)Z

    move-result v0

    if-nez v0, :cond_done

    const-string v0, "pttbridge"

    const-string v1, "heal: daemon not running - relaunching"

    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    invoke-static {}, Lcom/pttbridge/BridgeService;->launchDaemon()V

    :cond_done
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception v0

    return-void
.end method

.method public run()V
    .locals 2

    sget-boolean v0, Lcom/pttbridge/HealthRunner;->started:Z

    if-eqz v0, :cond_fresh

    return-void

    :cond_fresh
    const/4 v0, 0x1

    sput-boolean v0, Lcom/pttbridge/HealthRunner;->started:Z

    const-wide/32 v0, 0x15f90

    :try_start_0
    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_ret

    :goto_loop
    invoke-direct {p0}, Lcom/pttbridge/HealthRunner;->check()V

    const-wide/32 v0, 0xea60

    :try_start_1
    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_ret

    goto :goto_loop

    :catch_ret
    move-exception v0

    return-void
.end method
