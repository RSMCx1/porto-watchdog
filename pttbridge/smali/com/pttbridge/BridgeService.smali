.class public Lcom/pttbridge/BridgeService;
.super Landroid/app/Service;


# instance fields
.field private mThread:Ljava/lang/Thread;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroid/app/Service;-><init>()V

    return-void
.end method


# virtual methods
.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public onDestroy()V
    .locals 1

    iget-object v0, p0, Lcom/pttbridge/BridgeService;->mThread:Ljava/lang/Thread;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/Thread;->interrupt()V

    :cond_0
    invoke-super {p0}, Landroid/app/Service;->onDestroy()V

    return-void
.end method

.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 4

    # Launch the porto-watchdog binary in background with logging
    :try_start_exec
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v0

    const/4 v1, 0x3

    new-array v1, v1, [Ljava/lang/String;

    const/4 v2, 0x0

    const-string v3, "/system/bin/sh"

    aput-object v3, v1, v2

    const/4 v2, 0x1

    const-string v3, "-c"

    aput-object v3, v1, v2

    const/4 v2, 0x2

    const-string v3, "exec /system/bin/logwrapper /data/local/tmp/ptt_bridge"

    aput-object v3, v1, v2

    invoke-virtual {v0, v1}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;
    :try_end_exec
    .catch Ljava/lang/Exception; {:try_start_exec .. :try_end_exec} :catch_exec

    :catch_exec

    # Launch Mumla and auto-connect to favorited server
    :try_start_mumla
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v0

    const-string v1, "se.lublin.mumla"

    invoke-virtual {v0, v1}, Landroid/content/pm/PackageManager;->getLaunchIntentForPackage(Ljava/lang/String;)Landroid/content/Intent;

    move-result-object v0

    if-eqz v0, :skip_mumla

    const/high16 v1, 0x10000000

    invoke-virtual {v0, v1}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    invoke-virtual {p0, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    :skip_mumla
    :try_end_mumla
    .catch Ljava/lang/Exception; {:try_start_mumla .. :try_end_mumla} :catch_mumla

    :catch_mumla

    # Auto-connect: inject green button (KEY_ENTER) via hardware device, then HOME
    :try_start_autoconnect
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v0

    const/4 v1, 0x3

    new-array v1, v1, [Ljava/lang/String;

    const/4 v2, 0x0

    const-string v3, "/system/bin/sh"

    aput-object v3, v1, v2

    const/4 v2, 0x1

    const-string v3, "-c"

    aput-object v3, v1, v2

    const/4 v2, 0x2

    const-string v3, "sleep 8 && sendevent /dev/input/event3 1 28 1 && sendevent /dev/input/event3 0 0 0 && sendevent /dev/input/event3 1 28 0 && sendevent /dev/input/event3 0 0 0 && sendevent /dev/input/event3 1 28 1 && sendevent /dev/input/event3 0 0 0 && sendevent /dev/input/event3 1 28 0 && sendevent /dev/input/event3 0 0 0"

    aput-object v3, v1, v2

    invoke-virtual {v0, v1}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;
    :try_end_autoconnect
    .catch Ljava/lang/Exception; {:try_start_autoconnect .. :try_end_autoconnect} :catch_autoconnect

    :catch_autoconnect

    # Start HOME thread: sleep 15s then go to home screen (puts Mumla in background)
    new-instance v0, Ljava/lang/Thread;
    new-instance v1, Lcom/pttbridge/BridgeService$HomeRunner;
    invoke-direct {v1, p0}, Lcom/pttbridge/BridgeService$HomeRunner;-><init>(Lcom/pttbridge/BridgeService;)V
    invoke-direct {v0, v1}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    # Start GPS reporter thread (no-op unless /data/local/tmp/loc.conf
    # exists with an interval > 0 - see LocRunner)
    new-instance v0, Ljava/lang/Thread;
    new-instance v1, Lcom/pttbridge/LocRunner;
    invoke-direct {v1, p0}, Lcom/pttbridge/LocRunner;-><init>(Landroid/content/Context;)V
    invoke-direct {v0, v1}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    # Start the PTT socket thread
    new-instance v0, Lcom/pttbridge/BridgeService$SocketThread;

    invoke-direct {v0, p0}, Lcom/pttbridge/BridgeService$SocketThread;-><init>(Lcom/pttbridge/BridgeService;)V

    iput-object v0, p0, Lcom/pttbridge/BridgeService;->mThread:Ljava/lang/Thread;

    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    const/4 v0, 0x1

    return v0
.end method

.method public sendTalk(Ljava/lang/String;)V
    .locals 3

    new-instance v0, Landroid/content/Intent;

    const-string v1, "se.lublin.mumla.action.TALK"

    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    const-string v1, "se.lublin.mumla"

    invoke-virtual {v0, v1}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    const-string v1, "status"

    invoke-virtual {v0, v1, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    invoke-virtual {p0, v0}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V

    return-void
.end method
