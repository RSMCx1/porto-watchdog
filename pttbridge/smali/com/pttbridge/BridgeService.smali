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

# Launch the porto-watchdog daemon (idempotence is the caller's job -
# check HealthRunner.isRunning first).
.method public static launchDaemon()V
    .locals 4

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

    # Resolved at runtime: radios that cannot exec from /data/local/tmp run the
    # copy packaged in the APK instead. Returns this radio's existing logwrapper
    # command unchanged unless input_source=keyevent.
    invoke-static {}, Lcom/pttbridge/Paths;->launchCommand()Ljava/lang/String;

    move-result-object v3

    aput-object v3, v1, v2

    invoke-virtual {v0, v1}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;
    :try_end_exec
    .catch Ljava/lang/Exception; {:try_start_exec .. :try_end_exec} :catch_exec

    :catch_exec
    return-void
.end method

# Launch Mumla and inject the auto-connect keypresses (green button
# twice after 8s), then hand over to Inject for radios that need the
# framework path instead. The input node is read from knob.conf's button_device=
# (the green button shares the gpio-keys device with the side buttons),
# falling back to /dev/input/event3 - so one APK works across hardware revs
# whose /dev/input/eventN numbering differs (e.g. IMU-equipped units).
.method public static launchMumla(Landroid/content/Context;)V
    .locals 4

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

    const-string v3, "sleep 8; B=$(grep '^button_device=' /data/local/tmp/knob.conf 2>/dev/null | head -1 | cut -d= -f2 | tr -cd 'a-z0-9/'); B=${B:-/dev/input/event3}; sendevent $B 1 28 1; sendevent $B 0 0 0; sendevent $B 1 28 0; sendevent $B 0 0 0; sendevent $B 1 28 1; sendevent $B 0 0 0; sendevent $B 1 28 0; sendevent $B 0 0 0"

    aput-object v3, v1, v2

    invoke-virtual {v0, v1}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;
    :try_end_autoconnect
    .catch Ljava/lang/Exception; {:try_start_autoconnect .. :try_end_autoconnect} :catch_autoconnect

    :catch_autoconnect
    # Auto-connect for radios where the sendevent sequence above cannot work:
    # SELinux may deny /dev/input outright, and gpio-keys need not even declare
    # KEY_ENTER. Inject no-ops unless input_source=keyevent, so evdev radios keep
    # exactly the behaviour above and never press ENTER twice. Placed after the
    # catch so a failed exec above does not skip it.
    invoke-static {}, Lcom/pttbridge/Inject;->autoConnect()V

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
    .locals 3

    # Daemon: only when not already running - repeated START intents
    # (and the HealthRunner) must never spawn duplicates
    invoke-static {}, Lcom/pttbridge/Paths;->daemon()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Lcom/pttbridge/HealthRunner;->isRunning(Ljava/lang/String;)Z

    move-result v0

    if-nez v0, :skip_daemon

    invoke-static {}, Lcom/pttbridge/BridgeService;->launchDaemon()V

    :skip_daemon
    # Mumla: only when not already running; a fresh launch gets the
    # auto-connect injection and the return-to-home thread
    const-string v0, "se.lublin.mumla"

    invoke-static {v0}, Lcom/pttbridge/HealthRunner;->isRunning(Ljava/lang/String;)Z

    move-result v0

    if-nez v0, :skip_mumla_start

    invoke-static {p0}, Lcom/pttbridge/BridgeService;->launchMumla(Landroid/content/Context;)V

    new-instance v0, Ljava/lang/Thread;

    new-instance v1, Lcom/pttbridge/BridgeService$HomeRunner;

    invoke-direct {v1, p0}, Lcom/pttbridge/BridgeService$HomeRunner;-><init>(Lcom/pttbridge/BridgeService;)V

    invoke-direct {v0, v1}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    :skip_mumla_start
    # Long-lived threads: once per service instance
    iget-object v0, p0, Lcom/pttbridge/BridgeService;->mThread:Ljava/lang/Thread;

    if-nez v0, :skip_threads

    # GPS reporter (no-op unless /data/local/tmp/loc.conf exists)
    new-instance v0, Ljava/lang/Thread;

    new-instance v1, Lcom/pttbridge/LocRunner;

    invoke-direct {v1, p0}, Lcom/pttbridge/LocRunner;-><init>(Landroid/content/Context;)V

    invoke-direct {v0, v1}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    # Self-healing watchdog (relaunches Mumla/daemon if they die)
    new-instance v0, Ljava/lang/Thread;

    new-instance v1, Lcom/pttbridge/HealthRunner;

    invoke-direct {v1, p0}, Lcom/pttbridge/HealthRunner;-><init>(Lcom/pttbridge/BridgeService;)V

    invoke-direct {v0, v1}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    # PTT socket server
    new-instance v0, Lcom/pttbridge/BridgeService$SocketThread;

    invoke-direct {v0, p0}, Lcom/pttbridge/BridgeService$SocketThread;-><init>(Lcom/pttbridge/BridgeService;)V

    iput-object v0, p0, Lcom/pttbridge/BridgeService;->mThread:Ljava/lang/Thread;

    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    :skip_threads
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
