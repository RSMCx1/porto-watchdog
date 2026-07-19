.class Lcom/pttbridge/BridgeService$HomeRunner;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;

# Sleeps 15 seconds then sends the user to the home screen.
# Uses startActivity(HOME intent) - same mechanism BridgeService
# already uses to launch Mumla, so permissions are guaranteed.

# instance fields
.field private outer:Lcom/pttbridge/BridgeService;


# direct methods
.method constructor <init>(Lcom/pttbridge/BridgeService;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/pttbridge/BridgeService$HomeRunner;->outer:Lcom/pttbridge/BridgeService;

    return-void
.end method


# virtual methods
.method public run()V
    .locals 3

    :try_start
    const-wide/16 v0, 15000

    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V

    new-instance v0, Landroid/content/Intent;

    const-string v1, "android.intent.action.MAIN"

    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    const-string v1, "android.intent.category.HOME"

    invoke-virtual {v0, v1}, Landroid/content/Intent;->addCategory(Ljava/lang/String;)Landroid/content/Intent;

    const/high16 v1, 0x10000000

    invoke-virtual {v0, v1}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    iget-object v1, p0, Lcom/pttbridge/BridgeService$HomeRunner;->outer:Lcom/pttbridge/BridgeService;

    invoke-virtual {v1, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    :try_end
    .catch Ljava/lang/Exception; {:try_start .. :try_end} :catch

    :catch
    return-void
.end method
