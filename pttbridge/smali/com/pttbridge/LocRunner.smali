.class public Lcom/pttbridge/LocRunner;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;

# GPS reporting bootstrap. Sleeps 20s (lets boot + WiFi settle), then
# reads /data/local/tmp/loc.conf. The file holds a single integer:
# the GPS update interval in seconds. If the file is missing, empty,
# or <= 0, GPS is never activated (feature is opt-in per radio).
#
# Fixes are delivered by LocListener to the porto-watchdog daemon via
# the abstract local socket "porto_loc" (see LocSender).
#
# Requires ACCESS_FINE_LOCATION granted once during onboarding:
#   adb shell pm grant com.pttbridge android.permission.ACCESS_FINE_LOCATION

.field private ctx:Landroid/content/Context;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/pttbridge/LocRunner;->ctx:Landroid/content/Context;

    return-void
.end method


# virtual methods
.method public run()V
    .locals 9

    :try_start
    const-wide/16 v0, 20000

    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V

    new-instance v0, Ljava/io/BufferedReader;

    new-instance v1, Ljava/io/FileReader;

    const-string v2, "/data/local/tmp/loc.conf"

    invoke-direct {v1, v2}, Ljava/io/FileReader;-><init>(Ljava/lang/String;)V

    invoke-direct {v0, v1}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    invoke-virtual {v0}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0}, Ljava/io/BufferedReader;->close()V

    invoke-virtual {v1}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v3

    if-lez v3, :bail

    iget-object v0, p0, Lcom/pttbridge/LocRunner;->ctx:Landroid/content/Context;

    const-string v1, "location"

    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/location/LocationManager;

    const-string v1, "gps"

    int-to-long v2, v3

    const-wide/16 v7, 0x3e8

    mul-long/2addr v2, v7

    const/4 v4, 0x0

    new-instance v5, Lcom/pttbridge/LocListener;

    invoke-direct {v5}, Lcom/pttbridge/LocListener;-><init>()V

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v6

    invoke-virtual/range {v0 .. v6}, Landroid/location/LocationManager;->requestLocationUpdates(Ljava/lang/String;JFLandroid/location/LocationListener;Landroid/os/Looper;)V
    :try_end
    .catch Ljava/lang/Exception; {:try_start .. :try_end} :bail

    :bail
    return-void
.end method
